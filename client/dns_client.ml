open Dns

module Pure = struct

  type 'key query_state =
    { protocol : Dns.proto ;
      key: 'key ;
      query : Packet.t ;
    } constraint 'key = 'a Rr_map.key

  let make_query rng protocol hostname
      : 'xy  ->
        Cstruct.t * 'xy query_state =
    (* SRV records: Service + Protocol are case-insensitive, see RFC2728 pg2. *)
    fun record_type ->
    let question = Packet.Question.create hostname record_type in
    let header = Randomconv.int16 rng, Packet.Flags.singleton `Recursion_desired in
    let query = Packet.create header question `Query in
    let cs , _ = Packet.encode protocol query in
    begin match protocol with
      | `Udp -> cs
      | `Tcp ->
        let len_field = Cstruct.create 2 in
        Cstruct.BE.set_uint16 len_field 0 (Cstruct.len cs) ;
        Cstruct.concat [len_field ; cs]
    end, { protocol ; query ; key = record_type }

  (* name: the originally requested domain name. *)
  let rec follow_cname name ~iterations:iterations_left ~answer ~state =
    let open Rresult in
    if iterations_left <= 0 then Error (`Msg "CNAME recursion too deep")
    else
      Domain_name.Map.find_opt name answer
      |> R.of_option ~none:(fun () ->
          R.error_msgf "Can't find relevant map in response:@ %a in [%a]"
            Domain_name.pp name
            Name_rr_map.pp answer
        ) >>= fun relevant_map ->
      match Rr_map.find state.key relevant_map with
        | Some response -> Ok response
        | None ->
          match Rr_map.(find Cname relevant_map) with
            | None -> Error (`Msg "Invalid DNS response")
            | Some (_ttl, redirected_host) ->
              let iterations = pred iterations_left in
              follow_cname redirected_host ~iterations ~answer ~state

  let consume_protocol_prefix buf =
    function (* consume TCP two-byte length prefix: *)
    | `Udp -> Ok buf
    | `Tcp ->
      match Cstruct.BE.get_uint16 buf 0 with
        | exception Invalid_argument _ -> Error () (* TODO *)
        | pkt_len when pkt_len > Cstruct.len buf -2 ->
          Logs.debug (fun m -> m "Partial: %d >= %d-2"
                          pkt_len (Cstruct.len buf));
          Error () (* TODO return remaining # *)
        | pkt_len ->
          if 2 + pkt_len < Cstruct.len buf then
            Logs.warn (fun m -> m "Extraneous data in DNS response");
          Ok (Cstruct.sub buf 2 pkt_len)

  let consume_rest_of_buffer state buf =
    let open Rresult in
    let to_msg t = function
      | Ok a -> Ok a
      | Error e ->
        R.error_msgf
          "QUERY: @[<v>hdr:%a (id: %d = %d) (q=q: %B)@ query:%a%a  opt:%a tsig:%B@,failed: %a@,@]"
          Packet.pp_header t
          (fst t.header) (fst state.query.header)
          (Packet.Question.compare t.question state.query.question = 0)
          Packet.Question.pp t.question
          Packet.pp_data t.data
          (Fmt.option Dns.Edns.pp) t.edns
          (match t.tsig with None -> false | Some _ -> true)
          Packet.pp_mismatch e
    in
    match Packet.decode buf with
    | Error `Partial -> `Partial
    | Error err ->
      let kerr _ = `Msg (Format.flush_str_formatter ()) in
      Format.kfprintf kerr Format.str_formatter "Error parsing response: %a" Packet.pp_err err
    | Ok t ->
      let r =
        to_msg t (Packet.reply_matches_request ~request:state.query t) >>= function
        | `Answer (answer, _) -> follow_cname (fst state.query.question) ~iterations:20 ~answer ~state
        | r -> Error (`Msg (Fmt.strf "Ok %a, expected answer" Packet.pp_reply r))
      in 
      match r with
      | Ok x -> `Ok x
      | Error (`Msg x) -> `Msg x

  let parse_response (type requested)
    : requested Rr_map.key query_state -> Cstruct.t ->
      [`Ok of requested | `Partial | `Msg of string] =
    fun state buf ->
    match consume_protocol_prefix buf state.protocol with
    | Ok buf -> consume_rest_of_buffer state buf
    | Error () -> `Partial

end


let stdlib_random n =
  let b = Cstruct.create n in
  for i = 0 to pred n do
    Cstruct.set_uint8 b i (Random.int 256)
  done;
  b

module type S = sig
  type flow
  type +'a io
  type io_addr
  type ns_addr = ([`TCP | `UDP]) * io_addr
  type stack
  type t

  val create : ?rng:(int -> Cstruct.t) -> ?nameserver:ns_addr -> stack -> t

  val nameserver : t -> ns_addr
  val rng : t -> (int -> Cstruct.t)

  val connect : ?nameserver:ns_addr -> t -> (flow, [> `Msg of string ]) result io
  val send : flow -> Cstruct.t -> (unit, [> `Msg of string ]) result io
  val recv : flow -> (Cstruct.t, [> `Msg of string ]) result io
  val close : flow -> unit io

  val bind : 'a io -> ('a -> 'b io) -> 'b io
  val lift : 'a -> 'a io
end

module Make = functor (Uflow:S) ->
struct

  let create ?rng ?nameserver stack = Uflow.create ?rng ?nameserver stack

  let nameserver t = Uflow.nameserver t

  let (>>=) = Uflow.bind

  (* result-bind *)
  let (>>|) a b =
    a >>= function
    | Ok a' -> b a'
    | Error e -> Uflow.lift (Error e)

  (* result-bind-and-lift *)
  let (>>|=) a f = a >>| fun b -> Uflow.lift (f b)

  let getaddrinfo (type requested) t ?nameserver (query_type:requested Dns.Rr_map.key) name
    : (requested, [> `Msg of string]) result Uflow.io =
    let proto, _ = match nameserver with None -> Uflow.nameserver t | Some x -> x in
    let tx, state =
      Pure.make_query (Uflow.rng t)
        (match proto with `UDP -> `Udp | `TCP -> `Tcp) name query_type
    in
    Uflow.connect ?nameserver t >>| fun socket ->
    Logs.debug (fun m -> m "Connected to NS.");
    (Uflow.send socket tx >>| fun () ->
     Logs.debug (fun m -> m "Receiving from NS");
     let rec recv_loop acc =
       Uflow.recv socket >>| fun recv_buffer ->
       Logs.debug (fun m -> m "Read @[<v>%d bytes@]"
                      (Cstruct.len recv_buffer)) ;
       let buf = Cstruct.append acc recv_buffer in
       match Pure.parse_response state buf with
       | `Ok x -> Uflow.lift (Ok x)
       | `Msg xxx -> Uflow.lift (Error (`Msg( "err: " ^ xxx)))
       | `Partial when proto = `TCP -> recv_loop buf
       | `Partial -> Uflow.lift (Error (`Msg "Truncated UDP response"))
    in recv_loop Cstruct.empty) >>= fun r ->
    Uflow.close socket >>= fun () ->
    Uflow.lift r

  let gethostbyname stack ?nameserver domain =
    getaddrinfo stack ?nameserver Dns.Rr_map.A domain >>|= fun (_ttl, resp) ->
    match Dns.Rr_map.Ipv4_set.choose_opt resp with
    | None -> Error (`Msg "No A record found")
    | Some ip -> Ok ip

  let gethostbyname6 stack ?nameserver domain =
    getaddrinfo stack ?nameserver Dns.Rr_map.Aaaa domain >>|= fun (_ttl, res) ->
    match Dns.Rr_map.Ipv6_set.choose_opt res with
    | None -> Error (`Msg "No AAAA record found")
    | Some ip -> Ok ip
end
