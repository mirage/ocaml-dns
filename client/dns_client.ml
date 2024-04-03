open Dns

let src = Logs.Src.create "dns_client" ~doc:"DNS client"
module Log = (val Logs.src_log src : Logs.LOG)

module Pure = struct

  type 'key query_state =
    { protocol : Dns.proto ;
      key: 'key ;
      query : Packet.t ;
    } constraint 'key = 'a Rr_map.key

  let make_query rng protocol ?(dnssec = false) edns hostname
      : 'xy  ->
        string * 'xy query_state =
    (* SRV records: Service + Protocol are case-insensitive, see RFC2728 pg2. *)
    fun record_type ->
    let edns = match edns with
      | `None -> None
      | `Manual e -> Some e
      | `Auto -> match protocol with
        | `Udp -> None
        | `Tcp -> Some (Edns.create ~extensions:[Edns.Tcp_keepalive (Some 1200)] ())
    in
    let question = Packet.Question.create hostname record_type in
    let header =
      let flags = Packet.Flags.singleton `Recursion_desired in
      let flags =
        if dnssec then Packet.Flags.add `Authentic_data flags else flags
      in
      Randomconv.int16 rng, flags
    in
    let query = Packet.create ?edns header question `Query in
    Log.debug (fun m -> m "sending %a" Dns.Packet.pp query);
    let cs , _ = Packet.encode protocol query in
    begin match protocol with
      | `Udp -> cs
      | `Tcp ->
        let len_field = Bytes.create 2 in
        Bytes.set_uint16_be len_field 0 (String.length cs) ;
        String.concat "" [Bytes.unsafe_to_string len_field ; cs]
    end, { protocol ; query ; key = record_type }

  (* name: the originally requested domain name. *)
  (* NOTE that this function compresses answers:
     foo.example CNAME 500 bar.example
     bar.example A 300 1.2.3.4
     is compressed to:
     foo.example A 300 1.2.3.4
     -> which is fine for applications (i think so)
     -> which is struggling for the cache (not entirely sure about this tbh)
     -> it is not clear whether it meets the DNS specifications nicely *)
  let rec follow_cname name ~iterations:iterations_left ~answer ~state =
    if iterations_left <= 0
    then Error (`Msg "CNAME recursion too deep")
    else
      match Domain_name.Map.find_opt name answer with
      | None -> Ok (`Need_soa name)
      | Some relevant_map ->
        match Rr_map.find state.key relevant_map with
        | Some response -> Ok (`Data response)
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
      match String.get_uint16_be buf 0 with
        | exception Invalid_argument _ -> Error () (* TODO *)
        | pkt_len when pkt_len > String.length buf -2 ->
          Log.debug (fun m -> m "Partial: %d >= %d-2"
                          pkt_len (String.length buf));
          Error () (* TODO return remaining # *)
        | pkt_len ->
          if 2 + pkt_len < String.length buf then
            Log.warn (fun m -> m "Extraneous data in DNS response");
          Ok (String.sub buf 2 pkt_len)

  let find_soa authority =
    Domain_name.Map.fold (fun k rr_map acc ->
        match Rr_map.(find Soa rr_map) with
        | Some soa -> Some (Domain_name.raw k, soa)
        | None -> acc)
      authority None

  let distinguish_answer state =
    let ( let* ) = Result.bind in
    function
    | `Answer (answer, authority) when not (Domain_name.Map.is_empty answer) ->
      begin
        let q = fst state.query.question in
        let* o = follow_cname q ~iterations:20 ~answer ~state in
        match o with
        | `Data x -> Ok (`Data x)
        | `Need_soa _name ->
          (* should we retain CNAMEs (and send them to the client)? *)
          (* should we 'adjust' the SOA name to be _name? *)
          match find_soa authority with
          | Some soa -> Ok (`No_data soa)
          | None -> Error (`Msg "invalid reply, couldn't find SOA")
      end
    | `Answer (_, authority) ->
      begin match find_soa authority with
        | Some soa -> Ok (`No_data soa)
        | None -> Error (`Msg "invalid reply, no SOA in no data")
      end
    | `Rcode_error (Rcode.NXDomain, Opcode.Query, Some (_answer, authority)) ->
      begin match find_soa authority with
        | Some soa -> Ok (`No_domain soa)
        | None -> Error (`Msg "invalid reply, no SOA in nodomain")
      end
    | r ->
      Error (`Msg (Fmt.str "Ok %a, expected answer" Packet.pp_reply r))

  let consume_rest_of_buffer state buf =
    let to_msg t =
      Result.map_error (fun e ->
          `Msg
            (Fmt.str
               "QUERY: @[<v>hdr:%a (id: %d = %d) (q=q: %B)@ query:%a%a \
                opt:%a tsig:%B@,failed: %a@,@]"
               Packet.pp_header t
               (fst t.header) (fst state.query.header)
               (Packet.Question.compare t.question state.query.question = 0)
               Packet.Question.pp t.question
               Packet.pp_data t.data
               (Fmt.option Dns.Edns.pp) t.edns
               (match t.tsig with None -> false | Some _ -> true)
               Packet.pp_mismatch e))
    in
    match Packet.decode buf with
    | Error `Partial as e -> e
    | Error err ->
      Error (`Msg (Fmt.str "Error parsing response: %a" Packet.pp_err err))
    | Ok t ->
      Log.debug (fun m -> m "received %a" Dns.Packet.pp t);
      to_msg t (Packet.reply_matches_request ~request:state.query t)

  let parse_response (type requested)
    : requested Rr_map.key query_state -> string ->
      (Packet.reply,
       [> `Partial
       | `Msg of string]) result =
    fun state buf ->
    match consume_protocol_prefix buf state.protocol with
    | Ok buf -> consume_rest_of_buffer state buf
    | Error () -> Error `Partial

  let handle_response (type requested)
    : requested Rr_map.key query_state -> string ->
      ( [ `Data of requested
        | `Partial
        | `No_data of [`raw] Domain_name.t * Soa.t
        | `No_domain of [`raw] Domain_name.t * Soa.t ],
        [`Msg of string]) result =
    fun state buf ->
    match parse_response state buf with
    | Error `Partial -> Ok `Partial
    | Error `Msg _ as e -> e
    | Ok reply -> distinguish_answer state reply
end

(* Anycast address of uncensoreddns.org *)
let default_resolver_hostname = Domain_name.(host_exn (of_string_exn "anycast.uncensoreddns.org"))
let default_resolvers = [
  Ipaddr.of_string_exn "2001:67c:28a4::" ;
  Ipaddr.of_string_exn "91.239.100.100" ;
]

module type S = sig
  type context
  type +'a io
  type io_addr
  type stack
  type t

  val create : ?nameservers:(Dns.proto * io_addr list) -> timeout:int64 -> stack -> t

  val nameservers : t -> Dns.proto * io_addr list
  val rng : int -> string
  val clock : unit -> int64

  val connect : t -> (Dns.proto * context, [> `Msg of string ]) result io
  val send_recv : context -> string -> (string, [> `Msg of string ]) result io
  val close : context -> unit io

  val bind : 'a io -> ('a -> 'b io) -> 'b io
  val lift : 'a -> 'a io
end

let localhost = Domain_name.of_string_exn "localhost"
let localsoa = Soa.create (Domain_name.prepend_label_exn localhost "ns")
let invalid = Domain_name.of_string_exn "invalid"
let invalidsoa = Soa.create (Domain_name.prepend_label_exn invalid "ns")

let rfc6761_special (type req) q_name (q_typ : req Dns.Rr_map.key) : (req Dns_cache.entry, unit) result =
  if Domain_name.is_subdomain ~domain:localhost ~subdomain:q_name then
    let open Dns.Rr_map in
    match q_typ with
    | A -> Ok (`Entry (300l, Ipaddr.V4.Set.singleton Ipaddr.V4.localhost))
    | Aaaa ->
      Ok (`Entry (300l, Ipaddr.V6.Set.singleton Ipaddr.V6.localhost))
    | _ -> Ok (`No_domain (localhost, localsoa))
  else if Domain_name.is_subdomain ~domain:invalid ~subdomain:q_name then
    Ok (`No_domain (invalid, invalidsoa))
  else
    Error ()

module Make = functor (Transport:S) ->
struct

  type t = {
    mutable cache : Dns_cache.t ;
    transport : Transport.t ;
    edns : [ `None | `Auto | `Manual of Dns.Edns.t ] ;
  }

  let transport { transport ; _ } = transport

  (* TODO eventually use Auto, and retry without on FormErr *)
  let create ?(cache_size = 32) ?(edns = `None) ?nameservers ?(timeout = Duration.of_sec 5) stack =
    { cache = Dns_cache.empty cache_size ;
      transport = Transport.create ?nameservers ~timeout stack ;
      edns ;
    }

  let nameservers { transport; _ } = Transport.nameservers transport

  let (>>=) = Transport.bind

  (* result-bind *)
  let (>>|) a b =
    a >>= function
    | Ok a' -> b a'
    | Error e -> Transport.lift (Error e)

  (* result-bind-and-lift *)
  let (>>|=) a f = a >>| fun b -> Transport.lift (f b)

  let lift_ok (type req) :
    (req Dns_cache.entry, 'a) result ->
    (req, [> `Msg of string
          | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
          | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t ]) result
    = function
      | Ok `Entry value -> Ok value
      | Ok (`No_data _ as nodata) -> Error nodata
      | Ok (`No_domain _ as nodom) -> Error nodom
      | Ok (`Serv_fail _)
      | Error _ -> Error (`Msg "")

  let get_raw_reply t query_type name =
    Transport.connect t.transport >>| fun (proto, socket) ->
    Log.debug (fun m -> m "Connected to NS.");
    let tx, state =
      Pure.make_query Transport.rng proto ~dnssec:true t.edns name query_type
    in
    (Transport.send_recv socket tx >>| fun recv_buffer ->
     Log.debug (fun m -> m "Read @[<v>%d bytes@]"
                    (String.length recv_buffer)) ;
     Log.debug (fun m -> m "received: %a" (Ohex.pp_hexdump ()) recv_buffer);
     Transport.lift (Pure.parse_response state recv_buffer)) >>= fun r ->
    Transport.close socket >>= fun () ->
    Transport.lift r

  let get_resource_record (type requested) t (query_type:requested Dns.Rr_map.key) name
    : (requested, [> `Msg of string
                  | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
                  | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t ]) result Transport.io =
    let domain_name = Domain_name.raw name in
    match rfc6761_special domain_name query_type |> lift_ok with
    | Ok _ as ok -> Transport.lift ok
    | Error ((`No_data _ | `No_domain _) as nod) -> Error nod |> Transport.lift
    | Error `Msg _ ->
      let cache', r =
        Dns_cache.get t.cache (Transport.clock ()) domain_name query_type
      in
      t.cache <- cache';
      match lift_ok (Result.map fst r) with
      | Ok _ as ok -> Transport.lift ok
      | Error ((`No_data _ | `No_domain _) as nod) -> Error nod |> Transport.lift
      | Error `Msg _ ->
        Transport.connect t.transport >>| fun (proto, socket) ->
        Log.debug (fun m -> m "Connected to NS.");
        let tx, state =
          Pure.make_query Transport.rng proto t.edns name query_type
        in
        (Transport.send_recv socket tx >>| fun recv_buffer ->
         Log.debug (fun m -> m "Read @[<v>%d bytes@]"
                        (String.length recv_buffer)) ;
         let update_cache entry =
           let rank = Dns_cache.NonAuthoritativeAnswer in
           let cache =
             Dns_cache.set t.cache (Transport.clock ()) domain_name query_type rank entry
           in
           t.cache <- cache
         in
         Transport.lift
           (match Pure.handle_response state recv_buffer with
            | Ok `Data x ->
              update_cache (`Entry x);
              Ok x
            | Ok ((`No_data _ | `No_domain _) as nodom) ->
              update_cache nodom;
              Error nodom
            | Error `Msg xxx -> Error (`Msg xxx)
            | Ok `Partial -> Error (`Msg "Truncated UDP response"))) >>= fun r ->
        Transport.close socket >>= fun () ->
        Transport.lift r

  let lift_cache_error query_type m =
    (match m with
     | Ok a -> Ok a
     | Error `Msg msg -> Error (`Msg msg)
     | Error (#Dns_cache.entry as e) ->
       Error (`Msg (Fmt.str "DNS cache error @[%a@]" (Dns_cache.pp_entry query_type) e)))
    |> Transport.lift

  let getaddrinfo (type requested) t (query_type:requested Dns.Rr_map.key) name
    : (requested, [> `Msg of string ]) result Transport.io =
    get_resource_record t query_type name >>= lift_cache_error query_type

  let gethostbyname stack domain =
    getaddrinfo stack Dns.Rr_map.A domain >>|= fun (_ttl, resp) ->
    match Ipaddr.V4.Set.choose_opt resp with
    | None -> Error (`Msg "No A record found")
    | Some ip -> Ok ip

  let gethostbyname6 stack domain =
    getaddrinfo stack Dns.Rr_map.Aaaa domain >>|= fun (_ttl, res) ->
    match Ipaddr.V6.Set.choose_opt res with
    | None -> Error (`Msg "No AAAA record found")
    | Some ip -> Ok ip
end
