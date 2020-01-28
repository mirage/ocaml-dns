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
  (* NOTE that this function compresses answers:
     foo.example CNAME 500 bar.example
     bar.example A 300 1.2.3.4
     is compressed to:
     foo.example A 300 1.2.3.4
     -> which is fine for applications (i think so)
     -> which is struggling for the cache (not entirely sure about this tbh)
     -> it is not clear whether it meets the DNS specifications nicely *)
  let rec follow_cname name ~iterations:iterations_left ~answer ~state =
    let open Rresult in
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

  let find_soa authority =
    Domain_name.Map.fold (fun k rr_map acc ->
        match Rr_map.(find Soa rr_map) with
        | Some soa -> Some (Domain_name.raw k, soa)
        | None -> acc)
      authority None

  let consume_rest_of_buffer state buf =
    let open Rresult in
    let to_msg t = function
      | Ok a -> Ok a
      | Error e ->
        R.error_msgf
          "QUERY: @[<v>hdr:%a (id: %d = %d) (q=q: %B)@ query:%a%a \
           opt:%a tsig:%B@,failed: %a@,@]"
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
    | Error `Partial -> Ok `Partial
    | Error err ->
      Rresult.R.error_msgf "Error parsing response: %a" Packet.pp_err err
    | Ok t ->
      to_msg t (Packet.reply_matches_request ~request:state.query t)
      >>= function
      | `Answer (answer, authority) when not (Domain_name.Map.is_empty answer) ->
        begin
          let q = fst state.query.question in
          follow_cname q ~iterations:20 ~answer ~state >>= function
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
      | `Rcode_error (NXDomain, Query, Some (_answer, authority)) ->
        begin match find_soa authority with
          | Some soa -> Ok (`No_domain soa)
          | None -> Error (`Msg "invalid reply, no SOA in nodomain")
        end
      | r ->
        Error (`Msg (Fmt.strf "Ok %a, expected answer" Packet.pp_reply r))

  let parse_response (type requested)
    : requested Rr_map.key query_state -> Cstruct.t ->
      ( [ `Data of requested | `Partial
        | `No_data of [`raw] Domain_name.t * Soa.t
        | `No_domain of [`raw] Domain_name.t * Soa.t ],
        [`Msg of string]) result =
    fun state buf ->
    match consume_protocol_prefix buf state.protocol with
    | Ok buf -> consume_rest_of_buffer state buf
    | Error () -> Ok `Partial

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

module Make = functor (Transport:S) ->
struct

  type t = {
    cache : Dns_cache.t ;
    clock : unit -> int64 ;
    transport : Transport.t ;
  }

  let create ?(size=32) ?rng ?nameserver ~clock stack =
    { cache = Dns_cache.empty size ;
      clock = clock ;
      transport = Transport.create ?rng ?nameserver stack
    }

  let nameserver { transport; _ } = Transport.nameserver transport

  let (>>=) = Transport.bind

  (* result-bind *)
  let (>>|) a b =
    a >>= function
    | Ok a' -> b a'
    | Error e -> Transport.lift (Error e)

  (* result-bind-and-lift *)
  let (>>|=) a f = a >>| fun b -> Transport.lift (f b)

  let get_resource_record (type requested) t ?nameserver (query_type:requested Dns.Rr_map.key) name
    : (requested, [> `Msg of string
                  | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
                  | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t ]) result Transport.io =
    let domain_name = Domain_name.raw name in
    match Dns_cache.get t.cache (t.clock ()) domain_name query_type with
    | Ok `Entry (B (query_type', value)) ->
      (* to satisfy the type checker, we need to prove that
         - query_type (we are looking for) = query_type' (in the cache)
         The Dns_cache does not carry this proof at the moment (using an
         Rr_map.B : B of 'a query_type * 'a instead.
         We do (instead of an Obj.magic) a compare of the keys, which exposes
         the necessary proof. *)
      begin match Dns.Rr_map.K.compare query_type' query_type with
        | Gmap.Order.Eq -> Transport.lift @@ Ok value
        | _ -> Transport.lift @@
          Rresult.R.error_msgf "should not happen request_type <> request_type'"
      end
    | Ok (`No_data _ as nodata) -> Error nodata |> Transport.lift
    | Ok (`No_domain _ as nodom) -> Error nodom |> Transport.lift
    | Ok (`Serv_fail _)
    | Error _ ->
      let proto, _ = match nameserver with
        | None -> Transport.nameserver t.transport | Some x -> x in
      let tx, state =
        Pure.make_query (Transport.rng t.transport)
          (match proto with `UDP -> `Udp | `TCP -> `Tcp) name query_type
      in
      Transport.connect ?nameserver t.transport >>| fun socket ->
      Logs.debug (fun m -> m "Connected to NS.");
      (Transport.send socket tx >>| fun () ->
       Logs.debug (fun m -> m "Receiving from NS");
       let update_cache entry =
         let rank = Dns_cache.NonAuthoritativeAnswer in
         Dns_cache.set t.cache (t.clock ()) domain_name query_type rank entry
       in
       let rec recv_loop acc =
         Transport.recv socket >>| fun recv_buffer ->
         Logs.debug (fun m -> m "Read @[<v>%d bytes@]"
                        (Cstruct.len recv_buffer)) ;
         let buf =
           if Cstruct.(equal empty acc)
           then recv_buffer
           else Cstruct.append acc recv_buffer
         in
         match Pure.parse_response state buf with
         | Ok `Data x ->
          update_cache (`Entry (Rr_map.B (query_type, x)));
          Ok x |> Transport.lift
        | Ok ((`No_data _ | `No_domain _) as nodom) ->
          update_cache nodom;
          Error nodom |> Transport.lift
        | Error `Msg xxx -> Error (`Msg xxx) |> Transport.lift
        | Ok `Partial when proto = `TCP -> recv_loop buf
        | Ok `Partial -> Error (`Msg "Truncated UDP response") |> Transport.lift
      in recv_loop Cstruct.empty) >>= fun r ->
      Transport.close socket >>= fun () ->
      Transport.lift r

  let lift_cache_error m =
    (match m with
     | Ok a -> Ok a
     | Error `Msg msg -> Error (`Msg msg)
     | Error (#Dns_cache.entry as e) ->
       Rresult.R.error_msgf "DNS cache error @[%a@]" Dns_cache.pp_entry e)
    |> Transport.lift

  let getaddrinfo (type requested) t ?nameserver (query_type:requested Dns.Rr_map.key) name
    : (requested, [> `Msg of string ]) result Transport.io =
    get_resource_record t ?nameserver query_type name >>= lift_cache_error

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
