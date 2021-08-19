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
        Cstruct.BE.set_uint16 len_field 0 (Cstruct.length cs) ;
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
        | pkt_len when pkt_len > Cstruct.length buf -2 ->
          Logs.debug (fun m -> m "Partial: %d >= %d-2"
                          pkt_len (Cstruct.length buf));
          Error () (* TODO return remaining # *)
        | pkt_len ->
          if 2 + pkt_len < Cstruct.length buf then
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

(* Anycast address of uncensoreddns.org *)
let default_resolver = "91.239.100.100", "2001:67c:28a4::"
let default_resolver_hostname =
  Domain_name.(host_exn (of_string_exn "anycast.uncensoreddns.org"))

module type S = sig
  type context
  type +'a io
  type io_addr
  type ns_addr = Dns.proto * io_addr
  type stack
  type t

  val create : ?nameserver:ns_addr -> timeout:int64 -> stack -> t

  val nameserver : t -> ns_addr
  val rng : int -> Cstruct.t
  val clock : unit -> int64

  val connect : ?nameserver:ns_addr -> t -> (context, [> `Msg of string ]) result io
  val send : context -> Cstruct.t -> (unit, [> `Msg of string ]) result io
  val recv : context -> (Cstruct.t, [> `Msg of string ]) result io
  val close : context -> unit io

  val bind : 'a io -> ('a -> 'b io) -> 'b io
  val lift : 'a -> 'a io
end

module With_tls (T : S) = struct
  type +'a io = 'a T.io

  type io_addr = Tls.Config.client * T.io_addr

  type ns_addr = Dns.proto * io_addr

  type stack = T.stack

  type t = {
    nameserver : ns_addr ;
    t : T.t ;
  }

  type context = {
    t : t ;
    context : T.context ;
    mutable tls : (Tls.Engine.state, [ `Msg of string ]) result ;
    mutable linger : Cstruct.t ;
  }

  let create ?nameserver ~timeout stack =
    (* TODO: default authenticator! *)
    let tls, ns = match nameserver with
      | None ->
        Tls.Config.client ~authenticator:(fun ~host:_ _ -> Ok None) (), None
      | Some (_proto, (tls, ns)) -> tls, Some (`Tcp, ns)
    in
    let t = T.create ?nameserver:ns ~timeout stack in
    let nameserver = `Tcp, (tls, snd (T.nameserver t)) in
    { nameserver ; t }

  let nameserver t = t.nameserver

  let bind = T.bind

  let lift = T.lift

  let (>>=) = T.bind

  let rng = T.rng
  let clock = T.clock

  let (>>==) a b = a >>= function
    | Ok x -> b x
    | Error `Msg m -> lift (Error ((`Msg m) :> [> `Msg of string ]))

  let send t data =
    lift t.tls >>== fun tls ->
    match Tls.Engine.send_application_data tls [data] with
    | None ->
      t.tls <- Error (`Msg "couldn't send data");
      lift (Error (`Msg "expected to be ready to send data"))
    | Some (tls', out) ->
      t.tls <- Ok tls';
      T.send t.context out

  let read_react t =
    let handle tls buf =
      match Tls.Engine.handle_tls tls buf with
      | Ok (r, `Response resp, `Data data) ->
        (match resp with
         | Some x -> T.send t.context x
         | None -> T.lift (Ok ())) >>== fun () ->
        (match r with
         | `Ok tls' -> t.tls <- Ok tls'
         | `Eof -> t.tls <- Error (`Msg "end of file")
         | `Alert a ->
           let m = Sexplib.Sexp.to_string_hum (Tls.Packet.sexp_of_alert_type a) in
           t.tls <- Error (`Msg ("TLS alert " ^ m)));
        lift t.tls >>== fun _ ->
        lift (Ok (match data with None -> Cstruct.empty | Some x -> x))
      | Error (f, `Response r) ->
        T.send t.context r >>== fun () ->
        let msg = `Msg (Tls.Engine.string_of_failure f) in
        t.tls <- Error msg;
        lift (Error msg)
    in
    match t.tls with
    | Error _ as e -> lift e
    | Ok _tls ->
      T.recv t.context >>== fun recv ->
      match t.tls with
      | Ok tls when Cstruct.length recv > 0 -> handle tls recv
      | Ok _ ->
        let e = `Msg "end of file" in
        t.tls <- Error e;
        lift (Error e)
      | Error _ as e -> lift e

  let rec recv t =
    if Cstruct.length t.linger > 0 then
      let data = t.linger in
      t.linger <- Cstruct.empty;
      lift (Ok data)
    else
      read_react t >>== fun d ->
      if Cstruct.length d = 0 then
        recv t
      else
        lift (Ok d)

  let connect ?(nameserver : ns_addr option) t : (context, [> `Msg of string ]) result io =
    let tls, nameserver = match nameserver with
      | None ->
        let proto, (tls_client, ns) = t.nameserver in
        tls_client, (proto, ns)
      | Some (proto, (tls_client, ns)) -> tls_client, (proto, ns)
    in
    T.connect ~nameserver t.t >>== fun context ->
    let tls, out = Tls.Engine.client tls in
    T.send context out >>== fun () ->
    let rec drain_handshake ctx =
      match ctx.tls with
      | Ok tls when not (Tls.Engine.handshake_in_progress tls) -> lift (Ok ctx)
      | _ ->
        read_react ctx >>== fun data ->
        ctx.linger <- Cstruct.append ctx.linger data;
        drain_handshake ctx
    in
    let context = { t ; context ; tls = Ok tls ; linger = Cstruct.empty } in
    drain_handshake context

  let close t =
    (match t.tls with
    | Ok tls ->
      let _tls', out = Tls.Engine.send_close_notify tls in
      t.tls <- Error (`Msg "connection closed");
      T.send t.context out >>= fun _ ->
      lift ()
    | Error _ -> lift ()) >>= fun () ->
    T.close t.context
end

let localhost = Domain_name.of_string_exn "localhost"
let localsoa = Soa.create (Domain_name.prepend_label_exn localhost "ns")
let invalid = Domain_name.of_string_exn "invalid"
let invalidsoa = Soa.create (Domain_name.prepend_label_exn invalid "ns")

let rfc6761_special (type req) q_name (q_typ : req Dns.Rr_map.key) : (req Dns_cache.entry, unit) result =
  if Domain_name.is_subdomain ~domain:localhost ~subdomain:q_name then
    let open Dns.Rr_map in
    match q_typ with
    | A -> Ok (`Entry (300l, Ipv4_set.singleton Ipaddr.V4.localhost))
    | Aaaa ->
      Ok (`Entry (300l, Ipv6_set.singleton Ipaddr.V6.localhost))
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
  }

  let create ?(size=32) ?nameserver ?(timeout = Duration.of_sec 5) stack =
    { cache = Dns_cache.empty size ;
      transport = Transport.create ?nameserver ~timeout stack
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

  let get_resource_record (type requested) t ?nameserver (query_type:requested Dns.Rr_map.key) name
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
      match lift_ok r with
      | Ok _ as ok -> Transport.lift ok
      | Error ((`No_data _ | `No_domain _) as nod) -> Error nod |> Transport.lift
      | Error `Msg _ ->
        let proto, _ = match nameserver with
          | None -> Transport.nameserver t.transport | Some x -> x in
        let tx, state =
          Pure.make_query Transport.rng proto name query_type
        in
        Transport.connect ?nameserver t.transport >>| fun socket ->
        Logs.debug (fun m -> m "Connected to NS.");
        (Transport.send socket tx >>| fun () ->
         Logs.debug (fun m -> m "Receiving from NS");
         let update_cache entry =
           let rank = Dns_cache.NonAuthoritativeAnswer in
           let cache =
             Dns_cache.set t.cache (Transport.clock ()) domain_name query_type rank entry
           in
           t.cache <- cache
         in
         let rec recv_loop acc =
           Transport.recv socket >>| fun recv_buffer ->
           Logs.debug (fun m -> m "Read @[<v>%d bytes@]"
                          (Cstruct.length recv_buffer)) ;
           let buf =
             if Cstruct.(equal empty acc)
             then recv_buffer
             else Cstruct.append acc recv_buffer
           in
           match Pure.parse_response state buf with
           | Ok `Data x ->
             update_cache (`Entry x);
             Ok x |> Transport.lift
           | Ok ((`No_data _ | `No_domain _) as nodom) ->
             update_cache nodom;
             Error nodom |> Transport.lift
           | Error `Msg xxx -> Error (`Msg xxx) |> Transport.lift
           | Ok `Partial when proto = `Tcp -> recv_loop buf
           | Ok `Partial -> Error (`Msg "Truncated UDP response") |> Transport.lift
         in recv_loop Cstruct.empty) >>= fun r ->
        Transport.close socket >>= fun () ->
        Transport.lift r

  let lift_cache_error query_type m =
    (match m with
     | Ok a -> Ok a
     | Error `Msg msg -> Error (`Msg msg)
     | Error (#Dns_cache.entry as e) ->
       Rresult.R.error_msgf "DNS cache error @[%a@]" (Dns_cache.pp_entry query_type) e)
    |> Transport.lift

  let getaddrinfo (type requested) t ?nameserver (query_type:requested Dns.Rr_map.key) name
    : (requested, [> `Msg of string ]) result Transport.io =
    get_resource_record t ?nameserver query_type name >>= lift_cache_error query_type

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
