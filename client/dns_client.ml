open Dns

module Pure = struct

  type 'key query_state =
    { protocol : Dns.proto ;
      key: 'key ;
      query : Packet.t ;
    } constraint 'key = 'a Rr_map.key

  let make_query rng protocol edns hostname
      : 'xy  ->
        Cstruct.t * 'xy query_state =
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
    let header = Randomconv.int16 rng, Packet.Flags.singleton `Recursion_desired in
    let query = Packet.create ?edns header question `Query in
    Logs.debug (fun m -> m "sending %a" Dns.Packet.pp query);
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
    let ( let* ) = Result.bind in
    let to_msg t = function
      | Ok a -> Ok a
      | Error e ->
        Error (`Msg
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
    | Error `Partial -> Ok `Partial
    | Error err ->
      Error (`Msg (Fmt.str "Error parsing response: %a" Packet.pp_err err))
    | Ok t ->
      Logs.debug (fun m -> m "received %a" Dns.Packet.pp t);
      let* a = to_msg t (Packet.reply_matches_request ~request:state.query t) in
      match a with
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
      | `Rcode_error (NXDomain, Query, Some (_answer, authority)) ->
        begin match find_soa authority with
          | Some soa -> Ok (`No_domain soa)
          | None -> Error (`Msg "invalid reply, no SOA in nodomain")
        end
      | r ->
        Error (`Msg (Fmt.str "Ok %a, expected answer" Packet.pp_reply r))

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
let default_resolvers = [
  Ipaddr.of_string_exn "2001:67c:28a4::" ;
  Ipaddr.of_string_exn "91.239.100.100" ;
]

(* generated on November 9th 2021 by app/extract_from_ipfire *)
(* adjusted the IPv6 anycast from uncensoreddns.org *)
let ip_domain =
Ipaddr.Map.add (Ipaddr.of_string_exn "91.239.100.100") Domain_name.(host_exn (of_string_exn "anycast.uncensoreddns.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:67c:28a4::") Domain_name.(host_exn (of_string_exn "anycast.uncensoreddns.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "1.1.1.1") Domain_name.(host_exn (of_string_exn "cloudflare-dns.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "1.0.0.1") Domain_name.(host_exn (of_string_exn "cloudflare-dns.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2606:4700:4700::1111") Domain_name.(host_exn (of_string_exn "cloudflare-dns.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2606:4700:4700::1001") Domain_name.(host_exn (of_string_exn "cloudflare-dns.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "5.1.66.255") Domain_name.(host_exn (of_string_exn "anycast01.ffmuc.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:678:e68:f000::") Domain_name.(host_exn (of_string_exn "anycast01.ffmuc.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "5.1.66.255") Domain_name.(host_exn (of_string_exn "dot.ffmuc.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:678:e68:f000::") Domain_name.(host_exn (of_string_exn "dot.ffmuc.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "185.222.222.222") Domain_name.(host_exn (of_string_exn "dns.sb"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "185.184.222.222") Domain_name.(host_exn (of_string_exn "dns.sb"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a09::") Domain_name.(host_exn (of_string_exn "dns.sb"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a09::1") Domain_name.(host_exn (of_string_exn "dns.sb"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "8.8.8.8") Domain_name.(host_exn (of_string_exn "dns.google"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "8.8.4.4") Domain_name.(host_exn (of_string_exn "dns.google"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "146.255.56.98") Domain_name.(host_exn (of_string_exn "dot1.applied-privacy.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a01:4f8:c0c:83ed::1") Domain_name.(host_exn (of_string_exn "dot1.applied-privacy.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "199.58.81.218") Domain_name.(host_exn (of_string_exn "dns.cmrg.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:470:1c:76d::53") Domain_name.(host_exn (of_string_exn "dns.cmrg.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "185.95.218.42") Domain_name.(host_exn (of_string_exn "dns.digitale-gesellschaft.ch"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "185.95.218.43") Domain_name.(host_exn (of_string_exn "dns.digitale-gesellschaft.ch"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a05:fc84::42") Domain_name.(host_exn (of_string_exn "dns.digitale-gesellschaft.ch"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a05:fc84::43") Domain_name.(host_exn (of_string_exn "dns.digitale-gesellschaft.ch"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "140.238.215.192") Domain_name.(host_exn (of_string_exn "dot.post-factum.tk"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "5.9.164.112") Domain_name.(host_exn (of_string_exn "dns3.digitalcourage.de"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "81.3.27.54") Domain_name.(host_exn (of_string_exn "recursor01.dns.ipfire.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:678:b28::54") Domain_name.(host_exn (of_string_exn "recursor01.dns.ipfire.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "81.3.27.54") Domain_name.(host_exn (of_string_exn "recursor01.dns.lightningwirelabs.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:678:b28::54") Domain_name.(host_exn (of_string_exn "recursor01.dns.lightningwirelabs.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "89.233.43.71") Domain_name.(host_exn (of_string_exn "unicast.uncensoreddns.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a01:3a0:53:53::") Domain_name.(host_exn (of_string_exn "unicast.uncensoreddns.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "95.216.24.230") Domain_name.(host_exn (of_string_exn "fi.dot.dns.snopyta.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a01:4f9:2a:1919::9301") Domain_name.(host_exn (of_string_exn "fi.dot.dns.snopyta.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "89.234.186.112") Domain_name.(host_exn (of_string_exn "dns.neutopia.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a00:5884:8209::2") Domain_name.(host_exn (of_string_exn "dns.neutopia.org"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "158.64.1.29") Domain_name.(host_exn (of_string_exn "kaitain.restena.lu"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:a18:1::29") Domain_name.(host_exn (of_string_exn "kaitain.restena.lu"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "185.49.141.37") Domain_name.(host_exn (of_string_exn "getdnsapi.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2a04:b900:0:100::37") Domain_name.(host_exn (of_string_exn "getdnsapi.net"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "145.100.185.17") Domain_name.(host_exn (of_string_exn "dnsovertls2.sinodun.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "145.100.185.18") Domain_name.(host_exn (of_string_exn "dnsovertls3.sinodun.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:610:1:40ba:145:100:185:17") Domain_name.(host_exn (of_string_exn "dnsovertls3.sinodun.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "2001:610:1:40ba:145:100:185:18") Domain_name.(host_exn (of_string_exn "dnsovertls3.sinodun.com"))
(Ipaddr.Map.add (Ipaddr.of_string_exn "96.113.151.145") Domain_name.(host_exn (of_string_exn "dot.xfinity.com"))
(Ipaddr.Map.empty)))))))))))))))))))))))))))))))))))))))))))))

let known_name ip =
  match Ipaddr.Map.find_opt ip ip_domain with
  | None -> Some ip, None
  | Some name -> None, Some name

module type S = sig
  type context
  type +'a io
  type io_addr
  type stack
  type t

  val create : ?nameservers:(Dns.proto * io_addr list) -> timeout:int64 -> stack -> t

  val nameservers : t -> Dns.proto * io_addr list
  val rng : int -> Cstruct.t
  val clock : unit -> int64

  val connect : t -> (context, [> `Msg of string ]) result io
  val send_recv : context -> Cstruct.t -> (Cstruct.t, [> `Msg of string ]) result io
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

  let create ?(size = 32) ?(edns = `Auto) ?nameservers ?(timeout = Duration.of_sec 5) stack =
    { cache = Dns_cache.empty size ;
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
      match lift_ok r with
      | Ok _ as ok -> Transport.lift ok
      | Error ((`No_data _ | `No_domain _) as nod) -> Error nod |> Transport.lift
      | Error `Msg _ ->
        let proto, _ = Transport.nameservers t.transport in
        let tx, state =
          Pure.make_query Transport.rng proto t.edns name query_type
        in
        Transport.connect t.transport >>| fun socket ->
        Logs.debug (fun m -> m "Connected to NS.");
        (Transport.send_recv socket tx >>| fun recv_buffer ->
         Logs.debug (fun m -> m "Read @[<v>%d bytes@]"
                        (Cstruct.length recv_buffer)) ;
         let update_cache entry =
           let rank = Dns_cache.NonAuthoritativeAnswer in
           let cache =
             Dns_cache.set t.cache (Transport.clock ()) domain_name query_type rank entry
           in
           t.cache <- cache
         in
         Transport.lift
           (match Pure.parse_response state recv_buffer with
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
