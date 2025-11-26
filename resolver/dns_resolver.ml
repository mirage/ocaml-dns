(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

type key = [ `raw ] Domain_name.t * Packet.Question.qtype

let pp_key = Dns_resolver_cache.pp_question

let src = Logs.Src.create "dns_resolver" ~doc:"DNS resolver"
module Log = (val Logs.src_log src : Logs.LOG)

(* The cache (a Map!?) for answers: once a specific type/name comes in, we know
   which questions can progress now *)
module QM = Map.Make(struct
    type t = key
    let compare (n, t) (n', t') =
      match Domain_name.compare n n' with
      | 0 -> Packet.Question.compare_qtype t t'
      | x -> x
  end)

type awaiting = {
  ts : int64;
  retry : int;
  proto : proto;
  zone : [ `raw ] Domain_name.t;
  edns : Edns.t option;
  ip : Ipaddr.t;
  port : int;
  question : key;
  id : int;
  checking_disabled : bool;
  dnssec_ok : bool;
}

let awaiting_eq a b =
  Ipaddr.compare a.ip b.ip = 0 &&
  Int.equal a.port b.port &&
  Domain_name.equal (fst a.question) (fst b.question) &&
  Packet.Question.compare_qtype (snd a.question) (snd b.question) = 0 &&
  Int.equal a.id b.id

module TM = Map.Make(struct
    type t = key * Ipaddr.t * int * int
    let compare ((n, t), ip, port, id) ((n', t'), ip', port', id') =
      let andThen v f = match v with 0 -> f () | x -> x in
      andThen (Domain_name.compare n n')
        (fun () -> andThen (Packet.Question.compare_qtype t t')
            (fun () -> andThen (Ipaddr.compare ip ip')
                (fun () -> andThen (Int.compare port port')
                    (fun () -> Int.compare id id'))))
  end)

let retry_interval = Duration.of_ms 500

type feature =
  [ `Dnssec | `Qname_minimisation | `Opportunistic_tls_authoritative ]

module FS = Set.Make(struct
    type t = feature
    let compare a b = match a, b with
      | `Dnssec, `Dnssec -> 0 | `Dnssec, _ -> 1 | _, `Dnssec -> -1
      | `Qname_minimisation, `Qname_minimisation -> 0
      | `Qname_minimisation, _ -> 1
      | _, `Qname_minimisation -> -1
      | `Opportunistic_tls_authoritative, `Opportunistic_tls_authoritative -> 0
(*      | `Opportunistic_tls_authoritative, _ -> 1
        | _, `Opportunistic_tls_authoritative -> -1 *)
  end)

type t = {
  ip_protocol : [ `Both | `Ipv4_only | `Ipv6_only ];
  features : FS.t  ;
  rng : int -> string ;
  primary : Dns_server.Primary.s ;
  cache : Dns_cache.t ;
  transit : awaiting TM.t ;
  queried : awaiting list QM.t ;
  mutable clients : Ipaddr.Set.t ;
  record_clients : bool ;
  require_domain : bool ;
}

let create ?(require_domain = true) ?(add_reserved = true) ?(record_clients = true) ?(cache_size = 10000) ?(ip_protocol = `Both) features now ts rng primary =
  let cache = Dns_cache.empty cache_size in
  let cache =
    List.fold_left (fun cache (name, b) ->
        Dns_cache.set cache ts
          name A Dns_cache.Additional
          (`Entry b))
      cache Dns_resolver_root.a_records
  in
  let cache =
    List.fold_left (fun cache (name, b) ->
        Dns_cache.set cache ts
          name Aaaa Dns_cache.Additional
          (`Entry b))
      cache Dns_resolver_root.aaaa_records
  in
  let cache =
    Dns_cache.set cache ts
      Domain_name.root Ns Dns_cache.Additional
      (`Entry Dns_resolver_root.ns_records)
  in
  let cache =
    Dns_cache.set cache ts
      Domain_name.root Ds Dns_cache.Additional
      (`Entry (Int32.max_int, Dnssec.root_ds))
  in
  let features = FS.of_list features in
  let primary =
    if add_reserved then
      let trie = Dns_server.Primary.data primary in
      let trie' = Dns_trie.insert_map Dns_resolver_root.reserved_zones trie in
      fst (Dns_server.Primary.with_data primary now ts trie')
    else
      primary
  in
  { ip_protocol ; features ; rng ; cache ; primary ; transit = TM.empty ; queried = QM.empty ;
    clients = Ipaddr.Set.empty ; record_clients ; require_domain }

let features t = FS.elements t.features

let pick rng = function
  | [] -> None
  | [ x ] -> Some x
  | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))

let build_query ?id ?(recursion_desired = false) ?(checking_disabled = false) ?(dnssec_ok = true) t ts proto question retry zone edns ip =
  let id = match id with Some id -> id | None -> Randomconv.int16 t.rng in
  let header =
    let flags =
        (* tell the NS we will do the checking.
           See: https://www.rfc-editor.org/rfc/rfc4035#section-4.6 *)
        let flags =
          if FS.mem `Dnssec t.features then
            Packet.Flags.singleton `Checking_disabled
          else Packet.Flags.empty
        in
        if recursion_desired then
          Packet.Flags.add `Recursion_desired flags
        else
          flags
    in
    id, flags
  in
  let el = { ts; retry; proto; zone; edns; ip; port = 53; question; id; checking_disabled; dnssec_ok } in
  let key = question, ip, el.port, id in
  let transit =
    if TM.mem key t.transit then
      Log.warn (fun m -> m "overwriting transit of %a" pp_key question) ;
    TM.add key el t.transit
  in
  let packet = Packet.create ?edns header (question :> Packet.Question.t) `Query in
  let cs, _ = Packet.encode proto packet in
  { t with transit }, cs

let query ?recursion_desired t ts await retry ip name typ =
  let k = (name, typ) in
  let await = { await with retry = succ await.retry } in
  (* TODO here we may want to use the _default protocol_ (and edns settings) instead of `Udp *)
  let payload_size = if FS.mem `Dnssec t.features then Some 1220 (* from RFC 4035 4.1 *) else None in
  let edns = Some (Edns.create ~dnssec_ok:(FS.mem `Dnssec t.features) ?payload_size ()) in
  let t, packet = build_query ?recursion_desired ~checking_disabled:await.checking_disabled ~dnssec_ok:await.dnssec_ok t ts `Udp k retry await.zone edns ip in
  let queried =
    let q = Option.value ~default:[] (QM.find_opt k t.queried) in
    if List.exists (awaiting_eq await) q then q else await :: q
  in
  let t = { t with queried = QM.add k queried t.queried } in
  Log.debug (fun m -> m "query: query %a %a" Ipaddr.pp ip pp_key k) ;
  (packet, ip), t

let was_in_transit t key id sender sport =
  let tm_key = key, sender, sport, id in
  match TM.find tm_key t with
  | exception Not_found ->
    Log.warn (fun m -> m "key %a not present in set (likely retransmitted)"
                  pp_key key);
    None, t
  | awaiting ->
    if Ipaddr.compare sender awaiting.ip = 0 && id = awaiting.id then
      Some (awaiting.zone, awaiting.edns), TM.remove tm_key t
    else
      (Log.warn (fun m -> m "unsolicited reply for %a (id %04X vs o_id %04X, sender %a vs o_sender %a)"
                    pp_key key id awaiting.id Ipaddr.pp sender Ipaddr.pp awaiting.ip);
       None, t)

let find_queries t k =
  match QM.find k t with
  | exception Not_found ->
    Log.warn (fun m -> m "couldn't find entry %a in map" pp_key k) ;
    t, []
  | vals ->
    QM.remove k t, vals

let handle_query ?(retry = 0) t ts awaiting =
  if Int64.sub ts awaiting.ts > Int64.shift_left retry_interval 2 then begin
    Log.warn (fun m -> m "dropping q %a from %a:%d (timed out)"
                  pp_key awaiting.question Ipaddr.pp awaiting.ip awaiting.port);
    `Nothing, t
  end else
    let dnssec = FS.mem `Dnssec t.features && not awaiting.checking_disabled in
    let qname_minimisation = FS.mem `Qname_minimisation t.features in
    let r, cache = Dns_resolver_cache.handle_query t.cache ~qname_minimisation ~dnssec ~dnssec_ok:awaiting.dnssec_ok ~rng:t.rng t.ip_protocol ts awaiting.question in
    let t = { t with cache } in
    match r with
    | `Queries _ when awaiting.retry >= 10 ->
      Log.warn (fun m -> m "dropping q %a from %a:%d (already sent 10 packets)"
                   pp_key awaiting.question Ipaddr.pp awaiting.ip awaiting.port);
      (* TODO reply with error! *)
      `Nothing, t
    | `Queries [] ->
      Log.warn (fun m -> m "dropping q %a from %a:%d (queries is empty)"
                   pp_key awaiting.question Ipaddr.pp awaiting.ip awaiting.port);
      `Nothing, t
    | `Queries qs ->
      let query_one (acc, t) (zone, (nam, types), ip) =
        Log.debug (fun m -> m "have to query (zone %a) %a using ip %a"
                      Domain_name.pp zone
                      Fmt.(list ~sep:(any ", ") pp_key)
                      (List.map (fun t -> (nam, t)) types)
                      Ipaddr.pp ip);
        let await = { awaiting with zone } in
        List.fold_left (fun (acc, t) typ ->
            let r, t = query t ts await retry ip nam typ in
            r :: acc, t)
          (acc, t) types
      in
      let r, t = List.fold_left query_one ([], t) qs in
      `Query r, t
    | `Reply (flags, answer, additional) ->
      let time = Int64.sub ts awaiting.ts in
      let max_size, edns = Edns.reply awaiting.edns in
      let packet = Packet.create ?edns ?additional (awaiting.id, flags) (awaiting.question :> Packet.Question.t) (answer :> Packet.data) in
      Log.debug (fun m -> m "answering %a after %a %d out packets: %a"
                    pp_key awaiting.question Duration.pp time awaiting.retry
                    Packet.pp packet) ;
      Dns_resolver_metrics.response_metric time;
      let cs, _ = Packet.encode ?max_size awaiting.proto packet in
      let ttl = Packet.minimum_ttl (answer :> Packet.data) in
      `Answer (ttl, cs), t

let scrub_it t proto zone edns ts ~signed qtype p =
  match Dns_resolver_utils.scrub zone ~signed qtype p, edns with
  | Ok xs, _ ->
    let cache =
      List.fold_left
        (fun t (n, Dns_resolver_utils.E (ty, e), r) ->
           (*Log.debug (fun m -> m "Dns_cache.set %a %a %a"
                            Rr_map.ppk (K ty) Domain_name.pp n (Dns_cache.pp_entry ty) e) ;*)
           Dns_cache.set t ts n ty r e)
        t xs
    in
    if Packet.Flags.mem `Truncation (snd p.header) && proto = `Udp then
      (Log.warn (fun m -> m "NS truncated reply, using TCP now") ;
       `Upgrade_to_tcp cache)
    else
      `Cache cache
  | Error Rcode.FormErr, Some _ ->
    Log.warn (fun m -> m "NS sent FormErr, retrying without edns!") ;
    `Query_without_edns
  | Error e, _ ->
    Log.warn (fun m -> m "NS didn't like us %a" Rcode.pp e) ;
    `Try_another_ns

let handle_primary t now ts proto sender sport packet _request buf =
  (* makes only sense to ask primary for query=true since we'll never issue questions from primary *)
  let handle_inner name =
    let t, answer, _, _ = Dns_server.Primary.handle_packet t now ts proto sender sport packet name in
    match answer with
    | None -> `None (* TODO incoming ??? are never replied to - should be revised!? *)
    | Some reply ->
      (* delegation if authoritative is not set! *)
      if Packet.Flags.mem `Authoritative (snd reply.header) then begin
        Log.debug (fun m -> m "authoritative reply %a" Packet.pp reply) ;
        let reply =
          match Dns_block.edns reply with
          | None -> reply
          | Some edns ->
            Dns_resolver_metrics.resolver_stats `Blocked;
            Dns.Packet.with_edns reply (Some edns)
        in
        let r = Packet.encode proto reply in
        let ttl = Packet.minimum_ttl reply.data in
        `Reply (t, (reply, ttl, r))
      end else match reply.data with
        | `Answer data -> `Delegation (data, reply.additional)
        | _ -> `None (* not authoritative, error!! *)
  in
  match Dns_server.(handle_tsig (Primary.server t) now packet buf) with
  | Error (e, data) ->
    Log.err (fun m -> m "tsig failed %a" Tsig_op.pp_e e);
    begin match data with
      | Some data -> `Reply (t, 0l, data)
      | None -> `None
    end
  | Ok None ->
    begin match handle_inner None with
      | `Reply (t, (_, ttl, (out, _))) -> `Reply (t, ttl, out)
      | `None -> `None
      | `Delegation d -> `Delegation d
    end
  | Ok (Some (name, tsig, mac, key)) ->
    match handle_inner (Some name) with
    | `Reply (t, (reply, ttl, (buf, max_size))) ->
      begin match Dns_server.((Primary.server t).tsig_sign) ~max_size ~mac name tsig ~key reply buf with
        | None ->
          Log.warn (fun m -> m "couldn't use %a to tsig sign, using unsigned reply" Domain_name.pp name) ;
          `Reply (t, ttl, buf)
        | Some (buf, _) -> `Reply (t, 0l, buf)
      end
    | `None -> `None
    | `Delegation x -> `Delegation x

let handle_awaiting_queries ?retry t ts (name, typ) =
  let queried, values = find_queries t.queried (name, typ) in
  let t = { t with queried } in
  List.fold_left (fun (t, out_a, out_q) awaiting ->
      Log.debug (fun m -> m "now querying %a" pp_key awaiting.question) ;
      match handle_query ?retry t ts awaiting with
      | `Nothing, t -> t, out_a, out_q
      | `Query pkts, t -> t, out_a, (List.map (fun (pkt, dst) -> (`Udp, dst, pkt)) pkts) @ out_q
      | `Answer (ttl, pkt), t -> t, (awaiting.proto, awaiting.ip, awaiting.port, ttl, pkt) :: out_a, out_q)
    (t, [], []) values

let resolve t ts proto sender sport req =
  match req.Packet.data, Packet.Question.qtype req.Packet.question with
  | `Query, Some q_type ->
    Log.debug (fun m -> m "resolving %a" Packet.Question.pp req.question) ;
    if not (Packet.Flags.mem `Recursion_desired (snd req.Packet.header)) then
      Log.warn (fun m -> m "recursion not desired") ;
    (* ask the cache *)
    let checking_disabled = Packet.Flags.mem `Checking_disabled (snd req.header)
    and dnssec_ok = match req.edns with None -> false | Some edns -> edns.Edns.dnssec_ok in
    let awaiting = { ts; retry = 0; proto; zone = Domain_name.root ; edns = req.edns; ip = sender; port = sport; question = (fst req.question, q_type); id = fst req.header; checking_disabled; dnssec_ok } in
    begin match handle_query t ts awaiting with
      | `Answer (ttl, pkt), t ->
        Log.debug (fun m -> m "answer %a" Packet.Question.pp req.question) ;
        t, [ (proto, sender, sport, ttl, pkt) ], []
      | `Nothing, t ->
        Log.debug (fun m -> m "nothing %a" Packet.Question.pp req.question) ;
        t, [], [] (* TODO: send a reply!? *)
      | `Query pkts, t ->
        Log.debug (fun m -> m "query %d %a" (List.length pkts) Packet.Question.pp req.question) ;
        t, [], List.map (fun (packet, dst) -> `Udp, dst, packet) pkts
    end
  | _ ->
    Log.err (fun m -> m "ignoring %a" Packet.pp req);
    let pkt = Packet.create
        (fst req.header, Packet.Flags.empty) req.question
        (`Rcode_error (Rcode.NotImp, Packet.opcode_data req.data, None))
    in
    let buf, _ = Packet.encode proto pkt in
    t, [ proto, sender, sport, 0l, buf ], []

let handle_reply t now ts proto sender sport packet reply =
  match reply, Packet.Question.qtype packet.Packet.question with
  | `Answer _, Some qtype
  | `Rcode_error (Rcode.NXDomain, Opcode.Query, _), Some qtype
  | `Rcode_error (Rcode.ServFail, Opcode.Query, _), Some qtype ->
    begin
      Log.debug (fun m -> m "handling reply to %a" Packet.Question.pp packet.question);
      (* (a) first check whether frame was in transit! *)
      let key = fst packet.question, qtype in
      let r, transit = was_in_transit t.transit key (fst packet.header) sender sport in
      let t = { t with transit } in
      match r with
      | None -> Ok (t, [], [])
      | Some (zone, edns) ->
        (* (b) DNSSec verification of RRs *)
        let t, packet, signed =
          if FS.mem `Dnssec t.features then
            let t, dnskeys =
              match qtype with
              | `K K Rr_map.Dnskey ->
                let cache, ds = Dns_cache.get t.cache ts zone Rr_map.Ds in
                { t with cache },
                begin match ds with
                  | Ok (`Entry (_, ds_set), _) ->
                    let keys = match reply with
                      | `Answer (a, _) -> Name_rr_map.find zone Rr_map.Dnskey a
                      | _ -> None
                    in
                    let ds_set = Dnssec.filter_ds_if_sha2_present ds_set in
                    Option.map (fun (_, dnskeys) ->
                        Rr_map.Ds_set.fold (fun ds acc ->
                            match Dnssec.validate_ds zone dnskeys ds with
                            | Ok key -> Rr_map.Dnskey_set.add key acc
                            | Error `Msg msg ->
                              Log.debug (fun m -> m "couldn't validate DS (for %a): %s"
                                            Domain_name.pp zone msg);
                              acc
                            | Error `Extended e ->
                              Log.debug (fun m -> m "couldn't validate DS (for %a): %a"
                                            Domain_name.pp zone
                                            Extended_error.pp e);
                              acc)
                          ds_set Rr_map.Dnskey_set.empty)
                      keys
                  | _ ->
                    Log.warn (fun m -> m "no DS in cache for %a" Domain_name.pp zone);
                    None
                end
              | _ ->
                let cache, dnskeys = Dns_cache.get t.cache ts zone Rr_map.Dnskey in
                { t with cache },
                match dnskeys with
                | Ok (`Entry (_, dnskey_set), _) -> Some dnskey_set
                | _ ->
                  Log.warn (fun m -> m "no DNSKEYS in cache for %a" Domain_name.pp zone);
                  None
            in
            let packet, signed =
              match dnskeys with
              | None ->
                Log.warn (fun m -> m "no DNSKEY present, couldn't validate packet");
                packet, false
              | Some dnskeys ->
                match Dnssec.verify_packet now dnskeys packet with
                | Ok packet -> packet, true
                | Error `Msg msg ->
                  Log.err (fun m -> m "error %s verifying reply %a"
                              msg Packet.pp_reply reply);
                  packet, false
            in
            t, packet, signed
          else
            t, packet, false
        in
        (* (c) now we scrub and either *)
        match scrub_it t.cache proto zone edns ts ~signed qtype packet with
        | `Query_without_edns ->
          let t, cs = build_query t ts proto key 1 zone None sender in
          Log.debug (fun m -> m "resolve: requery without edns %a %a"
                         Ipaddr.pp sender pp_key key) ;
          Ok (t, [], [ `Udp, sender, cs ])
        | `Upgrade_to_tcp cache ->
          (* RFC 2181 Sec 9: correct would be to drop entire frame, and retry with tcp *)
          (* but we're happy to retrieve the partial information, it may be useful *)
          let t = { t with cache } in
          (* this may provoke the very same question again -
             but since tcp is first, that should trigger the TCP connection,
             which is then reused... ok, we may send the same query twice
             with different ids *)
          (* TODO we may want to get rid of the handle_awaiting_queries
             entirely here!? *)
          let (t, out_a, out_q), recursion_desired =
            handle_awaiting_queries t ts key, false
          in
          let edns = Some (Edns.create ~dnssec_ok:(FS.mem `Dnssec t.features) ()) in
          let t, cs = build_query ~recursion_desired t ts `Tcp key 1 zone edns sender in
          Log.debug (fun m -> m "resolve: upgrade to tcp %a %a"
                         Ipaddr.pp sender pp_key key) ;
          Ok (t, out_a, (`Tcp, sender, cs) :: out_q)
        | `Try_another_ns ->
          (* is this the right behaviour? by luck we'll use another path *)
          Ok (handle_awaiting_queries t ts key)
        | `Cache cache ->
          let t = { t with cache } in
          Ok (handle_awaiting_queries t ts key)
    end
  | v, _ ->
    Log.err (fun m -> m "ignoring reply %a" Packet.pp_reply v);
    Error ()

let handle_delegation t ts proto sender sport req (delegation, add_data) =
  Log.debug (fun m -> m "handling delegation %a (for %a)" Packet.Answer.pp delegation Packet.pp req) ;
  match req.Packet.data, Packet.Question.qtype req.question with
  | `Query, Some qtype ->
    let dnssec = FS.mem `Dnssec t.features && not (Packet.Flags.mem `Checking_disabled (snd req.header))
    and dnssec_ok = match req.edns with None -> false | Some edns -> edns.Edns.dnssec_ok
    in
    let r, cache = Dns_resolver_cache.answer ~dnssec ~dnssec_ok t.cache ts (fst req.question) qtype in
    let t = { t with cache } in
    begin match r with
      | `Query name ->
        (* we should look into delegation for the actual delegation name,
           but instead we're looking for any glue (A) in additional *)
        let ips =
          let ip4s, ip6s =
            Domain_name.Map.fold (fun _ rrmap (ip4s, ip6s) ->
                (match Rr_map.(find A rrmap) with
                 | None -> ip4s
                 | Some (_, ip4s') -> Ipaddr.V4.Set.union ip4s ip4s'),
                (match Rr_map.(find Aaaa rrmap) with
                 | None -> ip6s
                 | Some (_, ip6s') -> Ipaddr.V6.Set.union ip6s ip6s'))
            add_data (Ipaddr.V4.Set.empty, Ipaddr.V6.Set.empty)
          in
          let ip4s = List.map (fun ip -> Ipaddr.V4 ip) (Ipaddr.V4.Set.elements ip4s)
          and ip6s = List.map (fun ip -> Ipaddr.V6 ip) (Ipaddr.V6.Set.elements ip6s)
          in
          match t.ip_protocol with
            | `Both -> ip4s @ ip6s
            | `Ipv4_only -> ip4s
            | `Ipv6_only -> ip6s
        in
        begin match pick t.rng ips with
          | None ->
            Log.err (fun m -> m "something is wrong, delegation but no IP");
            t, [], []
          | Some ip ->
            Log.debug (fun m -> m "found ip %a, maybe querying %a"
                           Ipaddr.pp ip pp_key (name, qtype)) ;
            (* TODO is Domain_name.root correct here? *)
            let checking_disabled = Packet.Flags.mem `Checking_disabled (snd req.header)
            and dnssec_ok = match req.edns with None -> false | Some edns -> edns.Edns.dnssec_ok
            in
            let await = { ts; retry = 0; proto; zone = Domain_name.root; edns = req.edns; ip = sender; port = sport; question = (fst req.question, qtype); id = fst req.header; checking_disabled; dnssec_ok } in
            let (cs, ip), t = query ~recursion_desired:true t ts await 0 ip name qtype in
            t, [], [ `Udp, ip, cs ]
        end
      | `Packet (flags, reply, additional) ->
        let max_size, edns = Edns.reply req.edns in
        Log.debug (fun m -> m "delegation reply for %a from cache: %a"
                       Packet.pp req Packet.pp_reply reply) ;
        let packet = Packet.create ?edns ?additional (fst req.header, flags) req.question (reply :> Packet.data) in
        let ttl = Packet.minimum_ttl (reply :> Packet.data) in
        let pkt, _ = Packet.encode ?max_size proto packet in
        Dns_resolver_metrics.response_metric 0L;
        t, [ proto, sender, sport, ttl, pkt ], []
        (* send it out! we've a cache hit here! *)
    end
  | _ ->
    Log.err (fun m -> m "ignoring %a" Packet.pp req) ;
    let pkt =
      Packet.create (fst req.header, Packet.Flags.empty)
        req.question (`Rcode_error (Rcode.NotImp, Packet.opcode_data req.data, None))
    in
    t, [ proto, sender, sport, 0l, fst (Packet.encode proto pkt) ], []

let handle_buf t now ts query_allowed proto sender sport buf =
  match Packet.decode buf with
(*  | Error (`Bad_edns_version v) ->
    Log.err (fun m -> m "bad edns version (from %a:%d) %u for@.%a"
                 Ipaddr.pp sender sport
                 v Cstruct.hexdump_pp buf) ;
    t, handle_error ~error:Dns_enum.BadVersOrSig proto sender sport buf, [] *)
  | Error e ->
    Dns_resolver_metrics.resolver_stats `Error;
    Log.err (fun m -> m "decode error (from %a:%d) %a for@.%a"
                 Ipaddr.pp sender sport
                 Packet.pp_err e Ohex.pp buf) ;
    let answer = match Packet.raw_error buf Rcode.FormErr with
      | None -> []
      | Some data -> [ proto, sender, sport, 0l, data ]
    in
    t, answer, []
  | Ok res ->
    Log.debug (fun m -> m "reacting to packet from %a:%d"
                   Ipaddr.pp sender sport) ;
    match res.Packet.data with
    | #Packet.reply as reply ->
      begin
        match handle_reply t now ts proto sender sport res reply with
        | Ok a ->
          Log.debug (fun m -> m "handled reply %a:%d"
                        Ipaddr.pp sender sport) ;
          a
        | Error () -> t, [], []
      end
    | #Packet.request as req when query_allowed ->
      Dns_resolver_metrics.resolver_stats `Queries;
      if t.record_clients then
        if not (Ipaddr.Set.mem sender t.clients) then begin
          t.clients <- Ipaddr.Set.add sender t.clients;
          Dns_resolver_metrics.resolver_stats `Clients
        end;
      begin
        match handle_primary t.primary now ts proto sender sport res req buf with
        | `Reply (primary, ttl, pkt) ->
          Dns_resolver_metrics.response_metric 0L;
          Log.debug (fun m -> m "handled primary %a:%d" Ipaddr.pp sender sport) ;
          { t with primary }, [ proto, sender, sport, ttl, pkt ], []
        | `Delegation dele ->
          Log.debug (fun m -> m "handled delegation %a:%d" Ipaddr.pp sender sport) ;
          handle_delegation t ts proto sender sport res dele
        | `None ->
          let dn, qtyp = res.question in
          if Domain_name.count_labels dn = 1 && (qtyp = `K (Rr_map.K A) || qtyp = `K (Rr_map.K Aaaa)) then
            let reply = Packet.create res.header res.question (`Answer (Name_rr_map.empty, Name_rr_map.empty)) in
            let data, _ = Packet.encode proto reply in
            t, [ proto, sender, sport, 0l, data ], []
          else begin
            Log.debug (fun m -> m "resolving %a:%d" Ipaddr.pp sender sport) ;
            (* DNSSEC request DS / DNSKEY / NS from auth *)
            resolve t ts proto sender sport res
          end
      end
    | _ ->
      Log.err (fun m -> m "ignoring unsolicited packet (query allowed? %b) %a" query_allowed Packet.pp res);
      t, [], []

let query_root t now proto =
  let root_ip () =
    match pick t.rng (Dns_resolver_root.ips t.ip_protocol) with
    | None -> assert false
    | Some x -> x
  in
  let ip =
    match Dns_cache.get t.cache now Domain_name.root Ns with
    | _, Ok (`Entry (_, names), _) ->
      let ip4s, ip6s =
        Domain_name.Host_set.fold (fun name (v4s, v6s) ->
            (match snd (Dns_cache.get t.cache now (Domain_name.raw name) A) with
             | Ok (`Entry (_, ips), _) -> Ipaddr.V4.Set.union ips v4s
             | _ -> v4s),
            (match snd (Dns_cache.get t.cache now (Domain_name.raw name) Aaaa) with
             | Ok (`Entry (_, ips), _) -> Ipaddr.V6.Set.union ips v6s
             | _ -> v6s))
          names (Ipaddr.V4.Set.empty, Ipaddr.V6.Set.empty)
      in
      let ip4s = List.map (fun ip -> Ipaddr.V4 ip) (Ipaddr.V4.Set.elements ip4s)
      and ip6s = List.map (fun ip -> Ipaddr.V6 ip) (Ipaddr.V6.Set.elements ip6s)
      in
      let ips = match t.ip_protocol with
        | `Both -> ip4s @ ip6s
        | `Ipv4_only -> ip4s
        | `Ipv6_only -> ip6s
      in
      begin match pick t.rng ips with
        | Some ip -> ip
        | None -> root_ip ()
      end
    | _ -> root_ip ()
  in
  let question = Domain_name.root, `K (Rr_map.K Ns)
  and id = Randomconv.int16 t.rng
  and edns = Some (Edns.create ())
  and checking_disabled = false
  and dnssec_ok = true
  in
  let el =
    { ts = now; retry = 0; proto; zone = Domain_name.root; edns; ip; port = 53; question; id; checking_disabled; dnssec_ok }
  in
  let key = question, ip, el.port, id in
  let t = { t with transit = TM.add key el t.transit } in
  let packet = Packet.create ?edns (id, Packet.Flags.empty) question `Query in
  let cs, _ = Packet.encode proto packet in
  t, (proto, ip, cs)

let max_retries = 5

let err_retries t question =
  let t, reqs = find_queries t question in
  t, List.fold_left (fun acc awaiting ->
      Log.debug (fun m -> m "now erroring to %a" pp_key awaiting.question) ;
      let packet = Packet.create (awaiting.id, Packet.Flags.empty)
          (awaiting.question :> Packet.Question.t)
          (`Rcode_error (Rcode.ServFail, Opcode.Query, None))
      in
      let buf, _ = Packet.encode awaiting.proto packet in
      (awaiting.proto, awaiting.ip, awaiting.port, 0l, buf) :: acc)
    [] reqs

let timer t ts =
  let transit, rem =
    TM.partition
      (fun _ awaiting -> Int64.sub ts awaiting.ts < retry_interval)
      t.transit
  in
  let t = { t with transit } in
  if not (TM.is_empty transit && TM.is_empty rem) then
    Log.debug (fun m -> m "try_other timer wheel -- keeping %d, running over %d"
                   (TM.cardinal transit) (TM.cardinal rem)) ;
  TM.fold (fun ((name, typ), _ip, _port, _id) awaiting (t, out_a, out_q) ->
      let retry = succ awaiting.retry in
      if retry < max_retries then begin
        let t, outa, outq = handle_awaiting_queries ~retry t ts (name, typ) in
        (t, outa @ out_a, outq @ out_q)
      end else begin
        Log.info (fun m -> m "retry limit exceeded for %a at %a!"
                      pp_key (name, typ) Ipaddr.pp awaiting.ip) ;
        let queried, out_as = err_retries t.queried (name, typ) in
        ({ t with queried }, out_as @ out_a, out_q)
      end)
    rem (t, [], [])

let primary_data t = Dns_server.Primary.data t.primary

let with_primary_data t now ts data =
  let primary, outs = Dns_server.Primary.with_data t.primary now ts data in
  { t with primary }, outs
