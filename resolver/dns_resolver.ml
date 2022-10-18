(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

let ( let* ) = Result.bind

type key = [ `raw ] Domain_name.t * Packet.Question.qtype

let pp_key = Dns_resolver_cache.pp_question

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
}

let retry_interval = Duration.of_ms 500

type t = {
  ip_protocol : [ `Both | `Ipv4_only | `Ipv6_only ];
  rng : int -> Cstruct.t ;
  primary : Dns_server.Primary.s ;
  cache : Dns_cache.t ;
  transit : awaiting QM.t ;
  queried : awaiting list QM.t ;
}

let create ?(cache_size = 10000) ?(ip_protocol = `Both) now rng primary =
  let cache = Dns_cache.empty cache_size in
  let cache =
    List.fold_left (fun cache (name, b) ->
        Dns_cache.set cache now
          name A Dns_cache.Additional
          (`Entry b))
      cache Dns_resolver_root.a_records
  in
  let cache =
    List.fold_left (fun cache (name, b) ->
        Dns_cache.set cache now
          name Aaaa Dns_cache.Additional
          (`Entry b))
      cache Dns_resolver_root.aaaa_records
  in
  let cache =
    Dns_cache.set cache now
      Domain_name.root Ns Dns_cache.Additional
      (`Entry Dns_resolver_root.ns_records)
  in
  let cache =
    Dns_cache.set cache now
      Domain_name.root Ds Dns_cache.Additional
      (`Entry (Int32.max_int, Dnssec.root_ds))
  in
  { ip_protocol ; rng ; cache ; primary ; transit = QM.empty ; queried = QM.empty }

let pick rng = function
  | [] -> None
  | [ x ] -> Some x
  | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))

let build_query ?id ?(recursion_desired = false) t ts proto question retry zone edns ip =
  let id = match id with Some id -> id | None -> Randomconv.int16 t.rng in
  let header =
    (* TODO not clear about this.. *)
    let flags =
      if recursion_desired then
        Packet.Flags.singleton `Recursion_desired
      else
        Packet.Flags.empty
    in
    id, flags
  in
  let el = { ts; retry; proto; zone; edns; ip; port = 53; question; id } in
  let transit =
    if QM.mem question t.transit then
      Logs.warn (fun m -> m "overwriting transit of %a" pp_key question) ;
    QM.add question el t.transit
  in
  let packet = Packet.create ?edns header (question :> Packet.Question.t) `Query in
  let cs, _ = Packet.encode proto packet in
  { t with transit }, cs

let maybe_query ?recursion_desired t ts await retry ip name typ =
  let k = (name, typ) in
  let await = { await with retry = succ await.retry } in
  if QM.mem k t.queried then
    let t = { t with queried = QM.add k (await :: QM.find k t.queried) t.queried } in
    None, t
  else
    (* TODO here we may want to use the _default protocol_ (and edns settings) instead of `Udp *)
    let edns = Some (Edns.create ~dnssec_ok:true ()) in
    let t, packet = build_query ?recursion_desired t ts `Udp k retry await.zone edns ip in
    let t = { t with queried = QM.add k [await] t.queried } in
    Logs.debug (fun m -> m "maybe_query: query %a %a" Ipaddr.pp ip pp_key k) ;
    Some (packet, ip), t

let was_in_transit t key id sender =
  match QM.find key t with
  | exception Not_found ->
    Logs.warn (fun m -> m "key %a not present in set (likely retransmitted)"
                  pp_key key);
    None, t
  | awaiting ->
    if Ipaddr.compare sender awaiting.ip = 0 && id = awaiting.id then
      Some (awaiting.zone, awaiting.edns), QM.remove key t
    else
      (Logs.warn (fun m -> m "unsolicited reply for %a (id %04X vs o_id %04X, sender %a vs o_sender %a)"
                    pp_key key id awaiting.id Ipaddr.pp sender Ipaddr.pp awaiting.ip);
       None, t)

let find_queries t k =
  match QM.find k t with
  | exception Not_found ->
    Logs.warn (fun m -> m "couldn't find entry %a in map" pp_key k) ;
    t, []
  | vals ->
    QM.remove k t, vals

let handle_query ?(retry = 0) t ts awaiting =
  if Int64.sub ts awaiting.ts > Int64.shift_left retry_interval 2 then begin
    Logs.warn (fun m -> m "dropping q %a from %a:%d (timed out)"
                  pp_key awaiting.question Ipaddr.pp awaiting.ip awaiting.port);
    `Nothing, t
  end else
    let r, cache = Dns_resolver_cache.handle_query t.cache ~rng:t.rng t.ip_protocol ts awaiting.question in
    let t = { t with cache } in
    match r with
    | `Query _ when awaiting.retry >= 30 ->
      Logs.warn (fun m -> m "dropping q %a from %a:%d (already sent 30 packets)"
                    pp_key awaiting.question Ipaddr.pp awaiting.ip awaiting.port);
      (* TODO reply with error! *)
      `Nothing, t
    | `Query (zone, (nam, types), ip) ->
      Logs.debug (fun m -> m "have to query (zone %a) %a using ip %a"
                     Domain_name.pp zone
                     Fmt.(list ~sep:(any ", ") pp_key)
                     (List.map (fun t -> (nam, t)) types)
                     Ipaddr.pp ip);
      let await = { awaiting with zone } in
      let r, t =
        List.fold_left (fun (acc, t) typ ->
            let r, t = maybe_query t ts await retry ip nam typ in
            Option.fold ~none:acc ~some:(fun a -> a :: acc) r, t)
          ([], t) types
      in
      `Query r, t
    | `Reply (flags, a) ->
      let time = Int64.sub ts awaiting.ts in
      let max_size, edns = Edns.reply awaiting.edns in
      let packet = Packet.create ?edns (awaiting.id, flags) (awaiting.question :> Packet.Question.t) (a :> Packet.data) in
      Logs.debug (fun m -> m "answering %a after %a %d out packets: %a"
                     pp_key awaiting.question Duration.pp time awaiting.retry
                     Packet.pp packet) ;
      let cs, _ = Packet.encode ?max_size awaiting.proto packet in
      `Answer cs, t

let scrub_it t proto zone edns ts ~signed qtype p =
  match Dns_resolver_utils.scrub zone ~signed qtype p, edns with
  | Ok xs, _ ->
    let cache =
      List.fold_left
        (fun t (n, Dns_resolver_utils.E (ty, e), r) ->
           (*Logs.debug (fun m -> m "Dns_cache.set %a %a %a"
                            Rr_map.ppk (K ty) Domain_name.pp n (Dns_cache.pp_entry ty) e) ;*)
           Dns_cache.set t ts n ty r e)
        t xs
    in
    if Packet.Flags.mem `Truncation (snd p.header) && proto = `Udp then
      (Logs.warn (fun m -> m "NS truncated reply, using TCP now") ;
       `Upgrade_to_tcp cache)
    else
      `Cache cache
  | Error Rcode.FormErr, Some _ ->
    Logs.warn (fun m -> m "NS sent FormErr, retrying without edns!") ;
    `Query_without_edns
  | Error e, _ ->
    Logs.warn (fun m -> m "NS didn't like us %a" Rcode.pp e) ;
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
        Logs.debug (fun m -> m "authoritative reply %a" Packet.pp reply) ;
        let r = Packet.encode proto reply in
        `Reply (t, (reply, r))
      end else match reply.data with
        | `Answer data -> `Delegation (data, reply.additional)
        | _ -> `None (* not authoritative, error!! *)
  in
  match Dns_server.(handle_tsig (Primary.server t) now packet buf) with
  | Error (e, data) ->
    Logs.err (fun m -> m "tsig failed %a" Tsig_op.pp_e e);
    begin match data with
      | Some data -> `Reply (t, data)
      | None -> `None
    end
  | Ok None ->
    begin match handle_inner None with
      | `Reply (t, (_, (out, _))) -> `Reply (t, out)
      | `None -> `None
      | `Delegation d -> `Delegation d
    end
  | Ok (Some (name, tsig, mac, key)) ->
    match handle_inner (Some name) with
    | `Reply (t, (reply, (buf, max_size))) ->
      begin match Dns_server.((Primary.server t).tsig_sign) ~max_size ~mac name tsig ~key reply buf with
        | None ->
          Logs.warn (fun m -> m "couldn't use %a to tsig sign, using unsigned reply" Domain_name.pp name) ;
          `Reply (t, buf)
        | Some (buf, _) -> `Reply (t, buf)
      end
    | `None -> `None
    | `Delegation x -> `Delegation x

let handle_awaiting_queries ?retry t ts (name, typ) =
  let queried, values = find_queries t.queried (name, typ) in
  let t = { t with queried } in
  List.fold_left (fun (t, out_a, out_q) awaiting ->
      Logs.debug (fun m -> m "now querying %a" pp_key awaiting.question) ;
      match handle_query ?retry t ts awaiting with
      | `Nothing, t -> t, out_a, out_q
      | `Query pkts, t -> t, out_a, (List.map (fun (pkt, dst) -> (`Udp, dst, pkt)) pkts) @ out_q
      | `Answer pkt, t -> t, (awaiting.proto, awaiting.ip, awaiting.port, pkt) :: out_a, out_q)
    (t, [], []) values

let resolve t ts proto sender sport req =
  match req.Packet.data, Packet.Question.qtype req.Packet.question with
  | `Query, Some q_type ->
    Logs.info (fun m -> m "resolving %a" Packet.Question.pp req.question) ;
    if not (Packet.Flags.mem `Recursion_desired (snd req.Packet.header)) then
      Logs.warn (fun m -> m "recursion not desired") ;
    (* ask the cache *)
    let awaiting = { ts; retry = 0; proto; zone = Domain_name.root ; edns = req.edns; ip = sender; port = sport; question = (fst req.question, q_type); id = fst req.header; } in
    begin match handle_query t ts awaiting with
      | `Answer pkt, t ->
        Logs.info (fun m -> m "answer %a" Packet.Question.pp req.question) ;
        t, [ (proto, sender, sport, pkt) ], []
      | `Nothing, t ->
        Logs.info (fun m -> m "nothing %a" Packet.Question.pp req.question) ;
        t, [], [] (* TODO: send a reply!? *)
      | `Query pkts, t ->
        Logs.info (fun m -> m "query %d %a" (List.length pkts) Packet.Question.pp req.question) ;
        t, [], List.map (fun (packet, dst) -> `Udp, dst, packet) pkts
    end
  | _ ->
    Logs.err (fun m -> m "ignoring %a" Packet.pp req);
    let pkt = Packet.create
        (fst req.header, Packet.Flags.empty) req.question
        (`Rcode_error (Rcode.NotImp, Packet.opcode_data req.data, None))
    in
    let buf, _ = Packet.encode proto pkt in
    t, [ proto, sender, sport, buf ], []

let handle_reply t now ts proto sender packet reply =
  match reply, Packet.Question.qtype packet.Packet.question with
  | `Answer _, Some qtype
  | `Rcode_error (Rcode.NXDomain, Opcode.Query, _), Some qtype
  | `Rcode_error (Rcode.ServFail, Opcode.Query, _), Some qtype ->
    begin
      Logs.info (fun m -> m "handling reply to %a" Packet.Question.pp packet.question);
      (* (a) first check whether frame was in transit! *)
      let key = fst packet.question, qtype in
      let r, transit = was_in_transit t.transit key (fst packet.header) sender in
      let t = { t with transit } in
      match r with
      | None -> Ok (t, [], [])
      | Some (zone, edns) ->
        (* (b) DNSSec verification of RRs *)
        let t, dnskeys =
          match qtype with
          | `K K Rr_map.Dnskey ->
            let cache, ds = Dns_cache.get t.cache ts zone Rr_map.Ds in
            { t with cache },
            begin match ds with
              | Ok (`Entry (_, ds_set), _) ->
                let keys = match packet.data with
                  | `Answer (a, _) -> Name_rr_map.find zone Rr_map.Dnskey a
                  | _ -> None
                in
                let ds_set =
                  (* RFC 4509 - drop SHA1 DS if SHA2 DS are present *)
                  if Rr_map.Ds_set.exists (fun ds ->
                      match ds.Ds.digest_type with
                      | Ds.SHA256 | Ds.SHA384 -> true | _ -> false)
                      ds_set
                  then
                    Rr_map.Ds_set.filter
                      (fun ds -> not (ds.Ds.digest_type = SHA1))
                      ds_set
                  else
                    ds_set
                in
                Option.map (fun (_, dnskeys) ->
                    Rr_map.Ds_set.fold (fun ds acc ->
                        match Dnssec.validate_ds zone dnskeys ds with
                        | Ok key -> Rr_map.Dnskey_set.add key acc
                        | Error `Msg msg ->
                          Logs.warn (fun m -> m "couldn't validate DS (for %a): %s"
                                        Domain_name.pp zone msg);
                          acc)
                      ds_set Rr_map.Dnskey_set.empty)
                  keys
              | _ ->
                Logs.warn (fun m -> m "no DS in cache for %a" Domain_name.pp zone);
                None
            end
          | _ ->
            let cache, dnskeys = Dns_cache.get t.cache ts zone Rr_map.Dnskey in
            { t with cache },
            match dnskeys with
            | Ok (`Entry (_, dnskey_set), _) -> Some dnskey_set
            | _ ->
              Logs.warn (fun m -> m "no DNSKEYS in cache for %a" Domain_name.pp zone);
              None
        in
        let* packet, signed =
          Option.fold
            ~none:(Ok (packet, false))
            ~some:(fun dnskeys ->
                let* packet =
                  Result.map_error (fun (`Msg msg) ->
                      Logs.err (fun m -> m "error %s verifying reply %a"
                                   msg Packet.pp_reply reply))
                    (Dnssec.verify_packet now dnskeys packet)
                in
                Ok (packet, true))
            dnskeys
        in
        (* (c) now we scrub and either *)
        match scrub_it t.cache proto zone edns ts ~signed qtype packet with
        | `Query_without_edns ->
          let t, cs = build_query t ts proto key 1 zone None sender in
          Logs.debug (fun m -> m "resolve: requery without edns %a %a"
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
          (* TODO why is edns none here?  is edns bad over tcp? *)
          let t, cs = build_query ~recursion_desired t ts `Tcp key 1 zone None sender in
          Logs.debug (fun m -> m "resolve: upgrade to tcp %a %a"
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
    Logs.err (fun m -> m "ignoring reply %a" Packet.pp_reply v);
    Error ()

let handle_delegation t ts proto sender sport req (delegation, add_data) =
  Logs.debug (fun m -> m "handling delegation %a (for %a)" Packet.Answer.pp delegation Packet.pp req) ;
  match req.Packet.data, Packet.Question.qtype req.question with
  | `Query, Some qtype ->
    let r, cache = Dns_resolver_cache.answer t.cache ts (fst req.question) qtype in
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
            Logs.err (fun m -> m "something is wrong, delegation but no IP");
            t, [], []
          | Some ip ->
            Logs.debug (fun m -> m "found ip %a, maybe querying %a"
                           Ipaddr.pp ip pp_key (name, qtype)) ;
            (* TODO is Domain_name.root correct here? *)
            let await = { ts; retry = 0; proto; zone = Domain_name.root; edns = req.edns; ip = sender; port = sport; question = (fst req.question, qtype); id = fst req.header; } in
            begin match maybe_query ~recursion_desired:true t ts await 0 ip name qtype with
              | None, t ->
                Logs.warn (fun m -> m "maybe_query for %a at %a returned nothing"
                              Domain_name.pp name Ipaddr.pp ip) ;
                t, [], []
              | Some (cs, ip), t -> t, [], [ `Udp, ip, cs ]
            end
        end
      | `Packet (flags, reply) ->
        let max_size, edns = Edns.reply req.edns in
        Logs.debug (fun m -> m "delegation reply for %a from cache: %a"
                       Packet.pp req Packet.pp_reply reply) ;
        let packet = Packet.create ?edns (fst req.header, flags) req.question (reply :> Packet.data) in
        let pkt, _ = Packet.encode ?max_size proto packet in
        t, [ proto, sender, sport, pkt ], []
        (* send it out! we've a cache hit here! *)
    end
  | _ ->
    Logs.err (fun m -> m "ignoring %a" Packet.pp req) ;
    let pkt =
      Packet.create (fst req.header, Packet.Flags.empty)
        req.question (`Rcode_error (Rcode.NotImp, Packet.opcode_data req.data, None))
    in
    t, [ proto, sender, sport, fst (Packet.encode proto pkt) ], []

let handle_buf t now ts query proto sender sport buf =
  match Packet.decode buf with
(*  | Error (`Bad_edns_version v) ->
    Logs.err (fun m -> m "bad edns version (from %a:%d) %u for@.%a"
                 Ipaddr.pp sender sport
                 v Cstruct.hexdump_pp buf) ;
    t, handle_error ~error:Dns_enum.BadVersOrSig proto sender sport buf, [] *)
  | Error e ->
    Logs.err (fun m -> m "decode error (from %a:%d) %a for@.%a"
                 Ipaddr.pp sender sport
                 Packet.pp_err e Cstruct.hexdump_pp buf) ;
    let answer = match Packet.raw_error buf Rcode.FormErr with
      | None -> []
      | Some data -> [ proto, sender, sport, data ]
    in
    t, answer, []
  | Ok res ->
    Logs.info (fun m -> m "reacting to packet from %a:%d"
                  Ipaddr.pp sender sport) ;
    match res.Packet.data with
    | #Packet.reply as reply ->
      begin
        match handle_reply t now ts proto sender res reply with
        | Ok a ->
          Logs.info (fun m -> m "handled reply %a:%d"
                        Ipaddr.pp sender sport) ;
          a
        | Error () -> t, [], []
      end
    | #Packet.request as req when query ->
      begin
        match handle_primary t.primary now ts proto sender sport res req buf with
        | `Reply (primary, pkt) ->
          Logs.info (fun m -> m "handled primary %a:%d" Ipaddr.pp sender sport) ;
          { t with primary }, [ proto, sender, sport, pkt ], []
        | `Delegation dele ->
          Logs.info (fun m -> m "handled delegation %a:%d" Ipaddr.pp sender sport) ;
          handle_delegation t ts proto sender sport res dele
        | `None ->
          Logs.info (fun m -> m "resolving %a:%d" Ipaddr.pp sender sport) ;
          (* DNSSEC request DS / DNSKEY / NS from auth *)
          resolve t ts proto sender sport res
      end
    | _ ->
      Logs.err (fun m -> m "ignoring unsolicited packet (query allowed? %b) %a" query Packet.pp res);
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
  in
  let el =
    { ts = now; retry = 0; proto; zone = Domain_name.root; edns; ip; port = 53; question; id; }
  in
  let t = { t with transit = QM.add question el t.transit } in
  let packet = Packet.create ?edns (id, Packet.Flags.empty) question `Query in
  let cs, _ = Packet.encode proto packet in
  t, (proto, ip, cs)

let max_retries = 5

let err_retries t question =
  let t, reqs = find_queries t question in
  t, List.fold_left (fun acc awaiting ->
      Logs.debug (fun m -> m "now erroring to %a" pp_key awaiting.question) ;
      let packet = Packet.create (awaiting.id, Packet.Flags.empty)
          (awaiting.question :> Packet.Question.t)
          (`Rcode_error (Rcode.ServFail, Opcode.Query, None))
      in
      let buf, _ = Packet.encode awaiting.proto packet in
      (awaiting.proto, awaiting.ip, awaiting.port, buf) :: acc)
    [] reqs

let timer t ts =
  let transit, rem =
    QM.partition
      (fun _ awaiting -> Int64.sub ts awaiting.ts < retry_interval)
      t.transit
  in
  let t = { t with transit } in
  if not (QM.is_empty transit && QM.is_empty rem) then
    Logs.debug (fun m -> m "try_other timer wheel -- keeping %d, running over %d"
                   (QM.cardinal transit) (QM.cardinal rem)) ;
  QM.fold (fun (name, typ) awaiting (t, out_a, out_q) ->
      let retry = succ awaiting.retry in
      if retry < max_retries then begin
        let t, outa, outq = handle_awaiting_queries ~retry t ts (name, typ) in
        (t, outa @ out_a, outq @ out_q)
      end else begin
        Logs.info (fun m -> m "retry limit exceeded for %a at %a!"
                      pp_key (name, typ) Ipaddr.pp awaiting.ip) ;
        let queried, out_as = err_retries t.queried (name, typ) in
        ({ t with queried }, out_as @ out_a, out_q)
      end)
    rem (t, [], [])
