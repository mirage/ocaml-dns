(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

(* The cache (a Map!?) for answers: once a specific type/name comes in, we know
   which questions can progress now *)
module QM = Map.Make(Packet.Question)

type awaiting =
  int64 * int * proto * Domain_name.t * Edns.t option * Ipaddr.V4.t * int * Packet.Question.t * int

let retry_interval = Duration.of_ms 500

type stats = {
  questions : int ;
  responses : int ;
  answers : int ;
  authoritative : int ;
  delegation : int ;
  errors : int ;
  drops : int ;
  retransmits : int ;
  total_out : int ;
  max_out : int ;
  total_time : int64 ;
  max_time : int64 ;
  drop_timeout : int ;
  drop_send : int ;
  retry_edns : int ;
  tcp_upgrade : int ;
}

let empty_stats () = {
  questions = 0 ; responses = 0 ; answers = 0 ;
  authoritative = 0 ; delegation = 0 ;
  errors = 0 ; drops = 0 ; retransmits = 0 ;
  total_out = 0 ; max_out = 0 ; drop_timeout = 0 ; drop_send = 0 ;
  retry_edns = 0 ; total_time = 0L ; max_time = 0L ; tcp_upgrade = 0 ;
}

let s = ref (empty_stats ())

let pp_stats pf s =
  let avg = if s.answers = 0 then 0L else Int64.div s.total_time (Int64.of_int s.answers) in
  let avg_out = if s.answers = 0 then 0. else float_of_int s.total_out /. float_of_int s.answers in
  Fmt.pf pf "%d questions, %d answers max %a (avg %a)@.%d received responses, %d authoritative, %d delegations, %d errors, %d dropped replies, %d retransmits, %d noedns retries, %d tcp upgrade@.%f average out (%d max), %d timeout drops %d max_out drops"
    s.questions s.answers Duration.pp s.max_time Duration.pp avg s.responses s.authoritative s.delegation s.errors s.drops s.retransmits s.retry_edns s.tcp_upgrade avg_out s.max_out s.drop_timeout s.drop_send

type t = {
  rng : int -> Cstruct.t ;
  primary : Udns_server.Primary.s ;
  cache : Udns_resolver_cache.t ;
  transit : awaiting QM.t ;
  queried : awaiting list QM.t ;
  mode : [ `Stub | `Recursive ] ;
}

let create ?(size = 10000) ?(mode = `Recursive) now rng primary =
  let cache = Udns_resolver_cache.empty size in
  let cache =
    List.fold_left (fun cache (name, b) ->
        Udns_resolver_cache.maybe_insert
          A name now Udns_resolver_cache.Additional
          (`Entry b) cache)
      cache Udns_resolver_root.a_records
  in
  let cache =
    Udns_resolver_cache.maybe_insert
      Ns Domain_name.root now Udns_resolver_cache.Additional
      (`Entry Udns_resolver_root.ns_records) cache
  in
  { rng ; cache ; primary ; transit = QM.empty ; queried = QM.empty ; mode }

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
  let el = (ts, retry, proto, zone, edns, ip, 53, question, id) in
  let transit =
    if QM.mem question t.transit then
      Logs.warn (fun m -> m "overwriting transit of %a" Packet.Question.pp question) ;
    QM.add question el t.transit
  in
  transit, Packet.create header question `Query

let maybe_query ?recursion_desired t ts retry out ip name typ (proto, zone, edns, orig_s, orig_p, orig_q, orig_id) =
  let k = (name, typ) in
  let await = (ts, succ out, proto, zone, edns, orig_s, orig_p, orig_q, orig_id) in
  if QM.mem k t.queried then
    let t = { t with queried = QM.add k (await :: QM.find k t.queried) t.queried } in
    `Nothing, t
  else
    let edns = Some (Edns.create ())
    and proto = `Udp
    in
    (* TODO here we may want to use the _default protocol_ (and edns settings) instead of `Udp *)
    let transit, packet = build_query ?recursion_desired t ts proto k retry zone edns ip in
    let t = { t with transit ; queried = QM.add k [await] t.queried } in
    let packet = Packet.with_edns packet edns in
    Logs.debug (fun m -> m "maybe_query: query %a %a" Ipaddr.V4.pp ip Packet.pp packet) ;
    let packet, _ = Packet.encode proto packet in
    `Query (packet, ip), t

let was_in_transit t key id sender =
  match QM.find key t with
  | exception Not_found ->
    s := { !s with drops = succ !s.drops } ;
    Logs.warn (fun m -> m "key %a not present in set (likely retransmitted)"
                  Packet.Question.pp key) ;
    None, t
  | (_ts, _retry, _proto, zone, edns, o_sender, _o_port, _o_q, o_id) ->
    if Ipaddr.V4.compare sender o_sender = 0 && id = o_id then
      Some (zone, edns), QM.remove key t
    else
      (Logs.warn (fun m -> m "unsolicited reply for %a (id %d vs o_id %d, sender %a vs o_sender %a)"
                    Packet.Question.pp key id o_id Ipaddr.V4.pp sender Ipaddr.V4.pp o_sender) ;
       None, t)

let find_queries t k =
  match QM.find k t with
  | exception Not_found ->
    Logs.warn (fun m -> m "couldn't find entry %a in map" Packet.Question.pp k) ;
    s := { !s with drops = succ !s.drops } ;
    t, []
  | vals ->
    QM.remove k t, vals

let stats t =
  Logs.info (fun m -> m "stats: %a@.%a@.%d cached resource records (capacity: %d)"
                pp_stats !s
                Udns_resolver_cache.pp_stats (Udns_resolver_cache.stats ())
                (Udns_resolver_cache.size t.cache) (Udns_resolver_cache.capacity t.cache)) ;
  let names = fst (List.split (QM.bindings t.transit)) in
  Logs.info (fun m -> m "%d queries in transit %a" (QM.cardinal t.transit)
                Fmt.(list ~sep:(unit "; ") Packet.Question.pp) names) ;
  let qs = List.map (fun (q, v) -> (List.length v, q)) (QM.bindings t.queried) in
  Logs.info (fun m -> m "%d queries %a" (QM.cardinal t.queried)
                Fmt.(list ~sep:(unit "; ")
                       (pair ~sep:(unit ": ") int Packet.Question.pp)) qs)

let handle_query t its out ?(retry = 0) proto edns from port ts q qid =
  if Int64.sub ts its > Int64.shift_left retry_interval 2 then begin
    Logs.warn (fun m -> m "dropping q %a from %a:%d (timed out)"
                  Packet.Question.pp q Ipaddr.V4.pp from port) ;
    s := { !s with drop_timeout = succ !s.drop_timeout } ;
    `Nothing, t
  end else
    let r, cache = Udns_resolver_cache.handle_query t.cache ~rng:t.rng (* primary *) ts q in
    let t = { t with cache } in
    match r with
    | `Query _ when out >= 30 ->
      Logs.warn (fun m -> m "dropping q %a from %a:%d (already sent 30 packets)"
                    Packet.Question.pp q Ipaddr.V4.pp from port) ;
      s := { !s with drop_send = succ !s.drop_send } ;
      (* TODO reply with error! *)
      `Nothing, t
    | `Query (zone, (nam, typ), ip) ->
      Logs.debug (fun m -> m "have to query (zone %a) %a using ip %a"
                     Domain_name.pp zone Packet.Question.pp (nam, typ) Ipaddr.V4.pp ip);
      maybe_query t ts retry out ip nam typ (proto, zone, edns, from, port, q, qid)
    | `Reply (flags, a) ->
      let max_out = if !s.max_out < out then out else !s.max_out in
      let time = Int64.sub ts its in
      let max_time = if !s.max_time < time then time else !s.max_time in
      s := { !s with
             answers = succ !s.answers ;
             max_out ; total_out = !s.total_out + out ;
             max_time ; total_time = Int64.add !s.total_time time ;
           } ;
      let max_size, edns = Edns.reply edns in
      let packet = Packet.create ?edns (qid, flags) q (a :> Packet.data) in
      Logs.debug (fun m -> m "answering %a after %a %d out packets: %a"
                     Packet.Question.pp q Duration.pp time out
                     Packet.pp packet) ;
      let cs, _ = Packet.encode ?max_size proto packet in
      `Answer cs, t
    | `Nothing -> `Nothing, t

let scrub_it mode t proto zone edns ts p =
  match Udns_resolver_utils.scrub ~mode zone p, edns with
  | Ok xs, _ ->
    let cache =
      List.fold_left
        (fun t (Rr_map.K ty, n, r, e) ->
           Logs.debug (fun m -> m "maybe_insert %a %a %a"
                            Rr_map.ppk (K ty) Domain_name.pp n Udns_resolver_cache.pp_res e) ;
           Udns_resolver_cache.maybe_insert ty n ts r e t)
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
    let t, answer, _, _ = Udns_server.Primary.handle_packet t now ts proto sender sport packet name in
    match answer with
    | None -> `None (* TODO incoming ??? are never replied to - should be revised!? *)
    | Some reply ->
      (* delegation if authoritative is not set! *)
      if Packet.Flags.mem `Authoritative (snd reply.header) then begin
        s := { !s with authoritative = succ !s.authoritative };
        Logs.debug (fun m -> m "authoritative reply %a" Packet.pp reply) ;
        let r = Packet.encode proto reply in
        `Reply (t, (reply, r))
      end else match reply.data with
        | `Answer data ->
          s := { !s with delegation = succ !s.delegation };
          `Delegation (data, reply.additional)
        | _ -> `None (* not authoritative, error!! *)
  in
  match Udns_server.(handle_tsig (Primary.server t) now packet buf) with
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
      begin match Udns_server.((Primary.server t).tsig_sign) ~max_size ~mac name tsig ~key reply buf with
        | None ->
          Logs.warn (fun m -> m "couldn't use %a to tsig sign, using unsigned reply" Domain_name.pp name) ;
          `Reply (t, buf)
        | Some (buf, _) -> `Reply (t, buf)
      end
    | `None -> `None
    | `Delegation x -> `Delegation x

let handle_awaiting_queries ?retry t ts q =
  let queried, values = find_queries t.queried q in
  let t = { t with queried } in
  List.fold_left (fun (t, out_a, out_q) (old_ts, out, proto, _, edns, from, port, q, qid) ->
      Logs.debug (fun m -> m "now querying %a" Packet.Question.pp q) ;
      match handle_query ?retry t old_ts out proto edns from port ts q qid with
      | `Nothing, t -> t, out_a, out_q
      | `Query (pkt, dst), t -> t, out_a, (`Udp, dst, pkt) :: out_q
      | `Answer pkt, t -> t, (proto, from, port, pkt) :: out_a, out_q)
    (t, [], []) values

let resolve t ts proto sender sport req =
  match req.Packet.data with
  | `Query ->
    Logs.info (fun m -> m "resolving %a" Packet.pp req) ;
    if not (Packet.Flags.mem `Recursion_desired (snd req.header)) then
      Logs.warn (fun m -> m "recursion not desired") ;
    s := { !s with questions = succ !s.questions };
    (* ask the cache *)
    begin match handle_query t ts 0 proto req.edns sender sport ts req.question (fst req.header) with
      | `Answer pkt, t -> t, [ (proto, sender, sport, pkt) ], []
      | `Nothing, t -> t, [], [] (* TODO: send a reply!? *)
      | `Query (packet, dst), t -> t, [], [ `Udp, dst, packet ]
    end
  | _ ->
    Logs.err (fun m -> m "ignoring %a" Packet.pp req);
    let pkt = Packet.create
        (fst req.header, Packet.Flags.empty) req.question
        (`Rcode_error (Rcode.NotImp, Packet.opcode_data req.data, None))
    in
    let buf, _ = Packet.encode proto pkt in
    t, [ proto, sender, sport, buf ], []

let handle_reply t ts proto sender packet reply =
  let id = fst packet.Packet.header in
  match reply with
  | `Answer _
  | `Rcode_error (Rcode.NXDomain, Opcode.Query, _)
  | `Rcode_error (Rcode.ServFail, Opcode.Query, _) ->
    Logs.info (fun m -> m "handling reply %a" Packet.pp packet);
    (* (a) first check whether frame was in transit! *)
    let r, transit = was_in_transit t.transit packet.question id sender in
    let t = { t with transit } in
    let r = match r with
      | None -> (t, [], [])
      | Some (zone, edns) ->
        s := { !s with responses = succ !s.responses } ;
        (* (b) now we scrub and either *)
        match scrub_it t.mode t.cache proto zone edns ts packet with
        | `Query_without_edns ->
          s := { !s with retry_edns = succ !s.retry_edns } ;
          let transit, packet = build_query t ts proto packet.question 1 zone None sender in
          Logs.debug (fun m -> m "resolve: requery without edns %a %a"
                         Ipaddr.V4.pp sender Packet.pp packet) ;
          let cs, _ = Packet.encode `Udp packet in
          ({ t with transit }, [], [ `Udp, sender, cs ])
        | `Upgrade_to_tcp cache ->
          s := { !s with tcp_upgrade = succ !s.tcp_upgrade } ;
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
            match t.mode with
            | `Stub -> (t, [], []), true
            | `Recursive -> handle_awaiting_queries t ts packet.question, false
          in
          (* TODO why is edns none here?  is edns bad over tcp? *)
          let transit, packet = build_query ~recursion_desired t ts `Tcp packet.question 1 zone None sender in
          Logs.debug (fun m -> m "resolve: upgrade to tcp %a %a"
                         Ipaddr.V4.pp sender Packet.pp packet) ;
          let cs, _ = Packet.encode `Tcp packet in
          ({ t with transit }, out_a, (`Tcp, sender, cs) :: out_q)
        | `Try_another_ns ->
          (* is this the right behaviour? by luck we'll use another path *)
          handle_awaiting_queries t ts packet.question
        | `Cache cache ->
          let t = { t with cache } in
          handle_awaiting_queries t ts packet.question
    in
    Ok r
  | v ->
    Logs.err (fun m -> m "ignoring reply %a" Packet.pp_reply v);
    Error ()

let handle_delegation t ts proto sender sport req (delegation, add_data) =
  Logs.debug (fun m -> m "handling delegation %a (for %a)" Packet.Query.pp delegation Packet.pp req) ;
  match req.Packet.data with
  | `Query ->
    begin match Udns_resolver_cache.answer t.cache ts req.question with
      | `Query (name, cache) ->
        let t = { t with cache } in
        (* we should look into delegation for the actual delegation name,
           but instead we're looking for any glue (A) in additional *)
        let ips = Domain_name.Map.fold (fun _ rrmap ips ->
            match Rr_map.(find A rrmap) with
            | None -> ips
            | Some (_, ips') -> Rr_map.Ipv4_set.union ips ips')
            add_data Rr_map.Ipv4_set.empty
        in
        begin match pick t.rng (Rr_map.Ipv4_set.elements ips) with
          | None ->
            Logs.err (fun m -> m "something is wrong, delegation but no IP");
            t, [], []
          | Some ip ->
            Logs.debug (fun m -> m "found ip %a, maybe querying %a"
                           Ipaddr.V4.pp ip Packet.Question.pp (name, snd req.question)) ;
            (* TODO is Domain_name.root correct here? *)
            begin match maybe_query ~recursion_desired:true t ts 0 0 ip name (snd req.question) (proto, Domain_name.root, req.edns, sender, sport, req.question, fst req.header) with
              | `Nothing, t ->
                Logs.warn (fun m -> m "maybe_query for %a at %a returned nothing"
                              Domain_name.pp name Ipaddr.V4.pp ip) ;
                t, [], []
              | `Query (cs, ip), t -> t, [], [ `Udp, ip, cs ]
            end
        end
      | `Packet (flags, reply, cache) ->
        let max_size, edns = Edns.reply req.edns in
        Logs.debug (fun m -> m "delegation reply for %a from cache: %a"
                       Packet.pp req Packet.pp_reply reply) ;
        let packet = Packet.create ?edns (fst req.header, flags) req.question (reply :> Packet.data) in
        let pkt, _ = Packet.encode ?max_size proto packet in
        { t with cache }, [ proto, sender, sport, pkt ], []
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
                 Ipaddr.V4.pp sender sport
                 v Cstruct.hexdump_pp buf) ;
    s := { !s with errors = succ !s.errors } ;
    t, handle_error ~error:Udns_enum.BadVersOrSig proto sender sport buf, [] *)
  | Error e ->
    Logs.err (fun m -> m "decode error (from %a:%d) %a for@.%a"
                 Ipaddr.V4.pp sender sport
                 Packet.pp_err e Cstruct.hexdump_pp buf) ;
    s := { !s with errors = succ !s.errors };
    let answer = match Packet.raw_error buf Rcode.FormErr with
      | None -> []
      | Some data -> [ proto, sender, sport, data ]
    in
    t, answer, []
  | Ok res ->
    Logs.info (fun m -> m "reacting to (from %a:%d) %a"
                  Ipaddr.V4.pp sender sport Packet.pp res) ;
    match res.Packet.data with
    | #Packet.reply as reply ->
      begin
        match handle_reply t ts proto sender res reply with
        | Ok a -> a
        | Error () -> t, [], []
      end
    | #Packet.request as req when query ->
      begin
        (* TODO there used to be a `No case here, and `None returned t, [], [] *)
        match handle_primary t.primary now ts proto sender sport res req buf with
        | `Reply (primary, pkt) -> { t with primary }, [ proto, sender, sport, pkt ], []
        | `Delegation dele -> handle_delegation t ts proto sender sport res dele
        | `None -> resolve t ts proto sender sport res
      end
    | _ ->
      Logs.err (fun m -> m "ignoring unsolicited packet (query allowed? %b) %a" query Packet.pp res);
      t, [], []

let query_root t now proto =
  let root_ip () =
    match pick t.rng (snd (List.split Udns_resolver_root.root_servers)) with
    | None -> assert false
    | Some x -> x
  in
  let ip =
    match Udns_resolver_cache.cached t.cache now Ns Domain_name.root with
    | Ok (`Entry Rr_map.(B (Ns, (_, names))), _) ->
      let ips =
        Domain_name.Set.fold (fun name acc ->
            match Udns_resolver_cache.cached t.cache now A name with
            | Ok (`Entry Rr_map.(B (A, (_, ips))), _) ->
              Rr_map.Ipv4_set.union ips acc
            | _ -> acc)
          names Rr_map.Ipv4_set.empty
      in
      begin match pick t.rng (Rr_map.Ipv4_set.elements ips) with
        | Some ip -> ip
        | None -> root_ip ()
      end
    | _ -> root_ip ()
  in
  let q = Packet.Question.create Domain_name.root Ns
  and id = Randomconv.int16 t.rng
  in
  let edns = Some (Edns.create ()) in
  let el = (now, 0, proto, Domain_name.root, edns, ip, 53, q, id) in
  let t = { t with transit = QM.add q el t.transit } in
  let packet = Packet.create ?edns (id, Packet.Flags.empty) q `Query in
  let cs, _ = Packet.encode proto packet in
  t, (proto, ip, cs)

let max_retries = 5

let err_retries t question =
  let t, reqs = find_queries t question in
  t, List.fold_left (fun acc (_, _, proto, _, _, ip, port, q, qid) ->
      Logs.debug (fun m -> m "now erroring to %a" Packet.Question.pp q) ;
      let packet = Packet.create (qid, Packet.Flags.empty) q
          (`Rcode_error (Rcode.ServFail, Opcode.Query, None))
      in
      let buf, _ = Packet.encode proto packet in
      (proto, ip, port, buf) :: acc)
    [] reqs

let try_other_timer t ts =
  let transit, rem =
    QM.partition
      (fun _ (c, _, _, _, _, _, _, _, _) -> Int64.sub ts c < retry_interval)
      t.transit
  in
  let t = { t with transit } in
  if QM.cardinal transit > 0 || QM.cardinal rem > 0 then
    Logs.debug (fun m -> m "try_other timer wheel -- keeping %d, running over %d"
                   (QM.cardinal transit) (QM.cardinal rem)) ;
  QM.fold (fun question (_, retry, _, _, _, qs, _, _, _) (t, out_a, out_q) ->
      let retry = succ retry in
      if retry < max_retries then begin
        s := { !s with retransmits = succ !s.retransmits } ;
        let t, outa, outq = handle_awaiting_queries ~retry t ts question in
        (t, outa @ out_a, outq @ out_q)
      end else begin
        Logs.info (fun m -> m "retry limit exceeded for %a at %a!"
                      Packet.Question.pp question Ipaddr.V4.pp qs) ;
        let queried, out_as = err_retries t.queried question in
        ({ t with queried }, out_as @ out_a, out_q)
      end)
    rem (t, [], [])

let _retry_timer t ts =
  if QM.cardinal t.transit > 0 then
    Logs.debug (fun m -> m "retry timer with %d entries" (QM.cardinal t.transit)) ;
  List.fold_left (fun (t, out_a, out_q) (question, (c, retry, proto, zone, edns, qs, _port, _query, id)) ->
      if Int64.sub ts c < retry_interval then
        (Logs.debug (fun m -> m "ignoring retransmit %a for now %a"
                        Packet.Question.pp question Duration.pp (Int64.sub ts c) ) ;
         (t, out_a, out_q))
      else
        let retry = succ retry in
        if retry < max_retries then begin
          s := { !s with retransmits = succ !s.retransmits } ;
          Logs.info (fun m -> m "retransmit %a (%d of %d) to %a"
                        Packet.Question.pp question retry max_retries Ipaddr.V4.pp qs) ;
          let transit, packet = build_query ~id t ts proto question retry zone edns qs in
          let cs, _ = Packet.encode `Udp packet in
          { t with transit }, out_a, (`Udp, qs, cs) :: out_q
        end else begin
          Logs.info (fun m -> m "retry limit exceeded for %a at %a!"
                        Packet.Question.pp question Ipaddr.V4.pp qs) ;
          (* answer all outstanding requestors! *)
          let transit = QM.remove question t.transit in
          let t = { t with transit } in
          let queried, out_as = err_retries t.queried question in
          ({ t with queried }, out_as @ out_a, out_q)
        end)
    (t, [], []) (QM.bindings t.transit)

let timer = try_other_timer
