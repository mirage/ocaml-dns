(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

[@@@ocaml.warning "-27"]
open Udns

(* The cache (a Map!?) for answers: once a specific type/name comes in, we know
   which questions can progress now *)
module QM = Map.Make(Packet.Question)

type awaiting =
  int64 * int * proto * Domain_name.t * Edns.t option
                * Ipaddr.V4.t * int * Packet.Question.t * int

open Rresult.R.Infix

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
          Udns_enum.A name now Udns_resolver_entry.Additional
          (Udns_resolver_entry.NoErr b) cache)
      cache Udns_resolver_root.a_records
  in
  let cache =
    Udns_resolver_cache.maybe_insert
      Udns_enum.NS Domain_name.root now Udns_resolver_entry.Additional
      (Udns_resolver_entry.NoErr Udns_resolver_root.ns_records) cache
  in
  { rng ; cache ; primary ; transit = QM.empty ; queried = QM.empty ; mode }

let pick rng = function
  | [] -> None
  | [ x ] -> Some x
  | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))

let header id =
  let flags = Packet.Header.FS.empty in
  { Packet.Header.id ; query = true ; operation = Udns_enum.Query ;
    rcode = Udns_enum.NoError ; flags }

let build_query ?id ?(recursion_desired = false) t ts proto question retry zone edns ip =
  let id = match id with Some id -> id | None -> Randomconv.int16 t.rng in
  let header =
    let hdr = header id in
    (* TODO not clear about this.. *)
    let flags =
      if recursion_desired then
        Packet.Header.FS.add `Recursion_desired hdr.flags
      else
        hdr.flags
    in
    { hdr with flags }
  in
  let query = `Query Packet.Query.empty in
  let el = (ts, retry, proto, zone, edns, ip, 53, question, id) in
  let transit =
    if QM.mem question t.transit then
      Logs.warn (fun m -> m "overwriting transit of %a" Packet.Question.pp question) ;
    QM.add question el t.transit
  in
  transit, header, query

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
    (* TODO: is `Udp good here? *)
    let transit, hdr, packet = build_query ?recursion_desired t ts proto k retry zone edns ip in
    let t = { t with transit ; queried = QM.add k [await] t.queried } in
    Logs.debug (fun m -> m "maybe_query: query %a %a %a %a" Ipaddr.V4.pp ip
                   Packet.Header.pp hdr Packet.Question.pp k Packet.pp packet) ;
    let packet, _ = Packet.encode ?edns proto hdr k packet in
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
                (Udns_resolver_cache.items t.cache) (Udns_resolver_cache.capacity t.cache)) ;
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
    let r, cache = Udns_resolver_cache.handle_query t.cache ~rng:t.rng (* primary *) ts q qid in
    let t = { t with cache } in
    match r with
    | `Query _ when out >= 30 ->
      Logs.warn (fun m -> m "dropping q %a from %a:%d (already sent 30 packets)"
                    Packet.Question.pp q Ipaddr.V4.pp from port) ;
      s := { !s with drop_send = succ !s.drop_send } ;
      (* TODO reply with error! *)
      `Nothing, t
    | `Query (zone, nam, typ, ip) ->
      Logs.debug (fun m -> m "have to query (zone %a) %a (%a) using ip %a"
                     Domain_name.pp zone
                     Domain_name.pp nam Udns_enum.pp_rr_typ typ Ipaddr.V4.pp ip) ;
      maybe_query t ts retry out ip nam typ (proto, zone, edns, from, port, q, qid)
    | `Answer (hdr, a) ->
      let max_out = if !s.max_out < out then out else !s.max_out in
      let time = Int64.sub ts its in
      let max_time = if !s.max_time < time then time else !s.max_time in
      s := { !s with
             answers = succ !s.answers ;
             max_out ; total_out = !s.total_out + out ;
             max_time ; total_time = Int64.add !s.total_time time ;
           } ;
      Logs.debug (fun m -> m "answering %a after %a %d out packets: %a %a"
                     Packet.Question.pp q Duration.pp time out
                     Packet.Header.pp hdr Packet.pp a) ;
      let max_size, edns = Edns.reply edns in
      let cs, _ = Packet.encode ?max_size ?edns proto hdr q a in
      `Answer cs, t
    | `Nothing -> `Nothing, t

let scrub_it mode t proto zone edns ts header q query =
  match Udns_resolver_utils.scrub ~mode zone header q query, edns with
  | Ok xs, _ ->
    let cache =
      List.fold_left
        (fun t (ty, n, r, e) ->
           Logs.debug (fun m -> m "maybe_insert %a %a %a"
                            Udns_enum.pp_rr_typ ty Domain_name.pp n Udns_resolver_entry.pp_res e) ;
           Udns_resolver_cache.maybe_insert ty n ts r e t)
        t xs
    in
    if Packet.Header.FS.mem `Truncation header.flags && proto = `Udp then
      (Logs.warn (fun m -> m "NS truncated reply, using TCP now") ;
       `Upgrade_to_tcp cache)
    else
      `Cache cache
  | Error Udns_enum.FormErr, Some _ ->
    Logs.warn (fun m -> m "NS sent FormErr, retrying without edns!") ;
    `Query_without_edns
  | Error e, _ ->
    Logs.warn (fun m -> m "NS didn't like us %a" Udns_enum.pp_rcode e) ;
    `Try_another_ns

let guard p err = if p then Ok () else Error (err ())

let handle_primary t now ts proto sender sport header question p additional edns tsig buf =
  (* makes only sense to ask primary for query=true since we'll never issue questions from primary *)
  let handle_inner name =
    if not header.Packet.Header.query then
      `No
    else
      match Udns_server.Primary.handle_frame t ts proto sender sport header question p additional name with
      | Ok (_, None, _, _) -> `None (* incoming notifications are never replied to *)
      | Ok (t, Some (header, p', additional), _, _) ->
          (* delegation if authoritative is not set! *)
          if Packet.Header.FS.mem `Authoritative header.flags then begin
            s := { !s with authoritative = succ !s.authoritative } ;
            let max_size, edns = Edns.reply edns in
            Logs.debug (fun m -> m "authoritative reply %a %a" Packet.Header.pp header Packet.pp p) ;
            let out = Packet.encode ?max_size ?additional ?edns proto header question p' in
            `Reply (t, (header, question, out))
          end else begin
            s := { !s with delegation = succ !s.delegation } ;
            `Delegation (p', additional)
          end
      | Error rcode ->
        Logs.debug (fun m -> m "authoritative returned %a" Udns_enum.pp_rcode rcode) ;
        `No
  in
  match Udns_server.handle_tsig (Udns_server.Primary.server t) now header question tsig buf with
  | Error (e, data) ->
    Logs.err (fun m -> m "tsig failed %a" Tsig_op.pp_e e) ;
    begin match data with
      | Some data -> `Reply (t, (header, question, (data, 0)))
      | None -> `None
    end
  | Ok None -> handle_inner None
  | Ok (Some (name, tsig, mac, key)) ->
    match handle_inner (Some name) with
    | `Reply (t, (header, question, (buf, max_size))) ->
      begin match Udns_server.((Primary.server t).tsig_sign) ~max_size ~mac name tsig ~key header question buf with
        | None ->
          Logs.warn (fun m -> m "couldn't use %a to tsig sign, using unsigned reply" Domain_name.pp name) ;
          `Reply (t, (header, question, (buf, max_size)))
        | Some (buf, _) -> `Reply (t, (header, question, (buf, 0)))
      end
    | x -> x

let supported = [ Udns_enum.A ; Udns_enum.NS ; Udns_enum.CNAME ;
                  Udns_enum.SOA ; Udns_enum.PTR ; Udns_enum.MX ;
                  Udns_enum.TXT ; Udns_enum.AAAA ; Udns_enum.SRV ;
                  Udns_enum.SSHFP ; Udns_enum.TLSA ;
                  Udns_enum.ANY ]

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

let resolve t ts proto sender sport header question p edns =
  let id = header.Packet.Header.id
  and error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with query = not header.query } in
    match Packet.error header question rcode with
    | None -> None
    | Some (cs, _) -> Some cs
  in
  match p with
  | `Query _ ->
    Logs.info (fun m -> m "resolving %a %a" Packet.Header.pp header Packet.Question.pp question) ;
    if not (Packet.Header.FS.mem `Recursion_desired header.flags) then
          Logs.warn (fun m -> m "recursion not desired") ;
        guard (List.mem (snd question) supported)
          (fun () ->
             Logs.err (fun m -> m "unsupported query type %a"
                          Udns_enum.pp_rr_typ (snd question)) ;
             error Udns_enum.NotImp) >>= fun () ->
        s := { !s with questions = succ !s.questions } ;
        (* ask the cache *)
        begin match handle_query t ts 0 proto edns sender sport ts question id with
          | `Answer pkt, t -> Ok (t, [ (proto, sender, sport, pkt) ], [])
          | `Nothing, t -> Ok (t, [], [])
          | `Query (packet, dst), t -> Ok (t, [], [ `Udp, dst, packet ])
        end
  | v ->
    Logs.err (fun m -> m "ignoring %a %a" Packet.Header.pp header Packet.pp v) ;
    Error (error Udns_enum.FormErr)

let handle_reply t ts proto sender header question v =
  let id = header.Packet.Header.id
  and error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with query = not header.query } in
    match Packet.error header question rcode with
    | None -> None
    | Some (cs, _) -> Some cs
  in
  match v with
  | `Query query ->
    Logs.info (fun m -> m "handling reply %a %a" Packet.Header.pp header
                  Packet.Question.pp question) ;
    (* (a) first check whether frame was in transit! *)
    let r, transit = was_in_transit t.transit question id sender in
    let t = { t with transit } in
    let r = match r with
      | None -> (t, [], [])
      | Some (zone, edns) ->
        s := { !s with responses = succ !s.responses } ;
        (* (b) now we scrub and either *)
        match scrub_it t.mode t.cache proto zone edns ts header question query with
        | `Query_without_edns ->
          s := { !s with retry_edns = succ !s.retry_edns } ;
          let transit, header, packet = build_query t ts proto question 1 zone None sender in
          Logs.debug (fun m -> m "resolve: requery without edns %a %a %a"
                         Ipaddr.V4.pp sender Packet.Header.pp header
                         Packet.pp packet) ;
          let cs, _ = Packet.encode `Udp header question packet in
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
            | `Recursive -> handle_awaiting_queries t ts question, false
          in
          (* TODO why is edns none here?  is edns bad over tcp? *)
          let transit, header, packet = build_query ~recursion_desired t ts `Tcp question 1 zone None sender in
          Logs.debug (fun m -> m "resolve: upgrade to tcp %a %a %a"
                         Ipaddr.V4.pp sender
                         Packet.Header.pp header
                         Packet.pp packet) ;
          let cs, _ = Packet.encode `Tcp header question packet in
          ({ t with transit }, out_a, (`Tcp, sender, cs) :: out_q)
        | `Try_another_ns ->
          (* is this the right behaviour? by luck we'll use another path *)
          handle_awaiting_queries t ts question
        | `Cache cache ->
          let t = { t with cache } in
          handle_awaiting_queries t ts question
    in
    Ok r
  | v ->
    Logs.err (fun m -> m "ignoring %a %a" Packet.Header.pp header Packet.pp v) ;
    Error (error Udns_enum.FormErr)

let handle_delegation t ts proto sender sport header question p additional edns (delegation, add_dele) =
  Logs.debug (fun m -> m "handling delegation %a (for %a)" Packet.pp delegation Packet.pp p) ;
  let error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with Packet.Header.query = not header.Packet.Header.query } in
    match Packet.error header question rcode with
    | None -> t, [], []
    | Some (cs, _) -> t, [ (proto, sender, sport, cs) ], []
  in
  match p with
  | `Query q ->
    begin match Udns_resolver_cache.answer t.cache ts question header.id with
      | `Query (name, cache) ->
        let t = { t with cache } in
        (* we should look into delegation for the actual delegation, but instead we're looking for glue A *)
        begin match add_dele with
          | None -> Logs.err (fun m -> m "no glue data") ; t, [], []
          | Some data ->
            let ips = Domain_name.Map.fold (fun n rrmap ips ->
                Logs.debug (fun m -> m "%a maybe in %a" Domain_name.pp n Rr_map.pp rrmap) ;
                match Rr_map.(find A rrmap) with
                | None -> ips
                | Some (_, ips') -> Rr_map.Ipv4_set.union ips ips')
                data Rr_map.Ipv4_set.empty
            in
            begin match pick t.rng (Rr_map.Ipv4_set.elements ips) with
              | None ->
                Logs.err (fun m -> m "something is wrong, delegation but no IP");
                t, [], []
              | Some ip ->
                Logs.debug (fun m -> m "found ip %a, maybe querying for %a %a"
                               Ipaddr.V4.pp ip Udns_enum.pp_rr_typ (snd question) Domain_name.pp name) ;
                (* TODO is Domain_name.root correct here? *)
                begin match maybe_query ~recursion_desired:true t ts 0 0 ip name (snd question) (proto, Domain_name.root, edns, sender, sport, question, header.Packet.Header.id) with
                  | `Nothing, t ->
                    Logs.warn (fun m -> m "maybe_query for %a at %a returned nothing"
                                  Domain_name.pp name Ipaddr.V4.pp ip) ;
                    t, [], []
                  | `Query (cs, ip), t -> t, [], [ (`Udp, ip, cs) ]
                end
            end
        end
      | `Packet (header, pkt, cache) ->
        let max_size, edns = Edns.reply edns in
        Logs.debug (fun m -> m "delegation reply from cache %a %a"
                       Packet.Header.pp header Packet.pp pkt) ;
        let pkt, _ = Packet.encode ?max_size ?edns proto header question pkt in
        { t with cache }, [ (proto, sender, sport, pkt) ], []
        (* send it out! we've a cache hit here! *)
    end
  | v ->
    Logs.err (fun m -> m "ignoring %a %a" Packet.Header.pp header Packet.pp v) ;
    error Udns_enum.FormErr

let handle_error ?(error = Udns_enum.FormErr) proto sender sport buf =
  match Packet.Header.decode buf with
  | Error e ->
    Logs.err (fun m -> m "couldn't parse header %a:@.%a"
                 Packet.pp_err e Cstruct.hexdump_pp buf) ;
    []
  | Ok header -> []
(* attempt to parse first question and reply with it
   let empty =
      `Query { question = [] ; answer = [] ;
               authority = [] ; additional = [] }
    and header = { header with Header.query = not header.Header.query }
    in
    match error header empty error with
    | None -> []
      | Some (cs, _) -> [ (proto, sender, sport, cs) ] *)

let handle t now ts query proto sender sport buf =
  match Packet.decode buf with
  | Error (`Bad_edns_version v) ->
    Logs.err (fun m -> m "bad edns version (from %a:%d) %u for@.%a"
                 Ipaddr.V4.pp sender sport
                 v Cstruct.hexdump_pp buf) ;
    s := { !s with errors = succ !s.errors } ;
    t, handle_error ~error:Udns_enum.BadVersOrSig proto sender sport buf, []
  | Error e ->
    Logs.err (fun m -> m "parse error (from %a:%d) %a for@.%a"
                 Ipaddr.V4.pp sender sport
                 Packet.pp_err e Cstruct.hexdump_pp buf) ;
    s := { !s with errors = succ !s.errors } ;
    t, handle_error proto sender sport buf, []
  | Ok ((header, question, p, additional, edns, tsig) as res) ->
    Logs.info (fun m -> m "reacting to (from %a:%d) %a"
                  Ipaddr.V4.pp sender sport Packet.pp_res res) ;
    match header.query, query with
    | true, true ->
      begin
        match handle_primary t.primary now ts proto sender sport header question p additional edns tsig buf with
        | `Reply (primary, (_, _, (pkt, _))) ->
          { t with primary }, [ (proto, sender, sport, pkt) ], []
        | `Delegation dele ->
          handle_delegation t ts proto sender sport header question p additional edns dele
        | `None -> t, [], []
        | `No ->
          match resolve t ts proto sender sport header question p edns with
          | Ok a -> a
          | Error (Some e) -> t, [ (proto, sender, sport, e) ], []
          | Error None -> t, [], []
      end
    | false, false ->
      begin
        match handle_reply t ts proto sender header question p with
        | Ok a -> a
        | Error (Some e) -> t, [ (proto, sender, sport, e) ], []
        | Error None -> t, [], []
      end
    | _, _ ->
      Logs.err (fun m -> m "ignoring unsolicited packet (query allowed? %b)" query);
      t, [], []

let query_root t now proto =
  let q_name = Domain_name.root
  and q_type = Udns_enum.NS
  in
  let ip, cache =
    match Udns_resolver_cache.find_ns t.cache t.rng now Domain_name.Set.empty q_name with
    | `HaveIP ip, cache -> ip, cache
    | _ ->
      let roots = snd (List.split Udns_resolver_root.root_servers) in
      (List.nth roots (Randomconv.int ~bound:(List.length roots) t.rng),
       t.cache)
  in
  let q = (q_name, q_type)
  and id = Randomconv.int16 t.rng
  in
  let edns = Some (Edns.create ()) in
  let el = (now, 0, proto, Domain_name.root, edns, ip, 53, q, id) in
  let t = { t with transit = QM.add q el t.transit ; cache } in
  let cs, _ = Packet.encode ?edns proto (header id) q (`Query Packet.Query.empty) in
  t, (proto, ip, cs)

let max_retries = 5

let err_retries t question =
  let t, reqs = find_queries t question in
  t, List.fold_left (fun acc (_, _, proto, _, _, ip, port, q, qid) ->
      Logs.debug (fun m -> m "now erroring to %a" Packet.Question.pp q) ;
      let header =
        let h = header qid in
        { h with Packet.Header.query = false }
      in
      match Packet.error header q Udns_enum.ServFail with
      | None -> acc
      | Some (pkt, _) -> (proto, ip, port, pkt) :: acc)
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
          let transit, header, packet = build_query ~id t ts proto question retry zone edns qs in
          let cs, _ = Packet.encode ?edns proto header question packet in
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
