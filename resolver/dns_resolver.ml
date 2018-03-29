(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* The cache (a Map!?) for answers: once a specific type/name comes in, we know
   which questions can progress now *)
module K = struct
  type t = Dns_enum.rr_typ * Dns_name.t

  let compare (t, n) (t', n') = match Dns_name.compare n n' with
    | 0 -> compare (Dns_enum.rr_typ_to_int t) (Dns_enum.rr_typ_to_int t')
    | x -> x
end

module QM = Map.Make(K)

type awaiting = int64 * int * Dns_packet.proto * Dns_packet.opts option * Ipaddr.V4.t * int * Dns_packet.question * int

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
  primary : Dns_server.Primary.s ;
  cache : Dns_resolver_cache.t ;
  transit : awaiting QM.t ;
  queried : awaiting list QM.t ;
}

let create ?(size = 10000) now rng primary =
  let cache = Dns_resolver_cache.empty size in
  let cache =
    List.fold_left (fun cache (name, rr) ->
        Dns_resolver_cache.maybe_insert
          Dns_enum.A name now Dns_resolver_entry.Additional
          (Dns_resolver_entry.NoErr [ rr ]) cache)
      cache Dns_resolver_root.a_records
  in
  let cache =
    Dns_resolver_cache.maybe_insert
      Dns_enum.NS Dns_name.root now Dns_resolver_entry.Additional
      (Dns_resolver_entry.NoErr Dns_resolver_root.ns_records) cache
  in
  { rng ; cache ; primary ; transit = QM.empty ; queried = QM.empty }

let header id = { Dns_packet.id ; query = true ; operation = Dns_enum.Query ;
                  authoritative = false ; truncation = false ; recursion_desired = false ;
                  recursion_available = false ; authentic_data = false ;
                  checking_disabled = false ; rcode = Dns_enum.NoError }

let build_query ?id ?(recursion_desired = false) t ts proto q retry edns ip =
  let id = match id with Some id -> id | None -> Randomconv.int16 t.rng in
  let header =
    let hdr = header id in
    { hdr with Dns_packet.recursion_desired }
  in
  let packet = header, `Query { Dns_packet.question = [q] ; answer = [] ; authority = [] ; additional = [] } in
  let el = (ts, retry, proto, edns, ip, 53, q, id) in
  let k = (q.Dns_packet.q_type, q.Dns_packet.q_name) in
  let transit =
    if QM.mem k t.transit then
      Logs.warn (fun m -> m "overwriting transit of %a (%a)" Dns_name.pp (snd k) Dns_enum.pp_rr_typ (fst k)) ;
    QM.add k el t.transit
  in
  transit, packet

let maybe_query ?recursion_desired t ts retry out ip typ name (proto, edns, orig_s, orig_p, orig_q, orig_id) =
  let k = (typ, name) in
  let await = (ts, succ out, proto, edns, orig_s, orig_p, orig_q, orig_id) in
  if QM.mem k t.queried then
    let t = { t with queried = QM.add k (await :: QM.find k t.queried) t.queried } in
    `Nothing, t
  else
    let edns = Some []
    and proto = `Udp
    in
    let quest = { Dns_packet.q_type = typ ; q_name = name } in
    (* TODO: is `Udp good here? *)
    let transit, packet = build_query ?recursion_desired t ts proto quest retry edns ip in
    let t = { t with transit ; queried = QM.add k [await] t.queried } in
    Logs.debug (fun m -> m "maybe_query: query %a %a" Ipaddr.V4.pp_hum ip Dns_packet.pp packet) ;
    let packet, _ = Dns_packet.encode ?edns proto packet in
    `Query (packet, ip), t

let was_in_transit t typ name id sender =
  let key = (typ, name) in
  match QM.find key t with
  | exception Not_found ->
    s := { !s with drops = succ !s.drops } ;
    Logs.warn (fun m -> m "key %a (%a) not present in set (likely retransmitted)"
                  Dns_name.pp name Dns_enum.pp_rr_typ typ) ;
    None, t
  | (_ts, _retry, _proto, edns, o_sender, _o_port, _o_q, o_id) ->
    if Ipaddr.V4.compare sender o_sender = 0 && id = o_id then
      Some edns, QM.remove key t
    else
      (Logs.warn (fun m -> m "unsolicited reply for %a (%a) (id %d vs o_id %d, sender %a vs o_sender %a)"
                    Dns_name.pp name Dns_enum.pp_rr_typ typ
                    id o_id Ipaddr.V4.pp_hum sender Ipaddr.V4.pp_hum o_sender) ;
       None, t)

let find_queries t k =
  match QM.find k t with
  | exception Not_found ->
    Logs.warn (fun m -> m "couldn't find entry %a (%a) in map"
                  Dns_name.pp (snd k) Dns_enum.pp_rr_typ (fst k)) ;
    s := { !s with drops = succ !s.drops } ;
    t, []
  | vals ->
    QM.remove k t, vals

let stats t =
  Logs.info (fun m -> m "stats: %a@.%a@.%d cached resource records (capacity: %d)"
                pp_stats !s
                Dns_resolver_cache.pp_stats (Dns_resolver_cache.stats ())
                (Dns_resolver_cache.items t.cache) (Dns_resolver_cache.capacity t.cache)) ;
  let names = QM.fold (fun (t, nam) _e acc ->
      (Printf.sprintf "%s (%s)" (Dns_name.to_string nam) (Dns_enum.rr_typ_to_string t)):: acc)
      t.transit []
  in
  Logs.info (fun m -> m "%d queries in transit %s" (QM.cardinal t.transit) (String.concat "; " names)) ;
  let qs = QM.fold (fun (t, nam) e acc ->
      (Printf.sprintf "[%d] %s (%s)" (List.length e) (Dns_name.to_string nam) (Dns_enum.rr_typ_to_string t)):: acc)
      t.queried []
  in
  Logs.info (fun m -> m "%d queries %s" (QM.cardinal t.queried) (String.concat "; " qs))

let handle_query t its out ?(retry = 0) proto edns from port ts q qid =
  if Int64.sub ts its > Int64.shift_left retry_interval 2 then begin
    Logs.warn (fun m -> m "dropping q %a from %a:%d (timed out)"
                  Dns_packet.pp_question q Ipaddr.V4.pp_hum from port) ;
    s := { !s with drop_timeout = succ !s.drop_timeout } ;
    `Nothing, t
  end else
    let r, cache = Dns_resolver_cache.handle_query t.cache ~rng:t.rng (* primary *) ts q qid in
    let t = { t with cache } in
    match r with
    | `Query _ when out >= 30 ->
      Logs.warn (fun m -> m "dropping q %a from %a:%d (already sent 30 packets)"
                    Dns_packet.pp_question q Ipaddr.V4.pp_hum from port) ;
      s := { !s with drop_send = succ !s.drop_send } ;
      (* TODO reply with error! *)
      `Nothing, t
    | `Query (nam, typ, ip) ->
      Logs.debug (fun m -> m "have to query %a (%s) using ip %a"
                     Dns_name.pp nam (Dns_enum.rr_typ_to_string typ) Ipaddr.V4.pp_hum ip) ;
      maybe_query t ts retry out ip typ nam (proto, edns, from, port, q, qid)
    | `Answer a ->
      let max_out = if !s.max_out < out then out else !s.max_out in
      let time = Int64.sub ts its in
      let max_time = if !s.max_time < time then time else !s.max_time in
      s := { !s with
             answers = succ !s.answers ;
             max_out ; total_out = !s.total_out + out ;
             max_time ; total_time = Int64.add !s.total_time time ;
           } ;
      Logs.debug (fun m -> m "answering %a (%a) after %a %d out packets: %a"
                     Dns_name.pp q.Dns_packet.q_name
                     Dns_enum.pp_rr_typ q.Dns_packet.q_type
                     Duration.pp time out
                     Dns_packet.pp a) ;
      let max_size, edns = match edns with
        | None -> None, None
        | Some x -> Dns_packet.payload_size x, Some []
      in
      let cs, _ = Dns_packet.encode ?max_size ?edns proto a in
      `Answer cs, t
    | `Nothing -> `Nothing, t

let scrub_it t proto edns ts q header query =
  match Dns_resolver_utils.scrub q header query, edns with
  | Ok xs, _ ->
    let cache =
      List.fold_left
        (fun t (ty, n, r, e) -> Dns_resolver_cache.maybe_insert ty n ts r e t)
        t xs
    in
    if header.Dns_packet.truncation && proto = `Udp then
      (Logs.warn (fun m -> m "NS truncated reply, using TCP now") ;
       `Upgrade_to_tcp cache)
    else
      `Cache cache
  | Error Dns_enum.FormErr, Some _ ->
    Logs.warn (fun m -> m "NS sent FormErr, retrying without edns!") ;
    `Query_without_edns
  | Error e, _ ->
    Logs.warn (fun m -> m "NS didn't like us %a" Dns_enum.pp_rcode e) ;
    `Try_another_ns

let guard p err = if p then Ok () else Error (err ())

let handle_primary t now ts proto sender header v tsig_off buf =
  (* makes only sense to ask primary for query=true since we'll never issue questions from primary *)
  let handle_inner name =
    if not header.Dns_packet.query then
      `No
    else
      match Dns_server.Primary.handle_frame t ts sender proto name (header, v) with
      | Ok (t, answer, _) ->
        begin match answer with
          | None ->
            Logs.err (fun m -> m "answer from authoritative is none, shouldn't happen") ;
            assert false
          | Some (header, v') ->
            (* delegation if authoritative is not set! *)
            if header.Dns_packet.authoritative then begin
              s := { !s with authoritative = succ !s.authoritative } ;
              let max_size, edns = match Dns_packet.find_edns v with
                | None -> None, None
                | Some edns -> Dns_packet.payload_size edns, Some []
              in
              Logs.debug (fun m -> m "authoritative reply %a %a" Dns_packet.pp_header header Dns_packet.pp_v v) ;
              let out = Dns_packet.encode ?max_size ?edns proto (header, v') in
              `Reply (t, out)
            end else begin
              s := { !s with delegation = succ !s.delegation } ;
              `Delegation v'
            end
        end
      | Error rcode ->
        Logs.debug (fun m -> m "authoritative returned %a" Dns_enum.pp_rcode rcode) ;
        `No
  in
  match Dns_server.handle_tsig (Dns_server.Primary.server t) now (header, v) tsig_off buf with
  | Error data -> `Reply (t, data)
  | Ok None ->
    begin match handle_inner None with
      | `No -> `No
      | `Delegation t -> `Delegation t
      | `Reply (t, (buf, _)) -> `Reply (t, buf)
    end
  | Ok (Some (name, tsig, mac, key)) ->
    match handle_inner (Some name) with
    | `Delegation a -> `Delegation a
    | `No -> `No
    | `Reply (t, (buf, max_size)) ->
      match Dns_server.((Primary.server t).tsig_sign) ~max_size ~mac name tsig ~key buf with
      | None ->
        Logs.warn (fun m -> m "couldn't use %a to tsig sign, using unsigned reply" Dns_name.pp name) ;
        `Reply (t, buf)
      | Some (buf, _) -> `Reply (t, buf)

let supported = [ Dns_enum.A ; Dns_enum.NS ; Dns_enum.CNAME ;
                  Dns_enum.SOA ; Dns_enum.PTR ; Dns_enum.MX ;
                  Dns_enum.TXT ; Dns_enum.AAAA ; Dns_enum.SRV ;
                  Dns_enum.SSHFP ; Dns_enum.TLSA ;
                  Dns_enum.ANY ]

let handle_awaiting_queries ?retry t ts q =
  let queried, values = find_queries t.queried (q.Dns_packet.q_type, q.Dns_packet.q_name) in
  let t = { t with queried } in
  List.fold_left (fun (t, out_a, out_q) (old_ts, out, proto, edns, from, port, q, qid) ->
      Logs.debug (fun m -> m "now querying %a" Dns_packet.pp_question q) ;
      match handle_query ?retry t old_ts out proto edns from port ts q qid with
      | `Nothing, t -> t, out_a, out_q
      | `Query (pkt, dst), t -> t, out_a, (`Udp, dst, pkt) :: out_q
      | `Answer pkt, t -> t, (proto, from, port, pkt) :: out_a, out_q)
    (t, [], []) values

let resolve t ts proto sender sport header v =
  let id = header.Dns_packet.id
  and error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with Dns_packet.query = not header.Dns_packet.query } in
    match Dns_packet.error header v rcode with
    | None -> None
    | Some (cs, _) -> Some cs
  in
  match v with
  | `Query query ->
    let q = match query.Dns_packet.question with | [x] -> Some x | _ -> None in
    Logs.info (fun m -> m "resolving %a %a" Dns_packet.pp_header header
                  Fmt.(option ~none:(unit "none") Dns_packet.pp_question) q) ;
    begin match query.Dns_packet.question with
      | [ q ] ->
        if header.Dns_packet.query then begin
          guard (header.Dns_packet.recursion_desired)
            (fun () ->
               Logs.err (fun m -> m "recursion not desired") ;
               error Dns_enum.FormErr) >>= fun () ->
          guard (List.mem q.Dns_packet.q_type supported)
            (fun () ->
               Logs.err (fun m -> m "unsupported query type %s"
                            (Dns_enum.rr_typ_to_string q.Dns_packet.q_type)) ;
               error Dns_enum.NotImp) >>= fun () ->
          s := { !s with questions = succ !s.questions } ;
          let edns = Dns_packet.find_edns v in
          (* ask the cache *)
          begin match handle_query t ts 0 proto edns sender sport ts q id with
            | `Answer pkt, t -> Ok (t, [ (proto, sender, sport, pkt) ], [])
            | `Nothing, t -> Ok (t, [], [])
            | `Query (packet, dst), t -> Ok (t, [], [ `Udp, dst, packet ])
          end
        end else (* is not a query, but a response *) begin
          let r =
            if sport <> 53 then begin
              Logs.err (fun m -> m "source port is not 53, but %d" sport) ;
              (t, [], [])
            end else begin
              (* (a) first check whether frame was in transit! *)
              let r, transit = was_in_transit t.transit q.Dns_packet.q_type q.Dns_packet.q_name id sender in
              let t = { t with transit } in
              match r with
              | None -> (t, [], [])
              | Some edns ->
                s := { !s with responses = succ !s.responses } ;
                (* (b) now we scrub and either *)
                match scrub_it t.cache proto edns ts q header query with
                | `Query_without_edns ->
                  s := { !s with retry_edns = succ !s.retry_edns } ;
                  let transit, packet = build_query t ts proto q 1 None sender in
                  Logs.debug (fun m -> m "resolve: requery without edns %a %a" Ipaddr.V4.pp_hum sender Dns_packet.pp packet) ;
                  let cs, _ = Dns_packet.encode `Udp packet in
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
                  let t, out_a, out_q = handle_awaiting_queries t ts q in
                  let transit, packet = build_query t ts `Tcp q 1 None sender in
                  Logs.debug (fun m -> m "resolve: upgrade to tcp %a %a" Dns_packet.pp_header header Dns_packet.pp_v v) ;
                  let cs, _ = Dns_packet.encode `Tcp packet in
                  ({ t with transit }, out_a, (`Tcp, sender, cs) :: out_q)
                | `Try_another_ns ->
                  (* is this the right behaviour? by luck we'll use another path *)
                  handle_awaiting_queries t ts q
                | `Cache cache ->
                  let t = { t with cache } in
                  handle_awaiting_queries t ts q
            end
          in
          Ok r
        end (* [ q ] && query or not *)
      | question ->
        Logs.warn (fun m -> m "got %d questions %a"
                      (List.length question)
                      Fmt.(list ~sep:(unit ";@ ") Dns_packet.pp_question) question) ;
        Error (error Dns_enum.FormErr)
    end (* `Query query *)
  | v ->
    Logs.err (fun m -> m "ignoring %a" Dns_packet.pp (header, v)) ;
    Error (error Dns_enum.FormErr)

let handle_delegation t ts proto sender sport header v v' =
  Logs.debug (fun m -> m "handling delegation %a (for %a)"
                 Dns_packet.pp_v v' Dns_packet.pp_v v) ;
  let error rcode =
    s := { !s with errors = succ !s.errors } ;
    let header = { header with Dns_packet.query = not header.Dns_packet.query } in
    match Dns_packet.error header v rcode with
    | None -> t, [], []
    | Some (cs, _) -> t, [ (proto, sender, sport, cs) ], []
  in
  match v with
  | `Query q ->
    begin match q.Dns_packet.question with
      | [ q ] ->
        begin match Dns_resolver_cache.answer t.cache ts q header.Dns_packet.id with
          | `Query (name, cache) ->
            (* parse v', which should contain an a record
               ask that for the very same query! *)
            let t = { t with cache } in
            let ip =
              match
                List.fold_left (fun acc rr -> match rr.Dns_packet.rdata with
                    | Dns_packet.A ip -> ip :: acc
                    | _ -> acc) []
                  (match v' with `Query v -> v.Dns_packet.additional | _ -> [])
              with
              | [] -> invalid_arg "bad delegation"
              | [ ip ] -> ip
              | ips ->
                List.nth ips (Randomconv.int ~bound:(List.length ips) t.rng)
            in
            let edns = Dns_packet.find_edns v in
            Logs.debug (fun m -> m "found ip %a, maybe querying for %a (%a)"
                           Ipaddr.V4.pp_hum ip Dns_enum.pp_rr_typ q.Dns_packet.q_type Dns_name.pp name) ;
            begin match maybe_query ~recursion_desired:true t ts 0 0 ip q.Dns_packet.q_type name (proto, edns, sender, sport, q, header.Dns_packet.id) with
              | `Nothing, t ->
                Logs.warn (fun m -> m "maybe_query for %a at %a returned nothing"
                              Dns_name.pp name Ipaddr.V4.pp_hum ip) ;
                t, [], []
              | `Query (cs, ip), t -> t, [], [ (`Udp, ip, cs) ]
            end
          | `Packet (pkt, cache) ->
            let max_size, edns = match Dns_packet.find_edns v with
              | None -> None, None
              | Some edns -> Dns_packet.payload_size edns, Some []
            in
            Logs.debug (fun m -> m "delegation reply from cache %a" Dns_packet.pp pkt) ;
            let pkt, _ = Dns_packet.encode ?max_size ?edns proto pkt in
            { t with cache }, [ (proto, sender, sport, pkt) ], []
            (* send it out! we've a cache hit here! *)
        end
      | question ->
        Logs.warn (fun m -> m "got %d questions %a"
                      (List.length question)
                      Fmt.(list ~sep:(unit ";@ ") Dns_packet.pp_question) question) ;
        error Dns_enum.FormErr
    end (* `Query query *)
  | v ->
    Logs.err (fun m -> m "ignoring %a" Dns_packet.pp (header, v)) ;
    error Dns_enum.FormErr

let handle_error proto sender sport buf =
  match Dns_packet.decode_header buf with
  | Error e ->
    Logs.err (fun m -> m "couldn't parse header %a:@.%a"
                 Dns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    []
  | Ok header ->
    let empty =
      `Query { Dns_packet.question = [] ; answer = [] ;
               authority = [] ; additional = [] }
    and header = { header with Dns_packet.query = not header.Dns_packet.query }
    in
    match Dns_packet.error header empty Dns_enum.FormErr with
    | None -> []
    | Some (cs, _) -> [ (proto, sender, sport, cs) ]

let handle t now ts proto sender sport buf =
  match Dns_packet.decode buf with
  | Error e ->
    Logs.err (fun m -> m "parse error (from %a:%d) %a for@.%a"
                 Ipaddr.V4.pp_hum sender sport
                 Dns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    s := { !s with errors = succ !s.errors } ;
    t, handle_error proto sender sport buf, []
  | Ok ((header, v), tsig_off) ->
    Logs.info (fun m -> m "reacting to (from %a:%d) %a: %a"
                  Ipaddr.V4.pp_hum sender sport
                  Dns_packet.pp_header header
                  Dns_packet.pp_v v) ;
    match handle_primary t.primary now ts proto sender header v tsig_off buf with
    | `Reply (primary, pkt) ->
      { t with primary }, [ (proto, sender, sport, pkt) ], []
    | `Delegation v' ->
      handle_delegation t ts proto sender sport header v v'
    | `No ->
      match resolve t ts proto sender sport header v with
      | Ok a -> a
      | Error (Some e) -> t, [ (proto, sender, sport, e) ], []
      | Error None -> t, [], []

let query_root t now proto =
  let q_name = Dns_name.root
  and q_type = Dns_enum.NS
  in
  match Dns_resolver_cache.find_ns t.cache t.rng now Dns_name.DomSet.empty q_name with
  | `HaveIP ip, cache ->
    let q = { Dns_packet.q_name ; q_type }
    and id = Randomconv.int16 t.rng
    in
    let packet = header id, `Query { Dns_packet.question = [q] ; answer = [] ; authority = [] ; additional = [] } in
    let edns = Some [] in
    let el = (now, 0, proto, edns, ip, 53, q, id) in
    let t = { t with transit = QM.add (q_type, q_name) el t.transit ; cache } in
    let cs, _ = Dns_packet.encode ?edns proto packet in
    t, (proto, ip, cs)
  | _ -> assert false

let max_retries = 5

let err_retries t q_type q_name =
  let t, reqs = find_queries t (q_type, q_name) in
  t, List.map (fun (_, _, proto, _, ip, port, q, qid) ->
      Logs.debug (fun m -> m "now erroring to %a" Dns_packet.pp_question q) ;
      let q = `Query { Dns_packet.question = [ q ] ; answer = [] ; authority = [] ; additional = [] } in
      let header =
        let h = header qid in
        { h with Dns_packet.query = false }
      in
      match Dns_packet.error header q Dns_enum.ServFail with
      | None -> assert false
      | Some (pkt, _) -> (proto, ip, port, pkt))
    reqs

let try_other_timer t ts =
  let transit, rem =
    QM.partition
      (fun _ (c, _, _, _, _, _, _, _) -> Int64.sub ts c < retry_interval)
      t.transit
  in
  let t = { t with transit } in
  if QM.cardinal transit > 0 || QM.cardinal rem > 0 then
    Logs.debug (fun m -> m "try_other timer wheel -- keeping %d, running over %d"
                   (QM.cardinal transit) (QM.cardinal rem)) ;
  QM.fold (fun (q_type, q_name) (_, retry, _, _, qs, _, _, _) (t, out_a, out_q) ->
      let retry = succ retry in
      if retry < max_retries then begin
        s := { !s with retransmits = succ !s.retransmits } ;
        let q = { Dns_packet.q_name ; q_type } in
        let t, outa, outq = handle_awaiting_queries ~retry t ts q in
        (t, outa @ out_a, outq @ out_q)
      end else begin
        Logs.info (fun m -> m "retry limit exceeded for %a (%a) at %a!"
                      Dns_name.pp q_name Dns_enum.pp_rr_typ q_type
                      Ipaddr.V4.pp_hum qs) ;
        let queried, out_as = err_retries t.queried q_type q_name in
        ({ t with queried }, out_as @ out_a, out_q)
      end)
    rem (t, [], [])

let _retry_timer t ts =
  if QM.cardinal t.transit > 0 then
    Logs.debug (fun m -> m "retry timer with %d entries" (QM.cardinal t.transit)) ;
  List.fold_left (fun (t, out_a, out_q) ((q_type, q_name), (c, retry, proto, edns, qs, _port, _query, id)) ->
      if Int64.sub ts c < retry_interval then
        (Logs.debug (fun m -> m "ignoring retransmit %a (%a) for now %a"
                        Dns_name.pp q_name Dns_enum.pp_rr_typ q_type
                        Duration.pp (Int64.sub ts c) ) ;
         (t, out_a, out_q))
      else
        let retry = succ retry in
        if retry < max_retries then begin
          s := { !s with retransmits = succ !s.retransmits } ;
          Logs.info (fun m -> m "retransmit %a %a (%d of %d) to %a"
                        Dns_name.pp q_name Dns_enum.pp_rr_typ q_type
                        retry max_retries Ipaddr.V4.pp_hum qs) ;
          let transit, packet = build_query ~id t ts proto { Dns_packet.q_type ; q_name } retry edns qs in
          let cs, _ = Dns_packet.encode ?edns proto packet in
          { t with transit }, out_a, (`Udp, qs, cs) :: out_q
        end else begin
          Logs.info (fun m -> m "retry limit exceeded for %a (%a) at %a!"
                        Dns_name.pp q_name Dns_enum.pp_rr_typ q_type
                        Ipaddr.V4.pp_hum qs) ;
          (* answer all outstanding requestors! *)
          let transit = QM.remove (q_type, q_name) t.transit in
          let t = { t with transit } in
          let queried, out_as = err_retries t.queried q_type q_name in
          ({ t with queried }, out_as @ out_a, out_q)
        end)
    (t, [], []) (QM.bindings t.transit)

let timer = try_other_timer
