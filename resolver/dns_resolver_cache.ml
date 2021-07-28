(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

module N = Domain_name.Set

let pp_err ppf = function
  | `Cache_miss -> Fmt.string ppf "cache miss"
  | `Cache_drop -> Fmt.string ppf "cache drop"

let pp_question ppf (name, typ) =
  Fmt.pf ppf "%a (%a)" Domain_name.pp name Packet.Question.pp_qtype typ

let find_nearest_ns rng ts t name =
  let pick = function
    | [] -> None
    | [ x ] -> Some x
    | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))
  in
  let find_ns name = match snd (Dns_cache.get t ts name Ns) with
    | Ok `Entry Rr_map.(B (Ns, (_, names))) -> Domain_name.Host_set.elements names
    | _ -> []
  and find_a name = match snd (Dns_cache.get t ts name A) with
    | Ok `Entry Rr_map.(B (A, (_, ips))) -> Rr_map.Ipv4_set.elements ips
    | _ -> []
  in
  let or_root f nam =
    if Domain_name.(equal root nam) then
      match pick (snd (List.split Dns_resolver_root.root_servers)) with
      | None -> assert false
      | Some ip -> `HaveIP (Domain_name.root, Ipaddr.V4 ip)
    else
      f (Domain_name.drop_label_exn nam)
  in
  let rec go nam =
    match pick (find_ns nam) with
    | None -> or_root go nam
    | Some ns ->
      let host = Domain_name.raw ns in
      match pick (find_a host) with
      | None ->
        if Domain_name.is_subdomain ~subdomain:ns ~domain:nam then
          (* we actually need glue *)
          or_root go nam
        else
          `NeedA host
      | Some ip -> `HaveIP (nam, Ipaddr.V4 ip)
  in
  go name

let resolve t ~rng ts name typ =
  (* the standard recursive algorithm *)
  let rec go t typ name =
    Logs.debug (fun m -> m "go %a" Domain_name.pp name) ;
    match find_nearest_ns rng ts t (Domain_name.raw name) with
    | `NeedA ns -> go t (`K (Rr_map.K A)) ns
    | `HaveIP (zone, ip) -> zone, name, typ, ip, t
  in
  go t typ name

let to_map (name, soa) = Name_rr_map.singleton name Soa soa

let follow_cname t ts typ ~name ttl ~alias =
  let rec follow t acc name =
    let t, r = Dns_cache.get_or_cname t ts name typ in
    match r with
    | Error _ ->
      Logs.debug (fun m -> m "follow_cname: cache miss, need to query %a"
                     Domain_name.pp name);
      `Query name, t
    | Ok `Entry (Rr_map.B (Cname, (_, alias))) ->
      let acc' = Domain_name.Map.add name (Rr_map.singleton Cname (ttl, alias)) acc in
      if Domain_name.Map.mem alias acc then begin
        Logs.warn (fun m -> m "follow_cname: cycle detected") ;
        `Out (Rcode.NoError, acc', Name_rr_map.empty), t
      end else begin
        Logs.debug (fun m -> m "follow_cname: alias to %a, follow again"
                       Domain_name.pp alias);
        follow t acc' alias
      end
    | Ok `Entry (Rr_map.B (k, v)) ->
      let acc' = Domain_name.Map.add name Rr_map.(singleton k v) acc in
      Logs.debug (fun m -> m "follow_cname: entry found, returning");
      `Out (Rcode.NoError, acc', Name_rr_map.empty), t
    | Ok `No_domain res ->
      Logs.debug (fun m -> m "follow_cname: nodom");
      `Out (Rcode.NXDomain, acc, to_map res), t
    | Ok `No_data res ->
      Logs.debug (fun m -> m "follow_cname: nodata");
      `Out (Rcode.NoError, acc, to_map res), t
    | Ok `Serv_fail res ->
      Logs.debug (fun m -> m "follow_cname: servfail") ;
      `Out (Rcode.ServFail, acc, to_map res), t
  in
  let initial = Name_rr_map.singleton name Cname (ttl, alias) in
  follow t initial alias

let answer t ts name typ =
  let packet _t _add rcode answer authority =
    (* TODO why was this RA + RD in here? should not be RD for recursive algorithm
       TODO should it be authoritative for recursive algorithm? *)
    let data = (answer, authority) in
    let flags = Packet.Flags.singleton `Recursion_desired
    (* XXX: we should look for a fixpoint here ;) *)
    (*    and additional, t = if add then additionals t ts answer else [], t *)
    and data = match rcode with
      | Rcode.NoError -> `Answer data
      | x ->
        let data = if Packet.Answer.is_empty data then None else Some data in
        `Rcode_error (x, Opcode.Query, data)
    in
    flags, data
  in
  match typ with
  | `Any ->
    let t, r = Dns_cache.get_any t ts name in
    begin match r with
      | Error e ->
        Logs.warn (fun m -> m "error %a while looking up %a, query"
                      pp_err e pp_question (name, typ));
        `Query name, t
      | Ok `No_domain res ->
        Logs.debug (fun m -> m "no domain while looking up %a, query" pp_question (name, typ));
        `Packet (packet t false Rcode.NXDomain Domain_name.Map.empty (to_map res)), t
      | Ok `Entries rr_map ->
        Logs.debug (fun m -> m "entries while looking up %a" pp_question (name, typ));
        let data = Domain_name.Map.singleton name rr_map in
        `Packet (packet t true Rcode.NoError data Domain_name.Map.empty), t
    end
  | `K (Rr_map.K ty) ->
    let t, r = Dns_cache.get_or_cname t ts name ty in
    match r with
    | Error e ->
      Logs.warn (fun m -> m "error %a while looking up %a, query"
                    pp_err e pp_question (name, typ));
      `Query name, t
    | Ok `No_domain res ->
      Logs.debug (fun m -> m "no domain while looking up %a, query" pp_question (name, typ));
      `Packet (packet t false Rcode.NXDomain Domain_name.Map.empty (to_map res)), t
    | Ok `No_data res ->
      Logs.debug (fun m -> m "no data while looking up %a" pp_question (name, typ));
      `Packet (packet t false Rcode.NoError Domain_name.Map.empty (to_map res)), t
    | Ok `Serv_fail res ->
      Logs.debug (fun m -> m "serv fail while looking up %a" pp_question (name, typ));
      `Packet (packet t false Rcode.ServFail Domain_name.Map.empty (to_map res)), t
    | Ok `Entry (Rr_map.B (Cname, (ttl, alias))) ->
      begin
        Logs.debug (fun m -> m "alias while looking up %a" pp_question (name, typ));
        match typ with
        | `Any ->
          let data = Name_rr_map.singleton name Cname (ttl, alias) in
          `Packet (packet t false Rcode.NoError data Domain_name.Map.empty), t
        | `K (K Cname) ->
          let data = Name_rr_map.singleton name Cname (ttl, alias) in
          `Packet (packet t false Rcode.NoError data Domain_name.Map.empty), t
        | `K (K ty) ->
          match follow_cname t ts ty ~name ttl ~alias with
          | `Out (rcode, an, au), t -> `Packet (packet t true rcode an au), t
          | `Query n, t -> `Query n, t
      end
    | Ok `Entry (Rr_map.B (k, v)) ->
      Logs.debug (fun m -> m "entry while looking up %a" pp_question (name, typ));
      let data = Name_rr_map.singleton name k v in
      `Packet (packet t true Rcode.NoError data Domain_name.Map.empty), t

let handle_query t ~rng ts (qname, qtype) =
  match answer t ts qname qtype with
  | `Packet (flags, data), t -> `Reply (flags, data), t
  | `Query name, t ->
    let zone, name', typ, ip, t = resolve t ~rng ts name qtype in
    Logs.debug (fun m -> m "resolve returned zone %a query %a (%a), ip %a"
                   Domain_name.pp zone Domain_name.pp name'
                   Packet.Question.pp_qtype typ Ipaddr.pp ip);
    `Query (zone, (name', typ), ip), t
