(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

module N = Domain_name.Set

let src = Logs.Src.create "dns_resolver_cache" ~doc:"DNS resolver cache"
module Log = (val Logs.src_log src : Logs.LOG)

let _pp_err ppf = function
  | `Cache_miss -> Fmt.string ppf "cache miss"
  | `Cache_drop -> Fmt.string ppf "cache drop"

let pp_question ppf (name, typ) =
  Fmt.pf ppf "%a (%a)" Domain_name.pp name Packet.Question.pp_qtype typ

let nsec_no_ds t ts name =
  let rec up name =
    match snd (Dns_cache.get t ts name Nsec) with
    | Ok (`Entry (_, nsec), _) ->
      not (Bit_map.mem (Rr_map.to_int Ds) nsec.Nsec.types)
    | _ ->
      if Domain_name.count_labels name >= 1 then
        up (Domain_name.drop_label_exn name)
      else
        false
  in
  up name

let nsec3_covering t ts name =
  let rec up name =
    match snd (Dns_cache.get_nsec3 t ts name) with
    | Ok nsec3 ->
      let Nsec3.{ iterations ; salt ; _ } = snd (List.hd nsec3) in
      let soa_name = Domain_name.drop_label_exn name in
      let hashed_name = Dnssec.nsec3_hashed_name salt iterations ~soa_name name in
      List.exists (fun (name, nsec3) ->
          let hashed_next_owner =
            Domain_name.prepend_label_exn soa_name
              (Base32.encode nsec3.Nsec3.next_owner_hashed)
          in
          (* TODO non-wc-expanded nsec3 only?? *)
          (Domain_name.compare name hashed_name < 0 &&
           Domain_name.compare hashed_name hashed_next_owner < 0) ||
          (* TODO wc nsec3 as well? *)
          (Domain_name.compare name hashed_name = 0 &&
           not (Bit_map.mem (Rr_map.to_int Ds) nsec3.types))
        )
        nsec3
    | Error _ ->
      if Domain_name.count_labels name > 1 then
        up (Domain_name.drop_label_exn name)
      else
        false
  in
  up name

let find_nearest_ns rng ip_proto dnssec ts t name =
  let pick = function
    | [] -> None
    | [ x ] -> Some x
    | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))
  in
  let find_ns name = match snd (Dns_cache.get t ts name Ns) with
    | Ok (`Entry (_, names), _) -> Domain_name.Host_set.elements names
    | _ -> []
  and find_dnskey name = match snd (Dns_cache.get t ts name Dnskey) with
    | Ok _ -> true
    | _ -> false
  and need_to_query_for_ds name = match snd (Dns_cache.get t ts name Ds) with
    | Ok _ -> false
    | Error _ -> not (nsec_no_ds t ts name || nsec3_covering t ts name)
  and have_ds name =
    match snd (Dns_cache.get t ts name Ds) with
    | Ok (`Entry _, _) -> true
    | _ -> false
  and find_address name =
    let ip4s =
      Result.fold
        ~ok:(function
            | `Entry (_, ips), _ ->
              List.map (fun ip -> Ipaddr.V4 ip) (Ipaddr.V4.Set.elements ips)
            | _ -> [])
        ~error:(fun _ -> [])
        (snd (Dns_cache.get t ts name A))
    and ip6s =
      Result.fold
        ~ok:(function
            | `Entry (_, ips), _ ->
              List.map (fun ip -> Ipaddr.V6 ip) (Ipaddr.V6.Set.elements ips)
            | _ -> [])
        ~error:(fun _ -> [])
        (snd (Dns_cache.get t ts name Aaaa))
    in
    match ip_proto with
    | `Both -> ip4s @ ip6s
    | `Ipv4_only -> ip4s
    | `Ipv6_only -> ip6s
  in
  let have_ip_or_dnskey name ip =
    if dnssec && not (find_dnskey name) && have_ds name then
      (* if dnssec is enabled, and have a DS record, and we don't have a dnskey,
         request it -- avoiding loops by only asking for dnskey if there's DS *)
      `NeedDnskey (name, ip)
    else
      `HaveIP (name, ip)
  in
  let or_root f nam =
    if Domain_name.(equal root nam) then
      match pick (Dns_resolver_root.ips ip_proto) with
      | None -> assert false
      | Some ip -> have_ip_or_dnskey nam ip
    else
      f (Domain_name.drop_label_exn nam)
  in
  let rec go nam =
    (* Log.warn (fun m -> m "go %a" Domain_name.pp nam); *)
    match pick (find_ns nam) with
    | None ->
      (* Log.warn (fun m -> m "go no NS for %a" Domain_name.pp nam); *)
      or_root go nam
    | Some _ when dnssec && need_to_query_for_ds nam ->
      (* dnssec enabled, and no DS -> query for DS (which is always provided by
         the domain above: "." has it for ".coop" / ".com" for "example/com"
         -> this also avoids loops, if we get a negative reply for DS, we move
            on (and run into the case below)
      *)
      (match or_root go nam with
       | `HaveIP (_name, ip) -> `NeedDs (nam, ip)
       | `NeedDnskey _ | `NeedAddress _ | `NeedDs _ as r -> r)
    | Some ns ->
      let host = Domain_name.raw ns in
      match pick (find_address host) with
      | None ->
        (* Log.warn (fun m -> m "go no address for NS %a (for %a)"
                      Domain_name.pp host
                      Domain_name.pp nam); *)
        if Domain_name.is_subdomain ~subdomain:ns ~domain:nam then
          (* we actually need glue *)
          or_root go nam
        else
          `NeedAddress (nam, host)
      | Some ip ->
        (* Log.warn (fun m -> m "go address for NS %a (for %a): %a (dnskey %B)"
                      Domain_name.pp host
                      Domain_name.pp nam
                      Ipaddr.pp ip
                      (find_dnskey nam)); *)
        have_ip_or_dnskey nam ip
  in
  go name

let resolve t ~dnssec ~rng ip_proto ts name typ =
  (* the standard recursive algorithm *)
  let addresses = match ip_proto with
    | `Both -> [`K (Rr_map.K A); `K (Rr_map.K Aaaa)]
    | `Ipv4_only -> [`K (Rr_map.K A)]
    | `Ipv6_only -> [`K (Rr_map.K Aaaa)]
  in
  (* with DNSSec:
     - input is qname and qtyp
     - (a) we have (validated) NS record (+DNSKEY) for zone -> move along
     - (b) we miss a NS entry -> drop label and find one
     ---> we also want to collect DS and DNSKEY entries (or non-existence of DS)
     ---> we get DS by dnssec ok in EDNS
     ---> we may have unsigned NS (+ glue), and need to ask the NS for NS (+dnssec)
     ---> we may have unsigned glue, and need to go down for signed A/AAAA
  *)
  let rec go t visited types zone name =
    Log.debug (fun m -> m "go %a (zone %a)" Domain_name.pp name Domain_name.pp zone) ;
    let t =
      if N.mem zone visited then
        (* we need to break the cycle if there's one domain pointing to NS in
           another domain, and this other domain NS pointing to one domain. *)
        (* if we lack glue here, we should query .. for NS again with the hope
           to get some glue *)
        Dns_cache.remove t zone
      else
        t
    in
    match find_nearest_ns rng ip_proto dnssec ts t (Domain_name.raw name) with
    | `NeedAddress (zone, ns) -> go t (N.add zone visited) addresses zone ns
    | `NeedDnskey (zone, ip) -> zone, zone, [`K (Rr_map.K Dnskey)], ip, t
    | `NeedDs (zone, ip) -> zone, zone, [`K (Rr_map.K Ds)], ip, t
    | `HaveIP (zone, ip) -> zone, name, types, ip, t
  in
  go t N.empty [typ] Domain_name.root name

let is_signed = function
  | Dns_cache.AuthoritativeAnswer signed
  | AuthoritativeAuthority signed -> signed
  | _ -> false

let to_map (name, soa) = Name_rr_map.singleton name Soa soa

let follow_cname t ts typ ~name ttl ~alias =
  let rec follow t acc name =
    let t, r = Dns_cache.get_or_cname t ts name typ in
    match r with
    | Error _ ->
      Log.debug (fun m -> m "follow_cname: cache miss, need to query %a"
                     Domain_name.pp name);
      `Query name, t
    | Ok (`Alias (_, alias), r) ->
      let acc' = Domain_name.Map.add name (Rr_map.singleton Cname (ttl, alias)) acc in
      if Domain_name.Map.mem alias acc then begin
        Log.warn (fun m -> m "follow_cname: cycle detected") ;
        `Out (Rcode.NoError, is_signed r, acc', Name_rr_map.empty), t
      end else begin
        Log.debug (fun m -> m "follow_cname: alias to %a, follow again"
                       Domain_name.pp alias);
        follow t acc' alias
      end
    | Ok (`Entry v, r) ->
      let acc' = Domain_name.Map.add name Rr_map.(singleton typ v) acc in
      Log.debug (fun m -> m "follow_cname: entry found, returning");
      `Out (Rcode.NoError, is_signed r, acc', Name_rr_map.empty), t
    | Ok (`No_domain res, r) ->
      Log.debug (fun m -> m "follow_cname: nodom");
      `Out (Rcode.NXDomain, is_signed r, acc, to_map res), t
    | Ok (`No_data res, r) ->
      Log.debug (fun m -> m "follow_cname: nodata");
      `Out (Rcode.NoError, is_signed r, acc, to_map res), t
    | Ok (`Serv_fail res, r) ->
      Log.debug (fun m -> m "follow_cname: servfail") ;
      `Out (Rcode.ServFail, is_signed r, acc, to_map res), t
  in
  let initial = Name_rr_map.singleton name Cname (ttl, alias) in
  follow t initial alias

let answer t ts name typ =
  let packet _t _add rcode ~signed answer authority =
    let data = (answer, authority) in
    let flags =
      let f = Packet.Flags.(add `Recursion_available (singleton `Recursion_desired)) in
      if signed then
        Packet.Flags.add `Authentic_data f
      else
        f
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
      | Error _e ->
        (* Log.warn (fun m -> m "error %a while looking up %a, query"
                      pp_err e pp_question (name, typ)); *)
        `Query name, t
      | Ok (`No_domain res, r) ->
        Log.debug (fun m -> m "no domain while looking up %a, query" pp_question (name, typ));
        `Packet (packet t false Rcode.NXDomain ~signed:(is_signed r) Domain_name.Map.empty (to_map res)), t
      | Ok (`Entries rr_map, r) ->
        Log.debug (fun m -> m "entries while looking up %a" pp_question (name, typ));
        let data = Domain_name.Map.singleton name rr_map in
        `Packet (packet t true Rcode.NoError ~signed:(is_signed r) data Domain_name.Map.empty), t
    end
  | `K (Rr_map.K ty) ->
    let t, r = Dns_cache.get_or_cname t ts name ty in
    match r with
    | Error _e ->
      (* Log.warn (fun m -> m "error %a while looking up %a, query"
                    _pp_err _e pp_question (name, typ)); *)
      `Query name, t
    | Ok (`No_domain res, r) ->
      Log.debug (fun m -> m "no domain while looking up %a" pp_question (name, typ));
      `Packet (packet t false Rcode.NXDomain ~signed:(is_signed r) Domain_name.Map.empty (to_map res)), t
    | Ok (`No_data res, r) ->
      Log.debug (fun m -> m "no data while looking up %a" pp_question (name, typ));
      `Packet (packet t false Rcode.NoError ~signed:(is_signed r) Domain_name.Map.empty (to_map res)), t
    | Ok (`Serv_fail res, _) ->
      Log.debug (fun m -> m "serv fail while looking up %a" pp_question (name, typ));
      `Packet (packet t false Rcode.ServFail ~signed:false Domain_name.Map.empty (to_map res)), t
    | Ok (`Alias (ttl, alias), r) ->
      begin
        Log.debug (fun m -> m "alias while looking up %a" pp_question (name, typ));
        match ty with
        | Cname ->
          let data = Name_rr_map.singleton name Cname (ttl, alias) in
          `Packet (packet t false Rcode.NoError ~signed:(is_signed r) data Domain_name.Map.empty), t
        | ty ->
          match follow_cname t ts ty ~name ttl ~alias with
          | `Out (rcode, signed, an, au), t -> `Packet (packet t true rcode ~signed an au), t
          | `Query n, t -> `Query n, t
      end
    | Ok (`Entry v, r) ->
      Log.debug (fun m -> m "entry while looking up %a" pp_question (name, typ));
      let data = Name_rr_map.singleton name ty v in
      `Packet (packet t true Rcode.NoError ~signed:(is_signed r) data Domain_name.Map.empty), t

let handle_query t ~dnssec ~rng ip_proto ts (qname, qtype) =
  match answer t ts qname qtype with
  | `Packet (flags, data), t ->
    Log.debug (fun m -> m "handle_query: reply %a (%a)" Domain_name.pp qname
                  Packet.Question.pp_qtype qtype);
    `Reply (flags, data), t
  | `Query name, t ->
    (* DS should be requested at the parent *)
    let name', recover =
      if Domain_name.count_labels name > 1 && qtype = `K (Rr_map.K Ds) then
        let n' = Domain_name.drop_label_exn name in
        n', fun n -> if Domain_name.equal n n' then name else n
      else
        name, Fun.id
    in
    let zone, name'', types, ip, t = resolve t ~dnssec ~rng ip_proto ts name' qtype in
    let name'' = recover name'' in
    Log.debug (fun m -> m "handle_query %a (%a) query %a, resolve zone %a query %a (%a), ip %a"
                  Domain_name.pp qname Packet.Question.pp_qtype qtype
                  Domain_name.pp name Domain_name.pp zone Domain_name.pp name''
                  Fmt.(list ~sep:(any ", ") Packet.Question.pp_qtype) types
                  Ipaddr.pp ip);
    `Query (zone, (name'', types), ip), t
