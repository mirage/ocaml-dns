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

let is_signed = function
  | Dns_cache.AuthoritativeAnswer signed
  | AuthoritativeAuthority signed -> signed
  | _ -> None

let find_nsec t ts typ name =
  let rec up name =
    match snd (Dns_cache.get t ts name Nsec) with
    | Ok (`Entry (ttl, nsec), rank) ->
      if Bit_map.mem (Rr_map.to_int typ) nsec.Nsec.types then
        Some (name, (ttl, nsec), rank)
      else
        None
    | _ ->
      if Domain_name.count_labels name >= 1 then
        up (Domain_name.drop_label_exn name)
      else
        None
  in
  up name

let nsec_no t ts typ name =
  match find_nsec t ts typ name with
  | Some _ -> true
  | None -> false

let find_nsec3 t ts typ name =
  let rec up name =
    match snd (Dns_cache.get_nsec3 t ts name) with
    | Ok nsec3 ->
      let (_, _, Nsec3.{ iterations ; salt ; _ }, _) = List.hd nsec3 in
      let soa_name = Domain_name.drop_label_exn name in
      let hashed_name = Dnssec.nsec3_hashed_name salt iterations ~soa_name name in
      List.find_opt (fun (name, _, nsec3, _) ->
          let name = Domain_name.drop_label_exn ~rev:true name in
          let hashed_next_owner =
            Domain_name.prepend_label_exn soa_name
              (Base32.encode nsec3.Nsec3.next_owner_hashed)
          in
          (* TODO non-wc-expanded nsec3 only?? *)
          (Domain_name.compare name hashed_name < 0 &&
           Domain_name.compare hashed_name hashed_next_owner < 0) ||
          (* TODO wc nsec3 as well? *)
          (Domain_name.compare name hashed_name = 0 &&
           not (Bit_map.mem (Rr_map.to_int typ) nsec3.types))
        )
          nsec3
    | Error _ ->
      if Domain_name.count_labels name > 1 then
        up (Domain_name.drop_label_exn name)
      else
        None
  in
  up name

let nsec3_covering t ts typ name =
  match find_nsec3 t ts typ name with
  | None -> false
  | Some _ -> true

let upwards_ds_nonexisting t ts name =
  let rec go name =
    if nsec_no t ts Ds name || nsec3_covering t ts Ds name then
      true
    else
      match Domain_name.drop_label name with
      | Error _ -> false
      | Ok name -> go name
  in
  go name

let find_nearest_ns ip_proto dnssec ts t name =
  let find_ns name = match snd (Dns_cache.get t ts name Ns) with
    | Ok (`Entry (_, names), r) -> Domain_name.Host_set.elements names, is_signed r
    | _ -> [], None
  and find_dnskey name = match snd (Dns_cache.get t ts name Dnskey) with
    | Ok _ -> true
    | _ -> false
  and dnskey_nonexisting name = match snd (Dns_cache.get t ts name Dnskey) with
    | Ok _ -> false
    | Error _ ->
      (* no need to check for Ds nonexistance upwards, since we're only called
         if we have a Ds *)
      nsec_no t ts Dnskey name || nsec3_covering t ts Dnskey name
  and need_to_query_for_ds name = match snd (Dns_cache.get t ts name Ds) with
    | Ok _ -> false
    | Error _ -> not (upwards_ds_nonexisting t ts name)
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
  let have_ips_or_dnskey name ips =
    if dnssec && not (find_dnskey name) && have_ds name then
      if dnskey_nonexisting name then (
        (* this is tricky, and likely bad - we have a DS but no DNSKEY *)
        Log.warn (fun m -> m "DS present for %a, but nonexisting DNSKEY (NSEC/NSEC3)"
                     Domain_name.pp name);
        `HaveIPs (name, ips))
      else
        (* if dnssec is enabled, and have a DS record, and we don't have a dnskey,
           request it -- avoiding loops by only asking for dnskey if there's DS *)
        `NeedDnskey (name, ips)
    else
      `HaveIPs (name, ips)
  in
  let rec go nam =
    (* Log.info (fun m -> m "go %a" Domain_name.pp nam); *)
    let ns, signed_ns = find_ns nam in
    match ns with
    | [] ->
      (* Log.warn (fun m -> m "go no NS for %a" Domain_name.pp nam); *)
      if Domain_name.(equal root nam) then
        [ have_ips_or_dnskey nam (Dns_resolver_root.ips ip_proto) ]
      else
        go (Domain_name.drop_label_exn nam)
    | _ when dnssec && need_to_query_for_ds nam ->
      (* dnssec enabled, and no DS (and no nonexistance proof for DS) ->
         query for DS (which is always provided by the domain above:
         "." has it for ".coop" / ".com" for "example/com"
         -> this also avoids loops, if we get a negative reply for DS, we move
            on (and run into the case below)
      *)
      (* Log.info (fun m -> m "need to query for DS %a" Domain_name.pp nam); *)
      List.map (function
       | `HaveIPs (_name, ips) -> `NeedDs (nam, ips)
       | `NeedDnskey _ | `NeedAddress _ | `NeedDs _
       | `NeedSignedNs _ as r -> r)
        (if Domain_name.(equal root nam) then
           [ have_ips_or_dnskey name (Dns_resolver_root.ips ip_proto) ]
         else
           go (Domain_name.drop_label_exn nam))
    | name_servers ->
      List.fold_left (fun acc ns ->
          let host = Domain_name.raw ns in
          match find_address host with
          | [] ->
            (* Log.info (fun m -> m "go no address for NS %a (for %a)"
                     Domain_name.pp host
                     Domain_name.pp nam); *)
            if Domain_name.is_subdomain ~subdomain:ns ~domain:nam then
              (* we actually need glue *)
              if Domain_name.(equal root nam) then
                have_ips_or_dnskey nam (Dns_resolver_root.ips ip_proto) :: acc
              else
                (go (Domain_name.drop_label_exn nam)) @ acc
            else
              `NeedAddress (nam, host) :: acc
          | ips ->
            (* Log.info (fun m -> m "go address for NS %a (for %a): %a (dnssec %B signed_ns %B have_ds %B find_dnskey %B)"
                     Domain_name.pp host
                     Domain_name.pp nam
                     Ipaddr.pp ip
                     dnssec (Option.is_some signed_ns) (have_ds nam)
                     (find_dnskey nam)); *)
            if dnssec && Option.is_none signed_ns && have_ds nam then
              if find_dnskey nam then
                `NeedSignedNs (nam, ips) :: acc
              else if dnskey_nonexisting nam then (
                (* Log.warn (fun m -> m "DS present for %a, but NSEC/NSEC3 for DNSKEY"
                         Domain_name.pp nam); *)
                have_ips_or_dnskey nam ips :: acc)
              else
                `NeedDnskey (nam, ips) :: acc
            else
              have_ips_or_dnskey nam ips :: acc)
        [] name_servers
  in
  go name

let resolve t ~dnssec ip_proto ts name typ =
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
    List.concat_map (function
        | `NeedAddress (zone, ns) -> go t (N.add zone visited) addresses zone ns
        | `NeedDnskey (zone, ips) -> [ zone, zone, [`K (Rr_map.K Dnskey)], ips, t ]
        | `NeedDs (zone, ips) -> [ zone, zone, [`K (Rr_map.K Ds)], ips, t ]
        | `HaveIPs (zone, ips) ->
          (* qname minimisation: if we can, query minimal qname (and NS)
             this is possible as long as we haven't received a negative reply on
             the NS query -- that's why we have another Dns_cache.get NS below *)
          let name' =
            let n = Domain_name.count_labels name
            and z = Domain_name.count_labels zone
            in
            let n' =
              if succ z < n then
                Domain_name.drop_label_exn ~amount:(n - succ z) name
              else
                name
            in
            match snd (Dns_cache.get t ts n' Ns) with
            | Ok (`Entry _, _) -> n'
            | _ -> name
          in
          let types = if Domain_name.equal name' name then types else [ `K (Rr_map.K Ns) ] in
          [ zone, name', types, ips, t ]
        | `NeedSignedNs (domain, ips) -> [ domain, domain, [ `K (Rr_map.K Ns) ], ips, t ])
      (find_nearest_ns ip_proto dnssec ts t (Domain_name.raw name))
  in
  go t N.empty [typ] Domain_name.root name

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

let signed_or_nonexisting ~dnssec t ts ty name r =
  if dnssec then
    Option.is_some (is_signed r) || nsec_no t ts ty name || nsec3_covering t ts ty name ||
    upwards_ds_nonexisting t ts name
  else
    true

let ttl k = function
  | Ok (`Entry v, _) -> Rr_map.ttl k v
  | Ok ((`No_data (_, soa), _) | (`No_domain (_, soa), _) | (`Serv_fail (_, soa), _)) ->
    soa.Soa.minimum
  | Ok (`Alias (ttl, _), _) -> ttl
  | Error _ -> 0l

let answer ~dnssec ~dnssec_ok t ts name (typ : Packet.Question.qtype) =
  let packet _t _add ty rcode ~ttl ~rrsig answer authority =
    let answer =
      if dnssec_ok then
        if Domain_name.Map.cardinal answer > 0 then
          match rrsig with
          | Some rrsig -> Name_rr_map.add name Rrsig (ttl, Rr_map.Rrsig_set.singleton rrsig) answer
          | None -> answer
        else
          answer
      else
        answer
    in
    let authority =
      if dnssec_ok then
        if Domain_name.Map.cardinal authority = 1 then
          let name, rr_map = Domain_name.Map.choose authority in
          match Rr_map.find Soa rr_map with
          | None -> authority
          | Some _soa ->
            let authority =
              match rrsig with
              | None -> authority
              | Some rrsig ->
                Name_rr_map.add name Rrsig (ttl, Rr_map.Rrsig_set.singleton rrsig) authority
            in
            match ty with
            | None -> authority
            | Some ty ->
              match find_nsec t ts ty name, find_nsec3 t ts ty name with
              | Some (name, (ttl, nsec), rank), _ ->
                let authority = Name_rr_map.add name Nsec (ttl, nsec) authority in
                (match is_signed rank with
                 | Some rrsig -> Name_rr_map.add name Rrsig (ttl, Rr_map.Rrsig_set.singleton rrsig) authority
                 | None -> authority)
              | _, Some (name, ttl, nsec3, rank) ->
                let authority = Name_rr_map.add name Nsec3 (ttl, nsec3) authority in
                (match is_signed rank with
                 | Some rrsig -> Name_rr_map.add name Rrsig (ttl, Rr_map.Rrsig_set.singleton rrsig) authority
                 | None -> authority)
              | None, _ -> authority
        else
          authority
      else
        authority
    in
    let data = (answer, authority) in
    let flags =
      let f = Packet.Flags.(add `Recursion_available (singleton `Recursion_desired)) in
      if dnssec && match rrsig with Some _ -> true | None -> false then
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
    flags, data, None
  in
  match typ with
  | `Any ->
    let t, r = Dns_cache.get_any t ts name in
    let ttl = match r with
      | Ok (`No_domain (_, soa), _) -> soa.Soa.minimum
      | Ok (`Entries _rrs, _) -> 0l
      | Error _ -> 0l
    in
    begin match r with
      | Error _e ->
        (* Log.warn (fun m -> m "error %a while looking up %a, query"
                      pp_err e pp_question (name, typ)); *)
        `Query name, t
      | Ok (`No_domain res, r) ->
        Log.debug (fun m -> m "no domain while looking up %a, query" pp_question (name, typ));
        `Packet (packet t false None Rcode.NXDomain ~ttl ~rrsig:(is_signed r) Domain_name.Map.empty (to_map res)), t
      | Ok (`Entries rr_map, r) ->
        Log.debug (fun m -> m "entries while looking up %a" pp_question (name, typ));
        let data = Domain_name.Map.singleton name rr_map in
        `Packet (packet t true None Rcode.NoError ~ttl ~rrsig:(is_signed r) data Domain_name.Map.empty), t
    end
  | `K (Rr_map.K ty) ->
    let t, r = Dns_cache.get_or_cname t ts name ty in
    let ttl = ttl ty r in
    match r with
    | Error _e ->
      (* Log.warn (fun m -> m "error %a while looking up %a, query"
                    _pp_err _e pp_question (name, typ)); *)
      `Query name, t
    | Ok (`No_domain res, r) ->
      if not (signed_or_nonexisting ~dnssec t ts ty name r) then `Query name, t else (
        Log.debug (fun m -> m "no domain while looking up %a" pp_question (name, typ));
        `Packet (packet t false (Some ty) Rcode.NXDomain ~ttl ~rrsig:(is_signed r) Domain_name.Map.empty (to_map res)), t)
    | Ok (`No_data res, r) ->
      if not (signed_or_nonexisting ~dnssec t ts ty name r) then `Query name, t else (
        Log.debug (fun m -> m "no data while looking up %a" pp_question (name, typ));
        `Packet (packet t false (Some ty) Rcode.NoError ~ttl ~rrsig:(is_signed r) Domain_name.Map.empty (to_map res)), t)
    | Ok (`Serv_fail res, r) ->
      if not (signed_or_nonexisting ~dnssec t ts ty name r) then `Query name, t else (
        Log.debug (fun m -> m "serv fail while looking up %a" pp_question (name, typ));
        `Packet (packet t false (Some ty) Rcode.ServFail ~ttl ~rrsig:None Domain_name.Map.empty (to_map res)), t)
    | Ok (`Alias (ttl, alias), r) ->
      if not (signed_or_nonexisting ~dnssec t ts ty name r) then `Query name, t else
      begin
        Log.debug (fun m -> m "alias while looking up %a" pp_question (name, typ));
        match ty with
        | Cname ->
          let data = Name_rr_map.singleton name Cname (ttl, alias) in
          `Packet (packet t false (Some ty) Rcode.NoError ~ttl ~rrsig:(is_signed r) data Domain_name.Map.empty), t
        | ty ->
          match follow_cname t ts ty ~name ttl ~alias with
          | `Out (rcode, rrsig, an, au), t -> `Packet (packet t true (Some ty) rcode ~ttl ~rrsig an au), t
          | `Query n, t -> `Query n, t
      end
    | Ok (`Entry v, r) ->
      if not (signed_or_nonexisting ~dnssec t ts ty name r) then `Query name, t else
        (Log.debug (fun m -> m "entry while looking up %a" pp_question (name, typ));
         let data = Name_rr_map.singleton name ty v in
         `Packet (packet t true (Some ty) Rcode.NoError ~ttl ~rrsig:(is_signed r) data Domain_name.Map.empty), t)

let pick_n rng n xs =
  let l = List.length xs in
  if n >= l then
    xs
  else
    let rec pick amount bound =
      if amount = 0 then
        []
      else
        let e = Randomconv.int ~bound rng in
        let ips'' = pick (amount - 1) (bound - 1) in
        e :: List.map (fun idx -> if idx < e then idx else succ idx) ips''
    in
    let idx = pick n l in
    List.map (List.nth xs) idx

let handle_query t ~dnssec ~dnssec_ok ~rng ip_proto ts (qname, qtype) =
  match answer ~dnssec ~dnssec_ok t ts qname qtype with
  | `Packet (flags, data, additional), t ->
    Log.debug (fun m -> m "handle_query: reply %a (%a)" Domain_name.pp qname
                  Packet.Question.pp_qtype qtype);
    `Reply (flags, data, additional), t
  | `Query name, t ->
    (* DS should be requested at the parent *)
    let name', recover =
      if Domain_name.count_labels name > 1 && qtype = `K (Rr_map.K Ds) then
        let n' = Domain_name.drop_label_exn name in
        n', fun n -> if Domain_name.equal n n' then name else n
      else
        name, Fun.id
    in
    let actions = resolve t ~dnssec ip_proto ts name' qtype in
    let up_to_three = pick_n rng 3 actions in
    let ip1 = 4 - List.length up_to_three in
    let ip2 = max 1 (3 - List.length up_to_three) in
    let _i, queries, t' =
      List.fold_left (fun (i, acc, _t) (zone, name'', types, ips, t) ->
          let name'' = recover name'' in
          let number_of_ips = if i = 0 then ip1 else ip2 in
          let ips = pick_n rng number_of_ips ips in
          Log.debug (fun m -> m "handle_query %a (%a) query %a, resolve zone %a query %a (%a), ips %a"
                        Domain_name.pp qname Packet.Question.pp_qtype qtype
                        Domain_name.pp name Domain_name.pp zone Domain_name.pp name''
                        Fmt.(list ~sep:(any ", ") Packet.Question.pp_qtype) types
                        Fmt.(list ~sep:(any ", ") Ipaddr.pp) ips);
          let actions =
            List.map (fun ip -> (zone, (name'', types), ip)) ips
          in
          succ i, acc @ actions, Some t)
        (0, [], None) up_to_three
    in
    `Queries queries, Option.value ~default:t t'
