(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

module N = Domain_name.Set

let pp_err ppf = function
  | `Cache_miss -> Fmt.string ppf "cache miss"
  | `Cache_drop -> Fmt.string ppf "cache drop"

let pp_question ppf (name, typ) =
  Fmt.pf ppf "%a (%a)" Domain_name.pp name Packet.Question.pp_qtype typ

(*
let resolve_ns t ts name =
  match cached t ts Dns_enum.A name with
  | Error _ ->
    Logs.debug (fun m -> m "resolve_ns: error %a, need A" Domain_name.pp name);

    `NeedA name, t
  | Ok (`Entry Rr_map.(B (k, v) as b), t) ->
    begin
      match k, v with
      | Rr_map.A, (_, ips) ->
        Logs.debug (fun m -> m "resolve_ns: found a %a: %a)"
                       Domain_name.pp name Fmt.(list ~sep:(unit ", ") Ipaddr.pp)
                       (Rr_map.Ipv4_set.elements ips));
        `HaveIPS ips, t
      | _ ->
        Logs.warn (fun m -> m "resolve_ns: ignoring %a (looked A %a)"
                      Rr_map.pp_b b Domain_name.pp name);
        `NeedA name, t
    end
  | Ok (`No_domain _, t) ->
    Logs.warn (fun m -> m "resolve_ns: NoDom cache lookup for %a"
                  Domain_name.pp name);
    `NoDom, t
  | Ok (`Alias (_, alias), t) ->
    Logs.warn (fun m -> m "resolve_ns: Alias cache lookup for %a: %a"
                  Domain_name.pp name Domain_name.pp alias );
    `NeedCname alias, t
  | Ok (`No_data _, t) ->
    Logs.warn (fun m -> m "resolve_ns: No data, cache lookup for %a"
                  Domain_name.pp name);
    `No, t
  | Ok (`Serv_fail _, t) ->
    Logs.warn (fun m -> m "resolve_ns: serv fail, cache lookup for %a"
                  Domain_name.pp name);
    `No, t
*)

(*
let find_ns t rng ts stash name =
  let pick = function
    | [] -> None
    | [ x ] -> Some x
    | xs -> Some (List.nth xs (Randomconv.int ~bound:(List.length xs) rng))
  in
  match cached t ts Dns_enum.NS name with
  | Error _ -> `NeedNS, t
  | Ok (NoErr Rr_map.(B (k, v) as b), t) ->
    (* TODO test case -- we can't pick right now, unfortunately
       the following setup is there in the wild:
       berliner-zeitung.de NS 1.ns.berlinonline.de, 2.ns.berlinonline.de, x.ns.berlinonline.de
       berlinonline.de NS 1.ns.berlinonline.net, 2.ns.berlinonline.net, dns-berlinonline-de.unbelievable-machine.net
       berlinonline.net NS 2.ns.berlinonline.de, x.ns.berlinonline.de, 1.ns.berlinonline.de.
       --> all delivered without glue *)
    begin match k, v with
      | Rr_map.Ns, (_, ns) ->
        begin
          let actual = Domain_name.Set.diff ns stash in
          match pick (Domain_name.Set.elements actual) with
          | None ->
            Logs.warn (fun m -> m "find_ns: couldn't take any name from %a (stash: %a), returning loop"
                          Fmt.(list ~sep:(unit ",@ ") Domain_name.pp) (Domain_name.Set.elements ns)
                          Fmt.(list ~sep:(unit ",@ ") Domain_name.pp) (Domain_name.Set.elements stash)) ;
            `Loop, t
          | Some nsname ->
            (* tricky conditional:
               foo.com NS ns1.foo.com ; ns1.foo.com CNAME ns1.bar.com (well, may not happen ;)
               foo.com NS ns1.foo.com -> NeedGlue foo.com *)
            match resolve_ns t ts nsname with
            | `NeedA aname, t when Domain_name.sub ~subdomain:aname ~domain:name -> `NeedGlue name, t
            | `NeedCname cname, t -> `NeedA cname, t
            | `HaveIPS ips, t ->
              (* TODO should use a non-empty list of ips here *)
              begin match pick (Rr_map.Ipv4_set.elements ips) with
                | None -> `NeedA nsname, t
                | Some ip -> `HaveIP ip, t
              end
            | `NeedA aname, t -> `NeedA aname, t
            | `No, t -> `No, t
            | `NoDom, t -> `NoDom, t
        end
      | Rr_map.Cname, (_, alias) -> `Cname alias, t (* foo.com CNAME bar.com case *)
      | _ ->
        Logs.err (fun m -> m "find_ns: looked for NS %a, but got %a"
                     Domain_name.pp name Rr_map.pp_b b) ;
        `No, t
    end
  | Ok (_, t) -> `No, t
*)

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

(* below fails for cafe-blaumond.de, somewhere stuck in an zone hop:
    querying a.b.c.d.e.f, getting NS for d.e.f + A
     still no entry for e.f -> retrying same question all the time
  let rec go cur rest zone ip =
    (* if we find a NS, and an A record, go down *)
    (* if we find a NS, and no A record, needa *)
    (* if we get error, finish with what we have *)
    (* if we find nodom, nodata -> finish with what we have *)
    (* servfail returns an error *)
    Logs.debug (fun m -> m "nearest ns cur %a rest %a zone %a ip %a"
                   Domain_name.pp cur
                   Fmt.(list ~sep:(unit ".") string) rest
                   Domain_name.pp zone
                   Ipaddr.pp ip) ;
    match pick find_ns cur with
    | None -> `HaveIP (zone, ip)
    | Some ns -> begin match pick find_a ns with
      | None -> `NeedA ns
      | Some ip -> match rest with
        | [] -> `HaveIP (cur, ip)
        | hd::tl -> go (Domain_name.prepend_Exn cur hd) tl cur ip
        end
  in
  go Domain_name.root (List.rev (Domain_name.to_strings name)) Domain_name.root root
*)

let resolve t ~rng ts name typ =
  (* the standard recursive algorithm *)
  let rec go t typ name =
    Logs.debug (fun m -> m "go %a" Domain_name.pp name) ;
    match find_nearest_ns rng ts t (Domain_name.raw name) with
    | `NeedA ns -> go t (`K (Rr_map.K A)) ns
    | `HaveIP (zone, ip) -> zone, name, typ, ip, t
  in
  go t typ name

(* this is with qname minimisation!!
let _resolve t ~rng ts name typ =
  (* TODO return the bailiwick (zone the NS is responsible for) as well *)
  (* TODO this is the query name minimisation approach, reimplement the
          original recursive algorithm as well *)
  (* the top-to-bottom approach, for TYP a.b.c, lookup:
     @root NS, . -> A1
     @A1 NS, c -> A2
     @A2 NS, b.c -> A3
     @A3 NS. a.b.c -> NoData
     @A3 TYP, a.b.c -> A4

     where A{1-3} are all domain names, where we try to find A records (or hope
     to get them as glue)

     now, we have the issue of glue records: NS c (A2) will return names x.c
     and y.c, but also address records for them (otherwise there's no way to
     find out their addresses without knowing their addresses)

     A2 may as well contain a.c, b.c, and c.d - if delivered without glue, c.d
     is the only option to proceed (well, or ServFail or asking someone else for
     NS c) *)
  (* goal is to find the query to send out.
     we're applying qname minimisation on the way down

     it's a bit complicated, OTOH we're doing qname minimisation, but also may
     have to jump to other names (of NS or CNAME) - which is slightly intricate *)
  (* TODO this is misplaced, this should be properly handled by find_ns! *)
  let root =
    let roots = snd (List.split Dns_resolver_root.root_servers) in
    List.nth roots (Randomconv.int ~bound:(List.length roots) rng)
  in
  let rec go t stash typ cur rest zone ip =
    Logs.debug (fun m -> m "resolve entry: stash %a typ %a cur %a rest %a zone %a ip %a"
                   Fmt.(list ~sep:(unit ", ") Domain_name.pp) (N.elements stash)
                   Dns_enum.pp_rr_typ typ Domain_name.pp cur
                   Domain_name.pp (Domain_name.of_strings_exn ~hostname:false rest)
                   Domain_name.pp zone
                   Ipaddr.pp ip) ;
    match find_ns t rng ts stash cur with
    | `NeedNS, t when Domain_name.equal cur Domain_name.root ->
      (* we don't have any root servers *)
      Ok (Domain_name.root, Domain_name.root, Dns_enum.NS, root, t)
    | `HaveIP ip, t ->
      Logs.debug (fun m -> m "resolve: have ip %a" Ipaddr.pp ip) ;
      begin match rest with
        | [] -> Ok (zone, cur, typ, ip, t)
        | hd::tl -> go t stash typ (Domain_name.prepend_exn cur hd) tl zone ip
      end
    | `NeedNS, t ->
      Logs.debug (fun m -> m "resolve: needns") ;
      Ok (zone, cur, Dns_enum.NS, ip, t)
    | `Cname name, t ->
      (* NS name -> CNAME foo, only use foo if rest is empty *)
      Logs.debug (fun m -> m "resolve: cname %a" Domain_name.pp name) ;
      begin match rest with
        | [] ->
          let rest = List.rev (Domain_name.to_strings name) in
          go t (N.add name stash) typ Domain_name.root rest Domain_name.root root
        | hd::tl ->
          go t stash typ (Domain_name.prepend_exn cur hd) tl zone ip
      end
    | `NoDom, _ ->
      (* this is wrong for NS which NoDom for too much (even if its a ENT) *)
      Logs.debug (fun m -> m "resolve: nodom to %a!" Domain_name.pp cur) ;
      Error "can't resolve"
    | `No, _ ->
      Logs.debug (fun m -> m "resolve: no to %a!" Domain_name.pp cur) ;
      (* we tried to locate the NS for cur, but failed to find it *)
      (* it was ServFail/NoData in our cache.  how can we proceed? *)
      (* - ask the very same question to ips (NS / cur) - but we need to stop at some point *)
      (* - if rest = [], we just ask for cur+typ the ips --- this is common, e.g.
            ns1.foo.com NS @(foo.com authoritative)? - NoData, ns1.foo.com A @(foo.com authoritative) yay *)
      (* - if rest != [], (i.e. detectportal.firefox.com.edgesuite.net ->
               edgesuite.net -> NoData *)
      (* - give up!? *)
      (* this opens the door to amplification attacks :/ -- i.e. asking for
         a.b.c.d.e.f results in 6 requests (for f, e.f, d.e.f, c.d.e.f, b.c.d.e.f, a.b.c.d.e.f)  *)
      begin match rest with
        | [] -> Ok (zone, cur, typ, ip, t)
        | hd::tl -> go t stash typ (Domain_name.prepend_exn cur hd) tl zone ip
      end
    | `NeedGlue name, t ->
      Logs.debug (fun m -> m "resolve: needGlue %a" Domain_name.pp name) ;
      Ok (zone, name, Dns_enum.NS, ip, t)
    | `Loop, _ -> Error "resolve: cycle detected in find_ns"
    | `NeedA name, t ->
      Logs.debug (fun m -> m "resolve: needA %a" Domain_name.pp name) ;
      (* TODO: unclear whether this conditional is needed *)
      if N.mem name stash then begin
        Error "resolve: cycle detected during NeedA"
      end else
        let n = List.rev (Domain_name.to_strings name) in
        go t (N.add name stash) Dns_enum.A Domain_name.root n Domain_name.root root
  in
  go t (N.singleton name) typ Domain_name.root (List.rev (Domain_name.to_strings name)) Domain_name.root root
*)


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
      let acc' = Domain_name.Map.add name Rr_map.(singleton Cname (ttl, alias)) acc in
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

(*
let additionals t ts rrs =
  (* TODO: also AAAA *)
  N.fold (fun nam (acc, t) ->
      match cached t ts Dns_enum.A nam with
      | Ok (NoErr answers, t) -> answers @ acc, t
      | _ -> acc, t)
    (Dns_packet.rr_names rrs)
    ([], t)
*)

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
