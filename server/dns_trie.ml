(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

module O = struct
  type t = string
  let compare = Domain_name.compare_label
end
module M = Map.Make(O)

type t = N of t M.t * Rr_map.t

let empty = N (M.empty, Rr_map.empty)

let is_empty (N (sub, map)) = M.is_empty sub && Rr_map.is_empty map

let bindings t =
  let rec go pre (N (sub, e)) =
    let subs = M.bindings sub in
    (pre, e) ::
    List.fold_left
      (fun acc (pre', va) ->
         acc @ go (Domain_name.prepend_label_exn pre pre') va) [] subs
  in
  go Domain_name.root t

let pp_map name ppf map =
  Fmt.(list ~sep:(any "@.") string) ppf
    (List.map (Rr_map.text_b name) (Rr_map.bindings map))

let pp ppf t = List.iter (fun (name, map) -> pp_map name ppf map) (bindings t)

let rec equal (N (sub, map)) (N (sub', map')) =
  Rr_map.equal { f = Rr_map.equal_rr } map map' && M.equal equal sub sub'

type e = [ `Delegation of [ `raw ] Domain_name.t * (int32 * Domain_name.Host_set.t)
         | `EmptyNonTerminal of [ `raw ] Domain_name.t * Soa.t
         | `NotAuthoritative
         | `NotFound of [ `raw ] Domain_name.t * Soa.t ]

let pp_e ppf = function
  | `Delegation (name, (ttl, ns)) ->
    Fmt.pf ppf "delegation %a to TTL %lu %a" Domain_name.pp name ttl
      Fmt.(list ~sep:(any ",@,") Domain_name.pp) (Domain_name.Host_set.elements ns)
  | `EmptyNonTerminal (name, soa) ->
    Fmt.pf ppf "empty non terminal %a SOA %a" Domain_name.pp name Soa.pp soa
  | `NotAuthoritative -> Fmt.string ppf "not authoritative"
  | `NotFound (name, soa) -> Fmt.pf ppf "not found %a soa %a" Domain_name.pp name Soa.pp soa


let ( let* ) = Result.bind

let guard p err = if p then Ok () else Error err

let ent name map =
  let soa = Rr_map.get Soa map in
  `EmptyNonTerminal (name, soa)

let to_ns name map =
  let ttl, ns =
    match Rr_map.find Ns map with
    | None -> 0l, Domain_name.Host_set.empty
    | Some (ttl, ns) -> ttl, ns
  in
  (name, ttl, ns)

let check_zone = function
  | None -> Error `NotAuthoritative
  | Some (`Delegation (name, (ttl, ns))) -> Error (`Delegation (name, (ttl, ns)))
  | Some (`Soa (z, zmap)) -> Ok (z, zmap)

let lookup_res zone ty m =
  let* z, zmap = check_zone zone in
  match Rr_map.find ty m with
  | Some v -> Ok (Rr_map.B (ty, v), to_ns z zmap)
  | None -> match Rr_map.find Cname m with
    | None when Rr_map.cardinal m = 1 && Rr_map.(mem Soa m) ->
      (* this is primary a hack for localhost, which must be NXDomain,
         but there's a SOA for localhost (to handle it authoritatively) *)
      (* TODO should we check that the label-node map is empty?
         well, if we have a proper authoritative zone, there'll be a NS *)
      let soa = Rr_map.get Rr_map.Soa zmap in
      Error (`NotFound (z, soa))
    | None -> Error (ent z zmap)
    | Some cname -> Ok (B (Cname, cname), to_ns z zmap)

let lookup_aux name t =
  let k = Domain_name.to_array name in
  let l = Array.length k in
  let fzone idx map =
    let name = Domain_name.(of_array (Array.sub (to_array name) 0 idx)) in
    match Rr_map.mem Soa map, Rr_map.find Ns map with
    | true, _ -> Some (`Soa (name, map))
    | false, Some ns -> Some (`Delegation (name, ns))
    | false, None -> None
  in
  let rec go idx zone = function
    | N (sub, map) ->
      let zone = match fzone idx map with None -> zone | Some x -> Some x in
      if idx = l then Ok (zone, sub, map)
      else match M.find (Array.get k idx) sub with
        | exception Not_found ->
          begin match zone with
            | None -> Error `NotAuthoritative
            | Some (`Delegation (name, (ttl, ns))) ->
              Error (`Delegation (name, (ttl, ns)))
            | Some (`Soa (name, map)) ->
              (* may still be a wildcard *)
              match M.find "*" sub with
              | exception Not_found ->
                let soa = Rr_map.get Soa map in
                Error (`NotFound (name, soa))
              | N (sub, map) -> Ok (zone, sub, map)
          end
        | x -> go (succ idx) zone x
  in
  go 0 None t

let lookup_with_cname name ty t =
  let* zone, _sub, map = lookup_aux name t in
  lookup_res zone ty map

let lookup name key t =
  let* zone, _sub, map = lookup_aux name t in
  let* z, zmap = check_zone zone in
  Option.to_result ~none:(ent z zmap) (Rr_map.find key map)

let lookup_any name t =
  match lookup_aux name t with
  | Error e -> Error e
  | Ok (zone, _sub, m) ->
    let* z, zmap = check_zone zone in
    Ok (m, to_ns z zmap)

let lookup_glue name t =
  match lookup_aux name t with
  | Error _ -> None, None
  | Ok (_zone, _sub, map) -> Rr_map.find A map, Rr_map.find Aaaa map

let zone name t =
  match lookup_aux name t with
  | Error (`NotFound (zone, soa)) -> Ok (zone, soa)
  | Error e -> Error e
  | Ok (zone, _, _) ->
    match check_zone zone with
    | Error e -> Error e
    | Ok (name, map) ->
      (* we ended with `Soa, which checked that map contains a Soa *)
      Ok (name, Rr_map.get Soa map)

let fold key (N (sub, map)) f s =
  let get name map acc =
    match Rr_map.find key map with
    | Some a -> f name a acc
    | None -> acc
  in
  let rec collect name sub acc =
    List.fold_left (fun acc (pre, N (sub, map)) ->
        let n' = Domain_name.prepend_label_exn name pre in
        let keys = get n' map acc in
        collect n' sub keys)
      acc (M.bindings sub)
  in
  let name = Domain_name.root in
  collect name sub (get name map s)

let collect_rrs name sub map =
  let collect_map top name rrmap =
    if not top && Rr_map.mem Ns rrmap then
      (* delegation *)
      let ns_entries =
        Option.fold ~none:[]
          ~some:(fun ns -> [ name, Rr_map.B (Ns, ns) ])
          (Rr_map.find Ns rrmap)
      and ds_entries =
        Option.fold ~none:[]
          ~some:(fun ds -> [ name, Rr_map.B (Ds, ds) ])
          (Rr_map.find Ds rrmap)
      and rrsig_entries =
        Option.fold ~none:[]
          ~some:(fun rrsig -> [ name, Rr_map.B (Rrsig, rrsig) ])
          (Rr_map.find Rrsig rrmap)
      in
      ns_entries @ ds_entries @ rrsig_entries, false
    else
      Rr_map.fold (fun v acc -> (name, v) :: acc) rrmap [], true
  in
  let rec go top name sub map =
    let entries, recurse = collect_map top name map in
    if recurse then
      List.fold_left
        (fun acc (pre, N (sub, map)) ->
           acc @ go false (Domain_name.prepend_label_exn name pre) sub map)
        entries (M.bindings sub)
    else
      entries
  in
  go true name sub map

let collect_entries name sub map =
  let ttlsoa =
    match Rr_map.find Soa map with
    | Some v -> Some v
    | None when Domain_name.(equal root name) ->
      Some { Soa.nameserver = Domain_name.root ;
             hostmaster = Domain_name.root ;
             serial = 0l ; refresh = 0l ; retry = 0l ;
             expiry = 0l ; minimum = 0l }
    | None -> None
  in
  match ttlsoa with
  | None -> Error `NotAuthoritative
  | Some soa ->
    let entries = collect_rrs name sub (Rr_map.remove Soa map) in
    let res =
      List.fold_left (fun acc (name, (Rr_map.B (k, v))) ->
          Name_rr_map.add name k v acc) Domain_name.Map.empty entries
    in
    Ok (soa, res)

let entries name t =
  let name = Domain_name.raw name in
  let* zone, sub, map = lookup_aux name t in
  match zone with
  | None -> Error `NotAuthoritative
  | Some (`Delegation (name, (ttl, ns))) ->
    Error (`Delegation (name, (ttl, ns)))
  | Some (`Soa (name', _)) when Domain_name.equal name name' ->
    collect_entries name sub map
  | Some (`Soa (_, _)) -> Error `NotAuthoritative

type zone_check = [ `Missing_soa of [ `raw ] Domain_name.t
                  | `Cname_other of [ `raw ] Domain_name.t
                  | `Bad_ttl of [ `raw ] Domain_name.t * Rr_map.b
                  | `Empty of [ `raw ] Domain_name.t * Rr_map.k
                  | `Missing_address of [ `host ] Domain_name.t
                  | `Soa_not_a_host of [ `raw ] Domain_name.t * string ]

let pp_zone_check ppf = function
  | `Missing_soa name -> Fmt.pf ppf "missing soa for %a" Domain_name.pp name
  | `Cname_other name -> Fmt.pf ppf "%a contains a cname record, and also other entries" Domain_name.pp name
  | `Bad_ttl (name, v) -> Fmt.pf ppf "bad TTL for %a %a" Domain_name.pp name Rr_map.pp_b v
  | `Empty (name, typ) -> Fmt.pf ppf "%a empty %a" Domain_name.pp name Rr_map.ppk typ
  | `Missing_address name -> Fmt.pf ppf "missing address record for %a" Domain_name.pp name
  | `Soa_not_a_host (name, msg) -> Fmt.pf ppf "%a the SOA nameserver is not a hostname: %s" Domain_name.pp name msg

(* TODO: check for no cname loops? and dangling cname!? *)
let check trie =
  let has_address name =
    match lookup name Rr_map.A trie with
    | Ok _ -> true
    | Error (`Delegation _) -> true
    | _ -> match lookup name Rr_map.Aaaa trie with
      | Ok _ -> true
      | _ -> false
  in
  let rec check_sub names state sub map =
    let name = Domain_name.of_strings_exn names in
    let state' =
      match Rr_map.find Soa map with
      | None -> begin match Rr_map.find Ns map with
          | None -> state
          | Some _ -> `None
        end
      | Some _ -> `Soa name
    in
    let* () =
      guard ((Rr_map.mem Cname map && Rr_map.cardinal map = 1) ||
             not (Rr_map.mem Cname map)) (`Cname_other name)
    in
    let* () =
      Rr_map.fold (fun v r ->
          let* () = r in
          match v with
          | B (Dnskey, (ttl, keys)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Dnskey_set.is_empty keys then
              Error (`Empty (name, Rr_map.K Dnskey))
            else Ok ()
          | B (Ns, (ttl, names)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Domain_name.Host_set.is_empty names then
              Error (`Empty (name, K Ns))
            else
              let domain = match state' with `None -> name | `Soa zone -> zone in
              Domain_name.Host_set.fold (fun name r ->
                  let* () = r in
                  if Domain_name.is_subdomain ~subdomain:name ~domain then
                    guard (has_address name) (`Missing_address name)
                  else
                    Ok ()) names (Ok ())
          | B (Cname, (ttl, _)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v)) else Ok ()
          | B (Mx, (ttl, mxs)) ->
            if ttl < 0l then
              Error (`Bad_ttl (name, v))
            else if Rr_map.Mx_set.is_empty mxs then
              Error (`Empty (name, K Mx))
            else
              let domain = match state' with `None -> name | `Soa zone -> zone in
              Rr_map.Mx_set.fold (fun { mail_exchange ; _ } r ->
                  let* () = r in
                  if Domain_name.is_subdomain ~subdomain:mail_exchange ~domain then
                    guard (has_address mail_exchange) (`Missing_address mail_exchange)
                  else
                    Ok ())
                mxs (Ok ())
          | B (Ptr, (ttl, name)) ->
            if ttl < 0l then Error (`Bad_ttl (Domain_name.raw name, v)) else Ok ()
          | B (Soa, soa) ->
            begin match Domain_name.host soa.nameserver with
              | Error (`Msg m) -> Error (`Soa_not_a_host (soa.nameserver, m))
              | Ok _ -> Ok ()
            end
          | B (Txt, (ttl, txts)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Txt_set.is_empty txts then
              Error (`Empty (name, K Txt))
            else if
              Rr_map.Txt_set.exists (fun s -> String.length s > 0) txts
            then
              Ok ()
            else
              Error (`Empty (name, K Txt))
          | B (A, (ttl, a)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Ipaddr.V4.Set.is_empty a then
              Error (`Empty (name, K A))
            else Ok ()
          | B (Aaaa, (ttl, aaaa)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Ipaddr.V6.Set.is_empty aaaa then
              Error (`Empty (name, K Aaaa))
            else Ok ()
          | B (Srv, (ttl, srvs)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Srv_set.is_empty srvs then
              Error (`Empty (name, K Srv))
            else Ok ()
          | B (Caa, (ttl, caas)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Caa_set.is_empty caas then
              Error (`Empty (name, K Caa))
            else Ok ()
          | B (Tlsa, (ttl, tlsas)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Tlsa_set.is_empty tlsas then
              Error (`Empty (name, K Tlsa))
            else Ok ()
          | B (Sshfp, (ttl, sshfps)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Sshfp_set.is_empty sshfps then
              Error (`Empty (name, K Sshfp))
            else Ok ()
          | B (Ds, (ttl, ds)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Ds_set.is_empty ds then
              Error (`Empty (name, K Ds))
            else Ok ()
          | B (Rrsig, (ttl, rrs)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Rrsig_set.is_empty rrs then
              Error (`Empty (name, K Rrsig))
            else Ok ()
          | B (Nsec, (ttl, _rr)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else Ok ()
          | B (Nsec3, (ttl, _rr)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else Ok ()
          (* TODO LOC *)
          | B (Loc, (ttl, locs)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Loc_set.is_empty locs then
              Error (`Empty (name, K Loc))
            else if
              Rr_map.Loc_set.exists (fun s -> String.length s > 0) locs
            then
              Ok ()
            else
              Error (`Empty (name, K Loc))
          | B (Unknown x, (ttl, datas)) ->
            if ttl < 0l then Error (`Bad_ttl (name, v))
            else if Rr_map.Txt_set.is_empty datas then
              Error (`Empty (name, K (Unknown x)))
            else Ok ())
        map (Ok ())
    in
    M.fold (fun lbl (N (sub, map)) r ->
        let* () = r in
        check_sub (lbl :: names) state' sub map) sub (Ok ())
  in
  let (N (sub, map)) = trie in
  check_sub [] `None sub map

let find f name t =
  let lbls = Domain_name.to_array name in
  let l = Array.length lbls in
  let rec go idx (N (sub, map)) =
    if idx = l then
      let sub', map' = f sub map in
      N (sub', map')
    else
      let lbl = Array.get lbls idx in
      let node = match M.find lbl sub with
        | exception Not_found -> empty
        | x -> x
      in
      let node' = go (succ idx) node in
      if is_empty node' then
        N (M.remove lbl sub, map)
      else
        N (M.add lbl node' sub, map)
  in
  go 0 t

let replace name k v t =
  find (fun sub map -> sub, Rr_map.add k v map) name t

let insert name k v t =
  let merge sub map =
    let new_v = match Rr_map.find k map with
      | None -> v
      | Some v' -> Rr_map.union_rr k v' v
    in
    sub, Rr_map.add k new_v map
  in
  find merge name t

let replace_map m t =
  Domain_name.Map.fold (fun name map trie ->
      find (fun sub _ -> sub, map) name trie) m t

let insert_map m t =
  Domain_name.Map.fold (fun name map trie ->
      let union sub old = sub, Rr_map.union { f = Rr_map.unionee } old map in
      find union name trie)
    m t

let remove k ty v t =
  let remove sub map =
    let map' = match Rr_map.find ty map with
      | None -> map
      | Some old -> match Rr_map.remove_rr ty old v with
        | None -> Rr_map.remove ty map
        | Some v' -> Rr_map.add ty v' map
    in
    sub, map'
  in
  find remove k t

let remove_ty k ty t =
  let remove sub map = sub, Rr_map.remove ty map in
  find remove k t

let remove_all k t =
  let remove sub _ = sub, Rr_map.empty in
  find remove k t

let remove_map m t =
  let merge k present remove = match present, remove with
    | None, None -> None
    | Some x, None -> Some x
    | None, Some _ -> None
    | Some x, Some y -> Rr_map.remove_rr k x y
  in
  Domain_name.Map.fold (fun name map trie ->
      let remove sub old = sub, Rr_map.merge { f = merge } old map in
      find remove name trie)
    m t

let remove_zone name t =
  let remove sub _ =
    (* go through all of sub, and retain those subtrees with Soa *)
    let rec fold_sub sub =
      M.fold (fun lbl node acc ->
          match go node with None -> acc | Some n -> M.add lbl n acc)
        sub M.empty
    and go (N (sub, map)) =
      match Rr_map.find Soa map with
      | None ->
        (* no SOA, continue search *)
        let sub' = fold_sub sub in
        if M.is_empty sub' then None else Some (N (sub', Rr_map.empty))
      | Some _ ->
        (* SOA, retain this submap *)
        Some (N (sub, map))
    in
    fold_sub sub, Rr_map.empty (* drop the initial RRmap in any case! *)
  in
  find remove name t

let diff zone req_soa ~old current =
  match entries zone current with
  | Error _ -> Error (`Msg "couldn't find zone in current trie")
  | Ok (soa, map) ->
    if not (Soa.newer ~old:req_soa soa) then
      Ok (soa, `Empty)
    else
      match entries zone old with
      | Error _ -> Ok (soa, `Full map)
      | Ok (oldsoa, oldmap) ->
        (* first, we fold over old map and collect the differences in two maps *)
        let (to_remove, to_add), names =
          Domain_name.Map.fold (fun name old ((to_remove, to_add), names) ->
              let newmap =
                match Domain_name.Map.find name map with
                | None -> Rr_map.empty | Some x -> x
              in
              (match Rr_map.diff ~old newmap with
               | None, None -> to_remove, to_add
               | Some rm, None -> Domain_name.Map.add name rm to_remove, to_add
               | None, Some add -> to_remove, Domain_name.Map.add name add to_add
               | Some rm, Some add ->
                 Domain_name.Map.add name rm to_remove,
                 Domain_name.Map.add name add to_add),
              Domain_name.Set.add name names)
            oldmap Domain_name.((Map.empty, Map.empty), Set.empty)
        in
        (* now we fold over newmap and add then unless already handled *)
        let to_add =
          Domain_name.Map.fold (fun name newmap to_add ->
              if Domain_name.Set.mem name names then
                to_add
              else
                Domain_name.Map.add name newmap to_add)
            map to_add
        in
        Ok (soa, `Difference (oldsoa, to_remove, to_add))
