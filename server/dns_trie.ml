(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

module O = struct
  type t = string
  let compare = Domain_name.compare_sub
end
module M = Map.Make(O)

type t = N of t M.t * Rr_map.t

let empty = N (M.empty, Rr_map.empty)

let bindings t =
  let rec go pre (N (sub, e)) =
    let subs = M.bindings sub in
    (pre, e) ::
    List.fold_left
      (fun acc (pre', va) ->
         acc @ go (Domain_name.prepend_exn ~hostname:false pre pre') va) [] subs
  in
  go Domain_name.root t

let pp_map name ppf map =
  Fmt.(list ~sep:(unit "@.") string) ppf
    (List.map (Rr_map.text_b name) (Rr_map.bindings map))

let pp ppf t = List.iter (fun (name, map) -> pp_map name ppf map) (bindings t)

let rec equal (N (sub, map)) (N (sub', map')) =
  Rr_map.equal { f = Rr_map.equal_rr } map map' && M.equal equal sub sub'

type e = [ `Delegation of Domain_name.t * (int32 * Domain_name.Set.t)
         | `EmptyNonTerminal of Domain_name.t * Soa.t
         | `NotAuthoritative
         | `NotFound of Domain_name.t * Soa.t ]

let pp_e ppf = function
  | `Delegation (name, (ttl, ns)) ->
    Fmt.pf ppf "delegation %a to TTL %lu %a" Domain_name.pp name ttl
      Fmt.(list ~sep:(unit ",@,") Domain_name.pp) (Domain_name.Set.elements ns)
  | `EmptyNonTerminal (name, soa) ->
    Fmt.pf ppf "empty non terminal %a SOA %a" Domain_name.pp name Soa.pp soa
  | `NotAuthoritative -> Fmt.string ppf "not authoritative"
  | `NotFound (name, soa) -> Fmt.pf ppf "not found %a soa %a" Domain_name.pp name Soa.pp soa


open Rresult.R.Infix

let guard p err = if p then Ok () else Error err

let ent name map =
  let soa = Rr_map.get Soa map in
  `EmptyNonTerminal (name, soa)

let to_ns name map =
  let ttl, ns =
    match Rr_map.find Ns map with
    | None -> 0l, Domain_name.Set.empty
    | Some (ttl, ns) -> ttl, ns
  in
  (name, ttl, ns)

let check_zone = function
  | None -> Error `NotAuthoritative
  | Some (`Delegation (name, (ttl, ns))) -> Error (`Delegation (name, (ttl, ns)))
  | Some (`Soa (z, zmap)) -> Ok (z, zmap)

let lookup_res zone ty m =
  check_zone zone >>= fun (z, zmap) ->
  guard (not (Rr_map.is_empty m)) (ent z zmap) >>= fun () ->
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
              let soa = Rr_map.get Soa map in
              Error (`NotFound (name, soa))
          end
        | x -> go (succ idx) zone x
  in
  go 0 None t

let lookup_with_cname name ty t =
  lookup_aux name t >>= fun (zone, _sub, map) ->
  lookup_res zone ty map

let lookup name key t =
  match lookup_aux name t with
  | Error e -> Error e
  | Ok (zone, _sub, map) ->
    match Rr_map.find key map with
    | Some v -> Ok v
    | None -> match zone with
      | None -> Error `NotAuthoritative
      | Some (`Delegation (name, (ttl, ns))) -> Error (`Delegation (name, (ttl, ns)))
      | Some (`Soa (z, zmap)) -> Error (ent z zmap)

let lookup_any name t =
  match lookup_aux name t with
  | Error e -> Error e
  | Ok (zone, _sub, m) ->
    check_zone zone >>= fun (z, zmap) ->
    Ok (m, to_ns z zmap)

let lookup_glue name t =
  match lookup_aux name t with
  | Error _ -> None, None
  | Ok (_zone, _sub, map) -> Rr_map.find A map, Rr_map.find Aaaa map

let zone name t =
  match lookup_aux name t with
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
        let n' = Domain_name.prepend_exn ~hostname:false name pre in
        let keys = get n' map acc in
        collect n' sub keys)
      acc (M.bindings sub)
  in
  let name = Domain_name.root in
  collect name sub (get name map s)

let collect_rrs name sub map =
  (* TODO: do not cross zone boundaries! or maybe not!? *)
  let collect_map name rrmap =
    (* collecting rr out of rrmap + name, no SOA! *)
    Rr_map.fold (fun v acc ->
        match v with
        | Rr_map.(B (Soa, _)) -> acc
        | v -> (name, v) :: acc)
      rrmap []
  in
  let rec go name sub map =
    let entries = collect_map name map in
    List.fold_left
      (fun acc (pre, N (sub, map)) ->
         acc @ go (Domain_name.prepend_exn ~hostname:false name pre) sub map)
      entries (M.bindings sub)
  in
  go name sub map

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
    let entries = collect_rrs name sub map in
    let map =
      List.fold_left (fun acc (name, (Rr_map.B (k, v))) ->
          Name_rr_map.add name k v acc) Domain_name.Map.empty entries
    in
    Ok (soa, map)

let entries name t =
  lookup_aux name t >>= fun (zone, sub, map) ->
  match zone with
  | None -> Error `NotAuthoritative
  | Some (`Delegation (name, (ttl, ns))) ->
    Error (`Delegation (name, (ttl, ns)))
  | Some (`Soa (name', _)) when Domain_name.equal name name' ->
    collect_entries name sub map
  | Some (`Soa (_, _)) -> Error `NotAuthoritative

type zone_check = [ `Missing_soa of Domain_name.t
                  | `Cname_other of Domain_name.t
                  | `Bad_ttl of Domain_name.t * Rr_map.b
                  | `Empty of Domain_name.t * Rr_map.k
                  | `Missing_address of Domain_name.t
                  | `Soa_not_ns of Domain_name.t ]

let pp_zone_check ppf = function
  | `Missing_soa name -> Fmt.pf ppf "missing soa for %a" Domain_name.pp name
  | `Cname_other name -> Fmt.pf ppf "%a contains a cname record, and also other entries" Domain_name.pp name
  | `Bad_ttl (name, v) -> Fmt.pf ppf "bad TTL for %a %a" Domain_name.pp name Rr_map.pp_b v
  | `Empty (name, typ) -> Fmt.pf ppf "%a empty %a" Domain_name.pp name Rr_map.ppk typ
  | `Missing_address name -> Fmt.pf ppf "missing address record for %a" Domain_name.pp name
  | `Soa_not_ns name -> Fmt.pf ppf "%a nameserver of SOA is not in nameserver set" Domain_name.pp name

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
    let name = Domain_name.of_strings_exn ~hostname:false names in
    let state' =
      match Rr_map.find Soa map with
      | None -> begin match Rr_map.find Ns map with
          | None -> state
          | Some _ -> `None
        end
      | Some _ -> `Soa name
    in
    guard ((Rr_map.mem Cname map && Rr_map.cardinal map = 1) ||
           not (Rr_map.mem Cname map)) (`Cname_other name) >>= fun () ->
    Rr_map.fold (fun v r ->
        r >>= fun () ->
        match v with
        | B (Dnskey, (ttl, keys)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Rr_map.Dnskey_set.is_empty keys then
            Error (`Empty (name, Rr_map.K Dnskey))
          else Ok ()
        | B (Ns, (ttl, names)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Domain_name.Set.cardinal names = 0 then
            Error (`Empty (name, K Ns))
          else
            let domain = match state' with `None -> name | `Soa zone -> zone in
            Domain_name.Set.fold (fun name r ->
                r >>= fun () ->
                if Domain_name.sub ~subdomain:name ~domain then
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
                r >>= fun () ->
                if Domain_name.sub ~subdomain:mail_exchange ~domain then
                  guard (has_address mail_exchange) (`Missing_address mail_exchange)
                else
                  Ok ())
              mxs (Ok ())
        | B (Ptr, (ttl, name)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v)) else Ok ()
        | B (Soa, soa) ->
          begin match Rr_map.find Ns map with
            | Some (_, names) ->
              if Domain_name.Set.mem soa.nameserver names then
                Ok ()
              else
                Error (`Soa_not_ns soa.nameserver)
            | None -> Ok () (* we're happy to only have a soa, but nothing else -- useful for grounding zones! *)
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
          else if Rr_map.Ipv4_set.is_empty a then
            Error (`Empty (name, K A))
          else Ok ()
        | B (Aaaa, (ttl, aaaa)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Rr_map.Ipv6_set.is_empty aaaa then
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
        | B (Unknown x, (ttl, datas)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Rr_map.Txt_set.is_empty datas then
            Error (`Empty (name, K (Unknown x)))
          else Ok ())
      map (Ok ()) >>= fun () ->
    M.fold (fun lbl (N (sub, map)) r ->
        r >>= fun () ->
        check_sub (lbl :: names) state' sub map) sub (Ok ())
  in
  let (N (sub, map)) = trie in
  check_sub [] `None sub map

let insert name k v t =
  let lbls = Domain_name.to_array name in
  let l = Array.length lbls in
  let rec go idx (N (sub, map)) =
    if idx = l then
      N (sub, Rr_map.add k v map)
    else
      let lbl = Array.get lbls idx in
      let node = match M.find lbl sub with
        | exception Not_found -> empty
        | x -> x
      in
      let node' = go (succ idx) node in
      N (M.add lbl node' sub, map)
  in
  go 0 t

let insert_map m t =
  Domain_name.Map.fold (fun name map trie ->
      Rr_map.fold (fun (B (k, v)) trie -> insert name k v trie) map trie)
    m t

let remove_aux k t a =
  let k = Domain_name.to_array k in
  let l = Array.length k in
  let rec go idx (N (sub, map)) =
    if idx = l then a sub map
    else
      let lbl = Array.get k idx in
      match M.find lbl sub with
      | exception Not_found -> N (sub, map)
      | x ->
        let N (sub', map') = go (succ idx) x in
        if M.is_empty sub' && Rr_map.is_empty map' then
          N (M.remove lbl sub, map)
        else
          N (M.add lbl (N (sub', map')) sub, map)
  in
  go 0 t

let remove k ty t =
  let remove sub map =
    let map' = Rr_map.remove ty map in
    N (sub, map')
  in
  remove_aux k t remove

let remove_all k t =
  let remove sub _ = N (sub, Rr_map.empty) in
  remove_aux k t remove

let remove_zone name t =
  let remove sub _ =
    let rec go sub =
      M.fold (fun lbl (N (sub, map)) s ->
          if Rr_map.mem Soa map then
            M.add lbl (N (sub, map)) s
          else
            let sub' = go sub in
            if sub' = M.empty then s else M.add lbl (N (sub', Rr_map.empty)) s)
        sub M.empty
    in
    N (go sub, Rr_map.empty)
  in
  remove_aux name t remove
