(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module O = struct
  type t = string
  let compare = Domain_name.compare_sub
end
module M = Map.Make(O)

type t = N of t M.t * Udns_map.t

let empty = N (M.empty, Udns_map.empty)

(*BISECT-IGNORE-BEGIN*)
let bindings t =
  let rec go pre (N (sub, e)) =
    let subs = M.bindings sub in
    (pre, e) ::
    List.fold_left
      (fun acc (pre', va) ->
         acc @ go (Domain_name.prepend_exn ~hostname:false pre pre') va) [] subs
  in
  go Domain_name.root t

let pp ppf t =
  Fmt.(list ~sep:(unit ",@ ") (pair ~sep:(unit ":@,") Domain_name.pp Udns_map.pp)) ppf
    (bindings t)
(*BISECT-IGNORE-END*)

let rec equal (N (sub, map)) (N (sub', map')) =
  Udns_map.equal Udns_map.equal_b map map' && M.equal equal sub sub'

open Rresult.R.Infix

let guard p err = if p then Ok () else Error err

let ent name map =
  let ttl, soa = Udns_map.get Udns_map.Soa map in
  `EmptyNonTerminal (name, ttl, soa)
let to_ns name map =
  let ttl, ns =
    match Udns_map.find Udns_map.Ns map with
    | None -> 0l, Domain_name.Set.empty
    | Some (ttl, ns) -> ttl, ns
  in
  (name, ttl, ns)

let lookup_res name zone ty m =
  match zone with
  | None -> Error `NotAuthoritative
  | Some (`Delegation (name, (ttl, ns))) ->
    Error (`Delegation (name, (ttl, ns)))
  | Some (`Soa (z, zmap)) ->
    guard (not (Udns_map.is_empty m)) (ent z zmap) >>= fun () ->
    match ty with
    | Udns_enum.ANY ->
      let bindings = Udns_map.bindings m in
      let rrs = List.(flatten (map (Udns_map.to_rr name) bindings))
      and names =
        List.fold_left
          (fun acc v -> Domain_name.Set.union acc (Udns_map.names v))
          Domain_name.Set.empty bindings
      in
      Ok (Udns_map.B (Udns_map.Any, (rrs, names)), to_ns z zmap)
    | _ -> match Udns_map.lookup_rr ty m with
      | Some v -> Ok (v, to_ns z zmap)
      | None -> match Udns_map.findb Udns_map.Cname m with
        | None when Udns_map.cardinal m = 1 && Udns_map.(mem Soa m) ->
          (* this is primary a hack for localhost, which must be NXDomain,
             but there's a SOA for localhost (to handle it authoritatively) *)
          (* TODO should we check that the label-node map is empty?
                well, if we have a proper authoritative zone, there'll be a NS *)
          let ttl, soa = Udns_map.get Udns_map.Soa zmap in
          Error (`NotFound (z, ttl, soa))
        | None -> Error (ent z zmap)
        | Some cname -> Ok (cname, to_ns z zmap)

let lookup_aux name t =
  let k = Domain_name.to_array name in
  let l = Array.length k in
  let fzone idx map =
    let name = Domain_name.(of_array (Array.sub (to_array name) 0 idx)) in
    match Udns_map.(mem Soa map, find Ns map) with
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
            | Some (`Delegation (name, (ttl, ns))) ->
              Error (`Delegation (name, (ttl, ns)))
            | None -> Error `NotAuthoritative
            | Some (`Soa (name, map)) ->
              let ttl, soa = Udns_map.get Udns_map.Soa map in
              Error (`NotFound (name, ttl, soa))
          end
        | x -> go (succ idx) zone x
  in
  go 0 None t

let lookupb name ty t =
  lookup_aux name t >>= fun (zone, _sub, map) ->
  lookup_res name zone ty map

let lookup name key t =
  match lookup_aux name t with
  | Error e -> Error e
  | Ok (_zone, _sub, map) ->
    match Udns_map.find key map with
    | Some v -> Ok v
    | None -> match Udns_map.find Udns_map.Soa map with
      | None -> Error `NotAuthoritative
      | Some (ttl, soa) -> Error (`NotFound (name, ttl, soa))

let lookup_ignore name ty t =
  match lookup_aux name t with
  | Error _ -> Error ()
  | Ok (_zone, _sub, map) ->
    match Udns_map.lookup_rr ty map with
    | None -> Error ()
    | Some v -> Ok v

let folde name key t f s =
  let get name map acc =
    match Udns_map.find key map with
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
  match lookup_aux name t with
  | Error e -> Error e
  | Ok (_zone, sub, map) -> Ok (collect name sub (get name map s))

let fold name t f acc =
  let rec foldm name (N (sub, map)) acc =
    let acc' = Udns_map.fold (f name) map acc in
    let dns_name = Domain_name.prepend_exn ~hostname:false in
    M.fold (fun pre v acc -> foldm (dns_name name pre) v acc) sub acc'
  in
  match lookup_aux name t with
  | Error e -> Error e
  | Ok (_zone, sub, map) -> Ok (foldm name (N (sub, map)) acc)

let collect_rrs name sub map =
  let collect_map name rrmap =
    (* collecting rr out of rrmap + name, no SOA! *)
    Udns_map.fold (fun v acc ->
        match v with
        | Udns_map.B (Udns_map.Soa, _) -> acc
        | v -> Udns_map.to_rr name v @ acc)
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
    match Udns_map.find Udns_map.Soa map with
    | Some v -> Some v
    | None when Domain_name.(equal root name) ->
      Some (0l, { Udns_packet.nameserver = Domain_name.root ;
                  hostmaster = Domain_name.root ;
                  serial = 0l ; refresh = 0l ; retry = 0l ;
                  expiry = 0l ; minimum = 0l })
    | None -> None
  in
  match ttlsoa with
  | None -> Error `NotAuthoritative
  | Some (ttl, soa) ->
    let entries = collect_rrs name sub map in
    Ok ({ Udns_packet.name ; ttl ; rdata = Udns_packet.SOA soa }, entries)

let entries name t =
  lookup_aux name t >>= fun (zone, sub, map) ->
  match zone with
  | None -> Error `NotAuthoritative
  | Some (`Delegation (name, (ttl, ns))) ->
    Error (`Delegation (name, (ttl, ns)))
  | Some (`Soa (name', _)) when Domain_name.equal name name' ->
    collect_entries name sub map
  | Some (`Soa (_, _)) -> Error `NotAuthoritative

type err = [ `Missing_soa of Domain_name.t
           | `Cname_other of Domain_name.t
           | `Any_not_allowed of Domain_name.t
           | `Bad_ttl of Domain_name.t * Udns_map.b
           | `Empty of Domain_name.t * Udns_enum.rr_typ
           | `Missing_address of Domain_name.t
           | `Soa_not_ns of Domain_name.t ]

(* TODO: check for no cname loops? and dangling cname!? *)
let check trie =
  let has_address name =
    match lookup name Udns_map.A trie with
    | Ok _ -> true
    | Error (`Delegation _) -> true
    | _ -> match lookup name Udns_map.Aaaa trie with
      | Ok _ -> true
      | _ -> false
  in
  let rec check_sub names state sub map =
    let name = Domain_name.of_strings_exn ~hostname:false (List.rev names) in
    let state' =
      match Udns_map.find Udns_map.Soa map with
      | None -> begin match Udns_map.find Udns_map.Ns map with
          | None -> state
          | Some _ -> `None
        end
      | Some _ -> `Soa name
    in
    guard ((Udns_map.mem Udns_map.Cname map && Udns_map.cardinal map = 1) ||
           not (Udns_map.mem Udns_map.Cname map)) (`Cname_other name) >>= fun () ->
    Udns_map.fold (fun v r ->
        r >>= fun () ->
        match v with
        | Udns_map.B (Udns_map.Dnskey, _) -> Ok ()
        | Udns_map.B (Udns_map.Any, _) -> Error (`Any_not_allowed name)
        | Udns_map.B (Udns_map.Ns, (ttl, names)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Domain_name.Set.cardinal names = 0 then
            Error (`Empty (name, Udns_enum.NS))
          else
            let domain = match state' with `None -> name | `Soa zone -> zone in
            Domain_name.Set.fold (fun name r ->
                r >>= fun () ->
                if Domain_name.sub ~subdomain:name ~domain then
                  guard (has_address name) (`Missing_address name)
                else
                  Ok ()) names (Ok ())
        | Udns_map.B (Udns_map.Cname, (ttl, _)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v)) else Ok ()
        | Udns_map.B (Udns_map.Mx, (ttl, mxs)) ->
          if ttl < 0l then
            Error (`Bad_ttl (name, v))
          else if Udns_map.MxSet.is_empty mxs then
            Error (`Empty (name, Udns_enum.MX))
          else
            let domain = match state' with `None -> name | `Soa zone -> zone in
            Udns_map.MxSet.fold (fun (_, name) r ->
                r >>= fun () ->
                if Domain_name.sub ~subdomain:name ~domain then
                  guard (has_address name) (`Missing_address name)
                else
                  Ok ())
              mxs (Ok ())
        | Udns_map.B (Udns_map.Ptr, (ttl, name)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v)) else Ok ()
        | Udns_map.B (Udns_map.Soa, (ttl, soa)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else begin match Udns_map.find Udns_map.Ns map with
            | Some (_, names) ->
              if Domain_name.Set.mem soa.Udns_packet.nameserver names then
                Ok ()
              else
                Error (`Soa_not_ns soa.Udns_packet.nameserver)
            | None -> Ok () (* we're happy to only have a soa, but nothing else -- useful for grounding zones! *)
          end
        | Udns_map.B (Udns_map.Txt, (ttl, txts)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Udns_map.TxtSet.is_empty txts then
            Error (`Empty (name, Udns_enum.TXT))
          else if
            Udns_map.TxtSet.exists (function
                | [] -> true
                | xs -> List.exists (fun s -> String.length s = 0) xs)
              txts
          then
            Error (`Empty (name, Udns_enum.TXT))
          else
            Ok ()
        | Udns_map.B (Udns_map.A, (ttl, a)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Udns_map.Ipv4Set.is_empty a then
            Error (`Empty (name, Udns_enum.A))
          else Ok ()
        | Udns_map.B (Udns_map.Aaaa, (ttl, aaaa)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Udns_map.Ipv6Set.is_empty aaaa then
            Error (`Empty (name, Udns_enum.AAAA))
          else Ok ()
        | Udns_map.B (Udns_map.Srv, (ttl, srvs)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Udns_map.SrvSet.is_empty srvs then
            Error (`Empty (name, Udns_enum.SRV))
          else Ok ()
        | Udns_map.B (Udns_map.Caa, (ttl, caas)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Udns_map.CaaSet.is_empty caas then
            Error (`Empty (name, Udns_enum.CAA))
          else Ok ()
        | Udns_map.B (Udns_map.Tlsa, (ttl, tlsas)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Udns_map.TlsaSet.is_empty tlsas then
            Error (`Empty (name, Udns_enum.TLSA))
          else Ok ()
        | Udns_map.B (Udns_map.Sshfp, (ttl, sshfps)) ->
          if ttl < 0l then Error (`Bad_ttl (name, v))
          else if Udns_map.SshfpSet.is_empty sshfps then
            Error (`Empty (name, Udns_enum.SSHFP))
          else Ok ())
      map (Ok ()) >>= fun () ->
    M.fold (fun lbl (N (sub, map)) r ->
        r >>= fun () ->
        check_sub (lbl :: names) state' sub map) sub (Ok ())
  in
  let (N (sub, map)) = trie in
  check_sub [] `None sub map

let insertb name b t =
  let k = Domain_name.to_array name in
  let l = Array.length k in
  let rec go idx (N (sub, map)) =
    if idx = l then
      N (sub, Udns_map.addb b map)
    else
      let lbl = Array.get k idx in
      let node = match M.find lbl sub with
        | exception Not_found -> empty
        | x -> x
      in
      let node' = go (succ idx) node in
      N (M.add lbl node' sub, map)
  in
  go 0 t

let insert name k v t = insertb name (Udns_map.B (k, v)) t

let insert_map m t =
  Domain_name.Map.fold (fun name map trie ->
      Udns_map.fold (fun v trie -> insertb name v trie) map trie)
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
        if M.is_empty sub' && Udns_map.is_empty map' then
          N (M.remove lbl sub, map)
        else
          N (M.add lbl (N (sub', map')) sub, map)
  in
  go 0 t

let remove k ty t =
  let remove sub map =
    if ty = Udns_enum.ANY then
      N (sub, Udns_map.empty)
    else
      let map' = Udns_map.remove_rr ty map in
      N (sub, map')
  in
  remove_aux k t remove

let remove_zone name t =
  let remove sub _ =
    let rec go sub =
      M.fold (fun lbl (N (sub, map)) s ->
          if Udns_map.(mem Soa map) then
            M.add lbl (N (sub, map)) s
          else
            let sub' = go sub in
            if sub' = M.empty then s else M.add lbl (N (sub', Udns_map.empty)) s)
        sub M.empty
    in
    N (go sub, Udns_map.empty)
  in
  remove_aux name t remove

(*BISECT-IGNORE-BEGIN*)
let pp_err ppf = function
  | `Missing_soa name -> Fmt.pf ppf "missing soa for %a" Domain_name.pp name
  | `Cname_other name -> Fmt.pf ppf "%a contains a cname record, and also other entries" Domain_name.pp name
  | `Any_not_allowed name -> Fmt.pf ppf "resource type ANY is not allowed, but present for %a" Domain_name.pp name
  | `Bad_ttl (name, v) -> Fmt.pf ppf "bad TTL for %a %a" Domain_name.pp name Udns_map.pp_b v
  | `Empty (name, typ) -> Fmt.pf ppf "%a empty %a" Domain_name.pp name Udns_enum.pp_rr_typ typ
  | `Missing_address name -> Fmt.pf ppf "missing address record for %a" Domain_name.pp name
  | `Soa_not_ns name -> Fmt.pf ppf "%a nameserver of SOA is not in nameserver set" Domain_name.pp name

let pp_e ppf = function
  | `Delegation (name, (ttl, ns)) ->
    Fmt.pf ppf "delegation %a to TTL %lu %a" Domain_name.pp name ttl
      Fmt.(list ~sep:(unit ",@,") Domain_name.pp) (Domain_name.Set.elements ns)
  | `EmptyNonTerminal (name, ttl, soa) ->
    Fmt.pf ppf "empty non terminal %a TTL %lu SOA %a" Domain_name.pp name ttl Udns_packet.pp_soa soa
  | `NotAuthoritative -> Fmt.string ppf "not authoritative"
  | `NotFound (name, ttl, soa) -> Fmt.pf ppf "not found %a TTL %lu soa %a" Domain_name.pp name ttl Udns_packet.pp_soa soa
(*BISECT-IGNORE-END*)
