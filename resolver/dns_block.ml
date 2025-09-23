open Dns

let src = Logs.Src.create "dns_block" ~doc:"DNS block"
module Log = (val Logs.src_log src : Logs.LOG)

let nameserver =
  let lh = Domain_name.of_string_exn "localhost"
  and bl = Domain_name.of_string_exn "blocked"
  in
  fun ns -> Domain_name.equal ns lh || Domain_name.equal ns bl

let ipv4 =
  let lh = Ipaddr.V4.(Set.singleton localhost)
  and any = Ipaddr.V4.(Set.singleton any)
  in
  fun ipv4s -> Ipaddr.V4.Set.equal ipv4s lh || Ipaddr.V4.Set.equal ipv4s any

let ipv6 =
  let lh = Ipaddr.V6.(Set.singleton localhost)
  and un = Ipaddr.V6.(Set.singleton unspecified)
  in
  fun ipv6s -> Ipaddr.V6.Set.equal ipv6s lh || Ipaddr.V6.Set.equal ipv6s un

let likely reply =
  (* HACK! We assume blocked domains have a certain shape. *)
  let blocked_soa auth =
    Domain_name.Map.cardinal auth > 0 &&
    Domain_name.Map.for_all (fun _domain rr ->
        match Rr_map.find Rr_map.Soa rr with
        | None -> false
        | Some soa -> nameserver soa.nameserver)
      auth
  in
  match reply.Packet.data with
  | `Answer (answ, _auth) ->
    Domain_name.Map.for_all
      (fun _domain rr ->
         Rr_map.for_all
           (function
             | Rr_map.B (Rr_map.A, (_, ips)) -> ipv4 ips
             | Rr_map.B (Rr_map.Aaaa, (_, ips)) -> ipv6 ips
             | _ -> false)
           rr)
      answ
  | `Rcode_error (Rcode.NXDomain, _, Some (_answ, auth)) -> blocked_soa auth
  | _ -> false

let reason reply =
  let find_soa_hostmaster rr =
    match Rr_map.find Rr_map.Soa rr with
    | None -> None
    | Some soa ->
      if nameserver soa.Soa.nameserver then
        Some (Domain_name.to_string soa.Soa.hostmaster)
      else
        None
  in
  let find_soa_hostmaster_in_domain_map map =
    Domain_name.Map.fold (fun _domain rr acc ->
        match acc, find_soa_hostmaster rr with
        | None, x -> x
        | Some x, None -> Some x
        | Some x, Some y ->
          if not (String.equal x y) then
            Log.info (fun m -> m "finding blocklist resulted in %S and %S, using the first" x y);
          Some x) map None
  in
  let find_soa_hostmaster_in_reply answer authority =
    match find_soa_hostmaster_in_domain_map answer, find_soa_hostmaster_in_domain_map authority with
    | None, x -> x
    | Some x, None -> Some x
    | Some x, Some y ->
      if not (String.equal x y) then
        Log.info (fun m -> m "finding blocklist resulted in %S (answer) and %S (authority), using the first" x y);
      Some x
  in
  let r =
    match reply.Packet.data with
    | `Answer (answ, auth) -> find_soa_hostmaster_in_reply answ auth
    | `Rcode_error (Rcode.NXDomain, _, Some (answ, auth)) ->
      find_soa_hostmaster_in_reply answ auth
    | _ -> None
  in
  Option.map (fun reason -> "appears in blocklist " ^ reason) r

let edns reply =
  if likely reply then
    (* After guessing that a domain is blocked we add [`Filtered] extended error
       code and emit a [`Blocked] metrics event. *)
    let reason = reason reply in
    match reply.edns with
    | None ->
      Some (Edns.create ~extended_error:(`Blocked, reason) ())
    | Some ({ Edns.extensions = []; extended_rcode; version; dnssec_ok; payload_size }) ->
      Some (Edns.create ~extended_error:(`Blocked, reason) ~extended_rcode ~version ~dnssec_ok ~payload_size ())
    | Some edns ->
      Log.warn (fun m -> m "don't know how to extend edns to add extended error; not doing anything:@ %a" Edns.pp edns);
      Some edns
  else
    None
