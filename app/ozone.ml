(* (c) 2019 Hannes Mehnert, all rights reserved *)

(* goal is to check a given zonefile whether it is valid (and to-be-used
   by an authoritative NS - i.e. there must be a SOA record, TTL are good)
   if a NS/MX name is within the zone, it needs an address record
   the name of the file is taken as the domain name *)
open Dns

let ( let* ) = Result.bind

let load_zone ~zone_name zone =
  let* data = Bos.OS.File.read Fpath.(v zone) in
  if String.length data = 0 then
    Error `Empty
  else
    let* rrs = Dns_zone.parse data in
    let bad = Domain_name.Map.filter
        (fun name _ -> not (Domain_name.is_subdomain ~domain:zone_name ~subdomain:name))
        rrs
    in
    if not (Domain_name.Map.is_empty bad) then
      Error (`Msg (Fmt.str "Entries of domain '%a' are not in its zone, won't handle this:@.%a"
                     Domain_name.pp zone_name Dns.Name_rr_map.pp bad))
    else
      Ok (Dns_trie.insert_map rrs Dns_trie.empty)

let jump _ zone old zone_name =
  let zone_name =
    let z = Option.value ~default:Fpath.(basename (v zone)) zone_name in
    Domain_name.of_string_exn z
  in
  match load_zone ~zone_name zone with
  | Error `Empty ->
    (* zone removal *)
    Logs.app (fun m -> m "zone %a removed" Domain_name.pp zone_name) ;
    Ok ()
  | Error `Msg m -> Error (`Msg m)
  | Ok trie ->
    let* () =
      Result.map_error
        (fun e -> `Msg (Fmt.to_to_string Dns_trie.pp_zone_check e))
        (Dns_trie.check trie)
    in
    Logs.app (fun m -> m "successfully checked zone %a" Domain_name.pp zone_name) ;
    let zones =
      Dns_trie.fold Soa trie
        (fun name _ acc -> Domain_name.Set.add name acc)
        Domain_name.Set.empty
    in
    if Domain_name.Set.cardinal zones = 1 then
      let zone = Domain_name.Set.choose zones in
      let* zone_data = Dns_server.text zone trie in
      Logs.debug (fun m -> m "assembled zone data %s" zone_data) ;
      (match old with
       | None -> Ok ()
       | Some fn ->
         match load_zone ~zone_name fn with
         | Error `Empty ->
           (* zone addition *)
           Ok ()
         | Error `Msg m -> Error (`Msg m)
         | Ok old ->
           match Dns_trie.lookup zone Soa trie, Dns_trie.lookup zone Soa old with
           | Ok fresh, Ok old when Soa.newer ~old fresh ->
             Logs.debug (fun m -> m "zone %a newer than old" Domain_name.pp zone) ;
             Ok ()
           | Ok fresh, Ok old ->
             Error (`Msg (Fmt.str "SOA must increase for %a (old: %lu new: %lu)"
                            Domain_name.pp zone_name old.Soa.serial fresh.Soa.serial))
           | Error e, _ ->
             Error (`Msg (Fmt.str "SOA comparison wrong for %a, error %a while looking up new SOA"
                            Domain_name.pp zone_name Dns_trie.pp_e e))
           | _, Error e ->
             Error (`Msg (Fmt.str "SOA comparison wrong for %a, error %a while looking up old SOA"
                            Domain_name.pp zone_name Dns_trie.pp_e e)))
    else
      Error (`Msg "expected exactly one zone")

open Cmdliner

let newzone =
  let doc = "New zone file" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"ZONE")

let oldzone =
  let doc = "Old zone file" in
  Arg.(value & opt (some file) None & info [ "old" ] ~doc ~docv:"ZONE")

let zone_name =
  let doc = "Zone name (defaults to provided filename)" in
  Arg.(value & opt (some string) None & info [ "zone-name" ] ~doc ~docv:"ZONE")

let cmd =
  let term =
    Term.(term_result (const jump $ Dns_cli.setup_log $ newzone $ oldzone $ zone_name))
  and info = Cmd.info "ozone" ~version:"%%VERSION_NUM%%"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
