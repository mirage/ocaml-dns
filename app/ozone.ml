(* (c) 2019 Hannes Mehnert, all rights reserved *)

(* goal is to check a given zonefile whether it is valid (and to-be-uesd
   by an authoritative NS - i.e. there must be a SOA record, TTL are good)
   if a NS/MX name is within the zone, it needs an address record *)
open Dns
open Rresult.R.Infix

let load_zone zone =
  Bos.OS.File.read Fpath.(v zone) >>= fun data ->
  Dns_zone.parse data >>= fun rrs ->
  let domain = Domain_name.of_string_exn Fpath.(basename (v zone)) in
  (if not (Domain_name.Map.for_all (fun name _ -> Domain_name.sub ~domain ~subdomain:name) rrs) then
     Error (`Msg (Fmt.strf "an entry of %a is not in its zone, won't handle this@.%a"
                    Domain_name.pp domain Dns.Name_rr_map.pp rrs))
   else
     Ok ()) >>| fun () ->
  Dns_trie.insert_map rrs Dns_trie.empty

let jump _ zone old =
  load_zone zone >>= fun trie ->
  Rresult.R.error_to_msg ~pp_error:Dns_trie.pp_zone_check (Dns_trie.check trie) >>= fun () ->
  Logs.app (fun m -> m "successfully checked zone") ;
  let zones =
    Dns_trie.fold Soa trie
      (fun name _ acc -> Domain_name.Set.add name acc)
      Domain_name.Set.empty
  in
  if Domain_name.Set.cardinal zones = 1 then
    let zone = Domain_name.Set.choose zones in
    Dns_server.text zone trie >>= fun zone_data ->
    Logs.debug (fun m -> m "assembled zone data %s" zone_data) ;
    (match old with
     | None -> Ok ()
     | Some fn ->
       load_zone fn >>= fun old ->
       match Dns_trie.lookup zone Soa trie, Dns_trie.lookup zone Soa old with
       | Ok fresh, Ok old when Soa.newer ~old fresh ->
         Logs.debug (fun m -> m "zone %a newer than old" Domain_name.pp zone) ;
         Ok ()
       | _ ->
         Error (`Msg "SOA comparison wrong"))
  else
    Error (`Msg "expected exactly one zone")

open Cmdliner

let newzone =
  let doc = "New zone file" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"ZONE")

let oldzone =
  let doc = "Old zone file" in
  Arg.(value & opt (some file) None & info [ "old" ] ~doc ~docv:"ZONE")

let cmd =
  Term.(term_result (const jump $ Dns_cli.setup_log $ newzone $ oldzone)),
  Term.info "ozone" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
