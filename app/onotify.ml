(* (c) 2019 Hannes Mehnert, all rights reserved *)

open Udns

let notify zone serial key now =
  let question = (zone, Udns_enum.SOA)
  and n =
    let soa = { Soa.nameserver = zone ; hostmaster = zone ; serial ;
                refresh = 0l; retry = 0l ; expiry = 0l ; minimum = 0l }
    in
    (Domain_name.Map.singleton zone (Rr_map.singleton Rr_map.Soa soa),
     Name_rr_map.empty)
  and header =
    let hdr = Udns_cli.dns_header (Random.int 0xFFFF) in
    { hdr with operation = Udns_enum.Notify ; flags = Packet.Header.FS.singleton `Authoritative }
  in
  match key with
  | None -> Ok (header, question, fst (Packet.encode `Tcp header question (`Notify n)), Cstruct.empty)
  | Some (keyname, _, dnskey) ->
    Logs.debug (fun m -> m "signing with key %a: %a" Domain_name.pp keyname Dnskey.pp dnskey) ;
    match Udns_tsig.encode_and_sign ~proto:`Tcp header question (`Notify n) now dnskey keyname with
    | Ok (cs, mac) -> Ok (header, question, cs, mac)
    | Error e -> Error e

let jump _ serverip port zone key serial =
  Random.self_init () ;
  let now = Ptime_clock.now () in
  Logs.app (fun m -> m "notifying to %a:%d zone %a serial %lu"
               Ipaddr.V4.pp serverip port Domain_name.pp zone serial) ;
  match notify zone serial key now with
  | Error s -> Error (`Msg (Fmt.strf "signing %a" Udns_tsig.pp_s s))
  | Ok (header, question, data, mac) ->
    let data_len = Cstruct.len data in
    Logs.debug (fun m -> m "built data %d" data_len) ;
    let socket = Udns_cli.connect_tcp serverip port in
    Udns_cli.send_tcp socket data ;
    let read_data = Udns_cli.recv_tcp socket in
    Unix.close socket ;
    match key with
    | None ->
      begin match Packet.decode read_data with
        | Ok res when Packet.is_reply header question res ->
          Logs.app (fun m -> m "successful notify!") ;
          Ok ()
        | Ok res ->
          Error (`Msg (Fmt.strf "expected reply to %a %a, got %a!"
                         Packet.Header.pp header Packet.Question.pp question
                         Packet.pp_res res))
        | Error e ->
          Error (`Msg (Fmt.strf "failed to decode notify reply! %a" Packet.pp_err e))
      end
    | Some (keyname, _, dnskey) ->
      begin match Udns_tsig.decode_and_verify now dnskey keyname ~mac read_data with
        | Error e ->
          Error (`Msg (Fmt.strf "failed to decode TSIG signed notify reply! %a" Udns_tsig.pp_e e))
        | Ok (res, _, _) when Packet.is_reply header question res ->
          Logs.app (fun m -> m "successful TSIG signed notify!") ;
          Ok ()
        | Ok (res, _, _) ->
          Error (`Msg (Fmt.strf "expected reply to %a %a, got %a!"
                         Packet.Header.pp header Packet.Question.pp question
                         Packet.pp_res res))
      end

open Cmdliner

let serverip =
  let doc = "IP address of DNS server" in
  Arg.(required & pos 0 (some Udns_cli.ip_c) None & info [] ~doc ~docv:"SERVERIP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 53 & info [ "port" ] ~doc)

let serial =
  let doc = "Serial number" in
  Arg.(value & opt int32 1l & info [ "serial" ] ~doc)

let key =
  let doc = "DNS HMAC secret (name:[alg:]b64key)" in
  Arg.(value & opt (some Udns_cli.namekey_c) None & info [ "key" ] ~doc ~docv:"KEY")

let zone =
  let doc = "Zone to notify" in
  Arg.(required & pos 1 (some Udns_cli.name_c) None & info [] ~doc ~docv:"ZONE")

let cmd =
  Term.(term_result (const jump $ Udns_cli.setup_log $ serverip $ port $ zone $ key $ serial)),
  Term.info "onotify" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
