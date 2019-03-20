(* (c) 2019 Hannes Mehnert, all rights reserved *)

let notify zone serial key now =
  let notify =
    let question = [ { Udns_packet.q_name = zone ; q_type = Udns_enum.SOA } ]
    and answer =
      let soa = { Udns_packet.nameserver = zone ; hostmaster = zone ; serial ;
                  refresh = 0l; retry = 0l ; expiry = 0l ; minimum = 0l }
      in
      [ { Udns_packet.name = zone ; ttl = 0l ; rdata = Udns_packet.SOA soa } ]
    in
    { Udns_packet.question ; answer ; authority = [] ; additional = [] }
  and header =
    let hdr = Udns_cli.dns_header (Random.int 0xFFFF) in
    { hdr with Udns_packet.operation = Udns_enum.Notify ; authoritative = true }
  in
  let v = `Notify notify in
  match key with
  | None -> Ok (fst (Udns_packet.encode `Tcp header v), Cstruct.empty)
  | Some (keyname, _, dnskey) ->
    Logs.debug (fun m -> m "using key %a: %a" Domain_name.pp keyname Udns_packet.pp_dnskey dnskey) ;
    Udns_tsig.encode_and_sign ~proto:`Tcp header (`Notify notify) now dnskey keyname

let jump _ serverip port zone key serial =
  Random.self_init () ;
  let now = Ptime_clock.now () in
  Logs.app (fun m -> m "notifying to %a:%d zone %a serial %lu"
               Ipaddr.V4.pp serverip port
               Domain_name.pp zone
               serial) ;
  match notify zone serial key now with
  | Error msg -> `Error (false, msg)
  | Ok (data, mac) ->
    let data_len = Cstruct.len data in
    Logs.debug (fun m -> m "built data %d" data_len) ;
    let socket = Udns_cli.connect_tcp serverip port in
    Udns_cli.send_tcp socket data ;
    let read_data = Udns_cli.recv_tcp socket in
    Unix.close socket ;
    match key with
    | None ->
      begin match Udns_packet.decode read_data with
        | Ok _ -> Logs.app (fun m -> m "successfull notify!") ; `Ok ()
        | Error e -> `Error (false, "notify reply " ^ Fmt.to_to_string Udns_packet.pp_err e)
      end
    | Some (keyname, _, dnskey) ->
      begin match Udns_tsig.decode_and_verify now dnskey keyname ~mac read_data with
        | Error e -> `Error (false, "notify replied with error " ^ e)
        | Ok _ -> Logs.app (fun m -> m "successfull notify!") ; `Ok ()
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
  Term.(ret (const jump $ Udns_cli.setup_log $ serverip $ port $ zone $ key $ serial)),
  Term.info "onotify" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
