(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Udns

let create_update zone hostname ip_address =
  let zone = (zone, Rr.SOA)
  and update =
    let up =
      Domain_name.Map.singleton hostname
        [
          Packet.Update.Remove Rr.A ;
          Packet.Update.Add Rr_map.(B (A, (60l, Ipv4_set.singleton ip_address)))
        ]
    in
    (Domain_name.Map.empty, up)
  and header = Random.int 0xFFFF, Packet.Flags.empty
  in
  Packet.create header zone (`Update update)

let jump _ serverip port (keyname, zone, dnskey) hostname ip_address =
  Random.self_init () ;
  let now = Ptime_clock.now () in
  Logs.app (fun m -> m "updating to %a:%d zone %a A 600 %a %a"
               Ipaddr.V4.pp serverip port
               Domain_name.pp zone
               Domain_name.pp hostname
               Ipaddr.V4.pp ip_address) ;
  Logs.debug (fun m -> m "using key %a: %a" Domain_name.pp keyname Udns.Dnskey.pp dnskey) ;
  let p = create_update zone hostname ip_address in
  match Udns_tsig.encode_and_sign ~proto:`Tcp p now dnskey keyname with
  | Error s ->
    Error (`Msg (Fmt.strf "tsig sign error %a" Udns_tsig.pp_s s))
  | Ok (data, mac) ->
    let data_len = Cstruct.len data in
    Logs.debug (fun m -> m "built data %d" data_len) ;
    let socket = Udns_cli.connect_tcp serverip port in
    Udns_cli.send_tcp socket data ;
    let read_data = Udns_cli.recv_tcp socket in
    (try (Unix.close socket) with _ -> ()) ;
    match Udns_tsig.decode_and_verify now dnskey keyname ~mac read_data with
    | Error e ->
      Error (`Msg (Fmt.strf "nsupdate error %a" Udns_tsig.pp_e e))
    | Ok (reply, _, _) ->
      match Packet.reply_matches_request ~request:p reply with
      | Ok `Update_ack ->
        Logs.app (fun m -> m "successful and signed update!") ;
        Ok ()
      | Ok r ->
        Error (`Msg (Fmt.strf "nsupdate expected update ack, received %a" Packet.pp_reply r))
      | Error e ->
        Error (`Msg (Fmt.strf "nsupdate error %a (reply %a does not match request %a)"
                       Packet.pp_mismatch e Packet.pp reply Packet.pp p))

open Cmdliner

let serverip =
  let doc = "IP address of DNS server" in
  Arg.(required & pos 0 (some Udns_cli.ip_c) None & info [] ~doc ~docv:"SERVERIP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 53 & info [ "port" ] ~doc)

let key =
  let doc = "DNS HMAC secret (name:[alg:]b64key where name is yyy._update.zone)" in
  Arg.(required & pos 1 (some Udns_cli.namekey_c) None & info [] ~doc ~docv:"KEY")

let hostname =
  let doc = "Hostname to modify" in
  Arg.(required & pos 2 (some Udns_cli.name_c) None & info [] ~doc ~docv:"HOSTNAME")

let ip_address =
  let doc = "New IP address" in
  Arg.(required & pos 3 (some Udns_cli.ip_c) None & info [] ~doc ~docv:"IP")

let cmd =
  Term.(term_result (const jump $ Udns_cli.setup_log $ serverip $ port $ key $ hostname $ ip_address)),
  Term.info "oupdate" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
