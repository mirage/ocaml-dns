(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Dns

let create_update zone hostname ip_address =
  let zone = Packet.Question.create zone Soa
  and update =
    let up =
      Domain_name.Map.singleton hostname
        [
          Packet.Update.Remove (Rr_map.K A) ;
          Packet.Update.Add Rr_map.(B (A, (60l, Ipaddr.V4.Set.singleton ip_address)))
        ]
    in
    (Domain_name.Map.empty, up)
  and header = Randomconv.int16 Mirage_crypto_rng.generate, Packet.Flags.empty
  in
  Packet.create header zone (`Update update)

let jump _ serverip port (keyname, zone, dnskey) hostname ip_address =
  Mirage_crypto_rng_unix.initialize ();
  let now = Ptime_clock.now () in
  Logs.app (fun m -> m "updating to %a:%d zone %a A 600 %a %a"
               Ipaddr.pp serverip port
               Domain_name.pp zone
               Domain_name.pp hostname
               Ipaddr.V4.pp ip_address) ;
  Logs.debug (fun m -> m "using key %a: %a" Domain_name.pp keyname Dns.Dnskey.pp dnskey) ;
  let p = create_update zone hostname ip_address in
  match Dns_tsig.encode_and_sign ~proto:`Tcp p now dnskey keyname with
  | Error s ->
    Error (`Msg (Fmt.strf "tsig sign error %a" Dns_tsig.pp_s s))
  | Ok (data, mac) ->
    let data_len = Cstruct.length data in
    Logs.debug (fun m -> m "built data %d" data_len) ;
    let socket = Dns_cli.connect_tcp serverip port in
    Dns_cli.send_tcp socket data ;
    let read_data = Dns_cli.recv_tcp socket in
    (try (Unix.close socket) with _ -> ()) ;
    match Dns_tsig.decode_and_verify now dnskey keyname ~mac read_data with
    | Error e ->
      Error (`Msg (Fmt.strf "nsupdate error %a" Dns_tsig.pp_e e))
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
  Arg.(required & pos 0 (some Dns_cli.ip_c) None & info [] ~doc ~docv:"SERVERIP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 53 & info [ "port" ] ~doc)

let key =
  let doc = "DNS HMAC secret (name:alg:b64key where name is yyy._update.zone)" in
  Arg.(required & pos 1 (some Dns_cli.namekey_c) None & info [] ~doc ~docv:"KEY")

let hostname =
  let doc = "Hostname to modify" in
  Arg.(required & pos 2 (some Dns_cli.domain_name_c) None & info [] ~doc ~docv:"HOSTNAME")

let ipv4_c : Ipaddr.V4.t Arg.converter =
  let parse s =
    match Ipaddr.V4.of_string s with
    | Ok ip -> `Ok ip
    | Error (`Msg m) -> `Error ("failed to parse IP address: " ^ m)
  in
  parse, Ipaddr.V4.pp

let ip_address =
  let doc = "New IP address" in
  Arg.(required & pos 3 (some ipv4_c) None & info [] ~doc ~docv:"IP")

let cmd =
  Term.(term_result (const jump $ Dns_cli.setup_log $ serverip $ port $ key $ hostname $ ip_address)),
  Term.info "oupdate" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
