(* (c) 2019 Hannes Mehnert, all rights reserved *)

open Dns

let notify zone serial key now =
  let raw_zone = Domain_name.raw zone in
  let question = Packet.Question.create raw_zone Soa
  and soa =
    { Soa.nameserver = raw_zone ; hostmaster = raw_zone ; serial ;
      refresh = 0l; retry = 0l ; expiry = 0l ; minimum = 0l }
  and header = Randomconv.int16 Mirage_crypto_rng.generate, Packet.Flags.singleton `Authoritative
  in
  let p = Packet.create header question (`Notify (Some soa)) in
  match key with
  | None -> Ok (p, fst (Packet.encode `Tcp p), None)
  | Some (keyname, _, dnskey) ->
    Logs.debug (fun m -> m "signing with key %a: %a" Domain_name.pp keyname Dnskey.pp dnskey) ;
    match Dns_tsig.encode_and_sign ~proto:`Tcp p now dnskey keyname with
    | Ok (cs, mac) -> Ok (p, cs, Some mac)
    | Error e -> Error e

let jump _ serverip port zone key serial =
  Mirage_crypto_rng_unix.initialize ();
  let now = Ptime_clock.now () in
  Logs.app (fun m -> m "notifying to %a:%d zone %a serial %lu"
               Ipaddr.V4.pp serverip port Domain_name.pp zone serial) ;
  match notify zone serial key now with
  | Error s -> Error (`Msg (Fmt.strf "signing %a" Dns_tsig.pp_s s))
  | Ok (request, data, mac) ->
    let data_len = Cstruct.len data in
    Logs.debug (fun m -> m "built data %d" data_len) ;
    let socket = Dns_cli.connect_tcp serverip port in
    Dns_cli.send_tcp socket data ;
    let read_data = Dns_cli.recv_tcp socket in
    Unix.close socket ;
    match key with
    | None ->
      begin match Packet.decode read_data with
        | Ok reply ->
          begin match Packet.reply_matches_request ~request reply with
            | Ok `Notify_ack ->
              Logs.app (fun m -> m "successful notify!") ;
              Ok ()
            | Ok r -> Error (`Msg (Fmt.strf "expected notify ack, got %a" Packet.pp_reply r))
            | Error e -> Error (`Msg (Fmt.strf "notify reply %a is not ok %a"
                                        Packet.pp reply Packet.pp_mismatch e))
          end
        | Error e ->
          Error (`Msg (Fmt.strf "failed to decode notify reply! %a" Packet.pp_err e))
      end
    | Some (keyname, _, dnskey) ->
      match Dns_tsig.decode_and_verify now dnskey keyname ?mac read_data with
      | Error e ->
        Error (`Msg (Fmt.strf "failed to decode TSIG signed notify reply! %a" Dns_tsig.pp_e e))
      | Ok (reply, _, _) ->
        match Packet.reply_matches_request ~request reply with
        | Ok `Notify_ack ->
          Logs.app (fun m -> m "successful TSIG signed notify!") ;
          Ok ()
        | Ok r -> Error (`Msg (Fmt.strf "expected notify ack, got %a" Packet.pp_reply r))
        | Error e ->
          Error (`Msg (Fmt.strf "expected reply to %a %a, got %a!"
                         Packet.pp_mismatch e
                         Packet.pp request Packet.pp reply))

open Cmdliner

let serverip =
  let doc = "IP address of DNS server" in
  Arg.(required & pos 0 (some Dns_cli.ip_c) None & info [] ~doc ~docv:"SERVERIP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 53 & info [ "port" ] ~doc)

let serial =
  let doc = "Serial number" in
  Arg.(value & opt int32 1l & info [ "serial" ] ~doc)

let key =
  let doc = "DNS HMAC secret (name:alg:b64key)" in
  Arg.(value & opt (some Dns_cli.namekey_c) None & info [ "key" ] ~doc ~docv:"KEY")

let zone =
  let doc = "Zone to notify" in
  Arg.(required & pos 1 (some Dns_cli.name_c) None & info [] ~doc ~docv:"ZONE")

let cmd =
  Term.(term_result (const jump $ Dns_cli.setup_log $ serverip $ port $ zone $ key $ serial)),
  Term.info "onotify" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
