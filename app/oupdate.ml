(* (c) 2018 Hannes Mehnert, all rights reserved *)

let update zone hostname ip_address keyname dnskey now =
  let nsupdate =
    let zone = { Udns_packet.q_name = zone ; q_type = Udns_enum.SOA }
    and update = [
      Udns_packet.Remove (hostname, Udns_enum.A) ;
      Udns_packet.Add ({ Udns_packet.name = hostname ; ttl = 60l ; rdata = Udns_packet.A ip_address })
    ]
    in
    { Udns_packet.zone ; prereq = [] ; update ; addition = [] }
  and header =
    let hdr = Udns_cli.dns_header (Random.int 0xFFFF) in
    { hdr with Udns_packet.operation = Udns_enum.Update }
  in
  Udns_tsig.encode_and_sign ~proto:`Tcp header (`Update nsupdate) now dnskey keyname

let jump _ serverip port (keyname, zone, dnskey) hostname ip_address =
  Random.self_init () ;
  let now = Ptime_clock.now () in
  Logs.app (fun m -> m "updating to %a:%d zone %a A 600 %a %a"
               Ipaddr.V4.pp serverip port
               Domain_name.pp zone
               Domain_name.pp hostname
               Ipaddr.V4.pp ip_address) ;
  Logs.debug (fun m -> m "using key %a: %a" Domain_name.pp keyname Udns_packet.pp_dnskey dnskey) ;
  match update zone hostname ip_address keyname dnskey now with
  | Error msg -> `Error (false, msg)
  | Ok (data, mac) ->
    let data_len = Cstruct.len data in
    Logs.debug (fun m -> m "built data %d" data_len) ;
    let socket = Udns_cli.connect_tcp serverip port in
    Udns_cli.send_tcp socket data ;
    let read_data = Udns_cli.recv_tcp socket in
    match Udns_tsig.decode_and_verify now dnskey keyname ~mac read_data with
    | Error e -> `Error (false, "nsupdate replied with error " ^ e)
    | Ok _ ->
      Logs.app (fun m -> m "successfull update!") ;
      Unix.close socket ;
      `Ok ()

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
  Term.(ret (const jump $ Udns_cli.setup_log $ serverip $ port $ key $ hostname $ ip_address)),
  Term.info "oupdate" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
