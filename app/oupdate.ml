
let dns_header () =
  let id = Random.int 0xFFFF in
  { Dns_packet.id ; query = true ; operation = Dns_enum.Query ;
    authoritative = false ; truncation = false ; recursion_desired = false ;
    recursion_available = false ; authentic_data = false ; checking_disabled = false ;
    rcode = Dns_enum.NoError }

let update zone hostname ip_address keyname dnskey now =
  let nsupdate =
    let zone = { Dns_packet.q_name = zone ; q_type = Dns_enum.SOA }
    and update = [
      Dns_packet.Remove (hostname, Dns_enum.A) ;
      Dns_packet.Add ({ Dns_packet.name = hostname ; ttl = 60l ; rdata = Dns_packet.A ip_address })
    ]
    in
    { Dns_packet.zone ; prereq = [] ; update ; addition = [] }
  and header =
    let hdr = dns_header () in
    { hdr with Dns_packet.operation = Dns_enum.Update }
  in
  Dns_tsig.encode_and_sign ~proto:`Tcp header (`Update nsupdate) now dnskey keyname

let jump _ serverip port (keyname, dnskey) hostname ip_address =
  Random.self_init () ;
  let zone = Domain_name.drop_labels_exn ~amount:2 keyname in
  let now = Ptime_clock.now () in
  Logs.app (fun m -> m "updating to %a:%d zone %a A 600 %a %a"
               Ipaddr.V4.pp_hum serverip port
               Domain_name.pp zone
               Domain_name.pp hostname Ipaddr.V4.pp_hum ip_address) ;
  Logs.debug (fun m -> m "using key %a: %a" Domain_name.pp keyname Dns_packet.pp_dnskey dnskey) ;
  match update zone hostname ip_address keyname dnskey now with
  | Error msg -> `Error (false, msg)
  | Ok (data, mac) ->
    let data_len = Cstruct.len data in
    Logs.debug (fun m -> m "built data %d" data_len) ;
    let socket = Unix.(socket PF_INET SOCK_STREAM 0) in
    Unix.connect socket (Unix.ADDR_INET (Ipaddr_unix.V4.to_inet_addr serverip, port)) ;
    let buf =
      let len_buf = Cstruct.create 2 in
      Cstruct.BE.set_uint16 len_buf 0 data_len ;
      Cstruct.to_bytes (Cstruct.append len_buf data)
    in
    let send_len = Bytes.length buf in
    let written = Unix.send socket buf 0 send_len [] in
    Logs.debug (fun m -> m "wrote %d (should %d)" written send_len) ;
    if not (written = send_len) then
      `Error (false, "partial write")
    else
      let read_buf = Bytes.create 2 in
      let read_len = Unix.read socket read_buf 0 2 in
      Logs.debug (fun m -> m "read %d" read_len) ;
      if not (read_len = 2) then
        `Error (false, "partial read length header")
      else
        let read_len =
          let cs = Cstruct.of_bytes read_buf in
          Cstruct.BE.get_uint16 cs 0
        in
        let read_buf = Bytes.create read_len in
        let read_len' = Unix.read socket read_buf 0 read_len in
        Logs.debug (fun m -> m "read %d (should %d)" read_len' read_len) ;
        if not (read_len = read_len') then
        `Error (false, "partial read")
      else
        let data = Cstruct.of_bytes read_buf in
        match Dns_tsig.decode_and_verify now dnskey keyname ~mac data with
        | Error e -> `Error (false, "nsupdate replied with error " ^ e)
        | Ok _ ->
          Logs.app (fun m -> m "successfull update!") ;
          Unix.close socket ;
          `Ok ()

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let ip_c : Ipaddr.V4.t Arg.converter =
  let parse s =
      try
        `Ok (Ipaddr.V4.of_string_exn s)
      with
        Not_found -> `Error "failed to parse IP address"
  in
  parse, Ipaddr.V4.pp_hum

let serverip =
  let doc = "IP address of DNS server" in
  Arg.(required & pos 0 (some ip_c) None & info [] ~doc ~docv:"SERVERIP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 53 & info [ "port" ] ~doc)

let namekey_c =
  let parse s =
    match Astring.String.cut ~sep:":" s with
    | None -> `Error "invalid key"
    | Some (name, key) -> match Domain_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
      | Error _, _ | _, None -> `Error "failed to parse key"
      | Ok name, Some dnskey -> `Ok (name, dnskey)
  in
  parse, fun ppf (name, key) -> Fmt.pf ppf "key %a %a"
      Domain_name.pp name Dns_packet.pp_dnskey key

let key =
  let doc = "DNS HMAC secret (name:[alg:]b64key where name is yyy._update.zone)" in
  Arg.(required & pos 1 (some namekey_c) None & info [] ~doc ~docv:"KEY")

let name_c =
  (fun s -> match Domain_name.of_string s with
     | Error _ -> `Error "failed to parse hostname"
     | Ok name -> `Ok name), Domain_name.pp

let hostname =
  let doc = "Hostname to modify" in
  Arg.(required & pos 2 (some name_c) None & info [] ~doc ~docv:"HOSTNAME")

let ip_address =
  let doc = "New IP address" in
  Arg.(required & pos 3 (some ip_c) None & info [] ~doc ~docv:"IP")

let cmd =
  Term.(ret (const jump $ setup_log $ serverip $ port $ key $ hostname $ ip_address)),
  Term.info "oupdate" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
