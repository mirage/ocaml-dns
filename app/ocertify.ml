(* (c) 2018 Hannes Mehnert, all rights reserved *)
open Rresult.R.Infix

let find_or_generate_key key_filename bits seed =
  Bos.OS.File.exists key_filename >>= function
  | true ->
    Bos.OS.File.read key_filename >>= fun data ->
    (try Ok (X509.Encoding.Pem.Private_key.of_pem_cstruct1 (Cstruct.of_string data)) with
     | _ -> Error (`Msg "while parsing private key file"))
  | false ->
    let key =
      let g =
        match seed with
        | None -> None
        | Some seed ->
          let seed = Cstruct.of_string seed in
          Some Nocrypto.Rng.(create ~seed (module Generators.Fortuna))
      in
      `RSA (Nocrypto.Rsa.generate ?g bits)
    in
    let pem = X509.Encoding.Pem.Private_key.to_pem_cstruct1 key in
    Bos.OS.File.write ~mode:0o600 key_filename (Cstruct.to_string pem) >>= fun () ->
    Ok key

let dns_header () =
  let id =
    let b = Nocrypto.Rng.generate 2 in
    Cstruct.BE.get_uint16 b 0
  in
  { Dns_packet.id ; query = true ; operation = Dns_enum.Query ;
    authoritative = false ; truncation = false ; recursion_desired = false ;
    recursion_available = false ; authentic_data = false ; checking_disabled = false ;
    rcode = Dns_enum.NoError }

(* TODO EINTR, SIGPIPE *)
let send_tcp sock buf =
  let size = Cstruct.len buf in
  let size_cs =
    let b = Cstruct.create 2 in
    Cstruct.BE.set_uint16 b 0 size ;
    b
  in
  let data = Cstruct.(to_bytes (append size_cs buf)) in
  let whole = size + 2 in
  let rec out off =
    if off = whole then ()
    else
      let bytes = Unix.send sock data off (whole - off) [] in
      out (bytes + off)
  in
  out 0

let recv_tcp sock =
  let rec read_exactly buf len off =
    if off = len then ()
    else
      let n = Unix.recv sock buf off (len - off) [] in
      read_exactly buf len (off + n)
  in
  let buf = Bytes.create 2 in
  read_exactly buf 2 0 ;
  let len = Cstruct.BE.get_uint16 (Cstruct.of_bytes buf) 0 in
  let buf' = Bytes.create len in
  read_exactly buf' len 0 ;
  Cstruct.of_bytes buf'

let query_certificate sock public_key fqdn =
  let good_tlsa tlsa =
    if
      tlsa.Dns_packet.tlsa_cert_usage = Dns_enum.Domain_issued_certificate
      && tlsa.Dns_packet.tlsa_selector = Dns_enum.Tlsa_full_certificate
      && tlsa.Dns_packet.tlsa_matching_type = Dns_enum.Tlsa_no_hash
    then
      match X509.Encoding.parse tlsa.Dns_packet.tlsa_data with
      | Some cert ->
        let keys_equal a b = Cstruct.equal (X509.key_id a) (X509.key_id b) in
        if keys_equal (X509.public_key cert) public_key then
          Some cert
        else
          None
      | _ -> None
    else
      None
  in
  let header = dns_header ()
  and question = { Dns_packet.q_name = fqdn ; q_type = Dns_enum.TLSA }
  in
  let query = { Dns_packet.question = [ question ] ; answer = [] ; authority = [] ; additional = [] } in
  let buf, _ = Dns_packet.encode `Tcp header (`Query query) in
  send_tcp sock buf ;
  let data = recv_tcp sock in
  match Dns_packet.decode data with
  | Ok ((_, `Query q, _, _), _) ->
    (* collect TLSA pems *)
    let tlsa =
      List.fold_left (fun acc rr -> match rr.Dns_packet.rdata with
          | Dns_packet.TLSA tlsa ->
            begin match good_tlsa tlsa with
              | None -> acc
              | Some cert -> Some cert
            end
          | _ -> acc)
        None q.Dns_packet.answer
    in
    tlsa
  | Ok ((_, v, _, _), _) ->
    Logs.err (fun m -> m "expected a response, but got %a"
                 Dns_packet.pp_v v) ;
    None
  | Error e ->
    Logs.err (fun m -> m "error %a while decoding answer"
                 Dns_packet.pp_err e) ;
    None

let nsupdate_csr sock now hostname keyname zone dnskey csr =
  let tlsa =
    { Dns_packet.tlsa_cert_usage = Dns_enum.Domain_issued_certificate ;
      tlsa_selector = Dns_enum.Tlsa_selector_private ;
      tlsa_matching_type = Dns_enum.Tlsa_no_hash ;
      tlsa_data = X509.Encoding.cs_of_signing_request csr ;
    }
  in
  let nsupdate =
    let zone = { Dns_packet.q_name = zone ; q_type = Dns_enum.SOA }
    and update = [
      Dns_packet.Remove (hostname, Dns_enum.TLSA) ;
      Dns_packet.Add ({ Dns_packet.name = hostname ; ttl = 600l ; rdata = Dns_packet.TLSA tlsa })
    ]
    in
    { Dns_packet.zone ; prereq = [] ; update ; addition = [] }
  and header =
    let hdr = dns_header () in
    { hdr with Dns_packet.operation = Dns_enum.Update }
  in
  match
    Dns_tsig.encode_and_sign ~proto:`Tcp header (`Update nsupdate) now dnskey keyname >>= fun (data, mac) ->
    send_tcp sock data ;
    let data = recv_tcp sock in
    Dns_tsig.decode_and_verify now dnskey keyname ~mac data
  with
  | Error x -> Error (`Msg x)
  | Ok _ -> Ok ()

let jump dns_key dns_server hostname csr key seed bits cert force _ =
  Nocrypto_entropy_unix.initialize () ;
  let keyname, zone, dnskey =
    match Astring.String.cut ~sep:":" dns_key with
    | None -> invalid_arg "couldn't parse dnskey"
    | Some (name, key) ->
      match Dns_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
      | Error _, _ | _, None -> invalid_arg "failed to parse dnskey"
      | Ok name, Some dnskey ->
        let zone = (* drop first two labels of dnskey *)
          let arr = Dns_name.to_array name in
          Dns_name.of_array Array.(sub arr 0 (length arr - 2))
        in
        (name, zone, dnskey)
  in
  let fqdn = Dns_name.prepend_exn zone hostname
  and ip = Unix.inet_addr_of_string dns_server
  in
  let fn suffix = function
    | None -> Fpath.(v hostname + suffix)
    | Some x -> Fpath.v x
  in
  let csr_filename = fn "req" csr
  and key_filename = fn "key" key
  and cert_filename = fn "pem" cert
  in
  (Bos.OS.File.exists csr_filename >>= function
    | true ->
      Bos.OS.File.read csr_filename >>= fun data ->
      (try Ok (X509.Encoding.Pem.Certificate_signing_request.of_pem_cstruct1 (Cstruct.of_string data)) with
       | _ -> Error (`Msg "while parsing certificate signing request"))
    | false ->
      find_or_generate_key key_filename bits seed >>= fun key ->
      let req = X509.CA.request [ `CN (Dns_name.to_string fqdn) ] key in
      let pem = X509.Encoding.Pem.Certificate_signing_request.to_pem_cstruct1 req in
      Bos.OS.File.write csr_filename (Cstruct.to_string pem) >>= fun () ->
      Ok req) >>= fun req ->
  let public_key = (X509.CA.info req).X509.CA.public_key in
  (* before doing anything, let's check whether cert_filename is present, matches public key, and is valid *)
  let now, tomorrow =
    let (d, ps) = Ptime_clock.now_d_ps () in
    Ptime.v (d, ps), Ptime.v (succ d, ps)
  in
  (Bos.OS.File.exists cert_filename >>= function
    | true ->
      Bos.OS.File.read cert_filename >>= fun data ->
      (try Ok (Some (X509.Encoding.Pem.Certificate.of_pem_cstruct1 (Cstruct.of_string data))) with
       | _ -> Error (`Msg "while parsing certificate"))
    | false -> Ok None) >>= (function
      | Some cert when not force
                       && Cstruct.equal (X509.key_id (X509.public_key cert)) (X509.key_id public_key)
                       && Ptime.is_later (snd (X509.validity cert)) ~than:tomorrow ->
        Error (`Msg "valid certificate with matching key already present")
      | _ -> Ok ()) >>= fun () ->
  (* strategy: unless force is provided, we can request DNS, and if a
     certificate is present, compare its public key with csr public key *)
  let connect_tcp ip =
    let sa = Unix.ADDR_INET (ip, 53) in
    let sock = Unix.(socket PF_INET SOCK_STREAM 0) in
    Unix.(setsockopt sock SO_REUSEADDR true) ;
    try
      Unix.connect sock sa ;
      Ok sock
    with
    | Unix.Unix_error (e, f, _) ->
      let err =
        Printf.sprintf "error %s in function %s while connecting to %s\n"
          (Unix.error_message e) f (Unix.string_of_inet_addr ip)
      in
      Error (`Msg err)
  in
  let write_certificate cert =
    let cert = X509.Encoding.Pem.Certificate.to_pem_cstruct1 cert in
    Bos.OS.File.delete cert_filename >>= fun () ->
    Bos.OS.File.write cert_filename (Cstruct.to_string cert)
  in
  connect_tcp ip >>= fun sock ->
  match
    if not force then query_certificate sock public_key fqdn else None
  with
  | Some x -> write_certificate x
  | None ->
    nsupdate_csr sock now fqdn keyname zone dnskey req >>= fun () ->
    let rec request retries =
      if retries = 0 then
        Error (`Msg "failed to request certificate")
      else
        match query_certificate sock public_key fqdn with
        | None ->
          Unix.sleep 1 ;
          request (pred retries)
        | Some x -> write_certificate x
    in
    request 10

let jump_res dns_key dns_server hostname csr key seed bits cert force setup_log =
  match
    jump dns_key dns_server hostname csr key seed bits cert force setup_log
  with
  | Ok () -> `Ok ()
  | Error (`Msg m) -> `Error (false, m)

let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())


let dns_key =
  let doc = "nsupdate key (name:type:value)" in
  Arg.(required & pos 0 (some string) None & info [] ~doc)

let dns_server =
  let doc = "DNS server IP" in
  Arg.(required & pos 1 (some string) None & info [] ~doc)

let hostname =
  let doc = "Hostname to issue a certificate for" in
  Arg.(required & pos 2 (some string) None & info [] ~doc)

let csr =
  let doc = "certificate signing request filename (defaults to hostname.req)" in
  Arg.(value & opt (some string) None & info [ "csr" ] ~doc)

let key =
  let doc = "private key filename (default to hostname.key)" in
  Arg.(value & opt (some string) None & info [ "key" ] ~doc)

let seed =
  let doc = "private key seed" in
  Arg.(value & opt (some string) None & info [ "seed" ] ~doc)

let bits =
  let doc = "private key bits" in
  Arg.(value & opt int 4096 & info [ "bits" ] ~doc)

let cert =
  let doc = "certificate filename (defaults to hostname.pem)" in
  Arg.(value & opt (some string) None & info [ "certificate" ] ~doc)

let force =
  let doc = "force signing request to DNS" in
  Arg.(value & flag & info [ "force" ] ~doc)

let ocertify =
  let doc = "ocertify requests a signed certificate" in
  let man = [ `S "BUGS"; `P "Submit bugs to me";] in
  Term.(ret (const jump_res $ dns_key $ dns_server $ hostname $ csr $ key $ seed $ bits $ cert $ force $ setup_log)),
  Term.info "ocertify" ~version:"%%VERSION_NUM%%" ~doc ~man

let () = match Term.eval ocertify with `Ok () -> exit 0 | _ -> exit 1
