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
  Udns_cli.dns_header id

let query_certificate sock public_key fqdn =
  let good_tlsa tlsa =
    if
      tlsa.Udns_packet.tlsa_cert_usage = Udns_enum.Domain_issued_certificate
      && tlsa.Udns_packet.tlsa_selector = Udns_enum.Tlsa_full_certificate
      && tlsa.Udns_packet.tlsa_matching_type = Udns_enum.Tlsa_no_hash
    then
      match X509.Encoding.parse tlsa.Udns_packet.tlsa_data with
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
  and question = { Udns_packet.q_name = fqdn ; q_type = Udns_enum.TLSA }
  in
  let query = { Udns_packet.question = [ question ] ; answer = [] ; authority = [] ; additional = [] } in
  let buf, _ = Udns_packet.encode `Tcp header (`Query query) in
  Udns_cli.send_tcp sock buf ;
  let data = Udns_cli.recv_tcp sock in
  match Udns_packet.decode data with
  | Ok ((_, `Query q, _, _), _) ->
    (* collect TLSA pems *)
    let tlsa =
      List.fold_left (fun acc rr -> match rr.Udns_packet.rdata with
          | Udns_packet.TLSA tlsa ->
            begin match good_tlsa tlsa with
              | None -> acc
              | Some cert -> Some cert
            end
          | _ -> acc)
        None q.Udns_packet.answer
    in
    tlsa
  | Ok ((_, v, _, _), _) ->
    Logs.err (fun m -> m "expected a response, but got %a"
                 Udns_packet.pp_v v) ;
    None
  | Error e ->
    Logs.err (fun m -> m "error %a while decoding answer"
                 Udns_packet.pp_err e) ;
    None

let nsupdate_csr sock now hostname keyname zone dnskey csr =
  let tlsa =
    { Udns_packet.tlsa_cert_usage = Udns_enum.Domain_issued_certificate ;
      tlsa_selector = Udns_enum.Tlsa_selector_private ;
      tlsa_matching_type = Udns_enum.Tlsa_no_hash ;
      tlsa_data = X509.Encoding.cs_of_signing_request csr ;
    }
  in
  let nsupdate =
    let zone = { Udns_packet.q_name = zone ; q_type = Udns_enum.SOA }
    and update = [
      Udns_packet.Remove (hostname, Udns_enum.TLSA) ;
      Udns_packet.Add ({ Udns_packet.name = hostname ; ttl = 600l ; rdata = Udns_packet.TLSA tlsa })
    ]
    in
    { Udns_packet.zone ; prereq = [] ; update ; addition = [] }
  and header =
    let hdr = dns_header () in
    { hdr with Udns_packet.operation = Udns_enum.Update }
  in
  match
    Udns_tsig.encode_and_sign ~proto:`Tcp header (`Update nsupdate) now dnskey keyname >>= fun (data, mac) ->
    Udns_cli.send_tcp sock data ;
    let data = Udns_cli.recv_tcp sock in
    Udns_tsig.decode_and_verify now dnskey keyname ~mac data
  with
  | Error x -> Error (`Msg x)
  | Ok _ -> Ok ()

let jump server_ip port (keyname, zone, dnskey) hostname csr key seed bits cert force =
  Nocrypto_entropy_unix.initialize () ;
  let fn suffix = function
    | None -> Fpath.(v (Domain_name.to_string hostname) + suffix)
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
      let req = X509.CA.request [ `CN (Domain_name.to_string hostname) ] key in
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
  let write_certificate cert =
    let cert = X509.Encoding.Pem.Certificate.to_pem_cstruct1 cert in
    Bos.OS.File.delete cert_filename >>= fun () ->
    Bos.OS.File.write cert_filename (Cstruct.to_string cert)
  in
  let sock = Udns_cli.connect_tcp server_ip port in
  match
    if not force then query_certificate sock public_key hostname else None
  with
  | Some x -> write_certificate x
  | None ->
    nsupdate_csr sock now hostname keyname zone dnskey req >>= fun () ->
    let rec request retries =
      if retries = 0 then
        Error (`Msg "failed to request certificate")
      else
        match query_certificate sock public_key hostname with
        | None ->
          Unix.sleep 1 ;
          request (pred retries)
        | Some x -> write_certificate x
    in
    request 10

let jump_res _ dns_server port dns_key hostname csr key seed bits cert force =
  match
    jump dns_server port dns_key hostname csr key seed bits cert force
  with
  | Ok () -> `Ok ()
  | Error (`Msg m) -> `Error (false, m)

open Cmdliner

let dns_server =
  let doc = "DNS server IP" in
  Arg.(required & pos 0 (some Udns_cli.ip_c) None & info [] ~doc ~docv:"IP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 53 & info [ "port" ] ~doc)

let dns_key =
  let doc = "nsupdate key (name[:alg]:value, where name is YYY._update.zone)" in
  Arg.(required & pos 1 (some Udns_cli.namekey_c) None & info [] ~doc ~docv:"KEY")

let hostname =
  let doc = "Hostname (FQDN) to issue a certificate for" in
  Arg.(required & pos 2 (some Udns_cli.name_c) None & info [] ~doc ~docv:"HOSTNAME")

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
  Term.(ret (const jump_res $ Udns_cli.setup_log $ dns_server $ port $ dns_key $ hostname $ csr $ key $ seed $ bits $ cert $ force)),
  Term.info "ocertify" ~version:"%%VERSION_NUM%%" ~doc ~man

let () = match Term.eval ocertify with `Ok () -> exit 0 | _ -> exit 1
