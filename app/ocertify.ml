(* (c) 2018 Hannes Mehnert, all rights reserved *)
open Rresult.R.Infix

let find_or_generate_key key_filename keytype keydata seed bits =
  Bos.OS.File.exists key_filename >>= function
  | true ->
    Bos.OS.File.read key_filename >>= fun data ->
    X509.Private_key.decode_pem (Cstruct.of_string data)
  | false ->
    (match keydata with
     | None -> Ok None
     | Some s -> Base64.decode s >>| fun s -> Some s) >>= fun key_data ->
    let key = Dns_certify.generate ?key_seed:seed ~bits ?key_data keytype in
    let pem = X509.Private_key.encode_pem key in
    Bos.OS.File.write ~mode:0o600 key_filename (Cstruct.to_string pem) >>= fun () ->
    Ok key

let query_certificate sock fqdn csr =
  match Dns_certify.query Mirage_crypto_rng.generate (Ptime_clock.now ()) fqdn csr with
  | Error e -> Error e
  | Ok (out, cb) ->
    Dns_cli.send_tcp sock out;
    let data = Dns_cli.recv_tcp sock in
    cb data

let nsupdate_csr sock host keyname zone dnskey csr =
  match Dns_certify.nsupdate Mirage_crypto_rng.generate Ptime_clock.now ~host ~keyname ~zone dnskey csr with
  | Error s -> Error s
  | Ok (out, cb) ->
    Dns_cli.send_tcp sock out;
    let data = Dns_cli.recv_tcp sock in
    match cb data with
    | Ok () -> Ok ()
    | Error e -> Error (`Msg (Fmt.strf "nsupdate reply error %a" Dns_certify.pp_u_err e))

let jump _ server_ip port hostname more_hostnames dns_key_opt csr key keytype keydata seed bits cert force =
  Mirage_crypto_rng_unix.initialize ();
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
      X509.Signing_request.decode_pem (Cstruct.of_string data)
    | false ->
      find_or_generate_key key_filename keytype keydata seed bits >>= fun key ->
      let csr = Dns_certify.signing_request hostname ~more_hostnames key in
      let pem = X509.Signing_request.encode_pem csr in
      Bos.OS.File.write csr_filename (Cstruct.to_string pem) >>= fun () ->
      Ok csr) >>= fun csr ->
  (* before doing anything, let's check whether cert_filename is present,
     the public key matches, and the certificate is still valid *)
  let now = Ptime_clock.now () in
  let tomorrow =
    let (d, ps) = Ptime.Span.to_d_ps (Ptime.to_span now) in
    Ptime.v (succ d, ps)
  in
  (Bos.OS.File.exists cert_filename >>= function
    | true ->
      Bos.OS.File.read cert_filename >>= fun data ->
      X509.Certificate.decode_pem_multiple (Cstruct.of_string data) >>= fun certs ->
      begin
        match List.filter (fun c -> X509.Certificate.supports_hostname c hostname) certs with
        | [] -> Ok None
        | [ cert ] -> Ok (Some cert)
        | _ -> Error (`Msg "multiple certificates that match the hostname")
      end
    | false -> Ok None) >>= (function
      | Some cert ->
        if not force && Dns_certify.cert_matches_csr ~until:tomorrow now csr cert then
          Error (`Msg "valid certificate with matching key already present")
        else
          Ok ()
      | None -> Ok ()) >>= fun () ->
  (* strategy: unless force is provided, we can request DNS, and if a
     certificate is present, compare its public key with csr public key *)
  let write_certificate certs =
    let data = X509.Certificate.encode_pem_multiple certs in
    Bos.OS.File.delete cert_filename >>= fun () ->
    Bos.OS.File.write cert_filename (Cstruct.to_string data)
  in
  let sock = Dns_cli.connect_tcp server_ip port in
  (if force then
     Ok true
   else match query_certificate sock hostname csr with
     | Ok (server, chain) ->
       Logs.app (fun m -> m "found cached certificate in DNS");
       write_certificate (server :: chain) >>| fun () ->
       false
     | Error `No_tlsa ->
       Logs.debug (fun m -> m "no TLSA found, sending update");
       Ok true
     | Error (`Msg m) -> Error (`Msg m)
     | Error ((`Decode _ | `Bad_reply _ | `Unexpected_reply _) as e) ->
       Error (`Msg (Fmt.strf "error %a while parsing TLSA reply"
                      Dns_certify.pp_q_err e)))
  >>= (function
  | false -> Ok ()
  | true ->
    match dns_key_opt with
    | None -> Error (`Msg "no dnskey provided, but required for uploading CSR")
    | Some (keyname, zone, dnskey) ->
      nsupdate_csr sock hostname keyname zone dnskey csr >>= fun () ->
      let rec request retries =
        match query_certificate sock hostname csr with
        | Error (`Msg msg) -> Error (`Msg msg)
        | Error #Dns_certify.q_err when retries = 0 ->
          Error (`Msg "failed to retrieve certificate (tried 10 times)")
        | Error `No_tlsa ->
          Logs.warn (fun m -> m "still no tlsa, sleeping two more seconds");
          Unix.sleep 2;
          request (pred retries)
        | Error (#Dns_certify.q_err as e) ->
          Logs.err (fun m -> m "error %a while handling TLSA reply (retrying)"
                       Dns_certify.pp_q_err e);
          request (pred retries)
        | Ok (server, chain) -> write_certificate (server :: chain)
      in
      request 10) >>| fun () ->
  Logs.app (fun m -> m "success! your certificate is stored in %a (private key %a, csr %a)"
               Fpath.pp cert_filename Fpath.pp key_filename Fpath.pp csr_filename)

open Cmdliner

let dns_server =
  let doc = "DNS server IP" in
  Arg.(required & pos 0 (some Dns_cli.ip_c) None & info [] ~doc ~docv:"IP")

let port =
  let doc = "Port to connect to" in
  Arg.(value & opt int 53 & info [ "port" ] ~doc)

let dns_key =
  let doc = "nsupdate key (name:alg:b64key, where name is YYY._update.zone)" in
  Arg.(value & opt (some Dns_cli.namekey_c) None & info [ "dns-key" ] ~doc ~docv:"KEY")

let hostname =
  let doc = "Hostname (FQDN) to issue a certificate for" in
  Arg.(required & pos 1 (some Dns_cli.name_c) None & info [] ~doc ~docv:"HOSTNAME")

let more_hostnames =
  let doc = "Additional hostnames to be included in the certificate as SubjectAlternativeName extension" in
  Arg.(value & opt_all Dns_cli.domain_name_c [] & info ["additional"] ~doc ~docv:"HOSTNAME")

let csr =
  let doc = "certificate signing request filename (defaults to hostname.req)" in
  Arg.(value & opt (some string) None & info [ "csr" ] ~doc)

let key =
  let doc = "private key filename (default to hostname.key)" in
  Arg.(value & opt (some string) None & info [ "key" ] ~doc)

let seed =
  let doc = "private key seed (or full private key if keytype is a EC key)" in
  Arg.(value & opt (some string) None & info [ "seed" ] ~doc)

let bits =
  let doc = "private key bits" in
  Arg.(value & opt int 4096 & info [ "bits" ] ~doc)

let keydata =
  let doc = "private key (base64 encoded)" in
  Arg.(value & opt (some string) None & info [ "data" ] ~doc)

let keytype =
  let doc = "keytype to generate" in
  let types = [
    ("rsa", `RSA) ; ("ed25519", `ED25519) ;
    ("p256", `P256) ; ("p384", `P384) ; ("p521", `P521)
  ] in
  Arg.(value & opt (enum types) `RSA & info [ "type" ] ~doc)

let cert =
  let doc = "certificate filename (defaults to hostname.pem)" in
  Arg.(value & opt (some string) None & info [ "certificate" ] ~doc)

let force =
  let doc = "force signing request to DNS" in
  Arg.(value & flag & info [ "force" ] ~doc)

let ocertify =
  let doc = "ocertify requests a signed certificate" in
  let man = [ `S "BUGS"; `P "Submit bugs to me";] in
  Term.(term_result (const jump $ Dns_cli.setup_log $ dns_server $ port $ hostname $ more_hostnames $ dns_key $ csr $ key $ keytype $ keydata $ seed $ bits $ cert $ force)),
  Term.info "ocertify" ~version:"%%VERSION_NUM%%" ~doc ~man

let () = match Term.eval ocertify with `Ok () -> exit 0 | _ -> exit 1
