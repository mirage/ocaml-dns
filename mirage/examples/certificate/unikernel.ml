(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

open Lwt.Infix

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S: Mirage_stack_lwt.V4) = struct
  module DNS = Dns_mirage.Make(R)(P)(M)(T)(S)
  module TLS = Tls_mirage.Make(S.TCPV4)


  let letsencrypt_ca =
    let pem = {|-----BEGIN CERTIFICATE-----
MIIEkjCCA3qgAwIBAgIQCgFBQgAAAVOFc2oLheynCDANBgkqhkiG9w0BAQsFADA/
MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT
DkRTVCBSb290IENBIFgzMB4XDTE2MDMxNzE2NDA0NloXDTIxMDMxNzE2NDA0Nlow
SjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxIzAhBgNVBAMT
GkxldCdzIEVuY3J5cHQgQXV0aG9yaXR5IFgzMIIBIjANBgkqhkiG9w0BAQEFAAOC
AQ8AMIIBCgKCAQEAnNMM8FrlLke3cl03g7NoYzDq1zUmGSXhvb418XCSL7e4S0EF
q6meNQhY7LEqxGiHC6PjdeTm86dicbp5gWAf15Gan/PQeGdxyGkOlZHP/uaZ6WA8
SMx+yk13EiSdRxta67nsHjcAHJyse6cF6s5K671B5TaYucv9bTyWaN8jKkKQDIZ0
Z8h/pZq4UmEUEz9l6YKHy9v6Dlb2honzhT+Xhq+w3Brvaw2VFn3EK6BlspkENnWA
a6xK8xuQSXgvopZPKiAlKQTGdMDQMc2PMTiVFrqoM7hD8bEfwzB/onkxEz0tNvjj
/PIzark5McWvxI0NHWQWM6r6hCm21AvA2H3DkwIDAQABo4IBfTCCAXkwEgYDVR0T
AQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAYYwfwYIKwYBBQUHAQEEczBxMDIG
CCsGAQUFBzABhiZodHRwOi8vaXNyZy50cnVzdGlkLm9jc3AuaWRlbnRydXN0LmNv
bTA7BggrBgEFBQcwAoYvaHR0cDovL2FwcHMuaWRlbnRydXN0LmNvbS9yb290cy9k
c3Ryb290Y2F4My5wN2MwHwYDVR0jBBgwFoAUxKexpHsscfrb4UuQdf/EFWCFiRAw
VAYDVR0gBE0wSzAIBgZngQwBAgEwPwYLKwYBBAGC3xMBAQEwMDAuBggrBgEFBQcC
ARYiaHR0cDovL2Nwcy5yb290LXgxLmxldHNlbmNyeXB0Lm9yZzA8BgNVHR8ENTAz
MDGgL6AthitodHRwOi8vY3JsLmlkZW50cnVzdC5jb20vRFNUUk9PVENBWDNDUkwu
Y3JsMB0GA1UdDgQWBBSoSmpjBH3duubRObemRWXv86jsoTANBgkqhkiG9w0BAQsF
AAOCAQEA3TPXEfNjWDjdGBX7CVW+dla5cEilaUcne8IkCJLxWh9KEik3JHRRHGJo
uM2VcGfl96S8TihRzZvoroed6ti6WqEBmtzw3Wodatg+VyOeph4EYpr/1wXKtx8/
wApIvJSwtmVi4MFU5aMqrSDE6ea73Mj2tcMyo5jMd6jmeWUHK8so/joWUoHOUgwu
X4Po1QYz+3dszkDqMp4fklxBwXRsW10KXzPMTZ+sOPAveyxindmjkW8lGy+QsRlG
PfZ+G6Z6h7mjem0Y+iWlkYcV4PIWL1iwBi8saCbGS5jN2p8M+X+Q7UNKEkROb3N6
KOqkqm57TH2H3eDJAkSnh6/DNFu0Qg==
-----END CERTIFICATE-----|}
    in
    X509.Encoding.Pem.Certificate.of_pem_cstruct1 (Cstruct.of_string pem)

  let dns_header () =
    let id = Randomconv.int16 R.generate in
    { Dns_packet.id ; query = true ; operation = Dns_enum.Query ;
      authoritative = false ; truncation = false ; recursion_desired = false ;
      recursion_available = false ; authentic_data = false ; checking_disabled = false ;
      rcode = Dns_enum.NoError }

  let nsupdate_csr flow pclock keyname zone dnskey csr =
    let hostname = Dns_name.prepend_exn zone (Key_gen.hostname ()) in
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
    let now = Ptime.v (P.now_d_ps pclock) in
    match Dns_tsig.encode_and_sign ~proto:`Tcp header (`Update nsupdate) now dnskey keyname with
    | Error msg -> Lwt.return_error msg
    | Ok (data, mac) ->
      DNS.send_tcp (DNS.flow flow) data >>= function
      | Error () -> Lwt.return_error "tcp send err"
      | Ok () -> DNS.read_tcp flow >>= function
        | Error () -> Lwt.return_error "tcp recv err"
        | Ok data ->
          match Dns_tsig.decode_and_verify now dnskey keyname ~mac data with
          | Error e -> Lwt.return_error ("nsupdate reply " ^ e)
          | Ok _ -> Lwt.return_ok ()

  let query_certificate flow public_key q_name =
    let good_tlsa tlsa =
      if
        tlsa.Dns_packet.tlsa_cert_usage = Dns_enum.Domain_issued_certificate
        && tlsa.Dns_packet.tlsa_selector = Dns_enum.Tlsa_full_certificate
        && tlsa.Dns_packet.tlsa_matching_type = Dns_enum.Tlsa_no_hash
      then
        match X509.Encoding.parse tlsa.Dns_packet.tlsa_data with
        | Some cert ->
          let keys_equal a b =
            Cstruct.equal (X509.key_id a) (X509.key_id b)
          in
          if keys_equal (X509.public_key cert) public_key then
            Some cert
          else
            None
        | _ -> None
      else
        None
    in
    let header = dns_header ()
    and question = { Dns_packet.q_name ; q_type = Dns_enum.TLSA }
    in
    let query = { Dns_packet.question = [ question ] ; answer = [] ; authority = [] ; additional = [] } in
    let buf, _ = Dns_packet.encode `Tcp header (`Query query) in
    DNS.send_tcp (DNS.flow flow) buf >>= function
    | Error () -> Lwt.fail_with "couldn't send tcp"
    | Ok () ->
      DNS.read_tcp flow >>= function
      | Error () -> Lwt.fail_with "couldn't read tcp"
      | Ok data ->
        match Dns_packet.decode data with
        | Ok ((header, `Query q, _, _), _) ->
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
          Lwt.return tlsa
        | Ok ((_, v, _, _), _) ->
          Logs.err (fun m -> m "expected a response, but got %a"
                       Dns_packet.pp_v v) ;
          Lwt.return None
        | Error e ->
          Logs.err (fun m -> m "error %a while decoding answer"
                       Dns_packet.pp_err e) ;
          Lwt.return None

  let initialise_csr hostname seed =
    let private_key =
      let seed = Cstruct.of_string seed in
      let g = Nocrypto.Rng.(create ~seed (module Generators.Fortuna)) in
      Nocrypto.Rsa.generate ~g 4096
    in
    let public_key = `RSA (Nocrypto.Rsa.pub_of_priv private_key) in
    let csr = X509.CA.request [`CN hostname ] (`RSA private_key) in
    (private_key, public_key, csr)

  let rec handle flow =
    TLS.read flow >>= function
    | Ok `Eof ->
      Logs.info (fun f -> f "Closing connection!") ;
      TLS.close flow
    | Error e ->
      Logs.warn (fun f -> f "Error reading data from established connection: %a" TLS.pp_error e) ;
      TLS.close flow
    | Ok (`Data data) ->
      Logs.debug (fun f -> f "read: %d bytes:\n%s" (Cstruct.len data) (Cstruct.to_string data));
      TLS.write flow data >>= function
      | Ok () -> handle flow
      | Error e ->
        Logs.warn (fun m -> m "error %a while echoing" TLS.pp_write_error e) ;
        TLS.close flow

  let accept conf handle flow =
    let dst, dst_port = S.TCPV4.dst flow in
    Logs.info (fun f -> f "new tls connection from IP %s on port %d"
                  (Ipaddr.V4.to_string dst) dst_port);
    TLS.server_of_flow conf flow >>= function
    | Ok tls ->
      (match TLS.epoch tls with
       | Ok e ->
         Logs.info (fun m -> m "established TLS %a %a,%a,extended_ms=%b"
                       Sexplib.Sexp.pp_hum (Tls.Core.sexp_of_tls_version e.Tls.Core.protocol_version)
                       Sexplib.Sexp.pp_hum (Tls.Ciphersuite.sexp_of_ciphersuite e.Tls.Core.ciphersuite)
                       Fmt.(option ~none:(unit "no SNI") string) e.Tls.Core.own_name
                       e.Tls.Core.extended_ms)
       | Error () ->
         Logs.warn (fun m -> m "error while retrieving TLS epoch")) ;
      handle tls
    | Error e ->
      Logs.err (fun m -> m "TLS handshake error %a" TLS.pp_write_error e) ;
      Lwt.return_unit

  let query_certificate_or_csr flow pclock pub hostname keyname zone dnskey csr =
    query_certificate flow pub hostname >>= function
    | Some certificate ->
      Logs.info (fun m -> m "found certificate in DNS") ;
      Lwt.return certificate
    | None ->
      Logs.info (fun m -> m "no certificate in DNS, need to transmit the CSR") ;
      nsupdate_csr flow pclock keyname zone dnskey csr >>= function
      | Error msg ->
        Logs.err (fun m -> m "failed to nsupdate TLSA %s" msg) ;
        Lwt.fail_with "nsupdate issue"
      | Ok () ->
        let rec wait_for_cert () =
          query_certificate flow pub hostname >>= function
          | Some certificate ->
            Logs.info (fun m -> m "finally found a certificate") ;
            Lwt.return certificate
          | None ->
            Logs.info (fun m -> m "waiting for certificate") ;
            OS.Time.sleep_ns (Duration.of_sec 1) >>= fun () ->
            wait_for_cert ()
        in
        wait_for_cert ()

  let start _random pclock _mclock _ stack _ =
    let keyname, zone, dnskey =
      match Astring.String.cut ~sep:":" (Key_gen.dns_key ()) with
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
    let hostname = Dns_name.prepend_exn zone (Key_gen.hostname ())
    and seed = Key_gen.key_seed ()
    and dns = Key_gen.dns_server ()
    and port = Key_gen.port ()
    in

    let priv, pub, csr = initialise_csr (Dns_name.to_string hostname) seed in
    S.TCPV4.create_connection (S.tcpv4 stack) (dns, 53) >>= function
    | Error e ->
      Logs.err (fun m -> m "error %a while connecting to name server, shutting down" S.TCPV4.pp_error e) ;
      Lwt.return_unit
    | Ok flow ->
      let flow = DNS.of_flow flow in
      query_certificate_or_csr flow pclock pub hostname keyname zone dnskey csr >>= fun certificate ->
      S.TCPV4.close (DNS.flow flow) >>= fun () ->
      let config = Tls.Config.server ~certificates:(`Single ([certificate ; letsencrypt_ca], priv)) () in
      S.listen_tcpv4 stack ~port (accept config handle) ;
      S.listen stack
end
