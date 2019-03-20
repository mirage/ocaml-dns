(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_mirage_resolver" ~doc:"effectful DNS certify"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.C) (P : Mirage_clock_lwt.PCLOCK) (TIME : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) = struct

  module Dns = Udns_mirage.Make(S)

  let staging = {|-----BEGIN CERTIFICATE-----
MIIEqzCCApOgAwIBAgIRAIvhKg5ZRO08VGQx8JdhT+UwDQYJKoZIhvcNAQELBQAw
GjEYMBYGA1UEAwwPRmFrZSBMRSBSb290IFgxMB4XDTE2MDUyMzIyMDc1OVoXDTM2
MDUyMzIyMDc1OVowIjEgMB4GA1UEAwwXRmFrZSBMRSBJbnRlcm1lZGlhdGUgWDEw
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDtWKySDn7rWZc5ggjz3ZB0
8jO4xti3uzINfD5sQ7Lj7hzetUT+wQob+iXSZkhnvx+IvdbXF5/yt8aWPpUKnPym
oLxsYiI5gQBLxNDzIec0OIaflWqAr29m7J8+NNtApEN8nZFnf3bhehZW7AxmS1m0
ZnSsdHw0Fw+bgixPg2MQ9k9oefFeqa+7Kqdlz5bbrUYV2volxhDFtnI4Mh8BiWCN
xDH1Hizq+GKCcHsinDZWurCqder/afJBnQs+SBSL6MVApHt+d35zjBD92fO2Je56
dhMfzCgOKXeJ340WhW3TjD1zqLZXeaCyUNRnfOmWZV8nEhtHOFbUCU7r/KkjMZO9
AgMBAAGjgeMwgeAwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
HQYDVR0OBBYEFMDMA0a5WCDMXHJw8+EuyyCm9Wg6MHoGCCsGAQUFBwEBBG4wbDA0
BggrBgEFBQcwAYYoaHR0cDovL29jc3Auc3RnLXJvb3QteDEubGV0c2VuY3J5cHQu
b3JnLzA0BggrBgEFBQcwAoYoaHR0cDovL2NlcnQuc3RnLXJvb3QteDEubGV0c2Vu
Y3J5cHQub3JnLzAfBgNVHSMEGDAWgBTBJnSkikSg5vogKNhcI5pFiBh54DANBgkq
hkiG9w0BAQsFAAOCAgEABYSu4Il+fI0MYU42OTmEj+1HqQ5DvyAeyCA6sGuZdwjF
UGeVOv3NnLyfofuUOjEbY5irFCDtnv+0ckukUZN9lz4Q2YjWGUpW4TTu3ieTsaC9
AFvCSgNHJyWSVtWvB5XDxsqawl1KzHzzwr132bF2rtGtazSqVqK9E07sGHMCf+zp
DQVDVVGtqZPHwX3KqUtefE621b8RI6VCl4oD30Olf8pjuzG4JKBFRFclzLRjo/h7
IkkfjZ8wDa7faOjVXx6n+eUQ29cIMCzr8/rNWHS9pYGGQKJiY2xmVC9h12H99Xyf
zWE9vb5zKP3MVG6neX1hSdo7PEAb9fqRhHkqVsqUvJlIRmvXvVKTwNCP3eCjRCCI
PTAvjV+4ni786iXwwFYNz8l3PmPLCyQXWGohnJ8iBm+5nk7O2ynaPVW0U2W+pt2w
SVuvdDM5zGv2f9ltNWUiYZHJ1mmO97jSY/6YfdOUH66iRtQtDkHBRdkNBsMbD+Em
2TgBldtHNSJBfB3pm9FblgOcJ0FSWcUDWJ7vO0+NTXlgrRofRT6pVywzxVo6dND0
WzYlTWeUVsO40xJqhgUQRER9YLOLxJ0O6C8i0xFxAMKOtSdodMB3RIwt7RFQ0uyt
n5Z5MqkYhlMI3J1tPRTp1nEt9fyGspBOO05gi148Qasp+3N+svqKomoQglNoAxU=
-----END CERTIFICATE-----|}

  let production = {|-----BEGIN CERTIFICATE-----
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

  let nsupdate_csr flow host keyname zone dnskey csr =
    match
      Udns_certify.nsupdate R.generate (fun () -> Ptime.v (P.now_d_ps ()))
        ~host ~keyname ~zone dnskey csr
    with
    | Error msg -> Lwt.return_error msg
    | Ok (out, cb) ->
      Dns.send_tcp (Dns.flow flow) out >>= function
      | Error () -> Lwt.return_error "tcp send err"
      | Ok () -> Dns.read_tcp flow >|= function
        | Error () -> Error "tcp recv err"
        | Ok data -> match cb data with
          | Error e -> Error ("nsupdate reply " ^ e)
          | Ok () -> Ok ()

  let query_certificate flow public_key name =
    let out, cb = Udns_certify.query R.generate public_key name in
    Dns.send_tcp (Dns.flow flow) out >>= function
    | Error () -> Lwt.fail_with "couldn't send tcp"
    | Ok () ->
      Dns.read_tcp flow >|= function
      | Error () ->
        Log.err (fun m -> m "error while reading answer") ;
        None
      | Ok data ->
        match cb data with
        | Ok cert -> Some cert
        | Error e ->
          Log.err (fun m -> m "error %s while decoding answer" e) ;
          None

  let initialise_csr hostname additionals seed =
    let private_key =
      let g, print =
        match seed with
        | None -> (None, true)
        | Some seed ->
          let seed = Cstruct.of_string seed in
          Some (Nocrypto.Rng.(create ~seed (module Generators.Fortuna))), false
      in
      let key = Nocrypto.Rsa.generate ?g 4096 in
      (if print then
         let pem = X509.Encoding.Pem.Private_key.to_pem_cstruct1 (`RSA key) in
         Log.info (fun m -> m "using private key@.%s" (Cstruct.to_string pem))
       else
         ()) ;
      key
    in
    let public_key = `RSA (Nocrypto.Rsa.pub_of_priv private_key) in
    let extensions = match additionals with
      | [] -> []
      | hostnames ->
        let dns = List.map (fun name -> `DNS name) (hostname :: hostnames) in
        [ `Extensions [ (false, `Subject_alt_name dns) ] ]
    in
    let csr = X509.CA.request [`CN hostname ] ~extensions (`RSA private_key) in
    (private_key, public_key, csr)

  let query_certificate_or_csr flow pub hostname keyname zone dnskey csr =
    query_certificate flow pub hostname >>= function
    | Some certificate ->
      Log.info (fun m -> m "found certificate in DNS") ;
      Lwt.return certificate
    | None ->
      Log.info (fun m -> m "no certificate in DNS, need to transmit the CSR") ;
      nsupdate_csr flow hostname keyname zone dnskey csr >>= function
      | Error msg ->
        Log.err (fun m -> m "failed to nsupdate TLSA %s" msg) ;
        Lwt.fail_with "nsupdate issue"
      | Ok () ->
        let rec wait_for_cert () =
          query_certificate flow pub hostname >>= function
          | Some certificate ->
            Log.info (fun m -> m "finally found a certificate") ;
            Lwt.return certificate
          | None ->
            Log.info (fun m -> m "waiting for certificate") ;
            TIME.sleep_ns (Duration.of_sec 1) >>= fun () ->
            wait_for_cert ()
        in
        wait_for_cert ()

  let retrieve_certificate ?(ca = `Staging) stack ~dns_key ~hostname ?(additional_hostnames = []) ?key_seed dns port =
    let keyname, zone, dnskey =
      match Astring.String.cut ~sep:":" dns_key with
      | None -> invalid_arg "couldn't parse dnskey"
      | Some (name, key) ->
        match Domain_name.of_string ~hostname:false name, Udns.Dnskey.of_string key with
        | Error _, _ | _, None -> invalid_arg "failed to parse dnskey"
        | Ok name, Some dnskey ->
          let zone = Domain_name.drop_labels_exn ~amount:2 name in
          (name, zone, dnskey)
    in
    let not_sub subdomain = not (Domain_name.sub ~subdomain ~domain:zone) in
    if not_sub hostname || List.exists not_sub additional_hostnames then
      Lwt.fail_with "hostname not a subdomain of zone provided by dns_key"
    else
      let host, more =
        Domain_name.to_string hostname,
        List.map Domain_name.to_string additional_hostnames
      in
      let priv, pub, csr = initialise_csr host more key_seed in
      S.TCPV4.create_connection (S.tcpv4 stack) (dns, port) >>= function
      | Error e ->
        Log.err (fun m -> m "error %a while connecting to name server, shutting down" S.TCPV4.pp_error e) ;
        Lwt.fail_with "couldn't connect to name server"
      | Ok flow ->
        let flow = Dns.of_flow flow in
        query_certificate_or_csr flow pub hostname keyname zone dnskey csr >>= fun certificate ->
        S.TCPV4.close (Dns.flow flow) >|= fun () ->
        let ca = match ca with
          | `Production -> production
          | `Staging -> staging
        in
        let ca =
          X509.Encoding.Pem.Certificate.of_pem_cstruct1 (Cstruct.of_string ca)
        in
        `Single ([certificate ; ca], priv)
end
