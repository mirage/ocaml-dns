(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_certify_mirage" ~doc:"effectful DNS certify"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (P : Mirage_clock.PCLOCK) (TIME : Mirage_time.S) (S : Mirage_stack.V4) = struct

  module D = Dns_mirage.Make(S)

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
      Dns_certify.nsupdate R.generate (fun () -> Ptime.v (P.now_d_ps ()))
        ~host ~keyname ~zone dnskey csr
    with
    | Error s -> Lwt.return (Error s)
    | Ok (out, cb) ->
      D.send_tcp (D.flow flow) out >>= function
      | Error () -> Lwt.return (Error (`Msg "tcp sending error"))
      | Ok () -> D.read_tcp flow >|= function
        | Error () -> Error (`Msg "tcp receive err")
        | Ok data -> match cb data with
          | Error e -> Error (`Msg (Fmt.strf "nsupdate reply error %a" Dns_certify.pp_u_err e))
          | Ok () -> Ok ()

  let query_certificate flow public_key name =
    match Dns_certify.query R.generate public_key name with
    | Error e -> Lwt.return (Error e)
    | Ok (out, cb) ->
      D.send_tcp (D.flow flow) out >>= function
      | Error () -> Lwt.return (Error (`Msg "couldn't send tcp"))
      | Ok () ->
        D.read_tcp flow >|= function
        | Error () -> Error (`Msg "error while reading answer")
        | Ok data -> match cb data with
          | Error e -> Error e
          | Ok cert -> Ok cert

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
         let pem = X509.Private_key.encode_pem (`RSA key) in
         Log.info (fun m -> m "using private key@.%s" (Cstruct.to_string pem))
       else
         ()) ;
      key
    in
    let public_key = `RSA (Nocrypto.Rsa.pub_of_priv private_key) in
    let extensions =
      match additionals with
      | [] -> X509.Signing_request.Ext.empty
      | _ ->
        let ext =
          let additional = List.map Domain_name.to_string additionals in
          let gn = X509.General_name.(singleton DNS additional) in
          X509.Extension.(singleton Subject_alt_name (false, gn))
        in
        X509.Signing_request.Ext.(singleton Extensions ext)
    in
    let csr =
      X509.(Signing_request.create
              [ Distinguished_name.(Relative_distinguished_name.singleton (CN hostname)) ]
              ~extensions (`RSA private_key))
    in
    (private_key, public_key, csr)

  let query_certificate_or_csr flow pub hostname keyname zone dnskey csr =
    query_certificate flow pub hostname >>= function
    | Ok certificate ->
      Log.info (fun m -> m "found certificate in DNS") ;
      Lwt.return (Ok certificate)
    | Error (`Msg msg) ->
      Log.err (fun m -> m "error %s" msg) ;
      Lwt.return (Error (`Msg msg))
    | Error ((`Decode _ | `Bad_reply _ | `Unexpected_reply _) as e) ->
      Log.err (fun m -> m "query error %a, giving up" Dns_certify.pp_q_err e);
      Lwt.return (Error (`Msg "query error"))
    | Error `No_tlsa ->
      Log.info (fun m -> m "no certificate in DNS, need to transmit the CSR") ;
      nsupdate_csr flow hostname keyname zone dnskey csr >>= function
      | Error (`Msg msg) ->
        Log.err (fun m -> m "failed to nsupdate TLSA %s" msg) ;
        Lwt.fail_with "nsupdate issue"
      | Ok () ->
        let rec wait_for_cert ?(retry = 10) () =
          if retry = 0 then
            Lwt.return (Error (`Msg "too many retries, giving up"))
          else
            query_certificate flow pub hostname >>= function
            | Ok certificate ->
              Log.info (fun m -> m "finally found a certificate") ;
              Lwt.return (Ok certificate)
            | Error (`Msg msg) ->
              Log.err (fun m -> m "error while querying certificate %s" msg) ;
              Lwt.return (Error (`Msg msg))
            | Error (#Dns_certify.q_err as q) ->
              Log.info (fun m -> m "still waiting for certificate, got error %a" Dns_certify.pp_q_err q) ;
              TIME.sleep_ns (Duration.of_sec 2) >>= fun () ->
              wait_for_cert ~retry:(pred retry) ()
        in
        wait_for_cert ()

  let retrieve_certificate ?(ca = `Staging) stack ~dns_key ~hostname ?(additional_hostnames = []) ?key_seed dns port =
    (match ca with
     | `Staging -> Logs.warn (fun m -> m "staging environment - test use only")
     | `Production -> Logs.warn (fun m -> m "production environment - take care what you do"));
    let keyname, zone, dnskey =
      match Dns.Dnskey.name_key_of_string dns_key with
      | Ok (name, key) ->
        let zone = Domain_name.(host_exn (drop_label_exn ~amount:2 name)) in
        (name, zone, key)
      | Error (`Msg m) -> invalid_arg ("failed to parse dnskey: " ^ m)
    in
    let not_sub subdomain = not (Domain_name.is_subdomain ~subdomain ~domain:zone) in
    if not_sub hostname || List.exists not_sub additional_hostnames then
      Lwt.fail_with "hostname not a subdomain of zone provided by dns_key"
    else
      let priv, pub, csr =
        let host = Domain_name.to_string hostname in
        initialise_csr host additional_hostnames key_seed
      in
      S.TCPV4.create_connection (S.tcpv4 stack) (dns, port) >>= function
      | Error e ->
        Log.err (fun m -> m "error %a while connecting to name server, shutting down" S.TCPV4.pp_error e) ;
        Lwt.return (Error (`Msg "couldn't connect to name server"))
      | Ok flow ->
        let flow = D.of_flow flow in
        query_certificate_or_csr flow pub hostname keyname zone dnskey csr >>= fun certificate ->
        S.TCPV4.close (D.flow flow) >|= fun () ->
        match certificate with
        | Error e -> Error e
        | Ok certificate ->
          let ca = match ca with
            | `Production -> production
            | `Staging -> staging
          in
          match X509.Certificate.decode_pem (Cstruct.of_string ca) with
          | Ok ca -> Ok (`Single ([certificate ; ca], priv))
          | Error (`Msg msg) -> Error (`Msg msg)
end
