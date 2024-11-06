(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_certify_mirage" ~doc:"effectful DNS certify"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_crypto_rng_mirage.S) (P : Mirage_clock.PCLOCK) (TIME : Mirage_time.S) (S : Tcpip.Stack.V4V6) = struct

  module D = Dns_mirage.Make(S)

  let nsupdate_csr flow host keyname zone dnskey csr =
    match
      Dns_certify.nsupdate R.generate (fun () -> Ptime.v (P.now_d_ps ()))
        ~host ~keyname ~zone dnskey csr
    with
    | Error s -> Lwt.return (Error s)
    | Ok (out, cb) ->
      D.send_tcp (D.flow flow) (Cstruct.of_string out) >>= function
      | Error () -> Lwt.return (Error (`Msg "tcp sending error"))
      | Ok () -> D.read_tcp flow >|= function
        | Error () -> Error (`Msg "tcp receive err")
        | Ok data -> match cb (Cstruct.to_string data) with
          | Error e -> Error (`Msg (Fmt.str "nsupdate reply error %a" Dns_certify.pp_u_err e))
          | Ok () -> Ok ()

  let query_certificate flow name csr =
    match Dns_certify.query R.generate (Ptime.v (P.now_d_ps ())) name csr with
    | Error e -> Lwt.return (Error e)
    | Ok (out, cb) ->
      D.send_tcp (D.flow flow) (Cstruct.of_string out) >>= function
      | Error () -> Lwt.return (Error (`Msg "couldn't send tcp"))
      | Ok () ->
        D.read_tcp flow >|= function
        | Error () -> Error (`Msg "error while reading answer")
        | Ok data -> match cb (Cstruct.to_string data) with
          | Error e -> Error e
          | Ok cert -> Ok cert

  let query_certificate_or_csr flow hostname keyname zone dnskey csr =
    query_certificate flow hostname csr >>= function
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
            query_certificate flow hostname csr >>= function
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

  let retrieve_certificate stack (dns_key_name, dns_key) ~hostname ?(additional_hostnames = []) ?(key_type = `RSA) ?key_data ?key_seed ?bits dns port =
    let zone = Domain_name.(host_exn (drop_label_exn ~amount:2 dns_key_name)) in
    let not_sub subdomain = not (Domain_name.is_subdomain ~subdomain ~domain:zone) in
    if not_sub hostname then
      invalid_arg "hostname not a subdomain of zone provided by dns_key"
    else
      let key =
        let seed_or_data, data = match key_data, key_seed with
          | None, None -> invalid_arg "neither key_data nor key_seed is supplied"
          | Some data, _ -> Some `Data, data
          | None, Some seed -> Some `Seed, seed
        in
        Result.fold
          ~ok:Fun.id
          ~error:(function `Msg msg -> invalid_arg ("key generation failed: " ^ msg))
          (X509.Private_key.of_string ?seed_or_data ?bits key_type data)
      in
      match
        let more_hostnames = additional_hostnames in
        Dns_certify.signing_request hostname ~more_hostnames key
      with
      | Error (`Msg m) -> invalid_arg ("create signing request failed: " ^ m)
      | Ok csr ->
        S.TCP.create_connection (S.tcp stack) (dns, port) >>= function
        | Error e ->
          Log.err (fun m -> m "error %a while connecting to name server"
                      S.TCP.pp_error e);
          Lwt.return (Error (`Msg "couldn't connect to name server"))
        | Ok flow ->
          let flow = D.of_flow flow in
          query_certificate_or_csr flow hostname dns_key_name zone dns_key csr >>= fun certificate ->
          S.TCP.close (D.flow flow) >|= fun () ->
          match certificate with
          | Error e -> Error e
          | Ok (cert, chain) -> Ok (cert :: chain, key)
end
