(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

open Lwt.Infix

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S: Mirage_stack_lwt.V4) = struct
  module D = Dns_mirage_certify.Make(R)(P)(T)(S)
  module TLS = Tls_mirage.Make(S.TCPV4)

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

  let start _random pclock _mclock _ stack _ =
    let hostname = Domain_name.of_string_exn (Key_gen.hostname ()) in
    let additional_hostnames =
      List.map Domain_name.of_string_exn
        (Astring.String.cuts ~empty:false ~sep:"," (Key_gen.additional ()))
    in
    D.retrieve_certificate stack pclock ~dns_key:(Key_gen.dns_key ())
      ~hostname ~additional_hostnames ~key_seed:(Key_gen.key_seed ())
      (Key_gen.dns_server ()) (Key_gen.dns_port ()) >>= fun own_cert ->
    let config = Tls.Config.server ~certificates:own_cert () in
    S.listen_tcpv4 stack ~port:(Key_gen.port ()) (accept config handle) ;
    S.listen stack
end
