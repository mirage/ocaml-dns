
module Resolver = Dns_resolver_mirage.Make(Tcpip_stack_socket.V4V6)

open Lwt.Infix

let main () =
  Mirage_crypto_rng_unix.use_default ();
  Udpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false Ipaddr.V4.Prefix.global None >>= fun udp ->
  Tcpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false Ipaddr.V4.Prefix.global None >>= fun tcp ->
  Tcpip_stack_socket.V4V6.connect udp tcp >>= fun stack ->
  let resolver =
    let primary_t =
      (* setup DNS server state: *)
      Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate Dns_trie.empty
    in
    Dns_resolver.create ~dnssec:true ~ip_protocol:`Ipv4_only
      (Mirage_mtime.elapsed_ns ()) Mirage_crypto_rng.generate primary_t
  in
  Resolver.resolver ~port:53530 stack resolver;
  Tcpip_stack_socket.V4V6.listen stack >|= fun () ->
  Ok ()

let jump () =
  Lwt_main.run (main ())

open Cmdliner

let cmd =
  let term =
    Term.(term_result (const jump $ Dns_cli.setup_log))
  and info = Cmd.info "resolver" ~version:"%%VERSION_NUM%%"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
