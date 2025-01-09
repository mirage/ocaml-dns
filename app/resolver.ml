
module Rng = Mirage_crypto_rng_mirage.Make(Unix_os.Time)(Mclock)
module Resolver = Dns_resolver_mirage.Make(Rng)(Pclock)(Mclock)(Unix_os.Time)(Tcpip_stack_socket.V4V6)

open Lwt.Infix

let main () =
  Mirage_crypto_rng_unix.initialize (module Mirage_crypto_rng.Fortuna);
  Logs.set_level (Some Debug) ;
  Logs.set_reporter (Logs_fmt.reporter ());
  Udpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false Ipaddr.V4.Prefix.global None >>= fun udp ->
  Tcpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false Ipaddr.V4.Prefix.global None >>= fun tcp ->
  Tcpip_stack_socket.V4V6.connect udp tcp >>= fun stack ->
  let resolver =
    let primary_t =
      (* setup DNS server state: *)
      Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate Dns_trie.empty
    in
    Dns_resolver.create ~dnssec:true ~ip_protocol:`Ipv4_only
      (Mclock.elapsed_ns ()) Mirage_crypto_rng.generate primary_t
  in 
  Resolver.resolver ~port:5353 stack resolver;
  Tcpip_stack_socket.V4V6.listen stack

let () =
  Lwt_main.run (main ())
