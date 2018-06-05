(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) = struct

  module D = Dns_mirage.Make(R)(P)(M)(T)(S)

  let data =
    let n = Dns_name.of_string_exn
    and ip = Ipaddr.V4.of_string_exn
    and s = Dns_name.DomSet.singleton
    in
    let domain = n "mirage" in
    let m = Dns_name.prepend_exn domain in
    let ns = m "ns"
    and ttl = 2560l
    in
    let soa = Dns_packet.({ nameserver = ns ;
                            hostmaster = m "hostmaster" ;
                            serial = 1l ; refresh = 10l ; retry = 5l ;
                            expiry = 60l ; minimum = ttl })
    in
    let open Dns_trie in
    let open Dns_map in
    let t = insert domain (V (K.Soa, (ttl, soa))) Dns_trie.empty in
    let t = insert domain (V (K.Ns, (ttl, s ns))) t in
    let t = insert (m "router") (V (K.A, (ttl, [ ip "10.0.42.1" ]))) t in
    let t = insert ns (V (K.A, (ttl, [ ip "10.0.42.2" ]))) t in
    let t = insert (m "charrua") (V (K.A, (ttl, [ ip "10.0.42.3" ]))) t in
    let t = insert (m "secondary") (V (K.A, (ttl, [ ip "10.0.42.4" ]))) t in
    let t = insert (m "resolver") (V (K.A, (ttl, [ ip "10.0.42.5" ]))) t in
    let t = insert (m "www") (V (K.Cname, (ttl, m "router"))) t in
    let key_algorithm = Dns_enum.SHA256
    and flags = 0
    in
    let key = Cstruct.of_string "G/7zDZr98BTzoi9N6HEUFOg7byKfH9rsPav5JMm9l8Y=" in
    let t = insert (Dns_name.of_string_exn ~hostname:false "10.0.42.2.10.0.42.4._transfer.mirage")
        (V (K.Dnskey, [ { Dns_packet.flags ; key_algorithm ; key } ])) t
    in
    let key = Cstruct.of_string "/WcnjpqrErYrXi1dd4sv8dfwCwDFg0ZGm6N6Bq1VwMI=" in
    let t = insert (Dns_name.of_string_exn ~hostname:false "key._transfer.mirage")
        (V (K.Dnskey, [ { Dns_packet.flags ; key_algorithm ; key } ])) t
    in
    let key = Cstruct.of_string "eRhj4OoaGIIJ3I9hJFwYGhAkdiR5DNzia0WoGrYy70k=" in
    let t = insert (Dns_name.of_string_exn ~hostname:false "one._update.mirage")
        (V (K.Dnskey, [ { Dns_packet.flags ; key_algorithm ; key } ])) t
    in
    let key = Cstruct.of_string "/NzgCgIc4yKa7nZvWmODrHMbU+xpMeGiDLkZJGD/Evo=" in
    let t = insert (Dns_name.of_string_exn ~hostname:false "foo._key-management")
        (V (K.Dnskey, [ { Dns_packet.flags ; key_algorithm ; key } ])) t
    in
    let ptr_zone = n "42.0.10.in-addr.arpa" in
    let ptr_soa = Dns_packet.({ nameserver = ns ;
                                hostmaster = n "hostmaster.example" ;
                                serial = 1l ; refresh = 16384l ; retry = 2048l ;
                                expiry = 1048576l ; minimum = ttl })
    in
    let ptr_name = Dns_name.prepend_exn ptr_zone in
    let t = insert ptr_zone (V (K.Soa, (ttl, ptr_soa))) t in
    let t = insert ptr_zone (V (K.Ns, (ttl, s ns))) t in
    let t = insert (ptr_name "1") (V (K.Ptr, (ttl, m "router"))) t in
    let t = insert (ptr_name "2") (V (K.Ptr, (ttl, m "ns"))) t in
    let t = insert (ptr_name "3") (V (K.Ptr, (ttl, m "charrua"))) t in
    let t = insert (ptr_name "4") (V (K.Ptr, (ttl, m "secondary"))) t in
    let t = insert (ptr_name "5") (V (K.Ptr, (ttl, m "resolver"))) t in
    t

  let start _rng pclock mclock _ s _ =
    let trie = data in
    (match Dns_trie.check trie with
     | Ok () -> ()
     | Error e ->
       Logs.err (fun m -> m "error %a during check()" Dns_trie.pp_err e) ;
       invalid_arg "check") ;
    let t =
      UDns_server.Primary.create
        ~a:[UDns_server.tsig_auth] ~tsig_verify:Dns_tsig.verify
        ~tsig_sign:Dns_tsig.sign ~rng:R.generate trie
    in
    Logs.info (fun m -> m "loaded zone: %a"
                  (Rresult.R.pp ~ok:Fmt.string ~error:Fmt.string)
                  (UDns_server.text (Dns_name.of_string_exn "mirage") (UDns_server.Primary.server t))) ;
    D.primary s pclock mclock t ;
    S.listen s
end
