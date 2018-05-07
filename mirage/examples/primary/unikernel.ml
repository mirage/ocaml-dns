(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) = struct

  module D = Dns_mirage.Make(R)(P)(M)(T)(S)

  let data =
    let open Rresult.R.Infix in
    let n = Dns_name.of_string_exn
    and ip = Ipaddr.V4.of_string_exn
    and s = Dns_name.DomSet.singleton
    in
    let m host = n (host ^ ".mirage") in
    let ns = m "ns"
    and ttl = 2560l
    in
    let soa = Dns_packet.({ nameserver = ns ;
                            hostmaster = m "hostmaster" ;
                            serial = 1l ; refresh = 16384l ; retry = 2048l ;
                            expiry = 1048576l ; minimum = ttl })
    in
    let open Dns_trie in
    let open Dns_map in
    let t = insert (n "mirage") (V (K.Soa, (ttl, soa))) Dns_trie.empty in
    let t = insert (n "mirage") (V (K.Ns, (ttl, s ns))) t in
    let t = insert (m "router") (V (K.A, (ttl, [ ip "10.0.42.1" ]))) t in
    let t = insert ns (V (K.A, (ttl, [ ip "10.0.42.2" ]))) t in
    let t = insert (m "charrua") (V (K.A, (ttl, [ ip "10.0.42.3" ]))) t in
    let t = insert (m "secondary") (V (K.A, (ttl, [ ip "10.0.42.4" ]))) t in
    let t = insert (m "resolver") (V (K.A, (ttl, [ ip "10.0.42.5" ]))) t in
    let t = insert (m "www") (V (K.Cname, (ttl, m "router"))) t in
    let key_algorithm = Dns_enum.SHA256
    and flags = 0
    in
    let key = Cstruct.of_string "E0A7MFr4kfcGIRngRVBcBdFPg43XIb2qbGswcn66q4Q=" in
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
    let t = insert ptr_zone (V (K.Soa, (ttl, ptr_soa))) t in
    let t = insert ptr_zone (V (K.Ns, (ttl, s ns))) t in
    let t = insert (Dns_name.prepend_exn ptr_zone "1") (V (K.Ptr, (ttl, m "router"))) t in
    let t = insert (Dns_name.prepend_exn ptr_zone "2") (V (K.Ptr, (ttl, m "ns"))) t in
    let t = insert (Dns_name.prepend_exn ptr_zone "3") (V (K.Ptr, (ttl, m "charrua"))) t in
    let t = insert (Dns_name.prepend_exn ptr_zone "4") (V (K.Ptr, (ttl, m "secondary"))) t in
    let t = insert (Dns_name.prepend_exn ptr_zone "5") (V (K.Ptr, (ttl, m "resolver"))) t in
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
    D.primary s pclock mclock t ;
    S.listen s
end
