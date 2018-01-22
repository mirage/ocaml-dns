(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) = struct
  module D = Dns_mirage.Make(R)(P)(M)(T)(S)

  let start _r pclock mclock _ s _ =
    let key = Cstruct.of_string "/NzgCgIc4yKa7nZvWmODrHMbU+xpMeGiDLkZJGD/Evo=" in
    let trie =
      Dns_trie.insert (Dns_name.of_string_exn ~hostname:false "foo._key-management")
        (Dns_map.V (Dns_map.K.Dnskey, [ { Dns_packet.flags = 0 ; key_algorithm = Dns_enum.SHA256 ; key } ]))
        Dns_trie.empty
    in
    let trie =
      let inv s =
        let soa = { Dns_packet.nameserver = s ; hostmaster = s ;
                    serial = 0l ; refresh = 300l ; retry = 300l ;
                    expiry = 300l ; minimum = 300l }
        in
        Dns_map.(V (K.Soa, (300l, soa)))
      in
      Dns_name.DomSet.fold
        (fun n trie -> Dns_trie.insert n (inv n) trie)
        Dns_resolver_root.reserved_zones
        trie
    in
    (match Dns_trie.check trie with
     | Ok () -> ()
     | Error e ->
       Logs.err (fun m -> m "check after update returned %a" Dns_trie.pp_err e)) ;
    let now = M.elapsed_ns mclock in
    let server =
      Dns_server.Primary.create now ~a:[Dns_server.tsig_auth]
        ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign ~rng:R.generate
        trie
    in
    let p = Dns_resolver.create ~root:true now R.generate server () in
    D.resolver s pclock mclock p ;
    S.listen s
end
