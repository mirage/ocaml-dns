(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) = struct
  module D = Dns_mirage.Make(R)(P)(M)(T)(S)

  let start _r pclock mclock _ s _ =
    let trie =
      List.fold_left
        (fun trie (k, v) -> Dns_trie.insert k v trie)
        Dns_trie.empty Dns_resolver_root.reserved_zones
    in
    let key = Cstruct.of_string "/NzgCgIc4yKa7nZvWmODrHMbU+xpMeGiDLkZJGD/Evo=" in
    let trie =
      Dns_trie.insert (Dns_name.of_string_exn ~hostname:false "foo._key-management")
        (Dns_map.V (Dns_map.K.Dnskey, [ { Dns_packet.flags = 0 ; key_algorithm = Dns_enum.SHA256 ; key } ]))
        trie
    in
    let trie =
      let name = Dns_name.of_string_exn "resolver"
      and ip = Ipaddr.V4.of_string_exn "141.1.1.1"
      in
      let trie =
        Dns_trie.insert Dns_name.root
          Dns_map.(V (K.Ns, (300l, Dns_name.DomSet.singleton name))) trie
      in
      Dns_trie.insert name Dns_map.(V (K.A, (300l, [ ip ]))) trie
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
    let p = Dns_resolver.create now R.generate server in
    D.resolver s pclock mclock p ;
    S.listen s
end
