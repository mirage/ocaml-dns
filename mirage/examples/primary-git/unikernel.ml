(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) (RES: Resolver_lwt.S) (CON: Conduit_mirage.S) = struct

  module D = Dns_mirage.Make(R)(P)(M)(T)(S)

  let start _rng pclock mclock _ s resolver conduit _ =
    let (module Context) = Irmin_mirage.context (resolver, conduit) in
    let module Store = Store.Make(Context)(Inflator) in
    Store.pull () >>= fun () ->
    Store.retrieve [] >>= fun bindings ->
    Logs.info (fun m -> m "found %d bindings: %a" (List.length bindings)
                  Fmt.(list ~sep:(unit ",@ ") (pair ~sep:(unit ": ") string int))
                  (List.map (fun (k, v) -> String.concat "/" k, String.length v) bindings)) ;
    let trie =
      List.fold_left (fun trie (k, data) ->
          match Zonefile.load [] data with
          | Error msg ->
            Logs.err (fun m -> m "zonefile %s: %s" (String.concat "/" k) msg) ;
            trie
          | Ok rrs ->
            let trie' = Dns_trie.insert_map (Dns_map.of_rrs rrs) trie in
            match Dns_trie.check trie' with
            | Ok () -> trie'
            | Error e ->
              Logs.err (fun m -> m "error (while processing %s) %a during check()"
                           (String.concat "/" k) Dns_trie.pp_err e) ;
              trie)
        Dns_trie.empty bindings
    in
    let t =
      UDns_server.Primary.create ~a:[UDns_server.tsig_auth]
        ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign
        ~rng:R.generate trie
    in
    D.primary s pclock mclock t ;
    S.listen s
end
