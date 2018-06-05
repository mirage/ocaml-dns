(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) (KV : KV_RO) = struct

  module D = Dns_mirage.Make(R)(P)(M)(T)(S)

  let read_full kv name =
    KV.size kv name >>= function
    | Error e ->
      Logs.err (fun m -> m "error %a during size() of %s" KV.pp_error e name) ;
      Lwt.fail_with "size() zone file"
    | Ok s -> KV.read kv name 0L s >>= function
      | Error e ->
        Logs.err (fun m -> m "error %a during read() %s" KV.pp_error e name) ;
        Lwt.fail_with "read() zone file"
      | Ok datas ->
        Lwt.return (Cstruct.concat datas)

  let start _rng pclock mclock _ s kv _ =
    read_full kv "zone" >>= fun data ->
    match Zonefile.load [] (Cstruct.to_string data) with
    | Error msg ->
      Logs.err (fun m -> m "zonefile.load: %s" msg) ;
      invalid_arg "zone parser"
    | Ok rrs ->
      let trie = Dns_trie.insert_map (Dns_map.of_rrs rrs) Dns_trie.empty in
      (match Dns_trie.check trie with
       | Ok () -> ()
       | Error e ->
         Logs.err (fun m -> m "error %a during check()" Dns_trie.pp_err e) ;
         invalid_arg "check failed") ;
      let t =
        UDns_server.Primary.create ~a:[UDns_server.tsig_auth]
          ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign
          ~rng:R.generate trie
      in
      D.primary s pclock mclock t ;
      S.listen s
end
