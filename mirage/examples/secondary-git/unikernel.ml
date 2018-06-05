(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) = struct
  module D = Dns_mirage.Make(R)(P)(M)(T)(S)
  module Store = Irmin_unix.Git.FS.KV(* (Irmin_unix.Git.G) *)(Irmin.Contents.String)

  let info = Irmin_unix.info ~author:"udns-git"

  let start _rng pclock mclock _ s _ =
    let keys = List.fold_left (fun acc key ->
        match Astring.String.cut ~sep:":" key with
        | None -> Logs.err (fun m -> m "couldn't parse %s" key) ; acc
        | Some (name, key) -> match Dns_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
          | Error _, _ | _, None -> Logs.err (fun m -> m "failed to parse key %s" key) ; acc
          | Ok name, Some dnskey -> (name, dnskey) :: acc)
        [] (Key_gen.keys ())
    in
    let root = Key_gen.repo () in
    let config = Irmin_git.config ~bare:true root in
    Store.Repo.v config >>= fun repo ->
    let t =
      UDns_server.Secondary.create ~a:[ UDns_server.tsig_auth ]
        ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign
        ~rng:R.generate keys
    in
    let on_update t =
      (* find zones, text all of them *)
      let zones = UDns_server.Secondary.zones t in
      let server = UDns_server.Secondary.server t in
      Store.master repo >>= fun branch ->
      Lwt_list.iter_s (fun zone ->
          match UDns_server.text zone server with
          | Error str ->
            Logs.err (fun m -> m "updated zone %a, but failed text %s" Dns_name.pp zone str) ;
            Lwt.return_unit
          | Ok str ->
            Logs.info (fun m -> m "updated zone %a\n%s" Dns_name.pp zone str) ;
            let k = [ Dns_name.to_string zone ] in
            Store.find branch k >>= (function
                | Some old_str when String.equal str old_str ->
                  Logs.info (fun m -> m "nothing to do here") ;
                  Lwt.return_unit
                | _ ->
                  Store.set branch ~info:(info "zone transferred") k str) >|= fun () ->
            match Zonefile.load [] str with
            | Error msg ->
              Logs.err (fun m -> m "zonefile: %s" msg)
            | Ok rrs ->
              let trie = Dns_trie.insert_map (Dns_map.of_rrs rrs) Dns_trie.empty in
              (match Dns_trie.check trie with
               | Ok () -> ()
               | Error e ->
                 Logs.err (fun m -> m "error %a during check()" Dns_trie.pp_err e)) ;
              let s = UDns_server.Secondary.with_data t trie in
              match UDns_server.text zone (UDns_server.Secondary.server s) with
              | Error str ->
                Logs.err (fun m -> m "failed to produce zone %a second time %s" Dns_name.pp zone str)
              | Ok str' ->
                Logs.info (fun m -> m "generated zone (equal %b) %a:%s"
                              (String.equal str str') Dns_name.pp zone str'))
        zones
    in
    D.secondary ~on_update s pclock mclock t ;
    S.listen s
end
