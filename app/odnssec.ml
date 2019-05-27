open Lwt.Infix

open Dns

let ( let* ) = Result.bind

let pp_zone ppf (domain, query_type, query_value) =
  Fmt.string ppf
    (Rr_map.text_b domain (Rr_map.B (query_type, query_value)))

let pp_nameserver ppf = function
  | `Plaintext (ip, port) -> Fmt.pf ppf "TCP %a:%d" Ipaddr.pp ip port
  | `Tls (tls_cfg, ip, port) ->
    Fmt.pf ppf "TLS %a:%d%a" Ipaddr.pp ip port
      Fmt.(option ~none:(any "") (append (any "#") Domain_name.pp))
      ((Tls.Config.of_client tls_cfg).Tls.Config.peer_name)

let root_ds =
  (* <KeyDigest id="Klajeyz" validFrom="2017-02-02T00:00:00+00:00">
  <KeyTag>20326</KeyTag>
  <Algorithm>8</Algorithm>
  <DigestType>2</DigestType>
  <Digest>
  E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D
  </Digest>
  </KeyDigest> *)
  { Ds.key_tag = 20326 ;
    algorithm = Dnskey.RSA_SHA256 ;
    digest_type = SHA256 ;
    digest = Cstruct.of_hex "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" ;
  }

let validate_ds zone dnskeys ds =
  let* used_dnskey =
    let key_signing_keys =
      Rr_map.Dnskey_set.filter (fun dnsk ->
          Dnskey.F.mem `Secure_entry_point dnsk.Dnskey.flags &&
          Dnskey.key_tag dnsk = ds.Ds.key_tag)
        dnskeys
    in
    if Rr_map.Dnskey_set.cardinal key_signing_keys = 1 then
      Ok (Rr_map.Dnskey_set.choose key_signing_keys)
    else
      Error (`Msg "none or multiple key singing keys")
  in
  let* dgst = Dnssec.digest ds.Ds.digest_type zone used_dnskey in
  if Cstruct.equal ds.Ds.digest dgst then begin
    Logs.info (fun m -> m "DS for %a is good" Domain_name.pp zone);
    Ok used_dnskey
  end else
    Error (`Msg "key signing key couldn't be validated")

let jump () hostname =
  Lwt_main.run (
    let edns = Edns.create ~dnssec_ok:true () in
    let t = Dns_client_lwt.create ~edns:(`Manual edns) () in
    let (_, ns) = Dns_client_lwt.nameservers t in
    Logs.info (fun m -> m "querying NS %a for A records of %a"
                  pp_nameserver (List.hd ns) Domain_name.pp hostname);
    let validate_rrsig_keys dnskeys rrsigs requested_domain rr_map =
      let keys_rrsigs =
        Rr_map.Dnskey_set.fold (fun key acc ->
            let key_tag = Dnskey.key_tag key in
            match Rr_map.Rrsig_set.find_first_opt (fun rrsig -> rrsig.Rrsig.key_tag = key_tag) rrsigs with
            | Some rrsig -> (key, rrsig) :: acc
            | None -> acc)
         dnskeys []
      in
      let* () = if keys_rrsigs = [] then Error (`Msg "no matching key and rrsig found") else Ok () in
      List.fold_left (fun r (key, rrsig) ->
          let* () = r in
          let* key = Dnssec.dnskey_to_pk key in
          Dnssec.verify (Ptime_clock.now ()) key requested_domain rrsig rr_map)
        (Ok ()) keys_rrsigs
    in
    let retrieve_dnskey ds_set requested_domain =
      Dns_client_lwt.(get_rr_with_rrsig t Dnskey requested_domain) >|= function
        | Ok ((_ttl, keys) as rrs, Some (_ttl', rrsigs)) ->
          let keys_ds =
            Rr_map.Ds_set.fold (fun ds acc ->
              match validate_ds requested_domain keys ds with
              | Ok key -> Rr_map.Dnskey_set.add key acc
              | Error `Msg msg ->
                Logs.err (fun m -> m "couldn't validate DS (for %a): %s"
                            Domain_name.pp requested_domain msg);
                acc)
            ds_set Rr_map.Dnskey_set.empty
          in
          let rr_map = Rr_map.singleton Dnskey rrs in
          let* () = validate_rrsig_keys keys_ds rrsigs requested_domain rr_map in
          Logs.info (fun m -> m "verified RRSIG");
          let keys = Rr_map.Dnskey_set.filter (fun k -> Dnskey.F.mem `Zone k.Dnskey.flags) keys in
          Ok keys
        | Ok (_, None) ->
          Logs.err (fun m -> m "rrsig missing");
          Error (`Msg "...")
        | Error _ ->
          Logs.err (fun m -> m "error from resolver");
          Error (`Msg "bad request")
    in
    let retrieve_ds dnskeys requested_domain =
      Dns_client_lwt.(get_rr_with_rrsig t Ds requested_domain) >|= function
        | Ok ((_ttl, ds) as rrs, Some (_ttl', rrsigs)) ->
          let rr_map = Rr_map.singleton Ds rrs in
          let* () = validate_rrsig_keys dnskeys rrsigs requested_domain rr_map in
          Ok ds
        | Ok (_, None) ->
          Logs.err (fun m -> m "rrsig missing");
          Error (`Msg "...")
        | Error _ ->
          Logs.err (fun m -> m "error from resolver");
          Error (`Msg "bad request")
    in
    let rec retrieve_validated_dnskeys hostname =
      Logs.info (fun m -> m "validating and retrieving DNSKEYS for %a" Domain_name.pp hostname);
      if Domain_name.equal hostname Domain_name.root then begin
        Logs.info (fun m -> m "retrieving DNSKEYS for %a" Domain_name.pp hostname);
        retrieve_dnskey (Rr_map.Ds_set.singleton root_ds) hostname
      end else
        let open Lwt_result.Infix in
        retrieve_validated_dnskeys Domain_name.(drop_label_exn hostname) >>= fun parent_dnskeys ->
        Logs.info (fun m -> m "retrieving DS for %a" Domain_name.pp hostname);
        retrieve_ds parent_dnskeys hostname >>= fun ds ->
        Logs.info (fun m -> m "retrieving DNSKEYS for %a" Domain_name.pp hostname);
        retrieve_dnskey ds hostname
    in
    retrieve_validated_dnskeys hostname >|= fun _dnskeys ->
    Ok ()

(*
    Dns_client_lwt.(getaddrinfo t A host) >|= function
    | Ok (_ttl, addrs) when Ipaddr.V4.Set.is_empty addrs ->
      (* handle empty response? *)
      Logs.app (fun m -> m ";%a. IN %a"
                  Domain_name.pp host
                   Dns.Rr_map.ppk (Dns.Rr_map.K A))
    | Ok resp ->
      Logs.app (fun m -> m "%a" pp_zone (host, A, resp))
    | Error (`Msg msg) ->
      Logs.err (fun m -> m "Failed to lookup %a: %s\n"
                   Domain_name.pp host msg)
  *)
  )

open Cmdliner

let to_presult = function
  | Ok a -> `Ok a
  | Error s -> `Error s

let parse_domain : [ `raw ] Domain_name.t Arg.conv =
  (fun name ->
     Result.map_error
       (function `Msg m -> Fmt.str "Invalid domain: %S: %s" name m)
       (Domain_name.of_string name)
     |> to_presult),
  Domain_name.pp

let arg_domain : [ `raw ] Domain_name.t Term.t =
  let doc = "Host to operate on" in
  Arg.(value & opt parse_domain (Domain_name.of_string_exn "cloudflare.com")
       & info [ "host" ] ~docv:"HOST" ~doc)

let cmd =
  Term.(term_result (const jump $ Dns_cli.setup_log $ arg_domain)),
  Term.info "odnssec" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
