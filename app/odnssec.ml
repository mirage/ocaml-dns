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

let jump () hostname typ ns =
  match Dns.Rr_map.of_string typ with
  | Ok K k ->
    Lwt_main.run (
      let edns = Edns.create ~dnssec_ok:true ~payload_size:4096 () in
      let nameservers = match ns with
        | None -> None
        | Some ip -> Some (`Tcp, [ `Plaintext (ip, 53) ])
      in
      let t = Dns_client_lwt.create ?nameservers ~edns:(`Manual edns) () in
      let (_, ns) = Dns_client_lwt.nameservers t in
      Logs.info (fun m -> m "querying NS %a for A records of %a"
                    pp_nameserver (List.hd ns) Domain_name.pp hostname);
      let log_err = function
        | `Msg msg ->
          Logs.err (fun m -> m "error from resolver %s" msg);
          Error (`Msg "bad request")
        | `No_data _ ->
          Logs.err (fun m -> m "no data from resolver");
          Error (`Msg "no data")
        | `No_domain _ ->
          Logs.err (fun m -> m "no domain from resolver");
          Error (`Msg "no domain")
      in
      let now = Ptime_clock.now () in
      let retrieve_dnskey dnskeys ds_set requested_domain =
        Dns_client_lwt.(get_rr_with_rrsig t Dnskey requested_domain) >|= function
        | Ok ((_ttl, keys), answer, authority) ->
          let keys_ds =
            Rr_map.Ds_set.fold (fun ds acc ->
                match Dnssec.validate_ds requested_domain keys ds with
                | Ok key -> Rr_map.Dnskey_set.add key acc
                | Error `Msg msg ->
                  Logs.warn (fun m -> m "couldn't validate DS (for %a): %s"
                                Domain_name.pp requested_domain msg);
                  acc)
              ds_set Rr_map.Dnskey_set.empty
          in
          Logs.debug (fun m -> m "found %d DNSKEYS with matching DS" (Rr_map.Dnskey_set.cardinal keys_ds));
          let* _rrs = Dnssec.validate_answer now requested_domain keys_ds Rr_map.Dnskey answer authority in
          Logs.info (fun m -> m "verified RRSIG");
          let keys = Rr_map.Dnskey_set.filter (fun k -> Dnskey.F.mem `Zone k.Dnskey.flags) keys in
          Ok keys
        | Error `No_domain auth ->
          let* () = Dnssec.validate_nsec_no_domain now requested_domain dnskeys auth in
          Error (`Msg "no domain for DNSKEY")
        | Error `No_data (_answer, auth) ->
          let* () = Dnssec.validate_no_data now requested_domain dnskeys Dnskey auth in
          Error (`Msg "no data for DNSKEY")
        | Error e -> log_err e
      in
      let retrieve_ds dnskeys name =
        Dns_client_lwt.(get_rr_with_rrsig t Ds name) >|= function
        | Ok (_, answer, authority) ->
          begin
            match
              Dnssec.validate_answer ~follow_cname:false now name dnskeys Rr_map.Ds answer authority
            with
            | Ok (_, ds) -> Ok (Some ds)
            | Error `Msg msg ->
              Logs.warn (fun m -> m "retrieving DS: %s" msg);
              Ok None
          end
        | Error `No_domain auth ->
          Result.map (fun () -> None)
            (Dnssec.validate_nsec_no_domain now name dnskeys auth)
        | Error `No_data (_answer, auth) ->
          Result.map (fun () -> None)
            (Dnssec.validate_no_data now name dnskeys Rr_map.Ds auth)
        | Error e ->
          log_err e
      in
      let rec retrieve_validated_dnskeys hostname =
        Logs.info (fun m -> m "validating and retrieving DNSKEYS for %a" Domain_name.pp hostname);
        if Domain_name.equal hostname Domain_name.root then begin
          Logs.info (fun m -> m "retrieving DNSKEYS for %a" Domain_name.pp hostname);
          retrieve_dnskey Rr_map.Dnskey_set.empty (Rr_map.Ds_set.singleton root_ds) hostname
        end else
          let open Lwt_result.Infix in
          retrieve_validated_dnskeys Domain_name.(drop_label_exn hostname) >>= fun parent_dnskeys ->
          Logs.info (fun m -> m "retrieving DS for %a" Domain_name.pp hostname);
          retrieve_ds parent_dnskeys hostname >>= function
          | Some ds_set ->
            Logs.info (fun m -> m "retrieving DNSKEYS for %a" Domain_name.pp hostname);
            retrieve_dnskey parent_dnskeys ds_set hostname
          | None ->
            Logs.info (fun m -> m "no DS for %a, continuing with old keys" Domain_name.pp hostname);
            Lwt.return (Ok parent_dnskeys)
      in
      retrieve_validated_dnskeys hostname >>= function
      | Error _ as e -> Lwt.return e
      | Ok dnskeys ->
        Dns_client_lwt.(get_rr_with_rrsig t k hostname) >|= function
        | Ok (rrs, answer, authority) ->
          let* _rrs = Dnssec.validate_answer now hostname dnskeys k answer authority in
          Logs.app (fun m -> m "%a" pp_zone (hostname, k, rrs));
          Ok ()
        | Error `No_domain auth ->
          let* () = Dnssec.validate_nsec_no_domain now hostname dnskeys auth in
          Logs.info (fun m -> m "verified nxdomain");
          Ok ()
        | Error `No_data (_answer, auth) ->
          let* () = Dnssec.validate_no_data now hostname dnskeys k auth in
          Logs.info (fun m -> m "verified no data");
          Ok ()
        | Error e -> log_err e
    )
  | _ -> Error (`Msg "couldn't decode type")

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

let parse_ip =
  (fun ip -> Result.map_error (function `Msg m -> m) (Ipaddr.of_string ip) |> to_presult),
  Ipaddr.pp

let nameserver : Ipaddr.t option Term.t =
  let doc = "Nameserver to use" in
  Arg.(value & opt (some parse_ip) None & info [ "nameserver" ] ~docv:"NAMESERVER" ~doc)

let arg_typ : string Term.t =
  let doc = "Type to query" in
  Arg.(value & opt string "A" & info ["type"] ~docv:"TYPE" ~doc)

let cmd =
  Term.(term_result (const jump $ Dns_cli.setup_log $ arg_domain $ arg_typ $ nameserver)),
  Term.info "odnssec" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
