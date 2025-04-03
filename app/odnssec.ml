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

let jump () hostname typ ns =
  match Dns.Rr_map.of_string typ with
  | Ok K k ->
    Lwt_main.run (
      let edns = Edns.create ~dnssec_ok:true ~payload_size:4096 () in
      let nameservers = match ns with
        | None -> None
        | Some ip -> Some (`Tcp, [ `Plaintext (ip, 53) ])
      in
      let happy_eyeballs = Happy_eyeballs_lwt.create () in
      let t = Dns_client_lwt.create ?nameservers ~edns:(`Manual edns) happy_eyeballs in
      let (_, ns) = Dns_client_lwt.nameservers t in
      Logs.info (fun m -> m "querying NS %a for A records of %a"
                    pp_nameserver (List.hd ns) Domain_name.pp hostname);
      let log_err = function
        | `Msg msg ->
          Logs.err (fun m -> m "error from resolver %s" msg);
          Error (`Msg "bad request")
        | `Partial ->
          Logs.err (fun m -> m "partial from resolver");
          Error (`Msg "partial")
        | #Dnssec.err as e ->
          Logs.err (fun m -> m "dnssec error %a" Dnssec.pp_err e);
          Error (`Msg "error")
      in
      let now = Ptime_clock.now () in
      let retrieve_dnskey dnskeys ds_set requested_domain =
        Dns_client_lwt.(get_raw_reply t Dnskey requested_domain) >|= function
        | Error e -> log_err e
        | Ok reply ->
          let keys =
            match reply with
            | `Answer (answer, _) ->
              Option.map
                (fun (_, keys) ->
                   let valid_keys =
                     Rr_map.Ds_set.fold (fun ds acc ->
                         match Dnssec.validate_ds requested_domain keys ds with
                         | Ok key -> Rr_map.Dnskey_set.add key acc
                         | Error `Msg msg ->
                           Logs.warn (fun m -> m "couldn't validate DS (for %a): %s"
                                         Domain_name.pp requested_domain msg);
                           acc)
                       ds_set Rr_map.Dnskey_set.empty
                   in
                   Logs.debug (fun m -> m "found %d DNSKEYS with matching DS"
                                  (Rr_map.Dnskey_set.cardinal valid_keys));
                   valid_keys)
                (Name_rr_map.find requested_domain Dnskey answer)
            | _ -> None
          in
          let keys = Option.value ~default:dnskeys keys in
          match Dnssec.verify_reply now keys requested_domain Dnskey reply with
          | Error (`No_domain _ | `No_data _) ->
            Logs.warn (fun m -> m "no DNSKEY for %a"
                          Domain_name.pp requested_domain);
            Error (`Msg (Fmt.str "missing DNSKEY for %a"
                           Domain_name.pp requested_domain))
          | Error e -> log_err e
          | Ok (_, keys) ->
            Logs.info (fun m -> m "verified RRSIG for DNSKEYS");
            let keys =
              Rr_map.Dnskey_set.filter
                (fun k -> Dnskey.F.mem `Zone k.Dnskey.flags)
                keys
            in
            Ok keys
      in
      let retrieve_ds dnskeys name =
        Dns_client_lwt.(get_raw_reply t Ds name) >|= function
        | Error e -> log_err e
        | Ok reply ->
          match Dnssec.verify_reply ~follow_cname:false now dnskeys name Ds reply with
          | Ok (_, ds) -> Ok (Some ds)
          | Error (`No_domain _ | `No_data _) ->
            Logs.warn (fun m -> m "no data or no domain for DS in %a"
                          Domain_name.pp name);
            Ok None
          | Error (`Cname a) ->
            Logs.warn (fun m -> m "cname alias for %a (DS) to %a"
                          Domain_name.pp name
                          Domain_name.pp a);
            Ok None
          | Error e->
            log_err e
      in
      let rec retrieve_validated_dnskeys hostname =
        Logs.info (fun m -> m "validating and retrieving DNSKEYS for %a" Domain_name.pp hostname);
        if Domain_name.equal hostname Domain_name.root then begin
          Logs.info (fun m -> m "retrieving DNSKEYS for %a" Domain_name.pp hostname);
          retrieve_dnskey Rr_map.Dnskey_set.empty Dnssec.root_ds hostname
        end else
          let open Lwt_result.Infix in
          retrieve_validated_dnskeys Domain_name.(drop_label_exn hostname) >>= fun parent_dnskeys ->
          Logs.info (fun m -> m "retrieving DS for %a" Domain_name.pp hostname);
          retrieve_ds parent_dnskeys hostname >>= function
          | Some ds_set ->
            (* following 4509 - if there's a sha2 DS, drop sha1 ones *)
            let ds_set' =
              if
                Rr_map.Ds_set.exists
                  (fun ds ->
                     match ds.Ds.digest_type with
                     | Ds.SHA256 | Ds.SHA384 -> true
                     | _ -> false)
                  ds_set
              then
                Rr_map.Ds_set.filter
                  (fun ds -> not (ds.Ds.digest_type = Ds.SHA1))
                  ds_set
              else
                ds_set
            in
            if Rr_map.Ds_set.cardinal ds_set > Rr_map.Ds_set.cardinal ds_set' then
              Logs.warn (fun m -> m "dropped %d DS records (SHA1)"
                            (Rr_map.Ds_set.cardinal ds_set' - Rr_map.Ds_set.cardinal ds_set));
            Logs.info (fun m -> m "retrieving DNSKEYS for %a" Domain_name.pp hostname);
            retrieve_dnskey parent_dnskeys ds_set' hostname
          | None ->
            Logs.info (fun m -> m "no DS for %a, continuing with old keys" Domain_name.pp hostname);
            Lwt.return (Ok parent_dnskeys)
      in
      retrieve_validated_dnskeys hostname >>= function
      | Error _ as e -> Lwt.return e
      | Ok dnskeys ->
        Dns_client_lwt.(get_raw_reply t k hostname) >|= function
        | Error e -> log_err e
        | Ok reply ->
          match Dnssec.verify_reply now dnskeys hostname k reply with
          | Ok rrs ->
            Logs.app (fun m -> m "%a" pp_zone (hostname, k, rrs));
            Ok ()
          | Error (`No_domain _ | `No_data _) ->
            Logs.warn (fun m -> m "no data or no domain for %a (%a)"
                          Domain_name.pp hostname Rr_map.ppk (K k));
            Ok ()
          | Error e -> log_err e
    )
  | _ -> Error (`Msg "couldn't decode type")

open Cmdliner

let to_presult = function
  | Ok a -> `Ok a
  | Error s -> `Error s

let parse_domain : [ `raw ] Domain_name.t Arg.conv =
  Arg.conv'
    ((fun name ->
        Result.map_error
          (function `Msg m -> Fmt.str "Invalid domain: %S: %s" name m)
          (Domain_name.of_string name)),
     Domain_name.pp)

let arg_domain : [ `raw ] Domain_name.t Term.t =
  let doc = "Host to operate on" in
  Arg.(value & opt parse_domain (Domain_name.of_string_exn "cloudflare.com")
       & info [ "host" ] ~docv:"HOST" ~doc)

let parse_ip =
  Arg.conv'
    ((fun s ->
        match Ipaddr.of_string s with
        | Ok ip -> Ok ip
        | Error (`Msg m) -> Error ("failed to parse IP address: " ^ m)),
     Ipaddr.pp)

let nameserver : Ipaddr.t option Term.t =
  let doc = "Nameserver to use" in
  Arg.(value & opt (some parse_ip) None & info [ "nameserver" ] ~docv:"NAMESERVER" ~doc)

let arg_typ : string Term.t =
  let doc = "Type to query" in
  Arg.(value & opt string "A" & info ["type"] ~docv:"TYPE" ~doc)

let cmd =
  let term =
    Term.(term_result (const jump $ Dns_cli.setup_log $ arg_domain $ arg_typ $ nameserver))
  and info = Cmd.info "odnssec" ~version:"%%VERSION_NUM%%"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
