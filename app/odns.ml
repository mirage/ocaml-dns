(* odns client utility. *)
(* RFC 768  DNS over UDP *)
(* RFC 7766 DNS over TCP: https://tools.ietf.org/html/rfc7766 *)
(* RFC 6698 DANE: https://tools.ietf.org/html/rfc6698*)

let pp_zone ppf (domain,query_type,query_value) =
  (* TODO dig also prints 'IN' after the TTL, we don't... *)
  Fmt.string ppf
    (Dns.Rr_map.text_b domain (Dns.Rr_map.B (query_type, query_value)))

let pp_zone_tlsa ppf (domain,ttl,(tlsa:Dns.Tlsa.t)) =
  (* TODO this implementation differs a bit from Dns_map.text and tries to
     follow the `dig` output to make it easier to port existing scripts *)
  Fmt.pf ppf "%a.\t%ld\tIN\t%d\t%d\t%d\t%s"
    Domain_name.pp domain
    ttl
    (Dns.Tlsa.cert_usage_to_int tlsa.cert_usage)
    (Dns.Tlsa.selector_to_int tlsa.selector)
    (Dns.Tlsa.matching_type_to_int tlsa.matching_type)
    ( (* this produces output similar to `dig`, splitting the hex string
         in chunks of 56 chars (28 bytes): *)
      let `Hex hex = Hex.of_cstruct tlsa.data in
      let hlen = String.length hex in
      let rec loop acc = function
        | n when n + 56 >= hlen ->
          String.concat " " (List.rev @@ String.sub hex n (hlen-n)::acc)
          |> String.uppercase_ascii
        | n -> loop ((String.sub hex n 56)::acc) (n+56)
      in loop [] 0)

let pp_nameserver ppf = function
  | `Plaintext (ip, port) -> Fmt.pf ppf "TCP %a:%d" Ipaddr.pp ip port
  | `Tls (tls_cfg, ip, port) ->
    Fmt.pf ppf "TLS %a:%d%a" Ipaddr.pp ip port
      Fmt.(option ~none:(any "") (append (any "#") Domain_name.pp))
      ((Tls.Config.of_client tls_cfg).Tls.Config.peer_name)

let do_a nameservers domains () =
  let t = Dns_client_lwt.create ?nameservers () in
  let (_, ns) = Dns_client_lwt.nameservers t in
  Logs.info (fun m -> m "querying NS %a for A records of %a"
                pp_nameserver (List.hd ns) Fmt.(list ~sep:(any ", ") Domain_name.pp) domains);
  let job =
    Lwt_list.iter_p (fun domain ->
        let open Lwt in
        Logs.debug (fun m -> m "looking up %a" Domain_name.pp domain);
        Dns_client_lwt.(getaddrinfo t A domain)
        >|= function
        | Ok (_ttl, addrs) when Ipaddr.V4.Set.is_empty addrs ->
          (* handle empty response? *)
          Logs.app (fun m -> m ";%a. IN %a"
                       Domain_name.pp domain
                       Dns.Rr_map.ppk (Dns.Rr_map.K A))
        | Ok resp ->
          Logs.app (fun m -> m "%a" pp_zone (domain, A, resp))
        | Error (`Msg msg) ->
          Logs.err (fun m -> m "Failed to lookup %a: %s\n"
                       Domain_name.pp domain msg)
      ) domains
  in
  match Lwt_main.run job with
  | () -> Ok () (* TODO handle errors *)

let for_all_domains nameservers ~domains typ f =
  (* [for_all_domains] is a utility function that lets us avoid duplicating
     this block of code in all the subcommands.
     We leave {!do_a} simple to provide a more readable example. *)
  let t = Dns_client_lwt.create ?nameservers () in
  let _, ns = Dns_client_lwt.nameservers t in
  Logs.info (fun m -> m "NS: %a" pp_nameserver (List.hd ns));
  let open Lwt in
  match Lwt_main.run
          (Lwt_list.iter_p
             (fun domain ->
                Dns_client_lwt.getaddrinfo t typ domain
                >|= Rresult.R.reword_error
                  (function `Msg msg as res ->
                     Logs.err (fun m ->
                         m "Failed to lookup %a for %a: %s\n%!"
                           Dns.Rr_map.ppk (Dns.Rr_map.K typ)
                           Domain_name.pp domain msg) ;
                     res)
                >|= f domain)
             domains) with
  | () -> Ok () (* TODO catch failed jobs *)

let pp_response typ domain = function
  | Error _ -> ()
  | Ok resp -> Logs.app (fun m -> m "%a" pp_zone (domain, typ, resp))

let do_aaaa nameserver domains () =
  for_all_domains nameserver ~domains Dns.Rr_map.Aaaa
    (pp_response Dns.Rr_map.Aaaa)

let do_mx nameserver domains () =
  for_all_domains nameserver ~domains Dns.Rr_map.Mx
    (pp_response Dns.Rr_map.Mx)

let do_tlsa nameserver domains () =
  for_all_domains nameserver ~domains Dns.Rr_map.Tlsa
    (fun domain -> function
       | Ok (ttl, tlsa_resp) ->
         Dns.Rr_map.Tlsa_set.iter (fun tlsa ->
             Logs.app (fun m -> m "%a" pp_zone_tlsa (domain,ttl,tlsa))
           ) tlsa_resp
       | Error _ -> () )


let do_txt nameserver domains () =
  for_all_domains nameserver ~domains Dns.Rr_map.Txt
    (fun _domain -> function
       | Ok (ttl, txtset) ->
         Dns.Rr_map.Txt_set.iter (fun txtrr ->
             Logs.app (fun m -> m "%ld: @[<v>%s@]" ttl txtrr)
           ) txtset
       | Error _ -> () )


let do_any _nameserver _domains () =
  (* TODO *)
  Error (`Msg "ANY functionality is not present atm due to refactorings, come back later")

let do_dkim nameserver (selector:string) domains () =
  let domains = List.map (fun original_domain ->
      Domain_name.prepend_label_exn
        (Domain_name.prepend_label_exn
           (original_domain) "_domainkey") selector
    ) domains in
  for_all_domains nameserver ~domains Dns.Rr_map.Txt
    (fun _domain -> function
       | Ok (_ttl, txtset) ->
         Dns.Rr_map.Txt_set.iter (fun txt ->
             Logs.app (fun m -> m "%s" txt)
           ) txtset
       | Error _ -> () )


open Cmdliner

let sdocs = Manpage.s_common_options

let setup_log =
  let setup_log (style_renderer:Fmt.style_renderer option) level : unit =
    Fmt_tty.setup_std_outputs ?style_renderer () ;
    Logs.set_level level ;
    Logs.set_reporter (Logs_fmt.reporter ())
  in
  Term.(const setup_log $ Fmt_cli.style_renderer ~docs:sdocs ()
        $ Logs_cli.level ~docs:sdocs ())

let parse_ns : Ipaddr.t Arg.conv =
  ( fun ns ->
      match Ipaddr.of_string ns with
      | Ok ip -> `Ok ip
      | Error (`Msg m) -> `Error ("bad name server: " ^ m)),
  Ipaddr.pp

let arg_ns : 'a Term.t =
  let doc = "IP of nameserver to use" in
  Arg.(value & opt (some parse_ns) None & info ~docv:"NS-IP" ~doc ["ns"])

let arg_port : 'a Term.t =
  let doc = "Port of nameserver" in
  Arg.(value & opt int 53 & info ~docv:"NS-PORT" ~doc ["ns-port"])

let hostname : [ `host ] Domain_name.t Arg.conv =
  ( fun name ->
      Result.map_error
        (fun (`Msg m) -> Fmt.str "Invalid domain: %S: %s" name m)
        (Result.bind
           (Domain_name.of_string name)
           Domain_name.host)
      |> Rresult.R.to_presult) ,
  Domain_name.pp

let tls_hostname =
  let doc = "Hostname to use for TLS authentication" in
  Arg.(value & opt (some hostname) None &
       info ~docv:"HOSTNAME" ~doc ["tls-hostname"])

let tls_ca_file =
  let doc = "TLS trust anchor file" in
  Arg.(value & opt (some file) None &
       info ~docv:"CAs" ~doc ["tls-ca-file"])

let tls_ca_dir =
  let doc = "TLS trust anchor directory" in
  Arg.(value & opt (some dir) None &
       info ~docv:"CAs" ~doc ["tls-ca-directory"])

let tls_cert_fp =
  let doc = "TLS certificate fingerprint" in
  Arg.(value & opt (some string) None &
       info ~docv:"FP" ~doc ["tls-cert-fingerprint"])

let tls_key_fp =
  let doc = "TLS public key fingerprint" in
  Arg.(value & opt (some string) None &
       info ~docv:"FP" ~doc ["tls-key-fingerprint"])

let no_tls =
  let doc = "Disable DNS-over-TLS" in
  Arg.(value & flag & info ~docv:"no-tls" ~doc ["no-tls"])

let nameserver =
  let (let*) = Result.bind in
  let ns no_tls ca_file ca_dir cert_fp key_fp hostname ip port =
    if no_tls then
      Option.map (fun ip -> `Tcp, [ `Plaintext (ip, port)]) ip
    else
      match ip with
      | None -> None
      | Some ip ->
        let auth peer_name ip =
          let cfg =
            Result.map
              (fun authenticator -> Tls.Config.client ~authenticator ?peer_name ?ip ())
          in
          let time () = Some (Ptime_clock.now ()) in
          let of_fp data =
            let hash, fp =
              let h_of_string = function
                | "md5" -> Some `MD5
                | "sha" | "sha1" -> Some `SHA1
                | "sha224" -> Some `SHA224
                | "sha256" -> Some `SHA256
                | "sha384" -> Some `SHA384
                | "sha512" -> Some `SHA512
                | _ -> None
              in
              match String.split_on_char ':' data with
              | [] -> invalid_arg "empty fingerprint"
              | [ fp ] -> `SHA256, fp
              | hash :: rt -> match h_of_string (String.lowercase_ascii hash) with
                | Some h -> h, String.concat "" rt
                | None -> invalid_arg ("unknown hash: " ^ hash)
            in
            let hex = Hex.to_cstruct (`Hex fp) in
            hash, hex
          in
          match ca_file, ca_dir, cert_fp, key_fp with
          | None, None, None, None -> cfg (Ca_certs.authenticator ())
          | Some f, None, None, None ->
            let* data = Bos.OS.File.read (Fpath.v f) in
            let* certs = X509.Certificate.decode_pem_multiple (Cstruct.of_string data) in
            cfg (Ok (X509.Authenticator.chain_of_trust ~time certs))
          | None, Some d, None, None ->
            let* files = Bos.OS.Dir.contents (Fpath.v d) in
            let* certs =
              List.fold_left (fun r f ->
                  let* acc = r in
                  let* data = Bos.OS.File.read f in
                  let* cert = X509.Certificate.decode_pem (Cstruct.of_string data) in
                  Ok (cert :: acc))
                (Ok []) files
            in
            cfg (Ok (X509.Authenticator.chain_of_trust ~time certs))
          | None, None, Some fp, None ->
            let hash, fingerprint = of_fp fp in
            cfg (Ok (X509.Authenticator.server_cert_fingerprint ~time ~hash ~fingerprint))
          | None, None, None, Some fp ->
            let hash, fingerprint = of_fp fp in
            cfg (Ok (X509.Authenticator.server_key_fingerprint ~time ~hash ~fingerprint))
          | _ -> invalid_arg "only one of cert-file, cert-dir, key-fingerprint, cert-fingerprint is supported"
        in
        let ip' = match hostname with None -> Some ip | Some _ -> None in
        let tls = Result.get_ok (auth hostname ip') in
        Some (`Tcp, [ `Tls (tls, ip, if port = 53 then 853 else port);
                      `Plaintext (ip, port) ])
  in
  Term.(const ns $ no_tls $ tls_ca_file $ tls_ca_dir $ tls_cert_fp $ tls_key_fp $ tls_hostname $ arg_ns $ arg_port)

let parse_domain : [ `raw ] Domain_name.t Arg.conv =
  ( fun name ->
      Domain_name.of_string name
      |> Rresult.R.reword_error
        (fun (`Msg m) -> Fmt.str "Invalid domain: %S: %s" name m)
      |> Rresult.R.to_presult) ,
  Domain_name.pp

let arg_domains : [ `raw ] Domain_name.t list Term.t =
  let doc = "Domain names to operate on" in
  Arg.(non_empty & pos_all parse_domain []
       & info [] ~docv:"DOMAIN(s)" ~doc)

let arg_selector : string Term.t =
  let doc = "DKIM selector string" in
  Arg.(required & opt (some string) None
       & info ["selector"] ~docv:"SELECTOR" ~doc)

let cmd_a : unit Term.t * Term.info =
  let doc = "Query a NS for A records" in
  let man = [
    `P {| Output mimics that of $(b,dig A )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_a $ nameserver $ arg_domains $ setup_log)),
  Term.info "a" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_aaaa : unit Term.t * Term.info =
  let doc = "Query a NS for AAAA records" in
  let man = [
    `P {| Output mimics that of $(b,dig AAAA )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_aaaa $ nameserver $ arg_domains $ setup_log)),
  Term.info "aaaa" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_mx : unit Term.t * Term.info =
  let doc = "Query a NS for mailserver (MX) records" in
  let man = [
    `P {| Output mimics that of $(b,dig MX )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_mx $ nameserver $ arg_domains $ setup_log)),
  Term.info "mx" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_tlsa : unit Term.t * Term.info =
  let doc = "Query a NS for TLSA records (see DANE / RFC 7671)" in
  let man = [
    `S Manpage.s_arguments ;
    `S Manpage.s_description ;
    `P {|Note that you must specify which $(b,service name)
          you want to retrieve the key(s) of.
         To retrieve the $(b,HTTPS) cert of $(i,www.example.com),
          you would query the NS:
          $(mname) $(tname) $(b,_443._tcp.)$(i,www.example.com)
       |} ;
    `P {|Brief list of other handy service name prefixes:|};
    `P {| $(b,_5222._tcp) (XMPP); |} ;
    `P {| $(b,_853._tcp) (DNS-over-TLS); |} ;
    `P {| $(b,_25._tcp) (SMTP with STARTTLS); |} ;
    `P {| $(b,_465._tcp)(SMTP); |} ;
    `P {| $(b,_993._tcp) (IMAP) |} ;
    `S Manpage.s_options ;
  ] in
  Term.(term_result (const do_tlsa $ nameserver $ arg_domains $ setup_log)),
  Term.info "tlsa" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_txt : unit Term.t * Term.info =
  let doc = "Query a NS for TXT records" in
  let man = [
    `S Manpage.s_arguments ;
    `S Manpage.s_description ;
    `P {| Output format is currently: $(i,{TTL}: {text escaped in OCaml format})
          It would be nice to mirror `dig` output here.|} ;
    `S Manpage.s_options ;
  ] in
  Term.(term_result (const do_txt $ nameserver $ arg_domains $ setup_log)),
  Term.info "txt" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_any : unit Term.t * Term.info =
  let doc = "Query a NS for ANY records" in
  let man = [
    `S Manpage.s_arguments ;
    `S Manpage.s_description ;
    `P {| The output will be fairly similar to $(b,dig ANY )$(i,example.com)|} ;
    `S Manpage.s_options ;
  ] in
  Term.(term_result (const do_any $ nameserver $ arg_domains $ setup_log)),
  Term.info "any" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_dkim : unit Term.t * Term.info =
  let doc = "Query a NS for DKIM (RFC 6376) records for a given selector" in
  let man = [
    `S Manpage.s_arguments ;
    `S Manpage.s_description ;
    `S {| Looks up DKIM (DomainKeys Identified Mail) Signatures in
           accordance with RFC 6376.
          Basically it's a recursive TXT lookup on
           $(i,SELECTOR)._domainkeys.$(i,DOMAIN).
          Each key is printed on its own concatenated line.
       |} ;
    `S Manpage.s_options ;
  ] in
  Term.(term_result (const do_dkim $ nameserver $ arg_selector
                     $ arg_domains $ setup_log)),
  Term.info "dkim" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs


let cmd_help : 'a Term.t * Term.info =
  let doc = "OCaml uDns alternative to `dig`" in
  let man = [
    `P {|For more information about the available subcommands,
run them while passing the help flag: $(tname) $(i,SUBCOMMAND) $(b,--help)
|}
  ] in
  let help _ = `Help (`Pager, None) in
  Term.(ret (const help $ setup_log)),
  Term.info "odns" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmds =
  [ cmd_a ; cmd_tlsa; cmd_txt ; cmd_any; cmd_dkim ; cmd_aaaa ; cmd_mx ]

let () =
  Term.(exit @@ eval_choice cmd_help cmds)
