(* odns client utility. *)
(* RFC 768  DNS over UDP *)
(* RFC 7766 DNS over TCP: https://tools.ietf.org/html/rfc7766 *)
(* RFC 6698 DANE: https://tools.ietf.org/html/rfc6698*)

module Tls_client =
  Dns_client.Make(Dns_client.With_tls(Dns_client_lwt.Transport))

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

let setup_authenticator is_tls ta key_fp cert_fp =
  let open Rresult.R.Infix in
  let time () = Some (Ptime_clock.now ()) in
  match is_tls, ta, key_fp, cert_fp with
  | false, None, None, None -> Ok None
  | true, None, None, None ->
    Ca_certs.authenticator () >>| fun a -> Some a
  | _, Some f, None, None ->
    Bos.OS.File.read (Fpath.v f) >>= fun data ->
    X509.Certificate.decode_pem_multiple (Cstruct.of_string data) >>| fun cas ->
    Some (X509.Authenticator.chain_of_trust ~time cas)
  | _, None, Some (host, hash, data), None ->
    let fingerprints = [ host, Cstruct.of_string data ] in
    Ok (Some (X509.Authenticator.server_key_fingerprint ~time ~hash ~fingerprints))
  | _, None, None, Some (host, hash, data) ->
    let fingerprints = [ host, Cstruct.of_string data ] in
    Ok (Some (X509.Authenticator.server_cert_fingerprint ~time ~hash ~fingerprints))
  | _ -> Error (`Msg "multiple authenticators provided, expected one")

let setup_ns : type a b.
  Ipaddr.t option -> int option -> bool ->
  (X509.Authenticator.t option, [> `Msg of string]) result ->
  [`host] Domain_name.t option ->
  (Ipaddr.t * (a Dns.Rr_map.key -> b Domain_name.t -> (a, [> `Msg of string ]) result Lwt.t),
   [> `Msg of string ]) result =
  fun ip port is_udp authenticator peer_name ->
  let open Rresult.R.Infix in
  authenticator >>| function
  | Some authenticator ->
    let ip = match ip with
      | Some ip -> ip
      | None ->
        let t = Dns_client_lwt.create () in
        fst (snd (Dns_client_lwt.nameserver t))
    in
    let nameserver =
      let tls = Tls.Config.client ?peer_name ~authenticator () in
      `Tcp, (tls, (ip, Option.value ~default:853 port))
    in
    let t = Tls_client.create ~nameserver () in
    ip, Tls_client.getaddrinfo t ?nameserver:None
  | None ->
    let nameserver = match ip with
      | None -> None
      | Some ip ->
        let proto = if is_udp then `Udp else `Tcp in
        Some (proto, (ip, Option.value ~default:53 port))
    in
    let t = Dns_client_lwt.create ?nameserver () in
    fst (snd (Dns_client_lwt.nameserver t)),
    Dns_client_lwt.getaddrinfo t ?nameserver:None

let do_a ns domains () =
  let open Rresult.R.Infix in
  ns >>| fun (ns_ip, f) ->
  Logs.info (fun m -> m "querying NS %a for A records of %a"
                Ipaddr.pp ns_ip Fmt.(list ~sep:(unit", ") Domain_name.pp) domains);
  let job =
    Lwt_list.iter_p (fun domain ->
        let open Lwt in
        Logs.debug (fun m -> m "looking up %a" Domain_name.pp domain);
        f Dns.Rr_map.A domain
        >|= function
        | Ok (_ttl, addrs) when Dns.Rr_map.Ipv4_set.is_empty addrs ->
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
  Lwt_main.run job (* TODO handle errors *)

let for_all_domains ns ~domains typ f =
  (* [for_all_domains] is a utility function that lets us avoid duplicating
     this block of code in all the subcommands.
     We leave {!do_a} simple to provide a more readable example. *)
  let open Rresult.R.Infix in
  ns >>| fun (ns_ip, resolve) ->
  Logs.info (fun m -> m "NS: %a" Ipaddr.pp ns_ip);
  let open Lwt.Infix in
  Lwt_main.run
    (Lwt_list.iter_p
       (fun domain ->
          resolve typ domain >|= Rresult.R.reword_error
            (function `Msg msg as res ->
               Logs.err (fun m ->
                   m "Failed to lookup %a for %a: %s\n%!"
                     Dns.Rr_map.ppk (Dns.Rr_map.K typ)
                     Domain_name.pp domain msg) ;
               res)
          >|= f domain)
       domains) (* TODO catch failed jobs *)

let pp_response typ domain = function
  | Error _ -> ()
  | Ok resp -> Logs.app (fun m -> m "%a" pp_zone (domain, typ, resp))

let do_aaaa ns domains () =
  for_all_domains ns ~domains Dns.Rr_map.Aaaa (pp_response Dns.Rr_map.Aaaa)

let do_mx ns domains () =
  for_all_domains ns ~domains Dns.Rr_map.Mx
    (pp_response Dns.Rr_map.Mx)

let do_tlsa ns domains () =
  for_all_domains ns ~domains Dns.Rr_map.Tlsa
    (fun domain -> function
       | Ok (ttl, tlsa_resp) ->
         Dns.Rr_map.Tlsa_set.iter (fun tlsa ->
             Logs.app (fun m -> m "%a" pp_zone_tlsa (domain,ttl,tlsa))
           ) tlsa_resp
       | Error _ -> () )

let do_txt ns domains () =
  for_all_domains ns ~domains Dns.Rr_map.Txt
    (fun _domain -> function
       | Ok (ttl, txtset) ->
         Dns.Rr_map.Txt_set.iter (fun txtrr ->
             Logs.app (fun m -> m "%ld: @[<v>%s@]" ttl txtrr)
           ) txtset
       | Error _ -> () )

let do_any _ns _domains () =
  (* TODO *)
  Error (`Msg "ANY functionality is not present atm due to refactorings, come back later")

let do_dkim ns (selector:string) domains () =
  let domains = List.map (fun original_domain ->
      Domain_name.prepend_label_exn
        (Domain_name.prepend_label_exn
           (original_domain) "_domainkey") selector
    ) domains in
  for_all_domains ns ~domains Dns.Rr_map.Txt
    (fun _domain -> function
       | Ok (_ttl, txtset) ->
         Dns.Rr_map.Txt_set.iter (fun txt ->
             Logs.app (fun m -> m "%s" txt)
           ) txtset
       | Error _ -> () )

open Cmdliner

let sdocs = Manpage.s_common_options

let setup_log =
  let _setup_log (style_renderer:Fmt.style_renderer option) level : unit =
    Fmt_tty.setup_std_outputs ?style_renderer () ;
    Logs.set_level level ;
    Logs.set_reporter (Logs_fmt.reporter ())
  in
  Term.(const _setup_log $ Fmt_cli.style_renderer ~docs:sdocs ()
        $ Logs_cli.level ~docs:sdocs ())

let parse_ns : Ipaddr.t Arg.conv =
  ( fun ns ->
      match Ipaddr.of_string ns with
      | Ok ip -> `Ok ip
      | Error (`Msg m) -> `Error ("bad name server: " ^ m)),
  Ipaddr.pp

let arg_ns =
  let doc = "IP of nameserver to use" in
  Arg.(value & opt (some parse_ns) None & info ~docv:"NS-IP" ~doc ["ns"])

let arg_port =
  let doc = "Port of nameserver" in
  Arg.(value & opt (some int) None & info ~docv:"NS-PORT" ~doc ["ns-port"])

let arg_udp =
  let doc = "Connect via UDP to resolver" in
  Arg.(value & flag & info [ "udp" ] ~doc)

let arg_tls =
  let doc = "Connect via TLS to resolver" in
  Arg.(value & flag & info [ "tls" ] ~doc)

let hostname =
  let parse name =
    let open Rresult.R.Infix in
    Rresult.R.to_presult
      (Rresult.R.reword_error (fun (`Msg m) -> Fmt.strf "Invalid hostname: %s" m)
         (Domain_name.of_string name >>= fun dn ->
          Domain_name.host dn))
  in
  parse, Domain_name.pp

let arg_ns_hostname =
  let doc = "Ensure TLS certificate matches the given hostname" in
  Arg.(value & opt (some hostname) None & info ~docv:"HOSTNAME" ~doc
         ["ns-hostname"])

let arg_ta =
  let doc = "Authenticate TLS using the provided trust anchors" in
  Arg.(value & opt (some file) None & info ~docv:"FILE" ~doc ["trust-anchor"])

let hashes = [
  "md5", `MD5 ; "sha1", `SHA1 ; "sha224", `SHA224 ; "sha256", `SHA256 ;
  "sha384", `SHA384 ; "sha512", `SHA512 ;
]

let parse_hash s =
  match List.assoc_opt (String.lowercase_ascii s) hashes with
  | None -> Error (`Msg "unknown hash algorithm")
  | Some h -> Ok h

let pp_hash ppf h =
  let s, _ = List.find (fun (_, h') -> h = h') hashes in
  Fmt.string ppf s

let fp_c =
  let parse s =
    let open Rresult.R.Infix in
    Rresult.R.to_presult
      (Rresult.R.reword_error
         (fun (`Msg m) ->
            Fmt.strf "Invalid fingerprint (HOST:HASH_ALGO:BASE64) %s: %S" m s)
         (match String.split_on_char ':' s with
          | [ host ; algo ; data ] ->
            Domain_name.of_string host >>= fun dn ->
            Domain_name.host dn >>= fun hostname ->
            parse_hash algo >>= fun hash ->
            Base64.decode ~pad:false data >>| fun d ->
            (hostname, hash, d)
          | _ -> Error (`Msg "")))
  and pp ppf (host, algo, data) =
    Fmt.pf ppf "%a:%a:%s" Domain_name.pp host pp_hash algo
      (Base64.encode_string data)
  in
  parse, pp

let arg_key_fp =
  let doc = "Authenticate TLS using the public key fingerprint" in
  Arg.(value & opt (some fp_c) None & info ~docv:"HOST:HASH_ALGO:BASE64"
         ~doc ["key-fingerprint"])

let arg_cert_fp =
  let doc = "Authenticate TLS using the certificate fingerprint" in
  Arg.(value & opt (some fp_c) None & info ~docv:"HOST:HASH_ALGO:BASE64"
         ~doc ["cert-fingerprint"])

let parse_domain : [ `raw ] Domain_name.t Arg.conv =
  ( fun name ->
      Domain_name.of_string name
      |> Rresult.R.reword_error
        (fun (`Msg m) -> Fmt.strf "Invalid domain: %S: %s" name m)
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

let tls_auth =
  Term.(const setup_authenticator $ arg_tls $ arg_ta $ arg_key_fp $ arg_cert_fp)

let ns : type a b. unit ->
  (Ipaddr.t * (a Dns.Rr_map.key -> b Domain_name.t -> (a, [> `Msg of string ]) result Lwt.t),
   [> `Msg of string ]) result Term.t = fun () ->
  Term.(const setup_ns $ arg_ns $ arg_port $ arg_udp $ tls_auth $ arg_ns_hostname)

let cmd_a : unit Term.t * Term.info =
  let doc = "Query a NS for A records" in
  let man = [
    `P {| Output mimics that of $(b,dig A )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_a $ ns () $ arg_domains $ setup_log)),
  Term.info "a" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_aaaa : unit Term.t * Term.info =
  let doc = "Query a NS for AAAA records" in
  let man = [
    `P {| Output mimics that of $(b,dig AAAA )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_aaaa $ ns () $ arg_domains $ setup_log)),
  Term.info "aaaa" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_mx : unit Term.t * Term.info =
  let doc = "Query a NS for mailserver (MX) records" in
  let man = [
    `P {| Output mimics that of $(b,dig MX )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_mx $ ns () $ arg_domains $ setup_log)),
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
  Term.(term_result (const do_tlsa $ ns () $ arg_domains $ setup_log)),
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
  Term.(term_result (const do_txt $ ns () $ arg_domains $ setup_log)),
  Term.info "txt" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_any : unit Term.t * Term.info =
  let doc = "Query a NS for ANY records" in
  let man = [
    `S Manpage.s_arguments ;
    `S Manpage.s_description ;
    `P {| The output will be fairly similar to $(b,dig ANY )$(i,example.com)|} ;
    `S Manpage.s_options ;
  ] in
  Term.(term_result (const do_any $ ns () $ arg_domains $ setup_log)),
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
  Term.(term_result (const do_dkim $ ns () $ arg_selector $ arg_domains $ setup_log)),
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
