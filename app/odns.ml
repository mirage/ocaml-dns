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

let ns ip port is_udp = match ip with
  | None -> None
  | Some ip -> if is_udp then Some (`Udp, [ ip, port ]) else Some (`Tcp, [ ip, port ])

let do_a nameserver ns_port is_udp domains _ =
  let nameservers = ns nameserver ns_port is_udp in
  let t = Dns_client_lwt.create ?nameservers () in
  let (_, ns) = Dns_client_lwt.nameservers t in
  Logs.info (fun m -> m "querying NS %a for A records of %a"
                Ipaddr.pp (fst (List.hd ns)) Fmt.(list ~sep:(unit", ") Domain_name.pp) domains);
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

let for_all_domains nameserver ns_port is_udp ~domains typ f =
  (* [for_all_domains] is a utility function that lets us avoid duplicating
     this block of code in all the subcommands.
     We leave {!do_a} simple to provide a more readable example. *)
  let nameservers = ns nameserver ns_port is_udp in
  let t = Dns_client_lwt.create ?nameservers () in
  let _, ns = Dns_client_lwt.nameservers t in
  Logs.info (fun m -> m "NS: %a" Ipaddr.pp (fst (List.hd ns)));
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

let do_aaaa nameserver ns_port is_udp domains _ =
  for_all_domains nameserver ns_port is_udp ~domains Dns.Rr_map.Aaaa
    (pp_response Dns.Rr_map.Aaaa)

let do_mx nameserver ns_port is_udp domains _ =
  for_all_domains nameserver ns_port is_udp ~domains Dns.Rr_map.Mx
    (pp_response Dns.Rr_map.Mx)

let do_tlsa nameserver ns_port is_udp domains _ =
  for_all_domains nameserver ns_port is_udp ~domains Dns.Rr_map.Tlsa
    (fun domain -> function
       | Ok (ttl, tlsa_resp) ->
         Dns.Rr_map.Tlsa_set.iter (fun tlsa ->
             Logs.app (fun m -> m "%a" pp_zone_tlsa (domain,ttl,tlsa))
           ) tlsa_resp
       | Error _ -> () )


let do_txt nameserver ns_port is_udp domains _ =
  for_all_domains nameserver ns_port is_udp ~domains Dns.Rr_map.Txt
    (fun _domain -> function
       | Ok (ttl, txtset) ->
         Dns.Rr_map.Txt_set.iter (fun txtrr ->
             Logs.app (fun m -> m "%ld: @[<v>%s@]" ttl txtrr)
           ) txtset
       | Error _ -> () )


let do_any _nameserver _is_udp _domains _ =
  (* TODO *)
  Error (`Msg "ANY functionality is not present atm due to refactorings, come back later")

let do_dkim nameserver ns_port is_udp (selector:string) domains _ =
  let domains = List.map (fun original_domain ->
      Domain_name.prepend_label_exn
        (Domain_name.prepend_label_exn
           (original_domain) "_domainkey") selector
    ) domains in
  for_all_domains nameserver ns_port is_udp ~domains Dns.Rr_map.Txt
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

let arg_ns : 'a Term.t =
  let doc = "IP of nameserver to use" in
  Arg.(value & opt (some parse_ns) None & info ~docv:"NS-IP" ~doc ["ns"])

let arg_port : 'a Term.t =
  let doc = "Port of nameserver" in
  Arg.(value & opt int 53 & info ~docv:"NS-PORT" ~doc ["ns-port"])

let arg_udp =
  let doc = "Connect via UDP to resolver" in
  Arg.(value & flag & info [ "udp" ] ~doc)

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

let cmd_a : unit Term.t * Term.info =
  let doc = "Query a NS for A records" in
  let man = [
    `P {| Output mimics that of $(b,dig A )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_a $ arg_ns $ arg_port $ arg_udp $ arg_domains $ setup_log)),
  Term.info "a" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_aaaa : unit Term.t * Term.info =
  let doc = "Query a NS for AAAA records" in
  let man = [
    `P {| Output mimics that of $(b,dig AAAA )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_aaaa $ arg_ns $ arg_port $ arg_udp $ arg_domains $ setup_log)),
  Term.info "aaaa" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_mx : unit Term.t * Term.info =
  let doc = "Query a NS for mailserver (MX) records" in
  let man = [
    `P {| Output mimics that of $(b,dig MX )$(i,DOMAIN)|}
  ] in
  Term.(term_result (const do_mx $ arg_ns $ arg_port $ arg_udp $ arg_domains $ setup_log)),
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
  Term.(term_result (const do_tlsa $ arg_ns $ arg_port $ arg_udp $ arg_domains $ setup_log)),
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
  Term.(term_result (const do_txt $ arg_ns $ arg_port $ arg_udp $ arg_domains $ setup_log)),
  Term.info "txt" ~version:(Manpage.escape "%%VERSION%%") ~man ~doc ~sdocs

let cmd_any : unit Term.t * Term.info =
  let doc = "Query a NS for ANY records" in
  let man = [
    `S Manpage.s_arguments ;
    `S Manpage.s_description ;
    `P {| The output will be fairly similar to $(b,dig ANY )$(i,example.com)|} ;
    `S Manpage.s_options ;
  ] in
  Term.(term_result (const do_any $ arg_ns $ arg_udp $ arg_domains $ setup_log)),
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
  Term.(term_result (const do_dkim $ arg_ns $ arg_port $ arg_udp $ arg_selector
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
