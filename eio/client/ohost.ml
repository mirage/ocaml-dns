open Cmdliner

let (let+) r f = Result.map f r

(* Retrieve IPv4 address for domain name [dn] if any. *)
let ipv4 t dn () =
  match Dns_client_eio.gethostbyname t dn with
  | Ok addr -> Ok ("IPv4", Fmt.str "%a has IPv4 address %a\n" Domain_name.pp dn Ipaddr.V4.pp addr)
  | Error (`Msg m) -> Error ("IPv4", m)

let ipv6 t dn () =
  match Dns_client_eio.gethostbyname6 t dn with
  | Ok addr -> Ok ("IPv6", Fmt.str "%a has IPv6 address %a\n" Domain_name.pp dn Ipaddr.V6.pp addr)
  | Error (`Msg m) -> Error ("IPv6", m)

let mx t dn () =
  match Dns_client_eio.getaddrinfo t Mx dn with
  | Ok (_ttl, resp) -> Ok
  ("MX", Fmt.str "%a\n"
    (Fmt.list (fun ppf -> Fmt.pf ppf "%a mail is handled by %a" Domain_name.pp dn Dns.Mx.pp))
    (Dns.Rr_map.Mx_set.elements resp))
  | Error (`Msg m) -> Error ("MX", m)

let is_error = (function Error _ -> true | Ok _ -> false)

let display_host_ips h_name style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer () ;
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ());

  Eio_main.run @@ fun env ->
  Dns_client_eio.run env @@ fun stack ->
  let t = Dns_client_eio.create ~timeout:1_000_000_000L stack in
  let dn = Domain_name.(host_exn (of_string_exn h_name)) in
  let tasks = [ipv4 t dn; ipv6 t dn; mx t dn] in
  let results = Eio.Fiber.List.map (fun f -> f ()) tasks in

  List.iter
    (function
    | Ok (nm, s) -> Fmt.pr "[Ok] %4s: %s\n" nm s
    | Error (nm, msg) -> Fmt.pr "[Err] %4s: %s\n" nm msg
    )
    results

let cmd =
  let host_arg =
    let doc = "host/domain name, e.g. www.tarides.com" in
    Arg.(required & pos 0 (some' string) None & info [] ~docv:"HOST" ~doc)
  in
  let ohost_t =
    Term.(const
      display_host_ips
      $ host_arg
      $ Fmt_cli.style_renderer ()
      $ Logs_cli.level ()
    )
  in
  let doc = "Displays IPv4, IPv6 and Mail(MX) ip addresses for given host" in
  let man =
    [ `S Manpage.s_bugs
    ; `P "Email bug reports to gbikal AT gmail.com"
    ]
  in
  let info = Cmd.info "ohost" ~version:"%%VERSION%%" ~doc ~man in
  Cmd.v info ohost_t

let () = exit (Cmd.eval cmd)
