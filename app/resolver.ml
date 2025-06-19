
module Resolver = Dns_resolver_mirage.Make(Tcpip_stack_socket.V4V6)

open Lwt.Infix

let pp_val ppf f =
  let open Metrics in
  match value f with
  | V (String, s) -> Fmt.pf ppf "%S" s
  | V (Int, i) -> Fmt.pf ppf "%d" i
  | V (Int32, i32) -> Fmt.pf ppf "%ld" i32
  | V (Int64, i64) -> Fmt.pf ppf "%Ld" i64
  | V (Uint, u) -> Fmt.pf ppf "%u" u
  | V (Uint32, u32) -> Fmt.pf ppf "%lu" u32
  | V (Uint64, u64) -> Fmt.pf ppf "%Lu" u64
  | _ -> pp_value ppf f

let print_resolver_stats () =
  let map = Metrics.get_cache () in
  let dns_resolver_src =
    List.find (fun src -> Metrics.Src.name src = "dns-resolver") (Metrics.Src.list ())
  in
  let dns_resolver_metrics =
    match Metrics.SM.find_opt dns_resolver_src map with
    | None ->
      print_endline "no dns-resolver found";
      []
    | Some ms ->
      List.concat_map (fun (_tags, data) -> Metrics.Data.fields data) ms
  in
  List.iter (fun field ->
      Logs.app (fun m -> m "%s %a" (Metrics.key field) pp_val field))
    dns_resolver_metrics;
  exit 130

let main () =
  Mirage_crypto_rng_unix.use_default ();
  let reporter = Metrics.cache_reporter () in
  Metrics.set_reporter reporter;
  Metrics.enable_all ();
  Udpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false Ipaddr.V4.Prefix.global None >>= fun udp ->
  Tcpv4v6_socket.connect ~ipv4_only:true ~ipv6_only:false Ipaddr.V4.Prefix.global None >>= fun tcp ->
  Tcpip_stack_socket.V4V6.connect udp tcp >>= fun stack ->
  let resolver =
    let primary_t =
      (* setup DNS server state: *)
      Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate Dns_trie.empty
    in
    Dns_resolver.create ~dnssec:true ~ip_protocol:`Ipv4_only
      (Mirage_mtime.elapsed_ns ()) Mirage_crypto_rng.generate primary_t
  in
  let _resolver = Resolver.resolver ~port:53530 stack resolver in
  let _ : Sys.signal_behavior =
    Sys.signal Sys.sigint
      (Signal_handle
         (fun _ -> print_resolver_stats ()))
  in
  Tcpip_stack_socket.V4V6.listen stack >|= fun () ->
  Ok ()

let jump () =
  Lwt_main.run (main ())

open Cmdliner

let cmd =
  let term =
    Term.(term_result (const jump $ Dns_cli.setup_log))
  and info = Cmd.info "resolver" ~version:"%%VERSION_NUM%%"
  in
  Cmd.v info term

let () = exit (Cmd.eval cmd)
