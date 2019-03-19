let () =
  let t = Udns_client_unix.create () in
  let res =
    Udns_client_unix.gethostbyname t (Domain_name.of_string_exn Sys.argv.(1)) in
  match res with
  | Ok addr -> Fmt.pr "%a\n" Ipaddr.V4.pp addr
  | Error (`Msg x) -> Fmt.epr "Failed to resolve: %s\n" x; exit 1
