let () =
  let t = Udns_client_unix.create () in
  let domain = Domain_name.of_string_exn Sys.argv.(1) in
  let res =
    Udns_client_unix.gethostbyname t domain in
  match res with
  | Ok addr -> Fmt.pr "%a\n" Ipaddr.V4.pp addr
  | Error _ ->
    (* Here we fall back to trying to resolve the IPv6 address instead: *)
    ( match Udns_client_unix.gethostbyname6 t domain with
      | Ok addr -> Fmt.pr "%a\n" Ipaddr.V6.pp addr
      | Error (`Msg x) ->
        Fmt.epr "Failed to resolve: %s\n" x ;
        exit 1
    )
