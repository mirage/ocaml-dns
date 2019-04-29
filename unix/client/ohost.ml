let () =
  let t = Dns_client_unix.create () in
  let domain = Domain_name.of_string_exn Sys.argv.(1) in
  let ipv4 =
    match Dns_client_unix.gethostbyname t domain with
    | Ok addr -> Fmt.pr "%a has address %a\n"
                   Domain_name.pp domain Ipaddr.V4.pp addr ; Ok ()
    | Error _ as err -> err
  in
  let ipv6 =
    match Dns_client_unix.gethostbyname6 t domain with
    | Ok addr -> Fmt.pr "%a has IPv6 address %a\n"
                   Domain_name.pp domain Ipaddr.V6.pp addr ; Ok ()
    | Error _ as err -> err
  in
  let mx =
    match Dns_client_unix.getaddrinfo t Mx domain with
    | Ok (_ttl, resp) ->
      Fmt.pr "%a\n"
        (Fmt.list (fun ppf -> Fmt.pf ppf "%a mail is handled by %a"
                      Domain_name.pp domain
                      Dns.Mx.pp)) (Dns.Rr_map.Mx_set.elements resp) ;
      Ok ()
    | Error _ as err -> err
  in
  let results = [ ipv4 ; ipv6 ; mx ] in
  let is_error = (function Error _ -> true | Ok _ -> false) in
  match List.find_opt is_error results with
  | None | Some Ok _ -> () (* no errors *)
  | Some (Error `Msg msg) -> (* at least one error *)
    if List.for_all is_error results then
      (* Everything failed; print an error message *)
      ( Fmt.epr "Host %a not found: @[<v>%s@]\n"
          Domain_name.pp domain msg ;
        exit 1)
