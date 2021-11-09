(* a utility that takes https://wiki.ipfire.org/dns/public-servers
   as input and extracts a map from IP address to hostname *)

let ( let* ) = Result.bind

let get_ips data =
  let* table =
    Option.to_result ~none:(`Msg "could't find dns-over-tls-service table")
      Lambdasoup.(parse data |> select_one "h2#dns-over-tls-service + table")
    [@warning "-3"]
  in
  let tds = Lambdasoup.select "td" table in
  let rec more cur acc = function
    | a :: ip :: dn :: tl ->
      let txt = Fmt.str "%s | %s | %s" (Lambdasoup.to_string a) (Lambdasoup.to_string ip) (Lambdasoup.to_string dn) in
      begin match
          let* ip =
            Option.to_result ~none:(`Msg ("no IP in " ^ txt))
              (Lambdasoup.leaf_text ip)
          in
          if ip = "" then Error (`Msg "IP is empty")
          else
            let* ip = Ipaddr.of_string ip in
            let* dn =
              match Lambdasoup.leaf_text dn, cur with
              | None, None -> Error (`Msg ("no name " ^ txt))
              | Some txt, _ when String.length txt > 0 ->
                let* dn = Domain_name.of_string txt in
                Domain_name.host dn
              | _, Some name -> Ok name
              | _, None -> Error (`Msg "no name")
            in
            Ok (ip, dn)
        with
        | Ok (ip, dn) -> more (Some dn) ((ip, dn) :: acc) tl
        | Error `Msg msg ->
          Logs.warn (fun m -> m "%s" msg) ;
          more cur acc tl
      end
    | _ -> acc
  in
  Ok (more None [] (Lambdasoup.to_list tds))

let read_file file =
  try
    let fh = open_in file in
    try
      let content = really_input_string fh (in_channel_length fh) in
      close_in_noerr fh ;
      Ok content
    with _ ->
      close_in_noerr fh;
      Error (`Msg ("Error reading file: " ^ file))
  with _ -> Error (`Msg ("Error opening file " ^ file))

let write_file file data =
  try
    let fh = open_out file in
    try
      output_string fh data;
      close_out_noerr fh;
      Ok ()
    with _ ->
      close_out_noerr fh;
      Error (`Msg ("Error writing file: " ^ file))
  with _ -> Error (`Msg ("Error opening file " ^ file))

let jump () file out =
  let* data = read_file file in
  let* ips = get_ips data in
  let prefix = {|
let ip_domain =
|} in
  let data =
    List.map (fun (ip, dn) ->
        Fmt.str "Ipaddr.Map.add (Ipaddr.of_string_exn %S) Domain_name.(host_exn (of_string_exn %S))"
          (Ipaddr.to_string ip) (Domain_name.to_string dn))
      ips
  in
  let data =
    List.fold_left (fun acc s -> s ^ "\n(" ^ acc ^ ")")
      "Ipaddr.Map.empty" data
  in
  let data = prefix ^ data in
  match out with
  | None -> Logs.app (fun m -> m "%s" data); Ok ()
  | Some f -> write_file f data

open Cmdliner

let out =
  let doc = "output file" in
  Arg.(value & opt (some string) None & info [ "output" ] ~doc ~docv:"DATA")

let data =
  let doc = "data file" in
  Arg.(required & pos 0 (some file) None & info [] ~doc ~docv:"DATA")

let cmd =
  Term.(term_result (const jump $ Dns_cli.setup_log $ data $ out)),
  Term.info "extract_from_ipfire" ~version:"%%VERSION_NUM%%"

let () = match Term.eval cmd with `Ok () -> exit 0 | _ -> exit 1
