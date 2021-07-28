(* (c) 2018 Hannes Mehnert, all rights reserved *)
let setup_log style_renderer level =
  Fmt_tty.setup_std_outputs ?style_renderer ();
  Logs.set_level level;
  Logs.set_reporter (Logs_fmt.reporter ~dst:Format.std_formatter ())

let connect_tcp ip port =
  let sa = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ip, port) in
  let fam = match ip with Ipaddr.V4 _ -> Unix.PF_INET | Ipaddr.V6 _ -> Unix.PF_INET6 in
  let sock = Unix.(socket fam SOCK_STREAM 0) in
  Unix.(setsockopt sock SO_REUSEADDR true) ;
  Unix.connect sock sa ;
  sock

(* TODO EINTR, SIGPIPE *)
let send_tcp sock buf =
  let size = Cstruct.length buf in
  let size_cs =
    let b = Cstruct.create 2 in
    Cstruct.BE.set_uint16 b 0 size ;
    b
  in
  let data = Cstruct.(to_bytes (append size_cs buf)) in
  let whole = size + 2 in
  let rec out off =
    if off = whole then ()
    else
      let bytes = Unix.send sock data off (whole - off) [] in
      out (bytes + off)
  in
  out 0

let recv_tcp sock =
  let rec read_exactly buf len off =
    if off = len then ()
    else
      let n = Unix.recv sock buf off (len - off) [] in
      read_exactly buf len (off + n)
  in
  let buf = Bytes.create 2 in
  read_exactly buf 2 0 ;
  let len = Cstruct.BE.get_uint16 (Cstruct.of_bytes buf) 0 in
  let buf' = Bytes.create len in
  read_exactly buf' len 0 ;
  Cstruct.of_bytes buf'

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let ip_c : Ipaddr.t Arg.converter =
  let parse s =
    match Ipaddr.of_string s with
    | Ok ip -> `Ok ip
    | Error (`Msg m) -> `Error ("failed to parse IP address: " ^ m)
  in
  parse, Ipaddr.pp

let namekey_c =
  let parse s =
    let open Rresult.R.Infix in
    match Dns.Dnskey.name_key_of_string s with
    | Error (`Msg m) -> `Error ("failed to parse key: " ^ m)
    | Ok (name, key) ->
      let is_op s =
        Domain_name.(equal_label s "_update" || equal_label s "_transfer" || equal_label s "_notify")
      in
      let amount = match Domain_name.find_label ~rev:true name is_op with
        | None -> 0
        | Some x -> succ x
      in
      match
        Domain_name.drop_label ~amount name >>= Domain_name.host
      with
      | Error (`Msg m) -> `Error ("failed to parse zone (idx " ^ string_of_int amount ^ "): " ^ m)
      | Ok zone -> `Ok (name, zone, key)
  in
  parse, fun ppf (name, zone, key) -> Fmt.pf ppf "key name %a zone %a dnskey %a"
      Domain_name.pp name Domain_name.pp zone Dns.Dnskey.pp key

let name_c =
  (fun s -> match Domain_name.of_string s with
     | Error _ -> `Error "failed to parse hostname"
     | Ok name ->
       match Domain_name.host name with
       | Error (`Msg e) -> `Error ("failed to parse hostname: " ^ e)
       | Ok host -> `Ok host), Domain_name.pp

let domain_name_c =
  (fun s -> match Domain_name.of_string s with
     | Error _ -> `Error "failed to parse domain name"
     | Ok name -> `Ok name), Domain_name.pp
