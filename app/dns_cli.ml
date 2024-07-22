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
  let size = String.length buf in
  let size_buf =
    let b = Bytes.create 2 in
    Bytes.set_int16_be b 0 size ;
    b
  in
  let data = Bytes.cat size_buf (Bytes.of_string buf) in
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
  let len = Bytes.get_int16_be buf 0 in
  let buf' = Bytes.create len in
  read_exactly buf' len 0 ;
  Bytes.unsafe_to_string buf'

open Cmdliner

let setup_log =
  Term.(const setup_log
        $ Fmt_cli.style_renderer ()
        $ Logs_cli.level ())

let ip_c = Arg.conv (Ipaddr.of_string, Ipaddr.pp)

let namekey_c =
  let parse s =
    let ( let* ) = Result.bind in
    let* (name, key) = Dns.Dnskey.name_key_of_string s in
    let is_op s =
      Domain_name.(equal_label s "_update" || equal_label s "_transfer" || equal_label s "_notify")
    in
    let amount = match Domain_name.find_label ~rev:true name is_op with
      | None -> 0
      | Some x -> succ x
    in
    let* zone = Domain_name.drop_label ~amount name in
    let* zone = Domain_name.host zone in
    Ok (name, zone, key)
  in
  let pp ppf (name, zone, key) =
    Fmt.pf ppf "key name %a zone %a dnskey %a"
      Domain_name.pp name Domain_name.pp zone Dns.Dnskey.pp key
  in
  Arg.conv (parse, pp)

let name_c =
  Arg.conv
    ((fun s -> Result.bind (Domain_name.of_string s) Domain_name.host),
     Domain_name.pp)

let domain_name_c =
  Arg.conv (Domain_name.of_string, Domain_name.pp)
