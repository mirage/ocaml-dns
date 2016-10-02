open Mirage

let net =
  try match Sys.getenv "NET" with
    | "direct" -> `Direct
    | _        -> `Socket
  with Not_found -> `Socket

let dhcp =
  try match Sys.getenv "ADDR" with
    | "dhcp"   -> `Dhcp
    | "static" -> `Static
  with Not_found -> `Static

let stack console =
  match net, dhcp with
  | `Direct, `Dhcp   -> direct_stackv4_with_dhcp tap0
  | `Direct, `Static -> direct_stackv4_with_default_ipv4 tap0
  | `Socket, _       -> socket_stackv4 [Ipaddr.V4.any]

let client =
  foreign "Unikernel.Client" @@ console @-> stackv4 @-> job

let () =
  add_to_ocamlfind_libraries [ "dns.mirage"; ];
  register "dns-client" [ client $ default_console $ stack default_console ]
