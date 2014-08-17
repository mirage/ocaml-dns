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
  | `Direct, `Dhcp   -> direct_stackv4_with_dhcp console tap0
  | `Direct, `Static -> direct_stackv4_with_default_ipv4 console tap0
  | `Socket, _       -> socket_stackv4 console [Ipaddr.V4.any]

let client =
  foreign "Unikernel.Client" @@ console @-> stackv4 @-> entropy @-> job

let () =
  add_to_ocamlfind_libraries [ "dns.mirage"; "mirage-entropy-unix" ] ;
  register "dns-client" [ client $ default_console $ stack default_console $ default_entropy ]
