open Mirage

let data = crunch "./data"

let net =
  try match Sys.getenv "NET" with
    | "direct" -> `Direct
    | _        -> `Socket
  with Not_found -> `Direct

let dhcp =
  try match Sys.getenv "ADDR" with
    | "dhcp" -> `Dhcp
    | _ -> `Static
  with Not_found -> `Static

let stack =
  match net, dhcp with
  | `Direct, `Dhcp   -> direct_stackv4_with_dhcp default_console tap0
  | `Direct, `Static -> direct_stackv4_with_default_ipv4 default_console tap0
  | `Socket, _       -> socket_stackv4 default_console [Ipaddr.V4.any]

let main =
  foreign "Unikernel.Main" (console @-> kv_ro @-> stackv4 @-> job)

let () =
  add_to_ocamlfind_libraries [ "dns.lwt-core"; ];
  register "mdns-resp-test" [ main $ default_console $ data $ stack ]

