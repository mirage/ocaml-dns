(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage

let address =
  let network = Ipaddr.V4.Prefix.of_address_string_exn "10.0.42.4/24"
  and gateway = Ipaddr.V4.of_string "10.0.42.1"
  in
  { network ; gateway }

let net =
  if_impl Key.is_unix
    (socket_stackv4 [Ipaddr.V4.any])
    (static_ipv4_stack ~config:address ~arp:farp default_network)

let keys =
  let doc = Key.Arg.info ~doc:"nsupdate keys (name:type:value,...)" ["keys"] in
  Key.(create "keys" Arg.(opt (list string) [] doc))

let repo =
  let doc = Key.Arg.info ~doc:"git repository" ["repo"] in
  Key.(create "repo" Arg.(required string doc))

let dns_handler =
  let packages = [
    package "logs" ;
    package ~sublibs:["server" ; "crypto" ; "mirage" ; "zonefile" ] "udns" ;
    package "nocrypto" ;
    package "irmin-unix" ;
  ]
  and keys = Key.([ abstract keys ; abstract repo ])
  in
  foreign
    ~deps:[abstract nocrypto]
    ~keys
    ~packages
    "Unikernel.Main" (random @-> pclock @-> mclock @-> time @-> stackv4 @-> job)

let () =
  register "secondary" [dns_handler $ default_random $ default_posix_clock $ default_monotonic_clock $ default_time $ net ]
