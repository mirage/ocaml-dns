(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage

let address =
  let network = Ipaddr.V4.Prefix.of_address_string_exn "10.0.42.2/24"
  and gateway = Ipaddr.V4.of_string "10.0.42.1"
  in
  { network ; gateway }

let net =
  if_impl Key.is_unix
    (socket_stackv4 [Ipaddr.V4.any])
    (static_ipv4_stack ~config:address ~arp:farp default_network)

let remote_k =
  let doc = Key.Arg.info ~doc:"Remote repository to fetch content."
      ["r"; "remote"] in
  Key.(create "remote" Arg.(opt string "https//github.com/roburio/udns.git" doc))

let dns_handler =
  let packages = [
    package "logs" ;
    package ~sublibs:[ "server" ; "zonefile" ; "mirage.server" ] "udns" ;
    package "nocrypto" ;
    package ~min:"1.0.0" "irmin";
    package "irmin-mirage";
  ] in
  foreign
    ~deps:[abstract nocrypto]
    ~keys:[Key.abstract remote_k]
    ~packages
    "Unikernel.Main"
    (random @-> pclock @-> mclock @-> time @-> stackv4 @-> resolver @-> conduit @-> job)

let () =
  register "primary-git"
    [dns_handler $ default_random $ default_posix_clock $ default_monotonic_clock $
     default_time $ net $ resolver_dns net $ conduit_direct net]
