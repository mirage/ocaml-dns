open Mirage

let port =
  let doc = Key.Arg.info ~doc:"The TCP port on which to listen for incoming connections." ["port"] in
  Key.(create "port" Arg.(opt int 443 doc))

let dns_key =
  let doc = Key.Arg.info ~doc:"nsupdate key (name:type:value,...)" ["dns-key"] in
  Key.(create "dns-key" Arg.(required string doc))

let dns_server =
  let doc = Key.Arg.info ~doc:"dns server IP" ["dns-server"] in
  Key.(create "dns-server" Arg.(required ipv4_address doc))

let hostname =
  let doc = Key.Arg.info ~doc:"hostname" ["hostname"] in
  Key.(create "hostname" Arg.(required string doc))

let key_seed =
  let doc = Key.Arg.info ~doc:"certificate key seed" ["key-seed"] in
  Key.(create "key-seed" Arg.(required string doc))

let keys = Key.[
    abstract port ; abstract dns_key ; abstract dns_server ;
    abstract hostname ; abstract key_seed
  ]

let packages = [
  package "x509" ;
  package "duration" ;
  package "randomconv" ;
  package "logs" ;
  package ~sublibs:[ "crypto" ; "mirage" ] "udns" ;
  package ~sublibs:[ "mirage" ] "tls" ;
]

let main =
  foreign ~keys ~packages ~deps:[abstract nocrypto] "Unikernel.Main"
    (random @-> pclock @-> mclock @-> time @-> stackv4 @-> job)

let address =
  let network = Ipaddr.V4.Prefix.of_address_string_exn "10.0.42.12/24"
  and gateway = Ipaddr.V4.of_string "10.0.42.1"
  in
  { network ; gateway }

let net =
  if_impl Key.is_unix
    (socket_stackv4 [Ipaddr.V4.any])
    (static_ipv4_stack ~config:address ~arp:farp default_network)

let () =
  register "certification" [
    main $ default_random $ default_posix_clock $ default_monotonic_clock $ default_time $ net
  ]
