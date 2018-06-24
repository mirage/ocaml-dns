(* (c) 2018 Hannes Mehnert, all rights reserved *)

let root_servers =
  List.map (fun (n, ip) -> Domain_name.of_string_exn n, Ipaddr.V4.of_string_exn ip)
    [
      "a.root-servers.net", "198.41.0.4" ; (* , 2001:503:ba3e::2:30 VeriSign, Inc. *)
      "b.root-servers.net", "199.9.14.201" ; (* , 2001:500:200::b University of Southern California (ISI) *)
      "c.root-servers.net", "192.33.4.12" ; (* , 2001:500:2::c Cogent Communications *)
      "d.root-servers.net", "199.7.91.13" ; (* , 2001:500:2d::d University of Maryland *)
      "e.root-servers.net", "192.203.230.10" ; (* , 2001:500:a8::e NASA (Ames Research Center) *)
      "f.root-servers.net", "192.5.5.241" ; (* , 2001:500:2f::f Internet Systems Consortium, Inc. *)
      "g.root-servers.net", "192.112.36.4" ; (* , 2001:500:12::d0d US Department of Defense (NIC) *)
      "h.root-servers.net", "198.97.190.53" ; (* , 2001:500:1::53 US Army (Research Lab) *)
      "i.root-servers.net", "192.36.148.17" ; (* , 2001:7fe::53 Netnod *)
      "j.root-servers.net", "192.58.128.30" ; (* , 2001:503:c27::2:30 VeriSign, Inc. *)
      "k.root-servers.net", "193.0.14.129" ; (* , 2001:7fd::1 RIPE NCC *)
      "l.root-servers.net", "199.7.83.42" ; (* , 2001:500:9f::42 ICANN *)
      "m.root-servers.net", "202.12.27.33" (* , 2001:dc3::35 WIDE Project *)
  ]

let a_ttl = 3600000l
let ns_ttl = 518400l

let ns_records =
  List.map (fun (name, _) ->
      let ttl = ns_ttl
      and rdata = Dns_packet.NS name
      in
      { Dns_packet.name = Domain_name.root ; ttl ; rdata })
    root_servers

let a_records =
  List.map (fun (name, ip) ->
      let ttl = a_ttl
      and rdata = Dns_packet.A ip
      in
      name, { Dns_packet.name ; ttl ; rdata })
    root_servers

let reserved_zone_records =
  let n = Domain_name.of_string_exn in
  (* RFC 6761, avoid them to get out of here + multicast DNS 6762 *)
  let zones =
    Domain_name.Set.(add (n "local") (* multicast dns, RFC 6762 *)
                       (add (n "test") (add (n "invalid") (* RFC 6761 *)
                                          (add (n "localhost") (* RFC 6761, draft let-localhost-be-localhost *)
                                             empty))))
  in
  let rec gen acc pos up = function
    | n when succ n = up -> List.rev acc
    | n ->
      let net = string_of_int n ^ pos in
      gen (net :: acc) pos up (succ n)
  in
  let nets = [ (* RFC 6761 and RFC 6890 *)
    "0" (* 0.0.0.0/8 *) ;
    "10" (* 10.0.0.0/8 *) ;
    "127" (* 127.0.0.0/8 *) ;
    "254.169" (* "169.254.0.0/16" *) ;
    "0.0.192" (* "192.0.0.0/24" *) ;
    "2.0.192" (* "192.0.2.0/24" *) ;
    "168.192" (* "192.168.0.0/16" *) ;
    "18.198" ; "19.198" (* "198.18.0.0/15" *) ;
    "100.51.198" (* "198.51.100.0/24" *) ;
    "113.0.203" (* "203.0.113.0/24" *) ;
  ] @ gen [] ".100" 128 64 (* "100.64.0.0/10" ; *)
    @ gen [] ".172" 32 16 (* "172.16.0.0/12" ; *)
    @ gen [] "" 256 240 (* "240.0.0.0/4" *)
  in
  List.fold_left (fun m net ->
      let name = net ^ ".in-addr.arpa" in
      Domain_name.Set.add (n name) m)
    zones nets
(* XXX V6 reserved nets (also RFC6890) *)

let reserved_zones =
  let inv s =
    let soa = { Dns_packet.nameserver = s ; hostmaster = s ;
                serial = 0l ; refresh = 300l ; retry = 300l ;
                expiry = 300l ; minimum = 300l }
    in
    Dns_map.(B (Soa, (300l, soa)))
  in
  Domain_name.Set.fold (fun n acc -> (n, inv n) :: acc) reserved_zone_records []
