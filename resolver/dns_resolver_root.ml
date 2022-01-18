(* (c) 2018 Hannes Mehnert, all rights reserved *)
open Dns

let root_servers =
  List.map (fun (n, ip4, ip6) ->
      Domain_name.(host_exn (of_string_exn n)),
      Ipaddr.V4.of_string_exn ip4,
      Ipaddr.V6.of_string_exn ip6)
    [
      "a.root-servers.net", "198.41.0.4", "2001:503:ba3e::2:30" ; (* VeriSign, Inc. *)
      "b.root-servers.net", "199.9.14.201", "2001:500:200::b" ; (* University of Southern California (ISI) *)
      "c.root-servers.net", "192.33.4.12", "2001:500:2::c" ; (* Cogent Communications *)
      "d.root-servers.net", "199.7.91.13", "2001:500:2d::d" ; (* University of Maryland *)
      "e.root-servers.net", "192.203.230.10", "2001:500:a8::e" ; (* NASA (Ames Research Center) *)
      "f.root-servers.net", "192.5.5.241", "2001:500:2f::f" ; (* Internet Systems Consortium, Inc. *)
      "g.root-servers.net", "192.112.36.4", "2001:500:12::d0d" ; (* US Department of Defense (NIC) *)
      "h.root-servers.net", "198.97.190.53", "2001:500:1::53" ; (* US Army (Research Lab) *)
      "i.root-servers.net", "192.36.148.17", "2001:7fe::53" ; (* Netnod *)
      "j.root-servers.net", "192.58.128.30", "2001:503:c27::2:30" ; (* VeriSign, Inc. *)
      "k.root-servers.net", "193.0.14.129", "2001:7fd::1" ; (* RIPE NCC *)
      "l.root-servers.net", "199.7.83.42", "2001:500:9f::42" ; (* ICANN *)
      "m.root-servers.net", "202.12.27.33", "2001:dc3::35" ; (* WIDE Project *)
  ]

let a_ttl = 3600000l
let ns_ttl = 518400l

let ns_records =
  let ns =
    let add_to_set set (name, _, _) = Domain_name.Host_set.add name set in
    List.fold_left add_to_set Domain_name.Host_set.empty root_servers
  in
  (ns_ttl, ns)

let a_records =
  List.map (fun (name, ip, _) ->
      Domain_name.raw name, (a_ttl, Ipaddr.V4.Set.singleton ip))
    root_servers

let aaaa_records =
  List.map (fun (name, _, ip) ->
      Domain_name.raw name, (a_ttl, Ipaddr.V6.Set.singleton ip))
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
  let local_net_name = "127.in-addr.arpa" in
  Domain_name.Set.add (n local_net_name) zones

let stub_soa s =
  let nameserver = Domain_name.prepend_label_exn s "ns"
  and hostmaster = Domain_name.prepend_label_exn s "hostmaster"
  in
  { Soa.nameserver ; hostmaster ; serial = 0l ; refresh = 300l ; retry = 300l ;
    expiry = 300l ; minimum = 300l }

let reserved_zones =
  let inv s = Rr_map.(B (Soa, stub_soa s)) in
  Domain_name.Set.fold (fun n acc -> (n, inv n) :: acc) reserved_zone_records []

let reserved =
  Domain_name.Set.fold (fun name trie ->
      Dns_trie.insert name Rr_map.Soa (stub_soa name) trie)
    reserved_zone_records Dns_trie.empty

let root_servers =
  List.map (fun (n, ip4, ip6) -> Domain_name.raw n, ip4, ip6) root_servers
