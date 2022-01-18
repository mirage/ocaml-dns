(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Dns

val root_servers : ([ `raw ] Domain_name.t * Ipaddr.V4.t * Ipaddr.V6.t) list
(** [root_servers] are the root servers. *)

val ns_records : (int32 * Domain_name.Host_set.t)
(** [ns_records] is the root nameserver binding. *)

val a_records : ([ `raw ] Domain_name.t * (int32 * Ipaddr.V4.Set.t)) list
(** [a_records] is a list of names and bindings (A records) for the root
   servers. *)

val aaaa_records : ([ `raw ] Domain_name.t * (int32 * Ipaddr.V6.Set.t)) list
(** [aaaa_records] is a list of names and bindings (AAAA records) for the root
    servers. *)

val ips : [ `Both | `Ipv4_only | `Ipv6_only ] -> Ipaddr.t list
(** [ips ip_proto] is a list of ip addresses of the root servers. *)

val reserved_zones : ([ `raw ] Domain_name.t * Rr_map.b) list
(** [reserved_zones] is a list of names and bindings for reserved zones
   specified by RFCs (private network address ranges, private domains) *)

val reserved : Dns_trie.t
(** [reserved] is a trie with all [reserved_zones]. *)
