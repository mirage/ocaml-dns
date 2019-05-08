(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Dns

val root_servers : (Domain_name.t * Ipaddr.V4.t) list
(** [root_servers] are the root servers. *)

val ns_records : Rr_map.b
(** [ns_records] is the root nameserver binding. *)

val a_records : (Domain_name.t * Rr_map.b) list
(** [a_records] is a list of names and bindings (A records) for the root
   servers. *)

val reserved_zones : (Domain_name.t * Rr_map.b) list
(** [reserved_zones] is a list of names and bindings for reserved zones
   specified by RFCs (private network address ranges, private domains) *)

val reserved : Dns_trie.t
(** [reserved] is a trie with all [reserved_zones]. *)
