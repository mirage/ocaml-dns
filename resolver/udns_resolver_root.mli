(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Udns

val root_servers : (Domain_name.t * Ipaddr.V4.t) list

val ns_records : Rr_map.b

val a_records : (Domain_name.t * Rr_map.b) list

val reserved_zones : (Domain_name.t * Rr_map.b) list
