(* (c) 2018 Hannes Mehnert, all rights reserved *)

val root_servers : (Domain_name.t * Ipaddr.V4.t) list

val ns_records : Dns_packet.rr list

val a_records : (Domain_name.t * Dns_packet.rr) list

val reserved_zones : (Domain_name.t * Dns_map.v) list
