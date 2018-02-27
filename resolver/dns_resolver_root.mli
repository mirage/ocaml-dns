(* (c) 2018 Hannes Mehnert, all rights reserved *)

val root_servers : (Dns_name.t * Ipaddr.V4.t) list

val ns_records : Dns_packet.rr list

val a_records : (Dns_name.t * Dns_packet.rr) list

val reserved_zones : (Dns_name.t * Dns_map.v) list
