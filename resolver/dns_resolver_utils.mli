(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

val scrub : Dns_packet.question -> Dns_packet.header -> Dns_packet.query ->
  ((Dns_enum.rr_typ * Domain_name.t * Dns_resolver_entry.rank * Dns_resolver_entry.res) list,
   Dns_enum.rcode) result

val invalid_soa : Domain_name.t -> Dns_packet.rr
