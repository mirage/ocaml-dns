(* (c) 2017 Hannes Mehnert, all rights reserved *)

val scrub : Dns_packet.question -> Dns_packet.header -> Dns_packet.query ->
  ((Dns_enum.rr_typ * Dns_name.t * Dns_resolver_entry.rank * Dns_resolver_entry.res) list,
   [> `Msg of string ]) result

val invalid_soa : Dns_name.t -> Dns_packet.rr
