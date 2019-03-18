(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

val scrub : ?mode:[ `Recursive | `Stub ] -> Domain_name.t -> Udns_packet.question -> Udns_packet.header -> Udns_packet.query ->
  ((Udns_enum.rr_typ * Domain_name.t * Udns_resolver_entry.rank * Udns_resolver_entry.res) list,
   Udns_enum.rcode) result

val invalid_soa : Domain_name.t -> Udns_packet.rr
