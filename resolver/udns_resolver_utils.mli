(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

val scrub : ?mode:[ `Recursive | `Stub ] -> Domain_name.t ->
  Packet.Header.t -> Packet.Question.t -> Packet.Query.t ->
  ((Udns_enum.rr_typ * Domain_name.t * Udns_resolver_entry.rank * Udns_resolver_entry.res) list,
   Udns_enum.rcode) result

val invalid_soa : Domain_name.t -> Domain_name.t * (int32 * Soa.t)
