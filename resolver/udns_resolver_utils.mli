(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

val scrub : ?mode:[ `Recursive | `Stub ] -> Domain_name.t ->
  Packet.Header.t -> Packet.Question.t -> Packet.Query.t ->
  ((Udns_enum.rr_typ * Domain_name.t * Udns_resolver_cache.rank * Udns_resolver_cache.res) list,
   Udns_enum.rcode) result

val invalid_soa : Domain_name.t -> Soa.t
