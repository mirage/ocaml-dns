(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

val scrub : ?mode:[ `Recursive | `Stub ] -> Domain_name.t -> Packet.t ->
  ((Rr.t * Domain_name.t * Udns_resolver_cache.rank * Udns_resolver_cache.res) list,
   Rcode.t) result
(** [scrub ~mode bailiwick packet] returns a list of entries to-be-added to the
    cache. This respects only in-bailiwick resources records, and qualifies the
    [packet]. The purpose is to avoid cache poisoning by not accepting all
    resource records. *)

val invalid_soa : Domain_name.t -> Soa.t (** [invalid_soa name] returns a stub
   SOA for [name]. *)
