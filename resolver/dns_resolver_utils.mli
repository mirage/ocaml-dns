(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

val scrub : ?mode:[ `Recursive | `Stub ] -> [ `raw ] Domain_name.t -> Packet.Question.qtype -> Packet.t ->
  ((Rr_map.k * [ `raw ] Domain_name.t * Dns_cache.rank * Dns_cache.entry) list,
   Rcode.t) result
(** [scrub ~mode bailiwick packet] returns a list of entries to-be-added to the
    cache. This respects only in-bailiwick resources records, and qualifies the
    [packet]. The purpose is to avoid cache poisoning by not accepting all
    resource records. *)

val invalid_soa : [ `raw ] Domain_name.t -> Soa.t (** [invalid_soa name] returns a stub
   SOA for [name]. *)
