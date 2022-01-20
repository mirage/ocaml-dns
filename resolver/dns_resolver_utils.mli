(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

type e = E : 'a Rr_map.key * 'a Dns_cache.entry -> e

val scrub : [ `raw ] Domain_name.t -> signed:bool -> Packet.Question.qtype ->
  Packet.t ->
  (([ `raw ] Domain_name.t * e * Dns_cache.rank) list, Rcode.t) result
(** [scrub bailiwick packet] returns a list of entries to-be-added to the
    cache. This respects only in-bailiwick resources records, and qualifies the
    [packet]. The purpose is to avoid cache poisoning by not accepting all
    resource records. *)

val invalid_soa : [ `raw ] Domain_name.t -> Soa.t (** [invalid_soa name] returns a stub
   SOA for [name]. *)
