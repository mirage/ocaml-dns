(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
open Udns

type t

type stats

val pp_stats : stats Fmt.t

val stats : unit -> stats

val empty : int -> t

val size : t -> int

val capacity : t -> int

val pp : t Fmt.t

val cached : t -> int64 -> Udns_enum.rr_typ -> Domain_name.t ->
  (Udns_resolver_entry.res * t, [ `Cache_miss | `Cache_drop ]) result

val maybe_insert : Udns_enum.rr_typ -> Domain_name.t -> int64 -> Udns_resolver_entry.rank ->
  Udns_resolver_entry.res -> t -> t

val follow_cname : t -> int64 -> Udns_enum.rr_typ -> Domain_name.t -> Rr_map.b ->
  [ `NoError of Rr_map.t Domain_name.Map.t * t
  | `Cycle of Rr_map.t Domain_name.Map.t * t
  | `Query of Domain_name.t * t
  | `NoDom of (Rr_map.t Domain_name.Map.t * Rr_map.t Domain_name.Map.t) * t
  | `NoData of (Rr_map.t Domain_name.Map.t * Rr_map.t Domain_name.Map.t) * t
  | `ServFail of Rr_map.t Domain_name.Map.t * t
  ]

val answer : t -> int64 -> Packet.Question.t -> int ->
  [ `Query of Domain_name.t * t
  | `Packet of Packet.Header.t * Packet.t * t ]

val resolve_ns : t -> int64 -> Domain_name.t ->
  ([ `NeedA of Domain_name.t
   | `NeedCname of Domain_name.t
   | `HaveIPS of Rr_map.Ipv4_set.t
   | `NoDom
   | `No ] * t)

val find_ns : t -> (int -> Cstruct.t) -> int64 -> Domain_name.Set.t -> Domain_name.t ->
  [ `Loop | `NeedNS | `NoDom | `No | `Cname of Domain_name.t | `HaveIP of Ipaddr.V4.t | `NeedA of Domain_name.t | `NeedGlue of Domain_name.t ] * t

val resolve : t -> rng:(int -> Cstruct.t) ->  int64 -> Domain_name.t -> Udns_enum.rr_typ -> (Domain_name.t * Domain_name.t * Udns_enum.rr_typ * Ipaddr.V4.t * t, string) result

val handle_query : t -> rng:(int -> Cstruct.t) -> int64 -> Packet.Question.t -> int ->
  [ `Answer of Packet.Header.t * Packet.t
  | `Nothing
  | `Query of Domain_name.t * Domain_name.t * Udns_enum.rr_typ * Ipaddr.V4.t ] * t
