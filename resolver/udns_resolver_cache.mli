(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

type t

type stats

val pp_stats : stats Fmt.t

val stats : unit -> stats

val empty : int -> t

val items : t -> int

val capacity : t -> int

val pp : t Fmt.t

val cached : t -> int64 -> Udns_enum.rr_typ -> Domain_name.t ->
  (Udns_resolver_entry.res * t, [ `Cache_miss | `Cache_drop ]) result

val maybe_insert : Udns_enum.rr_typ -> Domain_name.t -> int64 -> Udns_resolver_entry.rank ->
  Udns_resolver_entry.res -> t -> t

val follow_cname : t -> int64 -> Udns_enum.rr_typ -> Domain_name.t -> Udns_packet.rr list ->
  [ `NoError of Udns_packet.rr list * t
  | `Cycle of Udns_packet.rr list * t
  | `Query of Domain_name.t * t
  | `NoDom of (Udns_packet.rr list * Udns_packet.rr) * t
  | `NoData of (Udns_packet.rr list * Udns_packet.rr) * t
  | `ServFail of Udns_packet.rr * t
  ]

val answer : t -> int64 -> Udns_packet.question -> int ->
  [ `Query of Domain_name.t * t
  | `Packet of Udns_packet.header * Udns_packet.v * t ]

val resolve_ns : t -> int64 -> Domain_name.t ->
  ([ `NeedA of Domain_name.t
   | `NeedCname of Domain_name.t
   | `HaveIPS of Ipaddr.V4.t list
   | `NoDom
   | `No ] * t)

val find_ns : t -> (int -> Cstruct.t) -> int64 -> Domain_name.Set.t -> Domain_name.t ->
  [ `Loop | `NeedNS | `NoDom | `No | `Cname of Domain_name.t | `HaveIP of Ipaddr.V4.t | `NeedA of Domain_name.t | `NeedGlue of Domain_name.t ] * t

val resolve : t -> rng:(int -> Cstruct.t) ->  int64 -> Domain_name.t -> Udns_enum.rr_typ -> (Domain_name.t * Domain_name.t * Udns_enum.rr_typ * Ipaddr.V4.t * t, string) result

val handle_query : t -> rng:(int -> Cstruct.t) -> int64 -> Udns_packet.question -> int ->
  [ `Answer of Udns_packet.header * Udns_packet.v
  | `Nothing
  | `Query of Domain_name.t * Domain_name.t * Udns_enum.rr_typ * Ipaddr.V4.t ] * t
