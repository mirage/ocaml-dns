(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

type t

type stats

val pp_stats : stats Fmt.t

val stats : unit -> stats

val empty : int -> t

val items : t -> int

val capacity : t -> int

val pp : t Fmt.t

val cached : t -> int64 -> Dns_enum.rr_typ -> Dns_name.t ->
  (Dns_resolver_entry.res * t, [ `Cache_miss | `Cache_drop ]) result

val maybe_insert : Dns_enum.rr_typ -> Dns_name.t -> int64 -> Dns_resolver_entry.rank ->
  Dns_resolver_entry.res -> t -> t

val follow_cname : t -> int64 -> Dns_enum.rr_typ -> Dns_name.t -> Dns_packet.rr list ->
  [ `NoError of Dns_packet.rr list * t
  | `Cycle of Dns_packet.rr list * t
  | `Query of Dns_name.t * t
  | `NoDom of (Dns_packet.rr list * Dns_packet.rr) * t
  | `NoData of (Dns_packet.rr list * Dns_packet.rr) * t
  | `ServFail of Dns_packet.rr * t
  ]

val answer : t -> int64 -> Dns_packet.question -> int ->
  [ `Query of Dns_name.t * t
  | `Packet of Dns_packet.header * Dns_packet.v * t ]

val resolve_ns : t -> int64 -> Dns_name.t ->
  ([ `NeedA of Dns_name.t
   | `NeedCname of Dns_name.t
   | `HaveIPS of Ipaddr.V4.t list
   | `NoDom
   | `No ] * t)

val find_ns : t -> (int -> Cstruct.t) -> int64 -> Dns_name.DomSet.t -> Dns_name.t ->
  [ `Loop | `NeedNS | `NoDom | `No | `Cname of Dns_name.t | `HaveIP of Ipaddr.V4.t | `NeedA of Dns_name.t | `NeedGlue of Dns_name.t ] * t

val resolve : t -> rng:(int -> Cstruct.t) ->  int64 -> Dns_name.t -> Dns_enum.rr_typ -> (Dns_name.t * Dns_enum.rr_typ * Ipaddr.V4.t * t, string) result

val handle_query : t -> rng:(int -> Cstruct.t) -> int64 -> Dns_packet.question -> int ->
  [ `Answer of Dns_packet.header * Dns_packet.v
  | `Nothing
  | `Query of Dns_name.t * Dns_enum.rr_typ * Ipaddr.V4.t ] * t
