(* (c) 2017 Hannes Mehnert, all rights reserved *)

type t

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

val resolve_ns : t -> int64 -> Dns_name.t ->
  ([ `NeedA of Dns_name.t
   | `HaveIP of Ipaddr.V4.t list ] * t, unit) result

val find_ns : t -> ?overlay:(Dns_name.t -> Ipaddr.V4.t option) -> int64 -> Dns_name.t -> [ `NeedNS | `No | `Cname of Dns_name.t | `HaveIP of Ipaddr.V4.t list | `NeedA of Dns_name.t ] * t

val root_servers : Ipaddr.V4.t list

val resolve : t -> ?overlay:(Dns_name.t -> Ipaddr.V4.t option) -> int64 -> Dns_name.t -> Dns_enum.rr_typ -> (Dns_name.t * Dns_enum.rr_typ * Ipaddr.V4.t list * t, string) result

val handle_query : t -> ?overlay:(Dns_name.t -> Ipaddr.V4.t option) -> Ipaddr.V4.t -> int -> int64 -> Dns_packet.question -> int ->
  [ `Answer of Cstruct.t * (Ipaddr.V4.t * int)
  | `Nothing
  | `Query of Dns_name.t * Dns_enum.rr_typ * Ipaddr.V4.t ] * t
