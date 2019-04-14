(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
open Udns

type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer
  | AuthoritativeAuthority
  | ZoneGlue
  | NonAuthoritativeAnswer
  | Additional

type t

type stats

val pp_stats : stats Fmt.t

val stats : unit -> stats

val empty : int -> t

val size : t -> int

val capacity : t -> int

val pp : t Fmt.t

type res = [
  | `Alias of int32 * Domain_name.t
  | `Entry of Rr_map.b
  | `No_data of Domain_name.t * Soa.t
  | `No_domain of Domain_name.t * Soa.t
  | `Serv_fail of Domain_name.t * Soa.t
]

val pp_res : res Fmt.t

val cached : t -> int64 -> Udns_enum.rr_typ -> Domain_name.t ->
  ([ res | `Entries of Rr_map.t ] * t, [ `Cache_miss | `Cache_drop ]) result

val maybe_insert : Udns_enum.rr_typ -> Domain_name.t -> int64 -> rank -> res -> t -> t

val follow_cname : t -> int64 -> Udns_enum.rr_typ -> name:Domain_name.t -> int32 -> alias:Domain_name.t ->
  [ `Out of Udns_enum.rcode * Name_rr_map.t * Name_rr_map.t * t
  | `Query of Domain_name.t * t
  ]

val answer : t -> int64 -> Packet.Question.t -> int ->
  [ `Query of Domain_name.t * t | `Packet of Packet.Header.t * Packet.t * t ]

(*
val resolve_ns : t -> int64 -> Domain_name.t ->
  [ `NeedA of Domain_name.t | `NeedCname of Domain_name.t | `HaveIPS of Rr_map.Ipv4_set.t | `NoDom | `No ] * t
*)
(*val find_ns : t -> (int -> Cstruct.t) -> int64 -> Domain_name.Set.t -> Domain_name.t ->
  [ `Loop | `NeedNS | `NoDom | `No | `Cname of Domain_name.t | `HaveIP of Ipaddr.V4.t | `NeedA of Domain_name.t | `NeedGlue of Domain_name.t ] * t
*)
val resolve : t -> rng:(int -> Cstruct.t) ->  int64 -> Domain_name.t -> Udns_enum.rr_typ ->
  (Domain_name.t * Domain_name.t * Udns_enum.rr_typ * Ipaddr.V4.t * t, string) result

val handle_query : t -> rng:(int -> Cstruct.t) -> int64 -> Packet.Question.t -> int ->
  [ `Answer of Packet.Header.t * Packet.t
  | `Nothing
  | `Query of Domain_name.t * Domain_name.t * Udns_enum.rr_typ * Ipaddr.V4.t ] * t
