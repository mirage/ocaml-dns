(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
open Dns

type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer
  | AuthoritativeAuthority
  | ZoneGlue
  | NonAuthoritativeAnswer
  | Additional

val pp_rank : rank Fmt.t

val compare_rank : rank -> rank -> int

type t

type stats

val pp_stats : stats Fmt.t

val stats : unit -> stats

val empty : int -> t

val size : t -> int

val capacity : t -> int

val pp : t Fmt.t

val pp_question : ([ `raw ] Domain_name.t * Packet.Question.qtype) Fmt.t

type res = [
  | `Alias of int32 * [ `raw ] Domain_name.t
  | `Entry of Rr_map.b
  | `No_data of [ `raw ] Domain_name.t * Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Soa.t
  | `Serv_fail of [ `raw ] Domain_name.t * Soa.t
]

val pp_res : res Fmt.t

val cached : t -> int64 -> 'a Rr_map.key -> [ `raw ] Domain_name.t ->
  (res * t, [ `Cache_miss | `Cache_drop ]) result

val maybe_insert : 'a Rr_map.key -> [ `raw ] Domain_name.t -> int64 -> rank -> res -> t -> t

val follow_cname : t -> int64 -> 'a Rr_map.key -> name:[ `raw ] Domain_name.t -> int32 ->
  alias:[ `raw ] Domain_name.t ->
  [ `Out of Rcode.t * Name_rr_map.t * Name_rr_map.t * t
  | `Query of [ `raw ] Domain_name.t * t
  ]

val answer : t -> int64 -> [ `raw ] Domain_name.t -> Packet.Question.qtype ->
  [ `Query of [ `raw ] Domain_name.t * t | `Packet of Packet.Flags.t * Packet.reply * t ]

(*
val resolve_ns : t -> int64 -> Domain_name.t ->
  [ `NeedA of Domain_name.t | `NeedCname of Domain_name.t | `HaveIPS of Rr_map.Ipv4_set.t | `NoDom | `No ] * t
*)

(*val find_ns : t -> (int -> Cstruct.t) -> int64 -> Domain_name.Set.t -> Domain_name.t ->
  [ `Loop | `NeedNS | `NoDom | `No | `Cname of Domain_name.t | `HaveIP of Ipaddr.t | `NeedA of Domain_name.t | `NeedGlue of Domain_name.t ] * t
*)

val resolve : t -> rng:(int -> Cstruct.t) ->  int64 -> [ `raw ] Domain_name.t ->
  Rr_map.k -> [ `raw ] Domain_name.t * [ `raw ] Domain_name.t * Rr_map.k * Ipaddr.t * t

val handle_query : t -> rng:(int -> Cstruct.t) -> int64 -> [ `raw ] Domain_name.t ->
  Packet.Question.qtype ->
  [ `Reply of Packet.Flags.t * Packet.reply
  | `Nothing
  | `Query of [ `raw ] Domain_name.t * ([ `raw ] Domain_name.t * Packet.Question.qtype) * Ipaddr.t ] * t
