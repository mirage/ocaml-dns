(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
open Dns

val pp_question : ([ `raw ] Domain_name.t * Packet.Question.qtype) Fmt.t

val follow_cname : Dns_cache.t -> int64 -> 'a Rr_map.key -> name:[ `raw ] Domain_name.t -> int32 ->
  alias:[ `raw ] Domain_name.t ->
  [ `Out of Rcode.t * Name_rr_map.t * Name_rr_map.t
  | `Query of [ `raw ] Domain_name.t ] * Dns_cache.t

val answer : Dns_cache.t -> int64 -> [ `raw ] Domain_name.t -> Packet.Question.qtype ->
  [ `Query of [ `raw ] Domain_name.t
  | `Packet of Packet.Flags.t * Packet.reply ] * Dns_cache.t

(*
val resolve_ns : Dns_cache.t -> int64 -> Domain_name.t ->
  [ `NeedA of Domain_name.t | `NeedCname of Domain_name.t | `HaveIPS of Rr_map.Ipv4_set.t | `NoDom | `No ] * Dns_cache.t
*)

(*val find_ns : Dns_cache.t -> (int -> Cstruct.t) -> int64 -> Domain_name.Set.t -> Domain_name.t ->
  [ `Loop | `NeedNS | `NoDom | `No | `Cname of Domain_name.t | `HaveIP of Ipaddr.t | `NeedA of Domain_name.t | `NeedGlue of Domain_name.t ] * Dns_cache.t
*)

val resolve : Dns_cache.t -> rng:(int -> Cstruct.t) ->  int64 -> [ `raw ] Domain_name.t ->
  Rr_map.k -> [ `raw ] Domain_name.t * [ `raw ] Domain_name.t * Rr_map.k * Ipaddr.t * Dns_cache.t

val handle_query : Dns_cache.t -> rng:(int -> Cstruct.t) -> int64 ->
  [ `raw ] Domain_name.t * Packet.Question.qtype ->
  [ `Reply of Packet.Flags.t * Packet.reply
  | `Nothing
  | `Query of [ `raw ] Domain_name.t * ([ `raw ] Domain_name.t * Packet.Question.qtype) * Ipaddr.t ] * Dns_cache.t
