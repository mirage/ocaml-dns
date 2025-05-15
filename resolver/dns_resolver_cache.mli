(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
open Dns

val pp_question : ([ `raw ] Domain_name.t * Packet.Question.qtype) Fmt.t

val follow_cname : Dns_cache.t -> int64 -> 'a Rr_map.key -> name:[ `raw ] Domain_name.t -> int32 ->
  alias:[ `raw ] Domain_name.t ->
  [ `Out of Rcode.t * bool * Name_rr_map.t * Name_rr_map.t
  | `Query of [ `raw ] Domain_name.t ] * Dns_cache.t

val answer : dnssec:bool -> Dns_cache.t -> int64 -> [ `raw ] Domain_name.t -> Packet.Question.qtype ->
  [ `Query of [ `raw ] Domain_name.t
  | `Packet of Packet.Flags.t * Packet.reply ] * Dns_cache.t

val resolve : Dns_cache.t -> dnssec:bool -> rng:(int -> string) -> [`Both | `Ipv4_only | `Ipv6_only] -> int64 -> [ `raw ] Domain_name.t ->
  Packet.Question.qtype ->
  [ `raw ] Domain_name.t * [ `raw ] Domain_name.t * Packet.Question.qtype list * Ipaddr.t * Dns_cache.t

val handle_query : Dns_cache.t -> dnssec:bool -> rng:(int -> string) ->
  [`Both | `Ipv4_only | `Ipv6_only ] ->
  int64 ->
  [ `raw ] Domain_name.t * Packet.Question.qtype ->
  [ `Reply of Packet.Flags.t * Packet.reply
  | `Query of [ `raw ] Domain_name.t * ([ `raw ] Domain_name.t * Packet.Question.qtype list) * Ipaddr.t ] * Dns_cache.t
