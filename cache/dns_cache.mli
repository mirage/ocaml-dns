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

val empty : int -> t

val size : t -> int

val capacity : t -> int

val pp : t Fmt.t

type entry = [
  | `Entry of Rr_map.b
  | `No_data of [ `raw ] Domain_name.t * Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Soa.t
  | `Serv_fail of [ `raw ] Domain_name.t * Soa.t
]

val pp_entry : entry Fmt.t

val get : t -> int64 -> [ `raw ] Domain_name.t -> 'a Rr_map.key ->
  (entry, [ `Cache_miss | `Cache_drop ]) result
(** [get lru_cache timestamp request_type name] *)

val set : t -> int64 -> [ `raw ] Domain_name.t -> 'a Rr_map.key -> rank ->
  entry -> unit
(** [set lru_cache timestamp request_type name rank value] *)
