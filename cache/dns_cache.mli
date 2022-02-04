(** DNS cache - a least recently used cache of DNS responses

    This data structure allows to insert and retrieve entries into a least
    recently used data structure. An [`Entry] weights the cardinality of the
    resource record map, all other entries have a weight of 1.

    The time to live is preserved, and when it is exceeded the entry is no
    longer returned.
*)

(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
open Dns

(** The variant of the rank in the cache. *)
type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer of bool
  | AuthoritativeAuthority of bool
  | ZoneGlue
  | NonAuthoritativeAnswer
  | Additional

val pp_rank : rank Fmt.t
(** [pp_rank ppf rank] pretty-prints the [rank] on [ppf]. *)

val compare_rank : rank -> rank -> int
(** [compare_rank a b] compares the ranks [a] with [b]. *)

(** The type of a DNS cache. *)
type t

val empty : int -> t
(** [empty maximum_size] is an empty DNS cache with the maximum size as
    capacity. *)

val size : t -> int
(** [size cache] is the number of bindings currently in the [cache]. *)

val capacity : t -> int
(** [capacity cache] is the used weight. *)

val pp : t Fmt.t
(** [pp ppf t] pretty prints the cache [t] on [ppf]. *)

(** The polymorphic variant of an entry: a resource record, or no data,
    no domain, or a server failure. *)
type 'a entry = [
  | `Entry of 'a
  | `No_data of [ `raw ] Domain_name.t * Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Soa.t
  | `Serv_fail of [ `raw ] Domain_name.t * Soa.t
]

val pp_entry : 'a Rr_map.key -> 'a entry Fmt.t
(** [pp_entry ppf entry] pretty-prints [entry] on [ppf]. *)

val get : t -> int64 -> [ `raw ] Domain_name.t -> 'a Rr_map.key ->
  t * ('a entry * rank, [ `Cache_miss | `Cache_drop ]) result
(** [get cache timestamp type name] retrieves the query [type, name] from the
    [cache] using [timestamp]. If the time to live is exceeded, a [`Cache_drop]
    is returned. If there is no entry in the cache, a [`Cache_miss] is
    returned. *)

val get_or_cname : t -> int64 -> [ `raw ] Domain_name.t -> 'a Rr_map.key ->
  t * ([ 'a entry | `Alias of int32 * [`raw] Domain_name.t] * rank,
       [ `Cache_miss | `Cache_drop ]) result
(** [get_or_cname cache timestamp type name] is the same as [get], but if a
    [`Cache_miss] is encountered, a lookup for an alias (CNAME) is done. *)

val get_any : t -> int64 -> [ `raw ] Domain_name.t ->
  t * ([ `Entries of Rr_map.t
       | `No_domain of [ `raw ] Domain_name.t * Soa.t ] * rank,
       [ `Cache_miss | `Cache_drop ]) result
(** [get_any cache timestamp name] retrieves all resource records for [name]
    in [cache]. *)

val get_nsec3 : t -> int64 -> [ `raw ] Domain_name.t ->
  t * (([`raw] Domain_name.t * Nsec3.t) list, [ `Cache_miss | `Cache_drop ]) result
(** [get_nsec3 cache timestamp name] retrieves all nsec3 resource records for
    the zone [name]. *)

val set : t -> int64 -> [ `raw ] Domain_name.t -> 'a Rr_map.key -> rank ->
  'a entry -> t
(** [set cache timestamp type name rank value] attempts to insert
    [type, name, value] into the [cache] using the [timestamp] and [rank]. If
    an entry already exists with a higher [rank], the [cache] is unchanged. *)
