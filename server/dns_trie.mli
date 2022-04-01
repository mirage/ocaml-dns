(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
(** Prefix tree data structure for domain names

    The key is a {!Dns_name}, whereas the value may be any resource record.  The
    representation is a tree, where the edges are domain name labels, and the
    nodes carry a {{!Dns_map.t}resource map}.
    Some special treatment is applied for zones, which must have a start of
    authority entry and a set of name servers.  End of authority, also known as
    delegation, is supported.  Aliases (canonical names, CNAME records) are also
    supported.

    The data structure tries to preserve invariants recommended by the domain
    name system, such as that for any name there may either be an alias or any
    other record, there must be a SOA record, and multiple NS records for an
    authoritative zone, a resource type must have entries of the given type (no
    NS record for A type, the ttl for all resource records of a rrset is the
    same.
*)

open Dns

(** {2 Abstract trie type} *)

type t
(** The type of the trie. *)

val pp : t Fmt.t
(** [pp ppf t] pretty prints [t] to [ppf]. *)

val empty : t
(** [empty] is the empty trie. *)

val equal : t -> t -> bool
(** [equal a b] compares [a] with [b]. *)

(** {2 Operations to modify the trie} *)

val insert_map : Rr_map.t Domain_name.Map.t -> t -> t
(** [insert_map m t] inserts all elements of the domain name map [m] into
    [t], potentially existing are unioned with {!Rr_map.unionee}. *)

val replace_map : Rr_map.t Domain_name.Map.t -> t -> t
(** [replace_map m t] replaces in the trie [t] all existing bindings of the
    domain name map [m] with the provided map. *)

val remove_map : Rr_map.t Domain_name.Map.t -> t -> t
(** [remove_map m t] removes all elements of the domain name map [m] from
    [t]. *)

val insert : 'a Domain_name.t -> 'b Rr_map.key -> 'b -> t -> t
(** [insert n k v t] inserts [k, v] under [n] in [t].  Existing entries are
    unioneed with {!Rr_map.union_rr}. *)

val replace : 'a Domain_name.t -> 'b Rr_map.key -> 'b -> t -> t
(** [replace n k v t] inserts [k, v] under [n] in [t].  Existing entries are
    replaced. *)

val remove : 'a Domain_name.t -> 'b Rr_map.key -> 'b -> t -> t
(** [remove k ty v t] removes [ty, v] from [t] at [k].  Beware, this may lead
    to a [t] where the initially mentioned invariants are violated. *)

val remove_ty : 'a Domain_name.t -> 'b Rr_map.key -> t -> t
(** [remove_ty k ty t] removes [ty] from [t] at [k]. Beware, this may lead to a
    [t] where the initially mentioned invariants are violated. *)

val remove_all : 'a Domain_name.t -> t -> t
(** [remove_all k t] removes all entries of [k] in [t]. Beware, this may lead to
   a [t] where the initially mentioned invariants are violated. *)

val remove_zone : 'a Domain_name.t -> t -> t
(** [remove_zone name t] remove the zone [name] from [t], retaining subzones
    (entries with [Soa] records).  This removes as well any delegations. *)


(** {2 Checking invariants} *)

type zone_check = [ `Missing_soa of [ `raw ] Domain_name.t
                  | `Cname_other of [ `raw ] Domain_name.t
                  | `Bad_ttl of [ `raw ] Domain_name.t * Rr_map.b
                  | `Empty of [ `raw ] Domain_name.t * Rr_map.k
                  | `Missing_address of [ `host ] Domain_name.t
                  | `Soa_not_a_host of [ `raw ] Domain_name.t * string ]

val pp_zone_check : zone_check Fmt.t
(** [pp_err ppf err] pretty prints the error [err]. *)

val check : t -> (unit, zone_check) result
(** [check t] checks all invariants. *)


(** {2 Lookup} *)

type e = [ `Delegation of [ `raw ] Domain_name.t * (int32 * Domain_name.Host_set.t)
         | `EmptyNonTerminal of [ `raw ] Domain_name.t * Soa.t
         | `NotAuthoritative
         | `NotFound of [ `raw ] Domain_name.t * Soa.t ]
(** The type of lookup errors. *)

val pp_e : e Fmt.t
(** [pp_e ppf e] pretty-prints [e] on [ppf]. *)

val zone : 'a Domain_name.t -> t ->
  ([ `raw ] Domain_name.t * Soa.t, e) result
(** [zone k t] returns either the zone and soa for [k] in [t], or an error. *)

val lookup_with_cname : 'a Domain_name.t -> 'b Rr_map.key -> t ->
  (Rr_map.b * ([ `raw ] Domain_name.t * int32 * Domain_name.Host_set.t), e) result
(** [lookup_with_cname k ty t] finds [k, ty] in [t]. It either returns the found
    resource record set and authority information, a cname alias and authority
    information, or an error. *)

val lookup : 'a Domain_name.t -> 'b Rr_map.key -> t -> ('b, e) result
(** [lookup k ty t] finds [k, ty] in [t], which may lead to an error. *)

val lookup_any : 'a Domain_name.t -> t ->
  (Rr_map.t * ([ `raw ] Domain_name.t * int32 * Domain_name.Host_set.t), e) result
(** [lookup_any k t] looks up all resource records of [k] in [t], and returns
    that and the authority information. *)

val lookup_glue : 'a Domain_name.t -> t ->
  (int32 * Ipaddr.V4.Set.t) option * (int32 * Ipaddr.V6.Set.t) option
(** [lookup_glue k t] finds glue records (A, AAAA) for [k] in [t]. It ignores
    potential DNS invariants, e.g. that there is no surrounding zone. *)

val entries : 'a Domain_name.t -> t ->
  (Dns.Soa.t * Rr_map.t Domain_name.Map.t, e) result
(** [entries name t] returns either the SOA and all entries for the requested
    [name], or an error. *)

val fold : 'a Rr_map.key -> t -> ([ `raw ] Domain_name.t -> 'a -> 'b -> 'b) -> 'b -> 'b
(** [fold key t f acc] calls [f] with [dname value acc] element in [t]. *)

val diff : 'a Domain_name.t -> Soa.t -> old:t -> t ->
  (Soa.t * [ `Empty | `Full of Name_rr_map.t | `Difference of Soa.t * Name_rr_map.t * Name_rr_map.t ],
   [> `Msg of string ]) result
(** [diff zone soa ~old trie] computes the difference of [zone] in [old] and
   [trie], and returns either [`Empty] if [soa] is equal or newer than the one
   in [trie], [`Full] (the same as [entries]) if [zone] is not present in [old],
   or [`Difference (old_soa, deleted, added)]. Best used with IXFR. An error
   occurs if [zone] is not present in [trie]. *)
