(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
(** Prefix tree data structure for domain names

    The key is a {!Dns_name}, whereas the value may be any resource record.  The
    representation is a tree, where the edges are domain name labels, and the
    nodes carry a {{!Udns_map.t}resource map}.
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

open Udns

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
    [t]. *)

val insert : Domain_name.t -> 'a Rr_map.key -> 'a -> t -> t
(** [insert n k v t] insert [k, v] under [n] in [t].  Existing entries are
    replaced. *)

val remove : Domain_name.t -> 'a Rr_map.key -> t -> t
(** [remove k ty t] removes [k, ty] from [t].  If [ty] is {!Udns_enum.ANY}, all
    entries of [k] are removed.  Beware, this may lead to a [t] where the
    initially mentioned invariants are violated. *)

val remove_all : Domain_name.t -> t -> t
(** [remove_all k t] removes all entries of [k] in [t]. Beware, this may lead to
   a [t] where the initially mentioned invariants are violated. *)

val remove_zone : Domain_name.t -> t -> t
(** [remove_zone name t] remove the zone [name] from [t], retaining subzones
    (entries with [Soa] records).  This removes as well any delegations. *)


(** {2 Checking invariants} *)

type zone_check = [ `Missing_soa of Domain_name.t
                  | `Cname_other of Domain_name.t
                  | `Bad_ttl of Domain_name.t * Rr_map.b
                  | `Empty of Domain_name.t * Rr_map.k
                  | `Missing_address of Domain_name.t
                  | `Soa_not_ns of Domain_name.t ]

val pp_zone_check : zone_check Fmt.t
(** [pp_err ppf err] pretty prints the error [err]. *)

val check : t -> (unit, zone_check) result
(** [check t] checks all invariants. *)


(** {2 Lookup} *)

type e = [ `Delegation of Domain_name.t * (int32 * Domain_name.Set.t)
         | `EmptyNonTerminal of Domain_name.t * Soa.t
         | `NotAuthoritative
         | `NotFound of Domain_name.t * Soa.t ]
(** The type of lookup errors. *)

val pp_e : e Fmt.t
(** [pp_e ppf e] pretty-prints [e] on [ppf]. *)

val zone : Domain_name.t -> t -> (Domain_name.t * Soa.t, e) result
(** [zone k t] returns either the zone and soa for [k] in [t], or an error. *)

val lookup_with_cname : Domain_name.t -> 'a Rr_map.key -> t ->
  (Rr_map.b * (Domain_name.t * int32 * Domain_name.Set.t), e) result
(** [lookup_with_cname k ty t] finds [k, ty] in [t]. It either returns the found
    resource record set and authority information, a cname alias and authority
    information, or an error. *)

val lookup : Domain_name.t -> 'a Rr_map.key -> t -> ('a, e) result
(** [lookup k ty t] finds [k, ty] in [t], which may lead to an error. *)

val lookup_any : Domain_name.t -> t ->
  (Rr_map.t * (Domain_name.t * int32 * Domain_name.Set.t), e) result
(** [lookup_any k t] looks up all resource records of [k] in [t], and returns
    that and the authority information. *)

val lookup_glue : Domain_name.t -> t ->
  (int32 * Rr_map.Ipv4_set.t) option * (int32 * Rr_map.Ipv6_set.t) option
(** [lookup_glue k t] finds glue records (A, AAAA) for [k] in [t]. It ignores
    potential DNS invariants, e.g. that there is no surrounding zone. *)

val entries : Domain_name.t -> t ->
  (Udns.Soa.t * Rr_map.t Domain_name.Map.t, e) result
(** [entries name t] returns either the SOA and all entries for the requested
    [name], or an error. *)

val fold : 'a Rr_map.key -> t -> (Domain_name.t -> 'a -> 'b -> 'b) -> 'b -> 'b
(** [fold key t f acc] calls [f] with [dname value acc] element in [t]. *)
