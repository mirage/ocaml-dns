(* (c) 2017 Hannes Mehnert, all rights reserved *)

type t
(** The type of a domain name, a sequence of labels separated by dots.  Each
    label may contain any bytes. The length of each label may not exceed 63
    charactes.  The total length of a domain name is limited to 253 (byte
    representation is 255), but other protocols (such as SMTP) may apply even
    smaller limits.  A domain name label is case preserving, comparison is done
    in a case insensitive manner.

    The invariants on the length of domain names are preserved throughout the
    module - no [t] will exist which violates these.

    The specification of domain names originates from
    {{:https://tools.ietf.org/html/rfc1035}RFC 1035}. *)

val is_hostname : t -> bool
(** [is_hostname t] is [true] if [t] is a hostname: the contents of the domain
    name is limited: each label may start with a digit or letter, followed by
    digits, letters, or hyphens. *)

val is_service : t -> bool
(** [is_service t] is [true] if [t] is a service label: the first label is a
    service name (containing of letters, digits, hyphens) prefixed with "_".
    The service name may not contain a hyphen following another hyphen, no hypen
    at the beginning or end, and must contain at least one letter.  The total
    length must be between 1 and at most 15 characters.  The second label is the
    protocol, prefixed by "_" (at the moment, tcp, udp, or sctp), and the
    remaining must be a host name. *)

val root : t
(** [root] is the root domain ("."), the empty label. *)

val prepend : ?hostname:bool -> t -> string -> (t, [> `Msg of string ]) result
(** [prepend ~hostname name pre] is either [t], the new domain name, or an error


    @raise Invalid_argument if [pre.name] is not a valid domain name. If
    [hostname] is provided and [true] (the default), the contents is
    additionally checked for being a valid host name using {!is_hostname}. *)

val prepend_exn : ?hostname:bool -> t -> string -> t
(** [prepend_exn ~hostname name pre] is [t], the new domain name.

    @raise Invalid_argument if [pre.name] is not a valid domain name. If
    [hostname] is provided and [true] (the default), the contents is
    additionally checked for being a valid host name using {!is_hostname}. *)

val of_string : ?hostname:bool -> string -> (t, [> `Msg of string ]) result
(** [of_string ~hostname name] is either [t], the domain name, or an error if
    the provided [name] is not a valid domain name.  If [hostname] is provided
    and [true] (the default), the contents is additionally checked for being a
    valid hostname using {!is_hostname}. *)

val of_string_exn : ?hostname:bool -> string -> t
(** [of_string_exn ~hostname name] is [t], the domain name.  If [hostname] is
    provided and [true] (the default), the contents is additionally checked for
    being a valid hostname using {!is_hostname}.

    @raise Invalid_argument if [name] is not a valid domain name. *)

val to_string : t -> string
(** [to_string t] is [String.concat ~sep:"." (to_strings t)], a human-readable
    representation of [t]. *)

val of_strings : ?hostname:bool -> string list -> (t, [> `Msg of string ]) result
(** [of_strings ~hostname labels] is either [t], a domain name, or an error if
    the provided [labels] violate domain name constraints.  If [hostname] is
    provided and [true] (the default), the labels are additionally checked for
    being a valid hostname using {!is_hostname}. *)

val of_strings_exn : ?hostname:bool -> string list -> t
(** [of_strings_exn ~hostname labels] is [t], a domain name.

    @raise Invalid_argument if [labels] are not a valid domain name. If
    [hostname] is provided and [true] (the default), the labels are
    additionally checked for being a valid hostname using
    {!is_hostname}. *)

val to_strings : t -> string list
(** [to_strings t] is the list of labels of [t]. *)

val of_array : string array -> t
(** [of_array a] is [t], a domain name from [a], an array containing a reversed
    domain name. *)

val to_array : t -> string array
(** [to_array t] is [a], an array containing the reversed domain name of [t]. *)

val canonical : t -> t
(** [canonical t] is [t'], the canonical domain name, as specified in RFC 4034
    (and 2535): all characters are lowercase. *)

val pp : t Fmt.t
(** [pp ppf t] pretty prints the domain name [t] on [ppf]. *)

val compare : t -> t -> int
(** [compare t t'] compares the domain names [t] and [t'] using a case
    insensitive string comparison. *)

val equal : t -> t -> bool
(** [equal t t'] is [compare t t' = 0]. *)

val compare_sub : string -> string -> int
(** [compare_sub t t'] compares the labels [t] and [t'] using a case
    insensitive string comparison. *)

val sub : subdomain:t -> domain:t -> bool
(** [sub ~subdomain ~domain] is [true] if [subdomain] contains any labels
    prepended to [domain]: [foo.bar.com] is a subdomain of [bar.com] and of
    [com], [sub ~subdomain:x ~domain:root] is true for all [x]. *)

module IntMap : Map.S with type key = int
(** The module of an integer map *)

type err =
  [ `Partial
  | `BadOffset of int
  | `BadTag of int
  | `BadContent of string
  | `TooLong ]
(** Errors while decoding a domain name. *)

val pp_err : err Fmt.t
(** [pp ppf error] pretty prints the [error] on [ppf]. *)

val decode : ?hostname:bool -> (t * int) IntMap.t -> Cstruct.t -> int ->
  (t * (t * int) IntMap.t * int, [> err ]) result
(** [decode ~hostname map buf off] decodes a domain name from [buf] at
    position [off].  If [hostname] is provided and [true] (the default), the
    domain name is additionally checked for being a hostname using
    {!is_hostname}.

    RFC 1035 specifies label compression: a domain name may either end with the
    root label or a pointer (byte offset from the beginning of the frame) to a
    domain name.  To support decompression, a [map] between offsets and domain
    names and length is passed around, and the absolute [offset] in the frame.
    The return value is either a decoded and decompressed domain name, an
    extended map, and the consumed bytes (as offset into the buffer), or an
    error.  *)

module DomMap : Map.S with type key = t
(** The module of a domain name map *)

val encode : ?compress:bool -> int DomMap.t -> Cstruct.t -> int -> t ->
  int DomMap.t * int
(** [encode ~compress map buf off t] encodes [t] into [buf], extending the
    [map].  If [compress] is [true] (the default), and a (sub)domain name of [t]
    is in [map], a pointer is inserted instead of the full domain name.

    NB: DNS (especially RFC 3597) mentions that pointers should only point to
    domain names in resource data which are well known (which means specified in
    RFC 1035).  To achieve this, the caller of [encode] if inside of other
    resource data fields needs to discard the returned [map], and continue to
    use the provided [map].  There should be no reason to use [~compress:false]
    (esp. these resource data fields which are _not_ well known may still
    contain pointers to well known ones.

    @raise Invalid_argument if the provided [buf] is too small.  *)

module DomSet : Set.S with type elt = t
(** The module of a domain name set *)
