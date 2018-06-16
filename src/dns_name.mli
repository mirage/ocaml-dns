(* (c) 2017 Hannes Mehnert, all rights reserved *)

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

val decode : ?hostname:bool -> (Domain_name.t * int) IntMap.t -> Cstruct.t ->
  int -> (Domain_name.t * (Domain_name.t * int) IntMap.t * int, [> err ]) result
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

val encode : ?compress:bool -> int Domain_name.Map.t -> Cstruct.t -> int ->
  Domain_name.t -> int Domain_name.Map.t * int
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
