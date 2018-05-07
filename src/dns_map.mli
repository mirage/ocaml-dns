(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* this code wouldn't exist without Justus Matthiesen, thanks for the help! *)

module Order : sig
  type (_,_) t =
    | Lt : ('a, 'b) t
    | Eq : ('a, 'a) t
    | Gt : ('a, 'b) t
end

module type KEY = sig
  type _ t
  val compare : 'a t -> 'b t -> ('a, 'b) Order.t
  val pp : Format.formatter -> 'a t -> 'a -> unit
end

module type S = sig
  type 'a key
  type t
  type v = V : 'a key * 'a -> v

  val empty : t
  val is_empty : t -> bool
  val mem : 'a key -> t -> bool
  val addv : v -> t -> t
  val add : 'a key -> 'a -> t -> t
  val singleton : 'a key -> 'a -> t
  val remove : 'a key -> t -> t
  val getv : 'a key -> t -> v
  val get : 'a key -> t -> 'a
  val findv : 'a key -> t -> v option
  val find : 'a key -> t -> 'a option
  val min_binding : t -> v
  val max_binding : t -> v
  val bindings : t -> v list
  val cardinal : t -> int
  val choose :  t -> v
  val iter : (v -> unit) -> t -> unit
  val fold : (v -> 'a -> 'a) -> t -> 'a -> 'a
  val for_all : (v -> bool) -> t -> bool
  val exists : (v -> bool) -> t -> bool
  val filter : (v -> bool) -> t -> t
  val pp : Format.formatter -> t -> unit
  val equal : (v -> v -> bool) -> t -> t -> bool
end


module Make : functor (Key : KEY) -> S with type 'a key = 'a Key.t

module K : sig
  type _ t =
    | Any : (Dns_packet.rr list * Dns_name.DomSet.t) t
    | Cname : (int32 * Dns_name.t) t
    | Mx : (int32 * (int * Dns_name.t) list) t
    | Ns : (int32 * Dns_name.DomSet.t) t
    | Ptr : (int32 * Dns_name.t) t
    | Soa : (int32 * Dns_packet.soa) t
    | Txt : (int32 * string list list) t
    | A : (int32 * Ipaddr.V4.t list) t
    | Aaaa : (int32 * Ipaddr.V6.t list) t
    | Srv : (int32 * Dns_packet.srv list) t
    | Dnskey : Dns_packet.dnskey list t
    | Caa : (int32 * Dns_packet.caa list) t
    | Tlsa : (int32 * Dns_packet.tlsa list) t
    | Sshfp : (int32 * Dns_packet.sshfp list) t
  val compare : 'a t -> 'b t -> ('a, 'b) Order.t
  val pp : Format.formatter -> 'a t -> 'a -> unit
end

type t
type 'a key = 'a K.t

type v = V : 'a key * 'a -> v

val empty : t
val is_empty : t -> bool
val equal : (v -> v -> bool) -> t -> t -> bool
val mem : 'a key -> t -> bool
val addv : v -> t -> t
val add : 'a key -> 'a -> t -> t
val singleton : 'a key -> 'a -> t
val remove : 'a key -> t -> t
val getv : 'a key -> t -> v
val get : 'a key -> t -> 'a
val findv : 'a key -> t -> v option
val find : 'a key -> t -> 'a option
val min_binding : t -> v
val max_binding : t -> v
val bindings : t -> v list
val cardinal : t -> int
val choose :  t -> v
val iter : (v -> unit) -> t -> unit
val fold : (v -> 'a -> 'a) -> t -> 'a -> 'a
val for_all : (v -> bool) -> t -> bool
val exists : (v -> bool) -> t -> bool
val filter : (v -> bool) -> t -> t
val pp : Format.formatter -> t -> unit


val k_to_rr_typ : 'a key -> Dns_enum.rr_typ
val to_rr_typ : v -> Dns_enum.rr_typ
val to_rr : Dns_name.t -> v -> Dns_packet.rr list
val names : v -> Dns_name.DomSet.t
val glue : ((int32 * Ipaddr.V4.t list) * (int32 * Ipaddr.V6.t list)) Dns_name.DomMap.t -> Dns_packet.rr list

val of_rdata : int32 -> Dns_packet.rdata -> v option

val lookup_rr : Dns_enum.rr_typ -> t -> v option
val remove_rr : Dns_enum.rr_typ -> t -> t

val add_rdata : v -> Dns_packet.rdata -> v option
val remove_rdata : v -> Dns_packet.rdata -> v option

val pp_v : v Fmt.t

val equal_v : v -> v -> bool

val of_rrs : Dns_packet.rr list -> t Dns_name.DomMap.t
