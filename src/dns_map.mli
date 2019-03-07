(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(** A map whose key are DNS resource record types and their values are the time
   to live and the resource record. This module uses a GADT to express the
   binding between record type and resource record. *)

module MxSet : Set.S with type elt = int * Domain_name.t
(** A set of MX records. *)

module TxtSet : Set.S with type elt = string list
(** A set of TXT records. *)

module Ipv4Set : Set.S with type elt = Ipaddr.V4.t
(** A set of IPv4 addresses. *)

module Ipv6Set : Set.S with type elt = Ipaddr.V6.t
(** A set of IPv6 addresses. *)

module SrvSet : Set.S with type elt = Dns_packet.srv
(** A set of SRV records. *)

module DnskeySet : Set.S with type elt = Dns_packet.dnskey
(** A set of DNS KEY records. *)

module CaaSet : Set.S with type elt = Dns_packet.caa
(** A set of CAA records. *)

module TlsaSet : Set.S with type elt = Dns_packet.tlsa
(** A set of TLSA records. *)

module SshfpSet : Set.S with type elt = Dns_packet.sshfp
(** A set of SSH FP records. *)

type _ k =
  | Any : (Dns_packet.rr list * Domain_name.Set.t) k
  | Cname : (int32 * Domain_name.t) k
  | Mx : (int32 * MxSet.t) k
  | Ns : (int32 * Domain_name.Set.t) k
  | Ptr : (int32 * Domain_name.t) k
  | Soa : (int32 * Dns_packet.soa) k
  | Txt : (int32 * TxtSet.t) k
  | A : (int32 * Ipv4Set.t) k
  | Aaaa : (int32 * Ipv6Set.t) k
  | Srv : (int32 * SrvSet.t) k
  | Dnskey : DnskeySet.t k
  | Caa : (int32 * CaaSet.t) k
  | Tlsa : (int32 * TlsaSet.t) k
  | Sshfp : (int32 * SshfpSet.t) k
  (** The type of map keys. *)

include Gmap.S with type 'a key = 'a k

(** {2 Conversion functions} *)

val k_to_rr_typ : 'a k -> Dns_enum.rr_typ
(** [k_to_rr_typ k] is the resource record typ of [k]. *)

val to_rr_typ : b -> Dns_enum.rr_typ
(** [to_rr_typ binding] is the resource record typ of the binding [k]. *)

val to_rr : Domain_name.t -> b -> Dns_packet.rr list
(** [to_rr name binding] results in a resource record list. *)

val names : b -> Domain_name.Set.t
(** [names binding] are the referenced domain names in the given binding. *)

val glue :
  ((int32 * Ipaddr.V4.t list) * (int32 * Ipaddr.V6.t list)) Domain_name.Map.t ->
  Dns_packet.rr list
(** [glue map] results in a resource record list to be appended in the
   additional section in a DNS frame as answer. *)

val of_rdata : int32 -> Dns_packet.rdata -> b option
(** [of_rdata ttl rdata] is a binding using data from rdata. *)

val lookup_rr : Dns_enum.rr_typ -> t -> b option
(** [lookup_rr typ t] looks up the [typ] in [t]. *)

val remove_rr : Dns_enum.rr_typ -> t -> t
(** [remove_rr typ t] removes the [typ] in [t]. *)

val add_rdata : b -> Dns_packet.rdata -> b option
(** [add_rdata binding rdata] adds rdata to the binding. *)

val remove_rdata : b -> Dns_packet.rdata -> b option
(** [remove_rdata binding rdata] removes rdata from the binding. *)

val pp_b : b Fmt.t
(** [pp_b ppf b] pretty-prints the binding [b]. *)

val equal_b : b -> b -> bool
(** [equal_b b b'] is [true] if the bindings are equal. *)

val of_rrs : Dns_packet.rr list -> t Domain_name.Map.t
(** [of_rrs rrs] is a domain-name indexed map of resource record maps. *)

val text : Domain_name.t -> b -> string
(** [text domain-name binding] is the zone file format of [binding] using
   [domain-name]. *)
