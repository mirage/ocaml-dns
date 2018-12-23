(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module MxSet : Set.S with type elt = int * Domain_name.t

module TxtSet : Set.S with type elt = string list

module Ipv4Set : Set.S with type elt = Ipaddr.V4.t

module Ipv6Set : Set.S with type elt = Ipaddr.V6.t

module SrvSet : Set.S with type elt = Dns_packet.srv

module DnskeySet : Set.S with type elt = Dns_packet.dnskey

module CaaSet : Set.S with type elt = Dns_packet.caa

module TlsaSet : Set.S with type elt = Dns_packet.tlsa

module SshfpSet : Set.S with type elt = Dns_packet.sshfp

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

include Gmap.S with type 'a key = 'a k

val k_to_rr_typ : 'a k -> Dns_enum.rr_typ
val to_rr_typ : b -> Dns_enum.rr_typ
val to_rr : Domain_name.t -> b -> Dns_packet.rr list
val names : b -> Domain_name.Set.t
val glue :
  ((int32 * Ipaddr.V4.t list) * (int32 * Ipaddr.V6.t list)) Domain_name.Map.t ->
  Dns_packet.rr list

val of_rdata : int32 -> Dns_packet.rdata -> b option

val lookup_rr : Dns_enum.rr_typ -> t -> b option
val remove_rr : Dns_enum.rr_typ -> t -> t

val add_rdata : b -> Dns_packet.rdata -> b option
val remove_rdata : b -> Dns_packet.rdata -> b option

val pp_b : b Fmt.t

val equal_b : b -> b -> bool

val of_rrs : Dns_packet.rr list -> t Domain_name.Map.t

val text : Domain_name.t -> b -> string
