(* (c) 2018 Hannes Mehnert, all rights reserved *)

type t

val create : int64 -> (int -> Cstruct.t) -> Dns_server.Primary.s -> unit -> t

val handle : t -> Ptime.t -> int64 -> Dns_packet.proto -> Ipaddr.V4.t -> int -> Cstruct.t ->
  t * (Dns_packet.proto * Ipaddr.V4.t * int * Cstruct.t) list
    * (Dns_packet.proto * Ipaddr.V4.t * Cstruct.t) list

val query_root : t -> int64 -> Dns_packet.proto ->
  t * (Dns_packet.proto * Ipaddr.V4.t * Cstruct.t)

val timer : t -> int64 ->
  t * (Dns_packet.proto * Ipaddr.V4.t * int * Cstruct.t) list
    * (Dns_packet.proto * Ipaddr.V4.t * Cstruct.t) list

val stats : t -> unit
