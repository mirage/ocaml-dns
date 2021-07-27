(* (c) 2018 Hannes Mehnert, all rights reserved *)

type t
(** The type of a DNS resolver. *)

val create : ?size:int -> int64 -> (int -> Cstruct.t) -> Dns_server.Primary.s -> t
(** [create ~size now rng primary] creates the value of a resolver,
   pre-filled with root NS and their IP addresses. *)

val handle_buf : t -> Ptime.t -> int64 -> bool -> Dns.proto -> Ipaddr.t ->
  int -> Cstruct.t ->
  t * (Dns.proto * Ipaddr.t * int * Cstruct.t) list
    * (Dns.proto * Ipaddr.t * Cstruct.t) list
(** [handle_buf t now ts query_or_reply proto sender source-port buf] handles
   resolution of [buf], which leads to a new [t], a list of answers to be
   transmitted (quadruple of protocol, ip address, port, buffer), and a list of
   queries (triple of protocol, ip address, buffer). *)

val query_root : t -> int64 -> Dns.proto ->
  t * (Dns.proto * Ipaddr.t * Cstruct.t)
(** [query_root t now proto] potentially requests an update of the root
   zone. Best invoked by a regular timer. *)

val timer : t -> int64 ->
  t * (Dns.proto * Ipaddr.t * int * Cstruct.t) list
    * (Dns.proto * Ipaddr.t * Cstruct.t) list
(** [timer t now] potentially retransmits DNS requests and/or sends NXDomain
    answers. *)
