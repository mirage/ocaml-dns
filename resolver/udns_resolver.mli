(* (c) 2018 Hannes Mehnert, all rights reserved *)

type t
(** The type of a DNS resolver. *)

val create : ?size:int -> ?mode:[ `Recursive | `Stub ] -> int64 -> (int -> Cstruct.t) -> Udns_server.Primary.s -> t
(** [create ~size ~mode now rng primary] creates the value of a resolver,
   pre-filled with root NS and their IP addresses. *)

val handle : t -> Ptime.t -> int64 -> bool -> Udns.proto -> Ipaddr.V4.t -> int -> Cstruct.t ->
  t * (Udns.proto * Ipaddr.V4.t * int * Cstruct.t) list
    * (Udns.proto * Ipaddr.V4.t * Cstruct.t) list
(** [handle t now ts query_or_reply proto sender source-port buf] handles
   resolution of [buf], which my involve further outgoing and reply packets. *)

val query_root : t -> int64 -> Udns.proto ->
  t * (Udns.proto * Ipaddr.V4.t * Cstruct.t)
(** [query_root t now proto] potentially requests an update of the root
   zone. Best invoked by a regular timer. *)

val timer : t -> int64 ->
  t * (Udns.proto * Ipaddr.V4.t * int * Cstruct.t) list
    * (Udns.proto * Ipaddr.V4.t * Cstruct.t) list
(** [timer t now] potentially retransmits DNS requests and/or sends NXDomain
    answers. *)

val stats : t -> unit
(** [stats t] logs some statistics of the cache. *)
