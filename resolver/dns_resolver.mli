(* (c) 2018 Hannes Mehnert, all rights reserved *)

type t
(** The type of a DNS resolver. *)

val create : ?cache_size:int ->
  ?ip_protocol:[ `Both | `Ipv4_only | `Ipv6_only ] ->
  ?dnssec:bool ->
  int64 -> (int -> string) -> Dns_server.Primary.s -> t
(** [create ~cache_size ~ip_protocol ~dnssec now rng primary] creates the value
    of a resolver, pre-filled with root NS and their IP addresses. If
    [ip_protocol] is provided, and set to [`V4_only], only IPv4 packets will be
    emitted. If [`V6_only] is set, only IPv6 packets will be emitted. If [`Both]
    (the default), either IPv4 and IPv6 packets are emitted. If [dnssec] is
    provided and [false] (defaults to [true]), DNSSec validation will be
    disabled. *)

val handle_buf : t -> Ptime.t -> int64 -> bool -> Dns.proto -> Ipaddr.t ->
  int -> string ->
  t * (Dns.proto * Ipaddr.t * int * int32 * string) list
    * (Dns.proto * Ipaddr.t * string) list
(** [handle_buf t now ts query_or_reply proto sender source-port buf] handles
   resolution of [buf], which leads to a new [t], a list of answers to be
    transmitted (quintuple of protocol, ip address, port, minimum ttl, buffer),
    and a list of queries (triple of protocol, ip address, buffer). *)

val query_root : t -> int64 -> Dns.proto ->
  t * (Dns.proto * Ipaddr.t * string)
(** [query_root t now proto] potentially requests an update of the root
   zone. Best invoked by a regular timer. *)

val timer : t -> int64 ->
  t * (Dns.proto * Ipaddr.t * int * int32 * string) list
    * (Dns.proto * Ipaddr.t * string) list
(** [timer t now] potentially retransmits DNS requests and/or sends NXDomain
    answers. *)
