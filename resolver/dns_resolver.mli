(* (c) 2018 Hannes Mehnert, all rights reserved *)

type t
(** The type of a DNS resolver. *)

type feature =
  [ `Dnssec | `Qname_minimisation | `Opportunistic_tls_authoritative ]

val create : ?require_domain:bool -> ?add_reserved:bool -> ?record_clients:bool -> ?cache_size:int ->
  ?ip_protocol:[ `Both | `Ipv4_only | `Ipv6_only ] ->
  feature list -> Ptime.t ->
  int64 -> (int -> string) -> Dns_server.Primary.s -> t
(** [create ~require_domain ~add_reserved ~record_clients ~cache_size ~ip_protocol features now ts rng primary]
    creates the value of a resolver, pre-filled with root NS and their IP
    addresses. If [ip_protocol] is provided, and set to [`V4_only], only IPv4
    packets will be emitted. If [`V6_only] is set, only IPv6 packets will be
    emitted. If [`Both] (the default), either IPv4 and IPv6 packets are
    emitted. If [record_clients] is true (the default), the metrics of
    the resolver will include the amount of clients.  This keeps a set of
    Ipaddr.t of all clients around, which may use some memory if it is a public
    resolver.

    The [add_reserved] is by default [true], and adds reserved zones (from RFC
    6303, 6761, 6762) to the primary server
    (see {!Dns_resolver_root.reserved_zones}).

    Some features can be specified, whether DNSSec validation should be done,
    whether query name minimisation should be done, and whether opportunistic
    encryption using TLS to the authoritative should be done.
*)

val features : t -> feature list

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

val primary_data : t -> Dns_trie.t
(** [primary_data t] is the DNS trie of the primary. *)

val with_primary_data : t -> Ptime.t -> int64 -> Dns_trie.t -> t * (Ipaddr.t * string list) list
(** [with_primary_data t now ts data] is a pair [(t', outs)] where [t'] is [t]
    updated with the [data] DNS trie, and [outs] is the data to send out (if
    any). *)
