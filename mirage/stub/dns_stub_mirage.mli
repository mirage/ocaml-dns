(* (c) 2025 Hannes Mehnert, all rights reserved *)

module Make (S : Tcpip.Stack.V4V6) : sig
  type t

  module H : sig
    include Happy_eyeballs_mirage.S with type stack = S.t and type flow = S.TCP.flow
    val connect_device : ?aaaa_timeout:int64 -> ?connect_delay:int64 ->
      ?connect_timeout:int64 -> ?resolve_timeout:int64 -> ?resolve_retries:int ->
      ?timer_interval:int64 -> ?getaddrinfo:getaddrinfo -> stack -> t Lwt.t
  end

  val create : ?require_domain:bool -> ?add_reserved:bool -> ?record_clients:bool -> ?cache_size:int -> ?udp:bool -> ?tcp:bool -> ?port:int ->
    ?tls:Tls.Config.server -> ?tls_port:int ->
    ?edns:[ `Auto | `Manual of Dns.Edns.t | `None ] ->
    ?nameservers:string list ->
    ?timeout:int64 ->
    ?on_update:(old:Dns_trie.t -> ?authenticated_key:[ `raw ] Domain_name.t ->
                update_source:Ipaddr.t -> Dns_trie.t -> unit Lwt.t) ->
    Dns_server.Primary.s -> happy_eyeballs:H.t -> S.t -> t Lwt.t
  (** [create ~require_domain ~add_reserved ~record_clients ~cache_size ~edns ~nameservers ~timeout ~on_update server ~happy_eyeballs stack]
      registers a stub resolver on the provided protocols [udp], [tcp], [tls]
      using [port] for udp and tcp (defaults to 53), [tls_port] for tls (defaults
      to 853) using the [resolver] configuration. The [timer] is in milliseconds
      and defaults to 500 milliseconds.

      If [record_clients] is true (the default), the metrics of the resolver
      will include the amount of clients.  This keeps a set of Ipaddr.t of all
      clients around, which may use some memory if it is a public resolver.

      The [add_reserved] is by default [true], and adds reserved zones (from RFC
      6303, 6761, 6762) to the primary server
      (see {!Dns_resolver_root.reserved_zones}). *)

  include Dns_resolver_mirage_shared.S with type t := t
end
