(* (c) 2025 Hannes Mehnert, all rights reserved *)

module Make (S : Tcpip.Stack.V4V6) : sig
  type t

  module H : Happy_eyeballs_mirage.S with type stack = S.t and type flow = S.TCP.flow


  val create : ?cache_size:int -> ?edns:[ `Auto | `Manual of Dns.Edns.t | `None ] ->
    ?nameservers:string list ->
    ?timeout:int64 ->
    ?on_update:(old:Dns_trie.t -> ?authenticated_key:[ `raw ] Domain_name.t ->
                update_source:Ipaddr.t -> Dns_trie.t -> unit Lwt.t) ->
    Dns_server.Primary.s -> happy_eyeballs:H.t -> S.t -> t Lwt.t
  (* with respect to resolver, lacking: udp tcp port tls tls_port *)
  (** [create ~cache_size ~edns ~nameservers ~timeout ~on_update server ~happy_eyeballs stack]
     registers a stub resolver on the provided protocols [udp], [tcp], [tls]
     using [port] for udp and tcp (defaults to 53), [tls_port] for tls (defaults
     to 853) using the [resolver] configuration. The [timer] is in milliseconds
     and defaults to 500 milliseconds.*)

  val resolve_external : t -> Ipaddr.t * int -> string -> (int32 * string) Lwt.t
  (** [resolve_external t (ip, port) data] resolves for [(ip, port)] the query
      [data] and returns a pair of the minimum TTL and a response. *)

  val primary_data : t -> Dns_trie.t
  (** [primary_data t] is the DNS trie of the primary for the resolver [t]. *)

  val update_primary_data : t -> Dns_trie.t -> unit
  (** [update_primary_data t data] updates the primary for the resolver [t]
      with the DNS trie [data]. Any 'notify's to secondaries are discarded -
      secondary name servers are not supported in this setup. *)

  val update_tls : t -> Tls.Config.server -> unit
  (** [update_tls t tls_config] updates the tls configuration to [tls_config].
      If the resolver wasn't already listening for TLS connections it will
      start listening. *)
end
