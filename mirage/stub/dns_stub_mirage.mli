(* (c) 2025 Hannes Mehnert, all rights reserved *)

module Make (S : Tcpip.Stack.V4V6) : sig
  type t

  module H : Happy_eyeballs_mirage.S with type stack = S.t and type flow = S.TCP.flow

  val create : ?cache_size:int -> ?udp:bool -> ?tcp:bool -> ?port:int ->
    ?edns:[ `Auto | `Manual of Dns.Edns.t | `None ] ->
    ?nameservers:string list ->
    ?timeout:int64 ->
    ?on_update:(old:Dns_trie.t -> ?authenticated_key:[ `raw ] Domain_name.t ->
                update_source:Ipaddr.t -> Dns_trie.t -> unit Lwt.t) ->
    Dns_server.Primary.s -> happy_eyeballs:H.t -> S.t -> t Lwt.t
  (* with respect to resolver, lacking: tls tls_port *)
  (** [create ~cache_size ~edns ~nameservers ~timeout ~on_update server ~happy_eyeballs stack]
      registers a stub resolver on the provided protocols [udp], [tcp], [tls]
      using [port] for udp and tcp (defaults to 53), [tls_port] for tls (defaults
      to 853) using the [resolver] configuration. The [timer] is in milliseconds
      and defaults to 500 milliseconds.*)

  include module type of Dns_resolver_mirage_shared with type t := t
end
