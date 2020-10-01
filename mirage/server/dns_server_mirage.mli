(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module Make (P : Mirage_clock.PCLOCK) (M : Mirage_clock.MCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4V6) : sig

  val primary :
    ?on_update:(old:Dns_trie.t -> authenticated_key:[`raw] Domain_name.t option -> update_source:Ipaddr.t -> Dns_server.Primary.s -> unit Lwt.t) ->
    ?on_notify:([ `Notify of Dns.Soa.t option | `Signed_notify of Dns.Soa.t option ] ->
                Dns_server.Primary.s ->
                (Dns_trie.t * ([ `raw ] Domain_name.t * Dns.Dnskey.t) list) option Lwt.t) ->
    ?timer:int -> ?port:int -> S.t -> Dns_server.Primary.s -> unit
  (** [primary ~on_update ~timer ~port stack primary] starts a primary server on
     [port] (default 53, both TCP and UDP) with the given [primary]
     configuration. [timer] is the DNS notify timer in seconds, and defaults to
     2 seconds. [on_update ~old ~authenticated_key ~update_source s] is a
     callback if the data served by the primary server [s] got updated by a
     potentially authenticated nsupdate packet, the used [authenticated_key]
     and source [update_source] are passed to the callback. The
     [on_notify notify s] callback is executed when a notify request is received
     by the primary DNS server (may be used for signaling of a (hidden) DNS
     secondary server). *)

  val secondary :
    ?on_update:(old:Dns_trie.t -> Dns_server.Secondary.s -> unit Lwt.t) ->
    ?timer:int -> ?port:int -> S.t -> Dns_server.Secondary.s ->
    unit
  (** [secondary ~on_update ~timer ~port stack secondary] starts a secondary
     server on [port] (default 53). The [on_update] callback is executed when
     the zone changes. The [timer] (in seconds, defaults to 5 seconds) is used
     for refreshing zones. *)
end
