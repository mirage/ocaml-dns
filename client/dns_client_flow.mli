(** TODO ideally there'd be something like mirage-flow-lwt that didn't depend
         on lwt and a ton of other things, and still provided [map]
         and [connect] and so on. leaving this stuff here for now until a
         better solution presents itself.
*)

module type S = sig
  type flow
  (** A flow is a connection produced by {!U.connect} *)

  type (+'ok,+'err) io constraint 'err = [> `Msg of string]
  (** [io] is the type of an effect. ['err] is a polymorphic variant. *)

  type io_addr
  (** An address for a given flow type, usually this will consist of
      IP address + a TCP/IP or UDP/IP port number, but for some flow types
      it can carry additional information for purposes of cryptographic
      verification. TODO at least that would be nice in the future. TODO
  *)

  type ns_addr = [ `TCP | `UDP] * io_addr
  (** TODO well this is kind of crude; it's a tuple to prevent having
      to do endless amounts of currying things when implementing flow types,
      and we need to know the protocol used so we can prefix packets for
      DNS-over-TCP and set correct socket options etc. therefore we can't
      just use the opaque [io_addr].
      TODO*)

  type stack
  (** A stack with which to connect, e.g. {!IPv4.tcpv4}*)

  type t
  (** The abstract state of a DNS client. *)

  val create : ?nameserver:ns_addr -> stack -> t
  (** [create ~nameserver stack] creates the state record of the DNS client. *)

  val nameserver : t -> ns_addr
  (** The address of a nameserver that is supposed to work with
      the underlying flow, can be used if the user does not want to
      bother with configuring their own.*)

  val connect : ?nameserver:ns_addr -> t -> (flow,'err) io
  (** [connect addr] is a new connection ([flow]) to [addr], or an error. *)

  val send : flow -> Cstruct.t -> (unit,'err) io
  (** [send flow buffer] sends [buffer] to the [flow] upstream.*)

  val recv : flow -> (Cstruct.t, 'err) io
  (** [recv flow] tries to read a [buffer] from the [flow] downstream.*)

  val close : flow -> (unit, 'err) io
  (** [close flow] closes the [flow], freeing up resources. *)

  val resolve : ('ok,'err) io -> ('ok -> ('next,'err) result) -> ('next,'err) io
  (** a.k.a. [>|=] *)

  val map : ('ok,'err) io -> ('ok -> ('next,'err) io) -> ('next,'err) io
  (** a.k.a. [>>=] *)

  val lift : ('ok, 'err) result -> ('ok,'err) io
end

module Make : functor (U : S) ->
sig

  val create : ?nameserver:U.ns_addr -> U.stack -> U.t
  (** [create ~nameserver stack] creates the state of the DNS client. *)

  val nameserver : U.t -> U.ns_addr
  (** [nameserver t] returns the default nameserver to be used. *)

  val getaddrinfo : U.t -> ?nameserver:U.ns_addr -> 'response Dns.Rr_map.key ->
    'a Domain_name.t -> ('response, 'err) U.io
  (** [getaddrinfo nameserver query_type name] is the [query_type]-dependent
      response from [nameserver] regarding [name], or an [Error _] message.
      See {!Dns_client.query_state} for more information about the
      result types.
  *)

  val gethostbyname : U.t -> ?nameserver:U.ns_addr -> [ `host ] Domain_name.t ->
    (Ipaddr.V4.t, 'err) U.io
    (** [gethostbyname state ~nameserver domain] is the IPv4 address of [domain]
        resolved via the [state] and [nameserver] specified.
        If the query fails, or if the [domain] does not have any IPv4 addresses,
        an [Error _] message is returned.
        Any extraneous IPv4 addresses are ignored.
        For an example of using this API, see [unix/ohost.ml]
        in the distribution of this package.
    *)

  val gethostbyname6 : U.t -> ?nameserver:U.ns_addr -> [ `host ] Domain_name.t ->
    (Ipaddr.V6.t, 'err) U.io
    (** [gethostbyname6 state ~nameserver domain] is the IPv6 address of
        [domain] resolved via the [state] and [nameserver] specified.

        It is the IPv6 equivalent of {!gethostbyname}.
    *)

end
