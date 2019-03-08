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

  type implementation
  (** An implementation with which to connect, e.g. {IPv4.tcpv4}*)

  val implementation : implementation
  (** A handle for an {implementation} instance.*)

  val default_ns : ns_addr
  (** This is documented in the {!Make} functor. TODO *)

  val connect : implementation -> ns_addr -> (flow,'err) io
  (** [connect addr] is a new connection ([flow]) to [addr], or an error. *)

  val send : flow -> Cstruct.t -> (unit,'err) io
  (** [send flow buffer] sends [buffer] to the [flow] upstream.*)

  val recv : flow -> (Cstruct.t, 'err) io
  (** [recv flow] tries to read a [buffer] from the [flow] downstream.*)

  val resolve : ('ok,'err) io -> ('ok -> ('next,'err) result) -> ('next,'err) io
  (** a.k.a. [>|=] *)

  val map : ('ok,'err) io -> ('ok -> ('next,'err) io) -> ('next,'err) io
  (** a.k.a. [>>=] *)
end

module Make : functor (U : S) ->
sig

  val default_ns : U.ns_addr
  (** The address of a nameserver that is supposed to work with
      the underlying flow, can be used if the user does not want to
      bother with configuring their own.*)

  val getaddrinfo : U.ns_addr -> 'response Dns_map.k ->
    Domain_name.t -> ('response, 'err) U.io
  (** [getaddrinfo nameserver query_type name] is the [query_type]-dependent
      response from [nameserver] regarding [name], or an [Error _] message.
      See {!Udns_client.query_state} for more information about the
      result types.
  *)

  val gethostbyname : U.ns_addr -> Domain_name.t ->
    (Ipaddr.V4.t, 'err) U.io
    (** [gethostbyname nameserver name] is the IPv4 address of [name]
        resolved via the [nameserver] specified.
        If the query fails, or if the [name] does not have any IPv4 addresses,
        an [Error _] message is returned.
        Any extraneous IPv4 addresses are ignored.
        For an example of using this API, see [unix/ohostname.ml]
        in the distribution of this package.
    *)

end
