(** TODO ideally there'd be something like mirage-flow-lwt that didn't depend
         on lwt and a ton of other things, and still provided [map]
         and [connect] and so on. leaving this stuff here for now until a
         better solution presents itself.
*)

val stdlib_random : int -> Cstruct.t
(** [stdlib_random len] is a buffer of size [len], filled with random data.
    This function is used by default (in the Unix and Lwt implementations) for
    filling the ID field of the DNS packet. Internally, the {!Random} module
    from the OCaml standard library is used, which is not cryptographically
    secure. If desired {!Nocrypto.Rng.generate} can be passed to {!S.create}. *)

module type S = sig
  type flow
  (** A flow is a network connection initialized by {!T.connect} *)

  type +'a io
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

  val create : ?rng:(int -> Cstruct.t) -> ?nameserver:ns_addr -> stack -> t
  (** [create ~rng ~nameserver stack] creates the state record of the DNS client. *)

  val nameserver : t -> ns_addr
  (** The address of a nameserver that is supposed to work with
      the underlying flow, can be used if the user does not want to
      bother with configuring their own.*)

  val rng : t -> (int -> Cstruct.t)
  (** [rng t] is a random number generator. *)

  val connect : ?nameserver:ns_addr -> t -> (flow, [> `Msg of string ]) result io
  (** [connect addr] is a new connection ([flow]) to [addr], or an error. *)

  val send : flow -> Cstruct.t -> (unit, [> `Msg of string ]) result io
  (** [send flow buffer] sends [buffer] to the [flow] upstream.*)

  val recv : flow -> (Cstruct.t, [> `Msg of string ]) result io
  (** [recv flow] tries to read a [buffer] from the [flow] downstream.*)

  val close : flow -> unit io
  (** [close flow] closes the [flow], freeing up resources. *)

  val bind : 'a io -> ('a -> 'b io) -> 'b io
  (** a.k.a. [>>=] *)

  val lift : 'a -> 'a io
end

module Make : functor (T : S) ->
sig

  type t

  val create : ?size:int -> ?rng:(int -> Cstruct.t) -> ?nameserver:T.ns_addr -> T.stack -> t
  (** [create ~size ~rng ~nameserver stack] creates the state of the DNS client. *)

  val nameserver : t -> T.ns_addr
  (** [nameserver t] returns the default nameserver to be used. *)

  val getaddrinfo : t -> ?nameserver:T.ns_addr -> 'response Dns.Rr_map.key ->
    'a Domain_name.t -> ('response, [> `Msg of string ]) result T.io
  (** [getaddrinfo nameserver query_type name] is the [query_type]-dependent
      response from [nameserver] regarding [name], or an [Error _] message.
      See {!Dns_client.query_state} for more information about the
      result types.
  *)

  val gethostbyname : t -> ?nameserver:T.ns_addr -> [ `host ] Domain_name.t ->
    (Ipaddr.V4.t, [> `Msg of string ]) result T.io
    (** [gethostbyname state ~nameserver domain] is the IPv4 address of [domain]
        resolved via the [state] and [nameserver] specified.
        If the query fails, or if the [domain] does not have any IPv4 addresses,
        an [Error _] message is returned.
        Any extraneous IPv4 addresses are ignored.
        For an example of using this API, see [unix/ohost.ml]
        in the distribution of this package.
    *)

  val gethostbyname6 : t -> ?nameserver:T.ns_addr -> [ `host ] Domain_name.t ->
    (Ipaddr.V6.t, [> `Msg of string ]) result T.io
    (** [gethostbyname6 state ~nameserver domain] is the IPv6 address of
        [domain] resolved via the [state] and [nameserver] specified.

        It is the IPv6 equivalent of {!gethostbyname}.
    *)

end

module Pure : sig
  (** The pure interface to the client part of uDns.

      Various helper modules to do with side effects are available from
      {!Dns_client_lwt}, {!Dns_client_unix} and so forth.
  *)

  type 'key query_state constraint 'key = 'a Dns.Rr_map.key
  (** [query_state] is parameterized over the query type, so the type of
      the representation of the answer depends on what the name server
      was asked to provide. See {!Dns_map.k} for a list of response types.
      The first element (the [int32]) in most of the tuples is the
      Time-To-Live (TTL) field returned from the server, which you can use to
      calculate when you should request fresh information in case you are writing
      a long-running application.
  *)

  val make_query :
    (int -> Cstruct.t) -> Dns.proto -> 'a Domain_name.t ->
    'query_type Dns.Rr_map.key ->
    Cstruct.t * 'query_type Dns.Rr_map.key query_state
  (** [make_query rng protocol name query_type] is [query, query_state]
      where [query] is the serialized DNS query to send to the name server,
      and [query_state] is the information required to validate the response. *)

  val parse_response : 'query_type Dns.Rr_map.key query_state -> Cstruct.t ->
    [ `Msg of string | `Ok of 'query_type | `Partial ]
  (** [parse_response query_state response] is the information contained in
      [response] parsed using [query_state] when the query was successful, or
      an [`Msg message] if the [response] did not match the [query_state]
      (or if the query failed).

      In a TCP usage context the [`Partial] means there are more packets.
      In a UDP usage context the [`Partial] means information was lost, due to an
      incomplete packet.
  *)

end