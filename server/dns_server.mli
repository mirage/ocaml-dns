(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

(** DNS Server implementation *)

(** Authentication, stored in a Dns_trie with privileges to operations embedded in the name. *)
module Authentication : sig
  (** A key is a pair of a [`raw Domain_name.t] and a [Dnskey.t]. In the name,
      operation privileges and potentially IP addresses are encoded, e.g.
      [foo._transfer.example.com] may do AXFR on [example.com] and any
      subdomain, e.g. [foo.example.com]. *)

  type operation = [
    | `Update
    | `Transfer
    | `Notify
  ]
  (** The type of operations, sorted by highest ot lowest privileges, an
      [`Update] may as well carry out a [`Transfer]. *)

  val operation_to_string : operation -> string
  (** [operation_to_string op] is the string representation of [op]. *)

  val all_ops : operation list
  (** [all_ops] is a list of all operations. *)

  val access_granted : required:operation -> operation -> bool
  (** [access_granted ~required key_operation] is [true] if [key_operation] is
      authorised for [required] operation. *)

  val zone_and_operation : 'a Domain_name.t -> ([`host] Domain_name.t * operation) option
  (** [zone_and_operation key] is [Some (zone, op)], the [zone] of the [key],
      and its operation [op]. If the [key] is not in the expected format, [None]
      is returned. *)

  val access : ?key:'a Domain_name.t -> zone:'b Domain_name.t -> operation -> bool
  (** [access op ~key ~zone] checks whether [key] is authorised for [op] on
      [zone]. *)

  type t
  (** Opaque type for storing authentication keys. *)
end

type t = private {
  data : Dns_trie.t ;
  auth : Authentication.t ;
  unauthenticated_zone_transfer : bool ;
  rng : int -> string ;
  tsig_verify : Tsig_op.verify ;
  tsig_sign : Tsig_op.sign ;
}
(** The state of a DNS server. *)

val create : ?unauthenticated_zone_transfer:bool ->
  ?tsig_verify:Tsig_op.verify ->
  ?tsig_sign:Tsig_op.sign ->
  ?auth:Authentication.t ->
  Dns_trie.t ->
  (int -> string) ->
  t
(** [create ~unauthenticated_zone_transfer ~tsig_verify ~tsig_sign ~auth data rng]
    constructs a [t]. See {!Primary.create} and {!Secondary.create} for the
    logic running a primary or secondary server. *)

val with_data : t -> Dns_trie.t -> t
(** [with_data t data] is [t'] where the [data] field is updated with the
    provided value. Be aware that this function breaks the semantics of a
    primary server with secondaries, since secondaries won't be notified and
    will be out of sync. Use if you know what you do. The data of a secondary
    will usually come via zone transfer from the primary name services. *)

val text : 'a Domain_name.t -> Dns_trie.t -> (string, [> `Msg of string ]) result
(** [text name trie] results in a string representation (zonefile) of the trie. *)

val handle_question : t -> Packet.Question.t ->
  (Packet.Flags.t * Packet.Answer.t * Name_rr_map.t option,
   Rcode.t * Packet.Answer.t option) result
(** [handle_question t question] handles the DNS query [question] by looking
    it up in the trie of [t]. The result is either an answer or an error. *)

val update_data : Dns_trie.t -> 'a Domain_name.t ->
  Dns.Packet.Update.prereq list Domain_name.Map.t
  * Dns.Packet.Update.update list Domain_name.Map.t ->
  ( Dns_trie.t * (Domain_name.Set.elt * Dns.Soa.t) list,
   Dns.Rcode.t )
  result
(** [update_data data domain update_content] applies the [update_content] to
    the [data] for [domain]. This function breaks the semantics of a primary
    server with secondaries, since the secondaries won't be notified of the
    update and will be out of sync. Use if you know what you are doing. *)

val handle_update : t -> proto -> [ `raw ] Domain_name.t option ->
  Packet.Question.t -> Packet.Update.t ->
  (Dns_trie.t * ([`raw] Domain_name.t * Soa.t) list, Rcode.t) result
(** [handle_update t proto keyname question update] authenticates the update
    request and processes the update. This function breaks the semantics of a
    primary server with secondaries, since the secondaries won't be notified.
    Use if you know what you are doing. *)

val handle_axfr_request : t -> proto -> [ `raw ] Domain_name.t option ->
  Packet.Question.t -> (Packet.Axfr.t, Rcode.t) result
(** [handle_axfr_request t proto keyname question] authenticates the zone
    transfer request and processes it. If the request is valid, and the zone
    available, a zone transfer is returned. *)

type trie_cache

val handle_ixfr_request : t -> trie_cache -> proto -> [ `raw ] Domain_name.t option ->
  Packet.Question.t -> Soa.t -> (Packet.Ixfr.t, Rcode.t) result
(** [handle_ixfr_request t cache proto keyname question soa] authenticates the
    incremental zone transfer request and processes it. If valid, an incremental
    zone transfer is returned. *)

val handle_tsig : ?mac:string -> t -> Ptime.t -> Packet.t ->
  string -> (([ `raw ] Domain_name.t * Tsig.t * string * Dnskey.t) option,
                Tsig_op.e * string option) result
(** [handle_tsig ~mac t now packet buffer] verifies the tsig
    signature if present, returning the keyname, tsig, mac, and used key. *)

type packet_callback = Packet.Question.t -> Packet.reply option
(** [packet_callback question] either returns a reply to a DNS question [Some reply] or [None]. *)

module Primary : sig

  type s
  (** The state of a primary DNS server. *)

  val server : s -> t
  (** [server s] is the server of the primary. *)

  val data : s -> Dns_trie.t
  (** [data s] is the data store of [s]. *)

  val with_data : s -> Ptime.t -> int64 -> Dns_trie.t ->
    s * (Ipaddr.t * string list) list
  (** [with_data s now ts trie] replaces the current data with [trie] in [s].
      The returned notifications should be send out. *)

  val with_keys : s -> Ptime.t -> int64 -> ('a Domain_name.t * Dnskey.t) list ->
    s * (Ipaddr.t * string list) list
  (** [with_keys s now ts keys] replaces the current keys with [keys] in [s],
      and generates notifications. *)

  val trie_cache : s -> trie_cache
  (** [trie_cache s] is the trie cache of the server. *)

  val create : ?trie_cache_entries:int -> ?keys:('a Domain_name.t * Dnskey.t) list ->
    ?unauthenticated_zone_transfer:bool ->
    ?tsig_verify:Tsig_op.verify -> ?tsig_sign:Tsig_op.sign ->
    rng:(int -> string) -> Dns_trie.t -> s
  (** [create ~trie_cache_entries ~keys ~unauthenticated_zone_transfer
      ~tsig_verify ~tsig_sign ~rng data] creates a primary server. If
      [unauthenticated_zone_transfer] is provided and [true] (defaults to
      [false]), anyone can transfer the zones. [trie_cache_entries] is the
      backlog to keep in memory for incremental zone transfers (IXFR, default is 5). This
      affects memory usage. *)

  val handle_packet : ?packet_callback:packet_callback -> s -> Ptime.t -> int64
    -> proto -> Ipaddr.t -> int -> Packet.t -> 'a Domain_name.t option ->
    s * Packet.t option * (Ipaddr.t * string list) list *
    [> `Notify of Soa.t option | `Keep ] option
  (** [handle_packet ~packet_callback s now ts src src_port proto key packet]
      handles the given [packet], returning new state, an answer, and
      potentially notify packets to secondary name servers. If [packet_callback]
      is specified, it is called for each incoming query. If it returns
      [Some reply], this reply is used instead of the usual lookup in the
      zone data. It can be used for custom query processing, such as for load
      balancing or transporting data. *)

  val handle_buf : ?packet_callback:packet_callback -> s -> Ptime.t -> int64
    -> proto -> Ipaddr.t -> int -> string ->
    s * string list * (Ipaddr.t * string list) list *
    [ `Notify of Soa.t option | `Signed_notify of Soa.t option | `Keep ] option *
    [ `raw ] Domain_name.t option
  (** [handle_buf ~packet_callback s now ts proto src src_port buffer] decodes
      the [buffer], processes the DNS frame using {!handle_packet}, and encodes
      the reply. The result is a new state, potentially a list of answers to the
      requestor, a list of notifications to send out, information whether a
      notify (or signed notify) was received, and the hmac key used for
      authentication. If [packet_callback] is specified, it is called for each
      incoming query. If it returns [Some reply], this reply is used instead of
      the usual lookup in the zone data. This can be used for custom query
      processing, such as for load balancing or transporting data. *)

  val closed : s -> Ipaddr.t -> s
  (** [closed s ip] marks the connection to [ip] closed. *)

  val timer : s -> Ptime.t -> int64 ->
    s * (Ipaddr.t * string list) list
  (** [timer s now ts] may encode some notifications to secondary name servers
     if previous ones were not acknowledged. *)

  val to_be_notified : s -> [ `host ] Domain_name.t ->
    (Ipaddr.t * [ `raw ] Domain_name.t option) list
  (** [to_be_notified s zone] returns a list of pairs of IP address and optional
     tsig key name of the servers to be notified for a zone change.  This list
     is based on (a) NS entries for the zone, (b) registered TSIG transfer keys,
     and (c) active connection (which transmitted a signed SOA). *)
end

module Secondary : sig

  type s
  (** The state of a secondary DNS server. *)

  val data : s -> Dns_trie.t
  (** [data s] is the zone data of [s]. *)

  val with_data : s -> Dns_trie.t -> s
  (** [with_data s trie] is [s] with its data replaced by [trie]. *)

  val create : ?primary:Ipaddr.t ->
   tsig_verify:Tsig_op.verify -> tsig_sign:Tsig_op.sign ->
    rng:(int -> string) -> ('a Domain_name.t * Dnskey.t) list -> s
  (** [create ~primary ~tsig_verify ~tsig_sign ~rng keys] creates a secondary
     DNS server state. *)

  val handle_packet : ?packet_callback:packet_callback -> s -> Ptime.t -> int64 ->
    Ipaddr.t -> Packet.t -> 'a Domain_name.t option ->
    s * Packet.t option * (Ipaddr.t * string) option
  (** [handle_packet s now ts ip proto key t] handles the incoming packet. *)

  val handle_buf : ?packet_callback:packet_callback -> s -> Ptime.t -> int64 ->
    proto -> Ipaddr.t -> string ->
    s * string option * (Ipaddr.t * string) option
  (** [handle_buf ~packet_callback s now ts proto src buf] decodes [buf], processes with
      {!handle_packet}, and encodes the results. *)

  val timer : s -> Ptime.t -> int64 ->
    s * (Ipaddr.t * string list) list
  (** [timer s now ts] may request SOA or retransmit AXFR. *)

  val closed : s -> Ptime.t -> int64 -> Ipaddr.t ->
    s * string list
  (** [closed s now ts ip] marks [ip] as closed, the returned buffers (SOA
      requests) should be sent to [ip]. *)
end
