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
  rng : int -> Cstruct.t ;
  tsig_verify : Tsig_op.verify ;
  tsig_sign : Tsig_op.sign ;
}
(** The state of a DNS server. *)

val create : ?unauthenticated_zone_transfer:bool ->
  ?tsig_verify:Tsig_op.verify ->
  ?tsig_sign:Tsig_op.sign ->
  ?auth:Authentication.t ->
  Dns_trie.t ->
  (int -> Cstruct.t) ->
  t
(** [create ~unauthenticated_zone_transfer ~tsig_verify ~tsig_sign ~auth data rng]
    constructs a [t]. See {!Primary.create} and {!Secondary.create} for the
    logic running a primary or secondary server. *)

val with_data : t -> Dns_trie.t -> t
(** [with_data t data] is [t'] where the [data] field is updated with the
    provided value. *)

val text : 'a Domain_name.t -> Dns_trie.t -> (string, [> `Msg of string ]) result
(** [text name trie] results in a string representation (zonefile) of the trie. *)

val handle_question : t -> Packet.Question.t ->
  (Packet.Flags.t * Packet.Answer.t * Name_rr_map.t option,
   Rcode.t * Packet.Answer.t option) result
(** [handle_question t question] handles the DNS query [question] by looking
    it up in the trie of [t]. *)

val update_data : Dns_trie.t -> 'a Domain_name.t ->
  Dns.Packet.Update.prereq list Domain_name.Map.t
  * Dns.Packet.Update.update list Domain_name.Map.t ->
  ( Dns_trie.t * (Domain_name.Set.elt * Dns.Soa.t) list,
   Dns.Rcode.t )
  result

val handle_update : t -> proto -> [ `raw ] Domain_name.t option ->
  Packet.Question.t -> Packet.Update.t ->
  (Dns_trie.t * ([`raw] Domain_name.t * Soa.t) list, Rcode.t) result
(** [handle_update t proto keyname question update] authenticates the update
    request and processes the update. *)

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

val handle_tsig : ?mac:Cstruct.t -> t -> Ptime.t -> Packet.t ->
  Cstruct.t -> (([ `raw ] Domain_name.t * Tsig.t * Cstruct.t * Dnskey.t) option,
                Tsig_op.e * Cstruct.t option) result
(** [handle_tsig ~mac t now packet buffer] verifies the tsig
    signature if present, returning the keyname, tsig, mac, and used key. *)

module Primary : sig

  type s
  (** The state of a primary DNS server. *)

  val server : s -> t
  (** [server s] is the server of the primary. *)

  val data : s -> Dns_trie.t
  (** [data s] is the data store of [s]. *)

  val with_data : s -> Ptime.t -> int64 -> Dns_trie.t ->
    s * (Ipaddr.t * Cstruct.t list) list
  (** [with_data s now ts trie] replaces the current data with [trie] in [s].
      The returned notifications should be send out. *)

  val with_keys : s -> Ptime.t -> int64 -> ('a Domain_name.t * Dnskey.t) list ->
    s * (Ipaddr.t * Cstruct.t list) list
  (** [with_keys s now ts keys] replaces the current keys with [keys] in [s],
      and generates notifications. *)

  val trie_cache : s -> trie_cache

  val create : ?keys:('a Domain_name.t * Dnskey.t) list ->
    ?unauthenticated_zone_transfer:bool ->
    ?tsig_verify:Tsig_op.verify -> ?tsig_sign:Tsig_op.sign ->
    rng:(int -> Cstruct.t) -> Dns_trie.t -> s
  (** [create ~keys ~unauthenticated_zone_transfer ~tsig_verify ~tsig_sign ~rng
     data] creates a primary server. If [unauthenticated_zone_transfer] is
     provided and [true] (defaults to [false]), anyone can transfer the zones. *)

  val handle_packet : s -> Ptime.t -> int64 -> proto -> Ipaddr.t -> int ->
    Packet.t -> 'a Domain_name.t option ->
    s * Packet.t option * (Ipaddr.t * Cstruct.t list) list *
    [> `Notify of Soa.t option | `Keep ] option
  (** [handle_packet s now ts src src_port proto key packet] handles the given
     [packet], returning new state, an answer, and potentially notify packets to
     secondary name servers. *)

  val handle_buf : s -> Ptime.t -> int64 -> proto ->
    Ipaddr.t -> int -> Cstruct.t ->
    s * Cstruct.t list * (Ipaddr.t * Cstruct.t list) list *
    [ `Notify of Soa.t option | `Signed_notify of Soa.t option | `Keep ] option *
    [ `raw ] Domain_name.t option
  (** [handle_buf s now ts proto src src_port buffer] decodes the [buffer],
     processes the DNS frame using {!handle_packet}, and encodes the reply.
     The result is a new state, potentially a list of answers to the requestor,
     a list of notifications to send out, information whether a notify (or
     signed notify) was received, and the hmac key used for authentication. *)

  val closed : s -> Ipaddr.t -> s
  (** [closed s ip] marks the connection to [ip] closed. *)

  val timer : s -> Ptime.t -> int64 ->
    s * (Ipaddr.t * Cstruct.t list) list
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
    rng:(int -> Cstruct.t) -> ('a Domain_name.t * Dnskey.t) list -> s
  (** [create ~primary ~tsig_verify ~tsig_sign ~rng keys] creates a secondary
     DNS server state. *)

  val handle_packet : s -> Ptime.t -> int64 -> Ipaddr.t ->
    Packet.t -> 'a Domain_name.t option ->
    s * Packet.t option * (Ipaddr.t * Cstruct.t) option
  (** [handle_packet s now ts ip proto key t] handles the incoming packet. *)

  val handle_buf : s -> Ptime.t -> int64 -> proto -> Ipaddr.t -> Cstruct.t ->
    s * Cstruct.t option * (Ipaddr.t * Cstruct.t) option
  (** [handle_buf s now ts proto src buf] decodes [buf], processes with
      {!handle_packet}, and encodes the results. *)

  val timer : s -> Ptime.t -> int64 ->
    s * (Ipaddr.t * Cstruct.t list) list
  (** [timer s now ts] may request SOA or retransmit AXFR. *)

  val closed : s -> Ptime.t -> int64 -> Ipaddr.t ->
    s * Cstruct.t list
  (** [closed s now ts ip] marks [ip] as closed, the returned buffers (SOA
      requests) should be sent to [ip]. *)
end
