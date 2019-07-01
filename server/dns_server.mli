(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

(** DNS Server implementation *)

(** Authentication, stored in a Dns_trie with privileges to operations embedded in the name. *)
module Authentication : sig
  type operation = [
    | `Update
    | `Transfer
  ]
  (** The type of operations. *)

  type a = Dns_trie.t -> proto -> ?key:[ `raw ] Domain_name.t -> operation -> zone:[ `raw ] Domain_name.t -> bool
  (** The authentifier function signature *)

  val tsig_auth : a
  (** [tsig_auth trie proto keyname operation zone] checks that [keyname]
     matches the [operation] and is in the [zone]: [foo._transfer.mirage] is
     valid to [`Transfer] the [mirage] zone. A key without a zone
     [foo._transfer] is valid for all zones! When using [tsig_auth], be aware
     that it does no cryptographic verification of the tsig signature!  *)

  type t
  (** The type for an authenticator. *)
end

type t = private {
  data : Dns_trie.t ;
  auth : Authentication.t ;
  rng : int -> Cstruct.t ;
  tsig_verify : Tsig_op.verify ;
  tsig_sign : Tsig_op.sign ;
}
(** The state of a DNS server. *)

val text : 'a Domain_name.t -> Dns_trie.t -> (string, [> `Msg of string ]) result
(** [text name trie] results in a string representation (zonefile) of the trie. *)

val handle_question : t -> Packet.Question.t ->
  (Packet.Flags.t * Packet.Answer.t * Name_rr_map.t option,
   Rcode.t * Packet.Answer.t option) result
(** [handle_question t question] handles the DNS query [question] by looking
    it up in the trie of [t]. *)

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

  val with_data : s -> Ptime.t -> int64 -> Dns_trie.t -> s * (Ipaddr.V4.t * Cstruct.t) list
  (** [with_data s now ts trie] replaces the current data with [trie] in [s].
      The returned notifications should be send out. *)

  val with_keys : s -> Ptime.t -> int64 -> ('a Domain_name.t * Dnskey.t) list ->
    s * (Ipaddr.V4.t * Cstruct.t) list
  (** [with_keys s now ts keys] replaces the current keys with [keys] in [s],
      and generates notifications. *)

  val create : ?keys:('a Domain_name.t * Dnskey.t) list ->
    ?a:Authentication.a list -> ?tsig_verify:Tsig_op.verify ->
    ?tsig_sign:Tsig_op.sign -> rng:(int -> Cstruct.t) -> Dns_trie.t -> s
  (** [create ~keys ~a ~tsig_verify ~tsig_sign ~rng data] creates a primary server. *)

  val handle_packet : s -> Ptime.t -> int64 -> proto -> Ipaddr.V4.t -> int ->
    Packet.t -> 'a Domain_name.t option ->
    s * Packet.t option * (Ipaddr.V4.t * Cstruct.t) list *
    [> `Notify of Soa.t option | `Keep ] option
  (** [handle_packet s now ts src src_port proto key packet] handles the given
     [packet], returning new state, an answer, and potentially notify packets to
     secondary name servers. *)

  val handle_buf : s -> Ptime.t -> int64 -> proto ->
    Ipaddr.V4.t -> int -> Cstruct.t ->
    s * Cstruct.t option * (Ipaddr.V4.t * Cstruct.t) list *
    [ `Notify of Soa.t option | `Signed_notify of Soa.t option | `Keep ] option
  (** [handle_buf s now ts proto src src_port buffer] decodes the [buffer],
     processes the DNS frame using {!handle_packet}, and encodes the reply. *)

  val closed : s -> Ipaddr.V4.t -> s
  (** [closed s ip] marks the connection to [ip] closed. *)

  val timer : s -> Ptime.t -> int64 -> s * (Ipaddr.V4.t * Cstruct.t) list
  (** [timer s now ts] may encode some notify if they were not acknowledget by the
     other side. *)

  val to_be_notified : s -> [ `host ] Domain_name.t ->
    (Ipaddr.V4.t * [ `raw ] Domain_name.t option) list
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

  val create : ?a:Authentication.a list -> ?primary:Ipaddr.V4.t ->
   tsig_verify:Tsig_op.verify -> tsig_sign:Tsig_op.sign ->
    rng:(int -> Cstruct.t) -> ('a Domain_name.t * Dnskey.t) list -> s
  (** [create ~a ~primary ~tsig_verify ~tsig_sign ~rng keys] creates a secondary
     DNS server state. *)

  val handle_packet : s -> Ptime.t -> int64 -> Ipaddr.V4.t ->
    Packet.t -> 'a Domain_name.t option ->
    s * Packet.t option * (proto * Ipaddr.V4.t * Cstruct.t) list
  (** [handle_packet s now ts ip proto key t] handles the incoming packet. *)

  val handle_buf : s -> Ptime.t -> int64 -> proto -> Ipaddr.V4.t -> Cstruct.t ->
    s * Cstruct.t option * (proto * Ipaddr.V4.t * Cstruct.t) list
  (** [handle_buf s now ts proto src buf] decodes [buf], processes with
      {!handle_packet}, and encodes the results. *)

  val timer : s -> Ptime.t -> int64 -> s * (proto * Ipaddr.V4.t * Cstruct.t) list
  (** [timer s now ts] may request SOA or retransmit AXFR. *)

  val closed : s -> Ptime.t -> int64 -> Ipaddr.V4.t ->
    s * (proto * Ipaddr.V4.t * Cstruct.t) list
  (** [closed s now ts ip] marks [ip] as closed. *)

end
