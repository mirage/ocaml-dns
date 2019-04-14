(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

(** DNS Server implementation *)

(** Authentication, stored in a Dns_trie with privileges to operations embedded in the name. *)
module Authentication : sig
  type operation = [
    | `Update
    | `Transfer
  ]
  (** The type of operations. *)

  type a = Udns_trie.t -> proto -> Domain_name.t option -> operation -> Domain_name.t -> bool
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
  data : Udns_trie.t ;
  auth : Authentication.t ;
  rng : int -> Cstruct.t ;
  tsig_verify : Tsig_op.verify ;
  tsig_sign : Tsig_op.sign ;
}
(** The state of a DNS server. *)

val create : Udns_trie.t -> Authentication.t -> (int -> Cstruct.t) ->
  Tsig_op.verify -> Tsig_op.sign -> t
(** [create trie auth rng verify sign] creates a state record. *)

val text : Domain_name.t -> Udns_trie.t -> (string, string) result
(** [text name trie] results in a string representation (zonefile) of the trie. *)

val handle_question : t -> Packet.Header.t ->
  Packet.Question.t ->
  (Packet.Header.t * Packet.t * Udns.Name_rr_map.t option, Udns_enum.rcode) result
(** [handle_question t header query] handles the DNS query [query] in the data
    of [t]: a whitelist of record types are looked up: A | NS | CNAME | SOA |
    PTR | MX | TXT | AAAA | SRV | ANY | CAA | SSHFP | TLSA | DNSKEY. *)

val handle_tsig : ?mac:Cstruct.t -> t -> Ptime.t -> Packet.Header.t ->
  Packet.Question.t -> (Domain_name.t * Tsig.t * int) option ->
  Cstruct.t -> ((Domain_name.t * Tsig.t * Cstruct.t * Dnskey.t) option,
                Tsig_op.e * Cstruct.t option) result
(** [handle_tsig ~mac t now hdr v tsig offset buffer] verifies the tsig
    signature if present, returning the keyname, tsig, mac, and used key. *)

module Primary : sig

  type s
  (** The state of a primary DNS server. *)

  val server : s -> t
  (** [server s] is the server of the primary. *)

  val data : s -> Udns_trie.t
  (** [data s] is the data store of [s]. *)

  val with_data : s -> int64 -> Udns_trie.t -> s * (Ipaddr.V4.t * int * Cstruct.t) list
  (** [with_data s ts trie] replaces the current data with [trie] in [s].
      The returned notifications should be send out. *)

  val create : ?keys:(Domain_name.t * Udns.Dnskey.t) list ->
    ?a:Authentication.a list -> tsig_verify:Tsig_op.verify ->
    tsig_sign:Tsig_op.sign -> rng:(int -> Cstruct.t) -> Udns_trie.t -> s
  (** [create ~keys ~a ~tsig_verify ~tsig_sign ~rng data] creates a primary server. *)

  val handle_frame : s -> int64 -> Udns.proto -> Ipaddr.V4.t -> int ->
    Packet.Header.t -> Packet.Question.t -> Packet.t ->
    Name_rr_map.t -> Domain_name.t option ->
    (s * (Packet.Header.t * Packet.t * Name_rr_map.t option) option * (Ipaddr.V4.t * int * Cstruct.t) list * [ `Notify of Soa.t option | `Signed_notify of Soa.t option ] option,
     Udns_enum.rcode) result
  (** [handle_frame s now src src_port proto key hdr v] handles the given
     [frame], returning new state, an answer, and potentially notify packets to
     secondary name servers. *)

  val handle : s -> Ptime.t -> int64 -> Udns.proto ->
    Ipaddr.V4.t -> int -> Cstruct.t ->
    s * Cstruct.t option * (Ipaddr.V4.t * int * Cstruct.t) list * [ `Notify of Soa.t option | `Signed_notify of Soa.t option ] option
  (** [handle s now ts proto src src_port buffer] decodes the [buffer],
     processes the DNS frame using {!handle_frame}, and encodes the reply. *)

  val closed : s -> Ipaddr.V4.t -> int -> s
  (** [closed s ip port] marks the connection to [ip, port] closed. *)

  val timer : s -> int64 -> s * (Ipaddr.V4.t * int * Cstruct.t) list
  (** [timer s now] may encode some notify if they were not acknowledget by the
     other side. *)

end

module Secondary : sig

  type s
  (** The state of a secondary DNS server. *)

  val data : s -> Udns_trie.t
  (** [data s] is the zone data of [s]. *)

  val with_data : s -> Udns_trie.t -> s
  (** [with_data s trie] is [s] with its data replaced by [trie]. *)

  val create : ?a:Authentication.a list -> ?primary:Ipaddr.V4.t ->
   tsig_verify:Tsig_op.verify -> tsig_sign:Tsig_op.sign ->
    rng:(int -> Cstruct.t) -> (Domain_name.t * Udns.Dnskey.t) list -> s
  (** [create ~a ~primary ~tsig_verify ~tsig_sign ~rng keys] creates a secondary
     DNS server state. *)

  val handle_frame : s -> Ptime.t -> int64 -> Ipaddr.V4.t ->
    Domain_name.t option -> Packet.Header.t -> Packet.Question.t -> Packet.t -> Name_rr_map.t ->
    (s * (Packet.Header.t * Packet.t * Name_rr_map.t option) option * (proto * Ipaddr.V4.t * int * Cstruct.t) list,
     Udns_enum.rcode) result
  (** [handle_frame s now ts ip proto key hdr v] handles the incoming frame. *)

  val handle : s -> Ptime.t -> int64 -> Udns.proto -> Ipaddr.V4.t -> Cstruct.t ->
    s * Cstruct.t option * (proto * Ipaddr.V4.t * int * Cstruct.t) list
  (** [handle s now ts proto src buf] decodes [buf], {!handle_frame}, and encodes the results. *)

  val timer : s -> Ptime.t -> int64 ->
    s * (proto * Ipaddr.V4.t * int * Cstruct.t) list
  (** [timer s now ts] may request SOA or retransmit AXFR. *)

  val closed : s -> Ptime.t -> int64 -> Ipaddr.V4.t -> int ->
    s * (proto * Ipaddr.V4.t * int * Cstruct.t) list
    (** [closed s now ts ip port] marks [ip, port] as closed. *)

end
