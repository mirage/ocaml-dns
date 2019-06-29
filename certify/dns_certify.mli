open Dns

val letsencrypt_name : 'a Domain_name.t -> ([ `raw ] Domain_name.t, [> `Msg of string ]) result
(** [letsencrypt_name host] is the service name at which we store let's encrypt
    certificates for the [host]. *)

type u_err = [ `Tsig of Dns_tsig.e | `Bad_reply of Packet.mismatch * Packet.t | `Unexpected_reply of Packet.reply  ]
(** The type of update errors. *)

val pp_u_err : u_err Fmt.t
(** [pp_u_err ppf u] pretty-prints [u] on [ppf]. *)

val nsupdate : (int -> Cstruct.t) -> (unit -> Ptime.t) -> host:[ `host ] Domain_name.t ->
  keyname:'b Domain_name.t -> zone:[ `host ] Domain_name.t -> Dns.Dnskey.t ->
  X509.CA.signing_request ->
  (Cstruct.t * (Cstruct.t -> (unit, [> u_err ]) result),
   [> `Msg of string ]) result
(** [nsupdate rng now ~host ~keyname ~zone dnskey csr] is a buffer with a DNS
   update that removes all TLSA records from the given [host], and adds a single
   TLSA record containing the certificate signing request. It also returns a
   function which decodes a given answer, checks it to be a valid reply, and
   returns either unit or an error. The outgoing packet is signed with the
    provided [dnskey], the answer is checked to be signed by the same key. If
    the sign operation fails, [nsupdate] returns an error. *)

type q_err = [
  | `Decode of Packet.err
  | `Bad_reply of Packet.mismatch * Packet.t
  | `Unexpected_reply of Packet.reply
  | `No_tlsa
]
(** The type for query errors. *)

val pp_q_err : q_err Fmt.t
(** [pp_q_err ppf q] pretty-prints [q] on [ppf]. *)

val query : (int -> Cstruct.t) -> X509.public_key -> [ `host ] Domain_name.t ->
  (Cstruct.t * (Cstruct.t -> (X509.t, [> q_err ]) result),
   [> `Msg of string ]) result
(** [query rng pubkey name] is a [buffer] with a DNS TLSA query for the given
   [name], and a function that decodes a given answer, either returning a X.509
   certificate or an error. *)
