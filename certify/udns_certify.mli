open Udns

val letsencrypt_name : Domain_name.t -> (Domain_name.t, [> `Msg of string ]) result
(** [letsencrypt_name host] is the service name at which we store let's encrypt
    certificates for the [host]. *)

type u_err = [ `Tsig of Udns_tsig.e | `Bad_reply of Packet.res ]

val pp_u_err : u_err Fmt.t

val nsupdate : (int -> Cstruct.t) -> (unit -> Ptime.t) -> host:Domain_name.t ->
  keyname:Domain_name.t -> zone:Domain_name.t -> Udns.Dnskey.t ->
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
  | `Bad_reply of Packet.res
  | `No_tlsa
]

val pp_q_err : q_err Fmt.t

val query : (int -> Cstruct.t) -> X509.public_key -> Domain_name.t ->
  (Cstruct.t * (Cstruct.t -> (X509.t, [> q_err ]) result),
   [> `Msg of string ]) result
(** [query rng pubkey name] is a buffer with a DNS TLSA query for the given
   [name], and a function that decodes a given answer, either returning a X509
   certificate or an error. *)
