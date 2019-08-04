(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

(** DNS TSIG signatures *)

val sign : Tsig_op.sign
(** [sign ~mac ~max_size name tsig ~key packet buffer] signs the given
    [buffer] with the provided [key], its [name], the [tsig]. The [mac]
    argument is expected when a reply to a signed DNS packet should be signed.
    If signing fails, an error may be produced. The result is a buffer and a
    mac. *)

val verify : Tsig_op.verify
(** [verify ~mac now packet name ~key tsig buffer] verifies the [buffer]
    using the provided [tsig], [key] and [name].*)

type s = [ `Key_algorithm of Dnskey.t | `Tsig_creation | `Sign ]
(** The type for signing errors. *)

val pp_s : s Fmt.t
(** [pp_s ppf s] pretty-prints [s] on [ppf]. *)

val encode_and_sign : ?proto:proto -> Packet.t -> Ptime.t -> Dns.Dnskey.t ->
  'a Domain_name.t -> (Cstruct.t * Cstruct.t, s) result
(** [encode_and_sign ~proto t now dnskey name] signs and encodes the DNS
    packet. *)

type e = [
  | `Decode of Packet.err
  | `Unsigned of Packet.t
  | `Crypto of Tsig_op.e
  | `Invalid_key of [ `raw ] Domain_name.t * [ `raw ] Domain_name.t
]
(** The type for decode and verify errors. *)

val pp_e : e Fmt.t
(** [pp_e ppf e] prety-prints [e] on [ppf]. *)

val decode_and_verify : Ptime.t -> Dnskey.t -> 'a Domain_name.t ->
  ?mac:Cstruct.t -> Cstruct.t ->
  (Packet.t * Tsig.t * Cstruct.t, e) result
(** [decode_and_verify now dnskey name ~mac buffer] decodes and verifies the
   given buffer using the key material, resulting in a DNS packet and the mac,
   or a failure. The optional [mac] argument should be provided if an answer to
   a signed DNS packet is to be decoded. *)

(**/**)
val compute_tsig : 'a Domain_name.t -> Tsig.t -> key:Cstruct.t ->
  Cstruct.t -> Cstruct.t
(** [compute_tsig name tsig ~key buffer] computes the mac over [buffer]
    and [tsig], using the provided [key] and [name]. *)
