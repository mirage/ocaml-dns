(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

(** DNS TSIG signatures *)

val compute_tsig : Domain_name.t -> Tsig.t -> key:Cstruct.t ->
  Cstruct.t -> Cstruct.t
(** [compute_tsig name tsig ~key buffer] computes the mac over [buffer]
    and [tsig], using the provided [key] and [name]. *)

val sign : Tsig_op.sign
(** [sign] is the signature function. *)

val verify : Tsig_op.verify
(** [verify] is the verify function. *)

type s = [ `Key_algorithm of Dnskey.t | `Tsig_creation | `Sign ]

val pp_s : s Fmt.t

val encode_and_sign : ?proto:proto -> ?additional:Name_rr_map.t -> Packet.Header.t ->
  Packet.Question.t -> Packet.t -> Ptime.t -> Udns.Dnskey.t -> Domain_name.t ->
  (Cstruct.t * Cstruct.t, s) result
(** [encode_and_sign ~proto hdr v now dnskey name] signs and encodes the DNS
    packet. *)

type e = [ `Decode of Packet.err | `Unsigned of Packet.res | `Crypto of Tsig_op.e | `Invalid_key of Domain_name.t * Domain_name.t ]

val pp_e : e Fmt.t

val decode_and_verify : Ptime.t -> Dnskey.t -> Domain_name.t ->
  ?mac:Cstruct.t -> Cstruct.t ->
  (Packet.res * Tsig.t * Cstruct.t, e) result
(** [decode_and_verify now dnskey name ~mac buffer] decodes and verifies the
   given buffer using the key material, resulting in a DNS packet and the mac,
   or a failure. *)
