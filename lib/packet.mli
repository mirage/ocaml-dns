(*
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2011-2014 Anil Madhavapeddy <anil@recoil.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

(** DNS packet manipulation using the {! Cstruct} library. Something of a
    catch-all for the time being.

    @author Richard Mortier <mort\@cantab.net>
    @author Anil Madhavapeddy anil\@recoil.org>
    @author Haris Rotsos
*)

open Name
open Cstruct

cenum digest_alg {
  SHA1 = 1;
  SHA256 = 2
} as uint8_t

val digest_alg_to_int : digest_alg -> int
val int_to_digest_alg : int -> digest_alg option

type gateway_tc
type pubkey_alg
type ipseckey_alg
type gateway
type hash_alg
type fp_type

(** Represent a DNSSEC algorithm, with the usual conversion functions. *)

cenum dnssec_alg {
  RSAMD5     = 1;
  DH         = 2;
  DSA        = 3;
  ECC        = 4;
  RSASHA1    = 5;
  RSANSEC3   = 7;
  RSASHA256  = 8;
  RSASHA512  = 10;
  INDIRECT   = 252;
  PRIVATEDNS = 253;
  PRIVATEOID = 254
} as uint8_t
val int_to_dnssec_alg : int -> dnssec_alg option
val dnssec_alg_to_int : dnssec_alg -> int

(** Represent the {! rr} type, with the usual conversion functions. *)
type q_type =
  |  Q_A
  |  Q_NS
  |  Q_MD
  |  Q_MF
  |  Q_CNAME
  |  Q_SOA
  |  Q_MB
  |  Q_MG
  |  Q_MR
  |  Q_NULL
  |  Q_WKS
  |  Q_PTR
  |  Q_HINFO
  |  Q_MINFO
  |  Q_MX
  |  Q_TXT
  |  Q_RP
  |  Q_AFSDB
  |  Q_X25
  |  Q_ISDN
  |  Q_RT
  |  Q_NSAP
  |  Q_NSAPPTR
  |  Q_SIG
  |  Q_KEY
  |  Q_PX
  |  Q_GPOS
  |  Q_AAAA
  |  Q_LOC
  |  Q_NXT
  |  Q_EID
  |  Q_NIMLOC
  |  Q_SRV
  |  Q_ATMA
  |  Q_NAPTR
  |  Q_KM
  |  Q_CERT
  |  Q_A6
  |  Q_DNAME
  |  Q_SINK
  |  Q_OPT
  |  Q_APL
  |  Q_DS
  |  Q_SSHFP
  |  Q_IPSECKEY
  |  Q_RRSIG
  |  Q_NSEC
  |  Q_DNSKEY
  |  Q_NSEC3
  |  Q_NSEC3PARAM

  |  Q_SPF
  |  Q_UINFO
  |  Q_UID
  |  Q_GID
  |  Q_UNSPEC

  |  Q_AXFR
  |  Q_MAILB
  |  Q_MAILA
  |  Q_ANY_TYP

  |  Q_TA
  |  Q_DLV
  |  Q_UNKNOWN of int

val q_type_to_int : q_type -> int

type rr_type =
  | RR_UNUSED   (* required by sig(0)*)
  | RR_A
  | RR_NS
  | RR_MD
  | RR_MF
  | RR_CNAME
  | RR_SOA
  | RR_MB
  | RR_MG
  | RR_MR
  | RR_NULL
  | RR_WKS
  | RR_PTR
  | RR_HINFO
  | RR_MINFO
  | RR_MX
  | RR_TXT
  | RR_RP
  | RR_AFSDB
  | RR_X25
  | RR_ISDN
  | RR_RT
  | RR_NSAP
  | RR_NSAPPTR
  | RR_SIG
  | RR_KEY
  | RR_PX
  | RR_GPOS
  | RR_AAAA
  | RR_LOC
  | RR_NXT
  | RR_EID
  | RR_NIMLOC
  | RR_SRV
  | RR_ATMA
  | RR_NAPTR
  | RR_KM
  | RR_CERT
  | RR_A6
  | RR_DNAME
  | RR_SINK
  | RR_OPT
  | RR_APL
  | RR_DS
  | RR_SSHFP
  | RR_IPSECKEY
  | RR_RRSIG
  | RR_NSEC
  | RR_DNSKEY
  | RR_NSEC3
  | RR_NSEC3PARAM
  | RR_SPF
  | RR_UINFO
  | RR_UID
  | RR_GID
  | RR_UNSPEC
val string_to_rr_type : string -> rr_type option
val rr_type_to_string : rr_type -> string
val int_to_rr_type : int -> rr_type option
val rr_type_to_int : rr_type -> int
type type_bit_map
type type_bit_maps

(** Represent RDATA elements; a variant type to avoid collision with the
    compact {! Trie} representation from {! RR}. *)

type rdata =
| A of Ipaddr.V4.t
| AAAA of Ipaddr.V6.t
| AFSDB of uint16 * domain_name
| CNAME of domain_name
| DNSKEY of uint16 * dnssec_alg * string
| DS of uint16 * dnssec_alg * digest_alg * string
| HINFO of string * string
| IPSECKEY of byte * gateway_tc * ipseckey_alg * gateway * string
| ISDN of string * string option
| MB of domain_name
| MD of domain_name
| MF of domain_name
| MG of domain_name
| MINFO of domain_name * domain_name
| MR of domain_name
| MX of uint16 * domain_name
| NS of domain_name
| NSEC of domain_name (* uncompressed *) * type_bit_maps
| NSEC3 of hash_alg * byte * uint16 * byte * string * byte * string * type_bit_maps
| NSEC3PARAM of hash_alg * byte * uint16 * byte * string
| PTR of domain_name
| RP of domain_name * domain_name
| RRSIG of rr_type * dnssec_alg * byte * int32 * int32 * int32 * uint16 *
    domain_name (* uncompressed *) * string
| SIG of dnssec_alg * int32 * int32 * uint16 * domain_name * string
| RT of uint16 * domain_name
| SOA of domain_name * domain_name * int32 * int32 * int32 * int32 * int32
| SRV of uint16 * uint16 * uint16 * domain_name
| SSHFP of pubkey_alg * fp_type * string
| TXT of string list
| UNKNOWN of int * string
| WKS of Ipaddr.V4.t * byte * string
| X25 of string
           (* udp size, rcode, do bit, options *)
| EDNS0 of (int * int * bool * ((int * string) list))

val hex_of_string : string -> string
val rdata_to_string : rdata -> string
val rdata_to_rr_type : rdata -> rr_type

val marshal_rdata: int Name.Map.t ->
  ?compress:bool -> int -> t -> rdata -> rr_type *  int Name.Map.t * int
(** Marshal the RR data into the DNS binary format.  Raises [Not_implemented]
    if the RR type is known but the logic is not implemented in the library
    yet. *)

val compare_rdata : rdata -> rdata -> int

exception Not_implemented

(** Parse an RDATA element from a packet, given the set of already encountered
    names, a starting index, and the type of the RDATA. Raises [Not_implemented]
    if the RR type is not recognized. *)
val parse_rdata :
  (int, label) Hashtbl.t -> int -> rr_type -> int -> int32 -> t -> rdata

(** The class of a {! rr}, and usual conversion functions. *)
type rr_class = RR_IN | RR_CS | RR_CH | RR_HS | RR_ANY
val rr_class_to_string : rr_class -> string

(** A [resource record], with usual conversion and parsing functions. *)
type rr = {
  name  : domain_name;
  cls   : rr_class;
  ttl   : int32;
  rdata : rdata;
}
val rr_to_string : rr -> string
val marshal_rr : ?compress:bool ->
  int Name.Map.t * int * t -> rr ->
  int Name.Map.t * int * t

val parse_rr :
  (int, label) Hashtbl.t -> int -> t -> rr * (int * t)

(** A predicate to test if a {! q_type } applies to an {! rr_type }. *)
val q_type_matches_rr_type : q_type -> rr_type -> bool

(** A question type, with the usual conversion functions. *)
val q_type_to_string : q_type -> string
val string_to_q_type : string -> q_type option

(** A question class, with the usual conversion functions. *)
type q_class = Q_IN | Q_CS | Q_CH | Q_HS | Q_NONE | Q_ANY_CLS
val q_class_to_string : q_class -> string
val string_to_q_class : string -> q_class option

(** A question, with the usual conversion functions. *)
type question = {
  q_name  : domain_name;
  q_type  : q_type;
  q_class : q_class;
}
val question_to_string : question -> string
val parse_question :
  (int, label) Hashtbl.t -> int -> t -> question * (int * t)

(** The [qr] field from the DNS header {! detail}. *)
type qr = Query | Response

(** A DNS opcode, with the usual conversion functions. *)
type opcode = Standard | Inverse | Status | Reserved | Notify | Update
val opcode_to_string : opcode -> string

(** A DNS response code, with the usual conversion functions. *)
type rcode =
  | NoError  | FormErr
  | ServFail | NXDomain | NotImp  | Refused
  | YXDomain | YXRRSet  | NXRRSet | NotAuth
  | NotZone  | BadVers  | BadKey  | BadTime
  | BadMode  | BadName  | BadAlg
val rcode_to_string : rcode -> string

(** The [detail] field from the DNS header, with the usual conversion
    functions. *)

type detail = {
  qr: qr;
  opcode: opcode;
  aa: bool;
  tc: bool;
  rd: bool;
  ra: bool;
  rcode: rcode;
}

(** And finally, the DNS packet itself, with conversion functions. *)
type t = {
  id          : int;
  detail      : detail;
  questions   : question list;
  answers     : rr list;
  authorities : rr list;
  additionals : rr list;
}

val to_string : t -> string
val parse : Buf.t -> t

(** The marshalling entry point, given a {! dns} structure.

    @return the marshalled packet
*)
val marshal : Buf.t -> t -> Buf.t
