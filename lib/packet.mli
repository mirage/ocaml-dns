(*
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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
cenum q_type {
  Q_A          = 1;
  Q_NS         = 2;
  Q_MD         = 3;
  Q_MF         = 4;
  Q_CNAME      = 5;
  Q_SOA        = 6;
  Q_MB         = 7;
  Q_MG         = 8;
  Q_MR         = 9;
  Q_NULL       = 10;
  Q_WKS        = 11;
  Q_PTR        = 12;
  Q_HINFO      = 13;
  Q_MINFO      = 14;
  Q_MX         = 15;
  Q_TXT        = 16;
  Q_RP         = 17;
  Q_AFSDB      = 18;
  Q_X25        = 19;
  Q_ISDN       = 20;
  Q_RT         = 21;
  Q_NSAP       = 22;
  Q_NSAPPTR    = 23;
  Q_SIG        = 24;
  Q_KEY        = 25;
  Q_PX         = 26;
  Q_GPOS       = 27;
  Q_AAAA       = 28;
  Q_LOC        = 29;
  Q_NXT        = 30;
  Q_EID        = 31;
  Q_NIMLOC     = 32;
  Q_SRV        = 33;
  Q_ATMA       = 34;
  Q_NAPTR      = 35;
  Q_KM         = 36;
  Q_CERT       = 37;
  Q_A6         = 38;
  Q_DNAME      = 39;
  Q_SINK       = 40;
  Q_OPT        = 41;
  Q_APL        = 42;
  Q_DS         = 43;
  Q_SSHFP      = 44;
  Q_IPSECKEY   = 45;
  Q_RRSIG      = 46;
  Q_NSEC       = 47;
  Q_DNSKEY     = 48;
  Q_NSEC3      = 50;
  Q_NSEC3PARAM = 51;

  Q_SPF        = 99;
  Q_UINFO      = 100;
  Q_UID        = 101;
  Q_GID        = 102;
  Q_UNSPEC     = 103;
  
  Q_AXFR    = 252;
  Q_MAILB   = 253;
  Q_MAILA   = 254;
  Q_ANY_TYP = 255;
  
  Q_TA    = 32768;
  Q_DLV   = 32769
} as uint8_t

val q_type_to_int : q_type -> int

type rr_type =
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
| A of ipv4
| AAAA of string
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
| RT of uint16 * domain_name
| SOA of domain_name * domain_name * int32 * int32 * int32 * int32 * int32
| SRV of uint16 * uint16 * uint16 * domain_name
| SSHFP of pubkey_alg * fp_type * string
| TXT of string list
| UNKNOWN of int * string
| WKS of int32 * byte * string
| X25 of string
           (* udp size, rcode, do bit, options *)
| EDNS0 of (int * int * bool * ((int * string) list)) 

val hex_of_string : string -> string 
val rdata_to_string : rdata -> string
val rdata_to_rr_type : rdata -> rr_type
val marshal_rdata: (Name.domain_name, int) Hashtbl.t -> int -> buf -> rdata ->
  (rr_type *  (Name.domain_name, int) Hashtbl.t * int)

(** Parse an RDATA element from a packet, given the set of already encountered
    names, a starting index, and the type of the RDATA. *)
val parse_rdata : 
  (int, label) Hashtbl.t -> int -> rr_type -> int -> int32 -> buf -> rdata

(** The class of a {! rr}, and usual conversion functions. *)
type rr_class = RR_IN | RR_CS | RR_CH | RR_HS
val rr_class_to_string : rr_class -> string

(** A [resource record], with usual conversion and parsing functions. *)
type rr = {
  name  : domain_name;
  cls   : rr_class;
  ttl   : int32;
  rdata : rdata;
}
val rr_to_string : rr -> string
val marshal_rr : ((Name.domain_name, int) Hashtbl.t * int * buf) -> rr -> 
  ( (Name.domain_name, int) Hashtbl.t * int * buf)

val parse_rr :
  (int, label) Hashtbl.t -> int -> buf -> rr * (int * buf)

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
  (int, label) Hashtbl.t -> int -> buf -> question * (int * buf)

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
val parse : (int, label) Hashtbl.t -> buf -> t

(** The marshalling entry point, given a {! dns} structure. 

    @return the marshalled packet
*)
val marshal : buf -> t -> buf
