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

type digest_alg
type gw_type
type pubkey_alg
type ipseckey_alg
type gateway
type hash_alg
type fp_type

(** Represent a DNSSEC algorithm, with the usual conversion functions. *)

type dnssec_alg
val int_to_dnssec_alg : int -> dnssec_alg
val dnssec_alg_to_int : dnssec_alg -> int
val string_to_dnssec_alg : string -> dnssec_alg
val dnssec_alg_to_string : dnssec_alg -> string

(** Represent the {! rr} type, with the usual conversion functions. *)


type rr_type
(*
 = [ 
| `A | `NS | `MD | `MF | `CNAME | `SOA | `MB | `MG | `MR | `NULL 
| `WKS | `PTR | `HINFO | `MINFO | `MX | `TXT | `RP | `AFSDB | `X25 
| `ISDN | `RT | `NSAP | `NSAP_PTR | `SIG | `KEY | `PX | `GPOS | `AAAA 
| `LOC | `NXT | `EID | `NIMLOC | `SRV | `ATMA | `NAPTR | `KM | `CERT 
| `A6 | `DNAME | `SINK | `OPT | `APL | `DS | `SSHFP | `IPSECKEY | `RRSIG
| `NSEC | `DNSKEY | `NSEC3 | `NSEC3PARAM | `SPF | `UINFO | `UID | `GID
| `UNSPEC
| `Unknown of int * bytes
]
val rr_type_to_int : rr_type -> int
val int_to_rr_type : int -> rr_type
val rr_type_to_string : rr_type -> string
val string_to_rr_type : string -> rr_type
*)
type type_bit_map
type type_bit_maps

(** Represent RDATA elements; a variant type to avoid collision with the
    compact {! Trie} representation from {! RR}. *)

type rr_rdata = [
| `A of ipv4
| `AAAA of bytes
| `AFSDB of uint16 * domain_name
| `CNAME of domain_name
| `DNSKEY of uint16 * dnssec_alg * string
| `DS of uint16 * dnssec_alg * digest_alg * string
| `HINFO of string * string
| `IPSECKEY of byte * gw_type * ipseckey_alg * gateway * bytes
| `ISDN of string * string option
| `MB of domain_name
| `MD of domain_name
| `MF of domain_name
| `MG of domain_name
| `MINFO of domain_name * domain_name
| `MR of domain_name
| `MX of uint16 * domain_name
| `NS of domain_name
| `NSEC of domain_name (* uncompressed *) * type_bit_maps
| `NSEC3 of hash_alg * byte * uint16 * byte * bytes * byte * bytes * 
    type_bit_maps
| `NSEC3PARAM of hash_alg * byte * uint16 * byte * bytes
| `PTR of domain_name
| `RP of domain_name * domain_name
| `RRSIG of rr_type * dnssec_alg * byte * int32 * int32 * int32 * uint16 * 
    domain_name (* uncompressed *) * bytes
| `RT of uint16 * domain_name
| `SOA of domain_name * domain_name * int32 * int32 * int32 * int32 * int32
| `SRV of uint16 * uint16 * uint16 * domain_name
| `SSHFP of pubkey_alg * fp_type * bytes
| `TXT of string list
| `UNKNOWN of int * bytes
| `UNSPEC of bytes
| `WKS of int32 * byte * string
| `X25 of string 
]
val rdata_to_string : rr_rdata -> string

(** Parse an RDATA element from a packet, given the set of already encountered
    names, a starting index, and the type of the RDATA. *)
val parse_rdata : 
  (int, label) Hashtbl.t -> int -> rr_type -> Cstruct.buf-> rr_rdata

(** The class of a {! rr}, and usual conversion functions. *)

type rr_class = [ `CH | `CS | `HS | `IN ]
(*
val int_to_rr_class : int -> rr_class
val rr_class_to_int : rr_class -> int
val rr_class_to_string : rr_class -> string
val string_to_rr_class : string -> rr_class
*)
(** A [resource record], with usual conversion and parsing functions. *)

type rr = {
  name  : domain_name;
  cls : rr_class;
  ttl   : int32;
  rdata : rr_rdata;
}
val rr_to_string : rr -> string
val parse_rr :
  (int, label) Hashtbl.t -> int -> Cstruct.buf -> rr * Cstruct.buf

(** A question type, with the usual conversion functions. *)

type q_type
(*
 = [ rr_type | `AXFR | `MAILB | `MAILA | `ANY | `TA | `DLV ]
val int_to_q_type : int -> q_type
val q_type_to_int : q_type -> int
val q_type_to_string : q_type -> string
val string_to_q_type : string -> q_type
*)

(** A question class, with the usual conversion functions. *)

type q_class
(*
 = [ rr_class | `NONE | `ANY ]
val int_to_q_class : int -> q_class
val q_class_to_int : q_class -> int
val q_class_to_string : q_class -> string
val string_to_q_class : string -> q_class
*)

(** A question, with the usual conversion functions. *)

type question = {
  q_name  : domain_name;
  q_type  : q_type;
  q_class : q_class;
}
val question_to_string : question -> string
val parse_question :
  (int, label) Hashtbl.t -> int -> Cstruct.buf -> question * Cstruct.buf

(** The [qr] field from the DNS header {! detail}. *)

type qr = [ `Query | `Answer ]
val bool_to_qr : bool -> qr
val qr_to_bool : qr -> bool

(** A DNS opcode, with the usual conversion functions. *)

type opcode = [ qr | `Status | `Reserved | `Notify | `Update ]
val int_to_opcode : int -> opcode
val opcode_to_int : opcode -> int

(** A DNS response code, with the usual conversion functions. *)

type rcode = [
| `NoError  | `FormErr
| `ServFail | `NXDomain | `NotImp  | `Refused
| `YXDomain | `YXRRSet  | `NXRRSet | `NotAuth
| `NotZone  | `BadVers  | `BadKey  | `BadTime
| `BadMode  | `BadName  | `BadAlg 
]
val int_to_rcode : int -> rcode
val rcode_to_int : rcode -> int
val rcode_to_string : rcode -> string

(** The [detail] field from the DNS header, with the usual conversion
    functions. *)
                 
(*
type detail = {
  qr: qr;
  opcode: opcode;
  aa: bool; 
  tc: bool; 
  rd: bool; 
  ra: bool;
  rcode: rcode;
}
val detail_to_string : detail -> string
val parse_detail : Cstruct.buf -> detail
val build_detail : detail -> Cstruct.buf
*)

(** And finally, the DNS packet itself, with conversion functions. *)

type dns = {
  id          : uint16;
  detail      : Bitstring.t;
  questions   : question list;
  answers     : rr list;
  authorities : rr list;
  additionals : rr list;
}
(*
val dns_to_string : dns -> string
*)
val parse_dns : (int, label) Hashtbl.t -> Bitstring.t-> dns

(*
(** The marshalling entry point, given a {! dns} structure. 

    @return the marshalled packet
*)
val marshal_dns : dns -> Bitstring.t
*)
