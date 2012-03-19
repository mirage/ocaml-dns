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

(** DNS packet manipulation using the {! Bitstring} library. Something of a
    catch-all for the time being.

    @author Richard Mortier <mort\@cantab.net>
    @author Anil Madhavapeddy anil\@recoil.org>
    @author Haris Rotsos
*)

open Name
open Uri_IP
open Wire

(** Represent a DNSSEC algorithm, with the usual conversion functions. *)

type dnssec_alg
val int_to_dnssec_alg : int -> dnssec_alg
val dnssec_alg_to_int : dnssec_alg -> int
val dnssec_alg_to_string : dnssec_alg -> string

(** Represent the {! rr} type, with the usual conversion functions. *)

type rr_type = [ 
|`A | `A6 | `AAAA | `AFSDB | `APL | `ATMA | `CERT | `CNAME | `DNAME | `DNSKEY
| `DS | `EID | `GID | `GPOS | `HINFO | `IPSECKEY | `ISDN | `KEY | `KM | `LOC
| `MB | `MD | `MF | `MG | `MINFO | `MR | `MX | `NAPTR | `NIMLOC | `NS | `NSAP
| `NSAP_PTR | `NSEC | `NULL | `NXT | `OPT | `PTR | `PX | `RP | `RRSIG | `RT 
| `SIG | `SINK | `SOA | `SPF | `SRV | `SSHFP | `TXT | `UID | `UINFO | `UNSPEC 
| `Unknown of int * bytes | `WKS | `X25 ]
val int_to_rr_type : int -> rr_type
val rr_type_to_int : rr_type -> int
val rr_type_to_string : rr_type -> string

(** Represent RDATA elements; a variant type to avoid collision with the
    compact {! Trie} representation from {! RR}. *)

type rr_rdata = [
| `A of ipv4
| `AAAA of bytes
| `AFSDB of int16 * domain_name
| `CNAME of domain_name
| `DNSKEY of int * dnssec_alg * string 
| `HINFO of string * string
| `ISDN of string * string option
| `MB of domain_name
| `MD of domain_name
| `MF of domain_name
| `MG of domain_name
| `MINFO of domain_name * domain_name
| `MR of domain_name
| `MX of int16 * domain_name
| `NS of domain_name
| `PTR of domain_name
| `RP of domain_name * domain_name
| `RT of int16 * domain_name
| `SOA of domain_name * domain_name * int32 * int32 * int32 * int32 * int32
| `SRV of int16 * int16 * int16 * domain_name
| `TXT of string list
| `UNSPEC of bytes
| `WKS of int32 * byte * string
| `X25 of string 

| `UNKNOWN of int * bytes
]
val rdata_to_string : rr_rdata -> string

(** Parse an RDATA element from a packet, given the set of already encountered
    names, a starting index, and the type of the RDATA. *)
val parse_rdata : 
  (int, label) Hashtbl.t -> int -> rr_type -> Bitstring.t-> rr_rdata

(** The class of a {! rr}, and usual conversion functions. *)

type rr_class = [ `CH | `CS | `HS | `IN ]
val int_to_rr_class : int -> rr_class
val rr_class_to_int : rr_class -> int
val rr_class_to_string : rr_class -> string
val string_to_rr_class : string -> rr_class

(** A [resource record], with usual conversion and parsing functions. *)

type rr = {
  rr_name  : domain_name;
  rr_class : rr_class;
  rr_ttl   : int32;
  rr_rdata : rr_rdata;
}
val rr_to_string : rr -> string
val parse_rr :
  (int, label) Hashtbl.t -> int -> Bitstring.t -> rr * Bitstring.t

(** A question type, with the usual conversion functions. *)

type q_type = [ rr_type | `AXFR | `MAILB | `MAILA | `ANY | `TA | `DLV ]
val int_to_q_type : int -> q_type
val q_type_to_int : q_type -> int
val q_type_to_string : q_type -> string
val string_to_q_type : string -> q_type

(** A question class, with the usual conversion functions. *)

type q_class = [ rr_class | `NONE | `ANY ]
val int_to_q_class : int -> q_class
val q_class_to_int : q_class -> int
val q_class_to_string : q_class -> string
val string_to_q_class : string -> q_class

(** A question, with the usual conversion functions. *)

type question = {
  q_name  : domain_name;
  q_type  : q_type;
  q_class : q_class;
}
val question_to_string : question -> string
val parse_question :
  (int, label) Hashtbl.t -> int -> Bitstring.t -> question * Bitstring.t

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
val parse_detail : Bitstring.t -> detail
val build_detail : detail -> Bitstring.t

(** And finally, the DNS packet itself, with conversion functions. *)

type dns = {
  id          : int16;
  detail      : Bitstring.t;
  questions   : question list;
  answers     : rr list;
  authorities : rr list;
  additionals : rr list;
}
val dns_to_string : dns -> string
val parse_dns : (int, label) Hashtbl.t -> Bitstring.t-> dns

(** The marshalling entry point, given a {! dns} structure. 

    @return the marshalled packet
*)
val marshal_dns : dns -> Bitstring.t
