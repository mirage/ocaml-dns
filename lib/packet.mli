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

open Name
open Uri_IP
open Wire

type rr_type = [
| `A | `NS | `MD | `MF | `CNAME | `SOA | `MB | `MG | `MR | `NULL 
| `WKS | `PTR | `HINFO | `MINFO | `MX | `TXT | `RP | `AFSDB | `X25 
| `ISDN | `RT | `NSAP | `NSAP_PTR | `SIG | `KEY | `PX | `GPOS | `AAAA 
| `LOC | `NXT | `EID | `NIMLOC | `SRV | `ATMA | `NAPTR | `KM | `CERT 
| `A6 | `DNAME | `SINK | `OPT | `APL | `DS | `SSHFP | `IPSECKEY 
| `RRSIG | `NSEC | `DNSKEY | `SPF | `UINFO | `UID | `GID | `UNSPEC
| `Unknown of int * bytes
]
val int_to_rr_type : int -> rr_type
val rr_type_to_int : rr_type -> int
val rr_type_to_string : rr_type -> string

type rr_rdata = [
| `A of ipv4
| `AAAA of bytes
| `AFSDB of int16 * domain_name
| `CNAME of domain_name
| `HINFO of string * string
| `ISDN of string
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
val parse_rdata : 
  (int, label) Hashtbl.t -> int -> rr_type -> Bitstring.t-> rr_rdata

type rr_class = [ `CH | `CS | `HS | `IN ]
val int_to_rr_class : int -> rr_class
val rr_class_to_int : rr_class -> int
val rr_class_to_string : rr_class -> string

type rr = {
  rr_name  : domain_name;
  rr_class : rr_class;
  rr_ttl   : int32;
  rr_rdata : rr_rdata;
}
val rr_to_string : rr -> string
val parse_rr :
  (int, label) Hashtbl.t -> int -> Bitstring.t -> rr * Bitstring.t

type q_type = [ rr_type | `AXFR | `MAILB | `MAILA | `ANY | `TA | `DLV ]
val int_to_q_type : int -> q_type
val q_type_to_int : q_type -> int
val q_type_to_string : q_type -> string

type q_class
val int_to_q_class : int -> q_class
val q_class_to_int : q_class -> int
val q_class_to_string : q_class -> string

type question
val question_to_string : question -> string
val parse_question :
  (int, label) Hashtbl.t -> int -> Bitstring.t -> question * Bitstring.t

type qr
val bool_to_qr : bool -> qr
val qr_to_bool : qr -> bool

type opcode
val int_to_opcode : int -> opcode
val opcode_to_int : opcode -> int

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

type detail
val detail_to_string : detail -> string
val parse_detail : Bitstring.t -> detail
val build_detail : detail -> Bitstring.t

type dns
val dns_to_string : dns -> string
val parse_dns : (int, label) Hashtbl.t -> Bitstring.t-> dns
val marshal_dns : dns -> Bitstring.t
