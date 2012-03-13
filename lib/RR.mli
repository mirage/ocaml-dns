(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
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
 *
 *)

(** Datatypes and handling for DNS Resource Records and RRSets. 

    @author Tim Deegan
    @author Richard Mortier <mort\@cantab.net> (documentation)
*)

open Name
open Wire

(** DNS serial number -- 32 bits. *)
type serial = int32 
type cstr = string Hashcons.hash_consed

(** A node in the trie. *)
and dnsnode = { 
  owner : Name.domain_name Hashcons.hash_consed;
  (** The name for which the node contains memoised attributes. *)
  mutable rrsets : rrset list; 
(** The set of attributes as  resource records. *)
} 

(** An RRset, comprising a 32 bit TTL and an {!type: rdata} record. *)
and rrset = { ttl : int32; rdata : rdata; }

(** A resource record. 

    NB. These are as stored in the DNS trie, which associates lists of
    payloads with each type in an attempt at a compact representation. As only
    one payload of each type can be marshalled into an RR in a packet, this
    necessitates a two-phase marshalling process. To prevent type collisions,
    {! Packet} represents each RR as a variant type with the same name.
*)
and rdata =
  | A of Uri_IP.ipv4 list
  | AAAA of cstr list
  | AFSDB of (int16 * dnsnode) list
  | CNAME of dnsnode list
  | HINFO of (cstr * cstr) list
  | ISDN of (cstr * cstr option) list
  | MB of dnsnode list
  | MG of dnsnode list
  | MINFO of (dnsnode * dnsnode) list
  | MR of dnsnode list
  | MX of (int16 * dnsnode) list
  | NS of dnsnode list
  | PTR of dnsnode list
  | RP of (dnsnode * dnsnode) list
  | RT of (int16 * dnsnode) list
  | SOA of (dnsnode * dnsnode * serial * int32 * int32 * int32 * int32) list
  | SRV of (int16 * int16 * int16 * dnsnode) list
  | TXT of cstr list list
  | UNSPEC of cstr list
(*   | DNSKEY of bool * dnssec_alg * string *)
  | Unknown of int * cstr list
  | WKS of (int32 * byte * cstr) list
  | X25 of cstr list

(** Extract relevant RRSets given a query type, a list of RRSets and a flag to
    say whether to return CNAMEs too. 

    @return the list of extracted {! rrset}s *)
val get_rrsets : Packet.q_type -> rrset list -> bool -> rrset list

(** Merge a new RRSet into a list of RRSets, reversing the order of the RRsets
    in the list.

    @return the new list and the TTL of the resulting RRset. *)
val merge_rrset : rrset -> rrset list -> int32 * rrset list
