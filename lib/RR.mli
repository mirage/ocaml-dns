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

open Uri_IP

(** DNS serial number -- 32 bits. *)
type serial = int32 

(** Character-string, memoised via {! Hashcons}. *)
and cstr = string Hashcons.hash_consed

(** A node in the trie. *)
and dnsnode = { 
  owner : string list Hashcons.hash_consed;
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
  | A of ipv4 list
  | NS of dnsnode list
  | CNAME of dnsnode list
  | SOA of (dnsnode * dnsnode * serial * int32 * int32 * int32 * int32) list
  | MB of dnsnode list
  | MG of dnsnode list
  | MR of dnsnode list
  | WKS of (int32 * int * cstr) list
  | PTR of dnsnode list
  | HINFO of (cstr * cstr) list
  | MINFO of (dnsnode * dnsnode) list
  | MX of (int * dnsnode) list
  | TXT of cstr list list
  | RP of (dnsnode * dnsnode) list
  | AFSDB of (int * dnsnode) list
  | X25 of cstr list
  | ISDN of (cstr * cstr option) list
  | RT of (int * dnsnode) list
  | AAAA of cstr list
  | SRV of (int * int * int * dnsnode) list
  | UNSPEC of cstr list
  | Unknown of int * cstr list

(* Hashcons values *)

(** Construct a {! Hashcons} character-string from a string. *)
val hashcons_charstring : string -> cstr

(** Construct a {! Hashcons} domain name (list of labels) from a domain
    name. *)
val hashcons_domainname : string list -> string list Hashcons.hash_consed

(** Clear the {! Hashcons} table. *)
val clear_cons_tables : unit -> unit

(** Extract relevant RRSets given a query type, a list of RRSets and a flag to
    say whether to return CNAMEs too. 

    @return the list of extracted {! rrset}s *)
val get_rrsets : 
  [> `A | `AAAA | `AFSDB | `ANY | `CNAME | `HINFO | `ISDN | `MAILB | `MB 
  | `MG | `MINFO | `MR | `MX | `NS | `PTR | `RP | `RT | `SOA 
  | `SRV | `TXT | `UNSPEC | `Unknown of int * string | `WKS | `X25 ] -> 
  rrset list -> bool -> rrset list

(** Merge a new RRSet into a list of RRSets, reversing the order of the RRsets
    in the list.

    @return the new list and the TTL of the resulting RRset. *)
val merge_rrset : rrset -> rrset list -> int32 * rrset list
