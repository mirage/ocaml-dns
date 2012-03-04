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

(** Interface to 256-way radix trie for DNS lookups.
    Non-standard behaviour: 
    + We don't support '\000' as a character in labels (because it has a
    special meaning in the internal radix trie keys).
    + We don't support RFC2673 bitstring labels. Could be done but they're not
    worth the bother: nobody uses them.

    @author Tim Deegan
*)

(** Node of the trie *)
type dnstrie

(** Lookup key for the trie. *)
type key

(** Malformed input to {! canon2key}. *)
exception BadDomainName of string

(** Missing data from a SOA/cut node. *)
exception TrieCorrupt

(** Convert a canonical [[ "www"; "example"; "com" ]] domain name into a key.
    N.B. Requires that the input is already lower-case!  
*)
val canon2key : string list -> key

(** Make a new, empty trie. *) 
val new_trie : unit -> dnstrie

(** Simple lookup function: just walk the trie. *)
val simple_lookup : key -> dnstrie -> RR.dnsnode option

(** Look up a DNS entry in the trie, with full return. *)
val lookup : key -> dnstrie ->
    [> `Delegated of bool * RR.dnsnode
     | `Found of bool * RR.dnsnode * RR.dnsnode
     | `NXDomain of RR.dnsnode
     | `NXDomainNSEC of RR.dnsnode * RR.dnsnode * RR.dnsnode
     | `NoError of RR.dnsnode
     | `NoErrorNSEC of RR.dnsnode * RR.dnsnode
     | `Wildcard of RR.dnsnode * RR.dnsnode
     | `WildcardNSEC of RR.dnsnode * RR.dnsnode * RR.dnsnode ]

(** Return the data mapped from this key, making new data if there is none
    there yet. *)
val lookup_or_insert : key -> dnstrie -> ?parent:dnstrie
  -> (unit -> RR.dnsnode) 
  -> RR.dnsnode

(** Sort out flags for a key's node: call after adding or removing NS, SOA and
    KEY RRs *)
val fix_flags : key -> dnstrie -> unit
