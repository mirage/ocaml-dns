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
 * dnsloader.mli -- how to build up a DNS trie from separate RRs
 *
 *)

open Name
open Uri_IP
open Wire

(* Loader database: the DNS trie plus a hash table of other names in use *)
type db = { trie : Trie.dnstrie; 
	    mutable names : (Name.key, RR.dnsnode) Hashtbl.t; } 

(* Make a new, empty database *)
val new_db : unit -> db

(* Call when guaranteed there will be no more updates *)
val no_more_updates : db -> unit

(* Insert RRs in the database: args are rdata, ttl, owner, db *)
val add_generic_rr : int -> string -> int32 -> domain_name -> db -> unit
val add_a_rr : ipv4 -> int32 -> domain_name -> db -> unit
val add_ns_rr : domain_name -> int32 -> domain_name -> db -> unit
val add_cname_rr : domain_name -> int32 -> domain_name -> db -> unit
val add_soa_rr : 
    domain_name -> domain_name -> RR.serial -> 
      int32 -> int32 -> int32 -> int32 -> 
	int32 -> domain_name -> db -> unit
val add_mb_rr : domain_name -> int32 -> domain_name -> db -> unit
val add_mg_rr : domain_name -> int32 -> domain_name -> db -> unit
val add_mr_rr : domain_name -> int32 -> domain_name -> db -> unit
val add_wks_rr : int32 -> int16 -> string -> int32 -> domain_name -> db -> unit
val add_ptr_rr : domain_name -> int32 -> domain_name -> db -> unit
val add_hinfo_rr : string -> string -> int32 -> domain_name -> db -> unit
val add_minfo_rr : 
    domain_name -> domain_name -> int32 -> domain_name -> db -> unit
val add_mx_rr : int -> domain_name -> int32 -> domain_name -> db -> unit
val add_txt_rr : string list -> int32 -> domain_name -> db -> unit
val add_rp_rr :
    domain_name -> domain_name -> int32 -> domain_name -> db -> unit
val add_afsdb_rr : int -> domain_name -> int32 -> domain_name -> db -> unit
val add_x25_rr : string -> int32 -> domain_name -> db -> unit
val add_isdn_rr : string -> string option -> int32 -> domain_name -> db -> unit
val add_rt_rr : int -> domain_name -> int32 -> domain_name -> db -> unit
val add_aaaa_rr : string -> int32 -> domain_name -> db -> unit
val add_srv_rr :
  int -> int -> int -> domain_name -> int32 -> domain_name -> db -> unit
val add_unspec_rr : string -> int32 -> domain_name -> db -> unit


(* Raised if we already had an RRSet for this name and type, but with 
   a different TTL.  Also possible: Trie.BadName.
   N.B. If TTLMismatch is raised, the RR was successfully added, and the RRSet
        now has the new ttl. *) 
exception TTLMismatch;;


(* State variables for the parser & lexer *)
type parserstate = {
    mutable db: db;
    mutable paren: int;
    mutable filename: string;
    mutable lineno: int;
    mutable origin: string list;
    mutable ttl: int32;
    mutable owner: string list;
  }
val state : parserstate
