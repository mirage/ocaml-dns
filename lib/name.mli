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

(** Domain name and label handling.

    @author Tim Deegan
    @author Richard Mortier <mort\@cantab.net> (documentation)
*)

open Cstruct

(** DNS label, including pointer and zero. *)
type label

(** Domain name, as a list of strings. *)
type domain_name = string list

(** Render a {! domain_name} to a simple string. *)
val domain_name_to_string : domain_name -> string

(** Convert a standard domain {! string} to a {! domain_name}. *)
val string_to_domain_name : string -> domain_name

(** Construct name for reverse lookup given an {! ipv4} address. *)
val for_reverse : ipv4 -> domain_name

(** Parse a {! domain_name} out of a {! Bitstring.t} given a set of already
    observed names from the packet, and the offset we are into the packet.
    
    @return {! domain_name} and the remainder
*)
val parse_name : 
  (int, label) Hashtbl.t -> int -> buf -> domain_name * (int * buf)

val marshal_name :
  (domain_name, int) Hashtbl.t -> int -> buf -> domain_name
  -> ((domain_name, int) Hashtbl.t * int * buf)
     
(** Construct a {! Hashcons} character-string from a string. *)
val hashcons_charstring : string -> string Hashcons.hash_consed

(** Construct a {! Hashcons} domain name (list of labels) from a {!
    domain_name}. *)
val hashcons_domainname : domain_name -> domain_name Hashcons.hash_consed

(** Clear the {! Hashcons} tables. *)
val clear_cons_tables : unit -> unit

(** Malformed input to {! canon2key}. *)
exception BadDomainName of string

(** Lookup key for the {! Trie}. *)
type key = string

(** Convert a canonical [[ "www"; "example"; "com" ]] domain name into a key.
    N.B. Requires that the input is already lower-case!  
*)
val canon2key : domain_name -> key








