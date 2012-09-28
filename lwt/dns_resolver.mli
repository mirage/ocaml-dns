(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
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

open Dns.Name
open Dns.Packet
open Cstruct

(** Lookup a {! domain_name }.

    @return the corresponding {! ipv4 } addresses.
*)
val gethostbyname : 
  ?server:string -> ?dns_port:int -> ?q_class:q_class -> ?q_type:q_type
  -> string -> ipv4 list Lwt.t

(** Reverse lookup an {! ipv4 } address. 

    @return the corresponding {! domain_name }s.
*)
val gethostbyaddr : 
  ?server:string -> ?dns_port:int -> ?q_class:q_class -> ?q_type:q_type
  -> ipv4 -> string list Lwt.t

(** Resolve a fully specified query, {! q_class }, {! q_type } and {!
    domain_name }.

    @return the full a {! dns } structure.
*)
val resolve : 
  string -> int -> q_class -> q_type -> domain_name -> Dns.Packet.t Lwt.t

val default_configuration_file : string
val get_resolvers :
  ?file:Lwt_io.file_name -> unit -> Dns.Resolvconf.t Lwt.t
