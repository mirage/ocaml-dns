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

exception Dns_resolve_timeout

type t = {
  servers : (string * int) list;
  search_domains : string list;
}

type config = [
  | `Resolv_conf of string
  | `Static of (string * int) list * string list
]

(** Create a resolver instance that either uses the system
    /etc/resolv.conf, or a statically specified preference
  *)
val create : ?config:config -> unit -> t Lwt.t

(** Lookup a {! domain_name }.

    @return the corresponding {! ipv4 } addresses.
*)
val gethostbyname : t -> ?q_class:q_class -> ?q_type:q_type
  -> string -> ipv4 list Lwt.t

(** Reverse lookup an {! ipv4 } address.

    @return the corresponding {! domain_name }s.
*)
val gethostbyaddr : t -> ?q_class:q_class -> ?q_type:q_type
  -> ipv4 -> string list Lwt.t

(** Resolve a fully specified query, {! q_class }, {! q_type } and {!
    domain_name }.

    @return the full a {! dns } structure.
*)
val resolve : t -> ?dnssec:bool -> q_class -> q_type ->
  domain_name -> Dns.Packet.t Lwt.t

val send_pkt : t -> Dns.Packet.t -> Dns.Packet.t Lwt.t
val build_query : ?dnssec:bool -> q_class -> q_type ->
  Name.domain_name -> Dns.Packet.t
