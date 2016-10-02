(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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

open Dns

type protocol = [
  | `Tcp (** force the use of TCP only *)
  | `Udp (** force the use of UDP only *)
  | `Automatic (** choose automatically depending on query type and size *)
]

type t = {
  client : (module Protocol.CLIENT);
  servers : (Ipaddr.t * int) list;
  search_domains : string list;
  protocol : protocol;
}

(** Defines the location of the stub resolvers to use for
    client resolution. *)
type config = [
  | `Resolv_conf of string  (** A [resolv.conf] filename *)
  | `Static of (Ipaddr.t * int) list * string list (** A list of [hostname,port] of stub resolvers, and a search domain list *)
]

(** Create a resolver instance that either uses the system
    [/etc/resolv.conf], or a statically specified preference
  *)
val create : ?client:(module Protocol.CLIENT) -> ?config:config
  -> ?protocol:protocol -> unit -> t Lwt.t

(** Lookup a {! Name.t }.
    @return the corresponding IPv4/6 addresses.
*)
val gethostbyname : t -> ?q_class:Packet.q_class -> ?q_type:Packet.q_type
  -> string -> Ipaddr.t list Lwt.t

(** Reverse lookup an IPv4 address.
    @return the corresponding {! Name.t }s.
*)
val gethostbyaddr : t -> ?q_class:Packet.q_class -> ?q_type:Packet.q_type
  -> Ipaddr.V4.t -> string list Lwt.t

(** Resolve a fully specified query, {! q_class }, {! q_type } and {! Name.t }.
    @return the full a {! dns } structure.
*)
val resolve : t -> ?dnssec:bool -> Packet.q_class -> Packet.q_type -> Name.t ->
              Packet.t Lwt.t
