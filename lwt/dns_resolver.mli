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
exception Dns_resolve_error of exn list

(** The type of pluggable DNS resolver modules for request contexts and
    custom metadata and wire protocols.
*)
module type RESOLVER = sig
  type context

  val get_id : unit -> int

  (** [marshal query] is a list of context-buffer pairs corresponding to the
      channel contexts and request buffers with which to attempt DNS requests.
      Requests are made in parallel and the first response to successfully
      parse is returned as the answer. Lagging requests are kept running until
      successful parse or timeout. With this behavior, it is easy to construct
      low-latency but network-environment-aware DNS resolvers.
  *)
  val marshal : Dns.Packet.t -> (context * Dns.Buf.t) list

  (** [parse ctxt buf] is the potential packet extracted out of [buf]
      with [ctxt]
  *)
  val parse : context -> Dns.Buf.t -> Dns.Packet.t option

  (** [timeout ctxt] is the exception resulting from a context [ctxt] that has
      timed-out
  *)
  val timeout : context -> exn
end

(** The default DNS resolver using the standard DNS protocol *)
module DNSProtocol : RESOLVER

type t = {
  resolver : (module RESOLVER);
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
val create : ?resolver:(module RESOLVER) -> ?config:config -> unit -> t Lwt.t

(** Lookup a {! domain_name }.

    @return the corresponding IPv4 addresses.
*)
val gethostbyname : t -> ?q_class:q_class -> ?q_type:q_type
  -> string -> Ipaddr.V4.t list Lwt.t

(** Reverse lookup an IPv4 address.

    @return the corresponding {! domain_name }s.
*)
val gethostbyaddr : t -> ?q_class:q_class -> ?q_type:q_type
  -> Ipaddr.V4.t -> string list Lwt.t

(** Resolve a fully specified query, {! q_class }, {! q_type } and {!
    domain_name }.

    @return the full a {! dns } structure.
*)
val resolve : t -> ?dnssec:bool -> q_class -> q_type ->
  domain_name -> Dns.Packet.t Lwt.t

val send_pkt : t -> Dns.Packet.t -> Dns.Packet.t Lwt.t
