(*
 * Copyright (c) 2015 Luke Dunstan <LukeDunstan81@gmail.com>
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

type ip_endpoint = Ipaddr.V4.t * int

module type TRANSPORT = sig
  val alloc : unit -> Dns.Buf.t
  val write : ip_endpoint -> Dns.Buf.t -> unit Lwt.t
  val sleep : float -> unit Lwt.t
end

module Make : functor (Transport : TRANSPORT) -> sig
  type t

  val of_zonebufs : string list -> t
  val of_zonebuf : string -> t
  val of_db : Dns.Loader.db -> t

  val add_unique_hostname : t -> Dns.Name.domain_name -> Ipaddr.V4.t -> unit
  val first_probe : t -> unit Lwt.t
  val announce : t -> repeat:int -> unit Lwt.t
  val process : t -> src:ip_endpoint -> dst:ip_endpoint -> Dns.Buf.t -> unit Lwt.t
  val stop_probe : t -> unit Lwt.t

  val trie : t -> Dns.Trie.dnstrie
end

