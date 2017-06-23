(*
 * Copyright (c) 2014 marklrh <marklrh@gmail.com>
 * Copyright (c) 2016 Vincent Bernardoff <vb@luminar.eu.org>
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

(** Async DNS resolution interface on Unix *)

open !Core
open !Async

val gethostbyname :
  ?log:Log.t ->
  ?server:string ->
  ?port:int ->
  ?q_class:Dns.Packet.q_class ->
  ?q_type:Dns.Packet.q_type ->
  string ->
  Ipaddr.t list Deferred.Or_error.t
