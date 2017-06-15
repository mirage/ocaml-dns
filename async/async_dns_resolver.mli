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

(** Async DNS resolution logic *)

open Core_kernel
open Async
open Dns

type commfn = {
  log : Log.t option;
  txfn : Cstruct.t -> unit Deferred.t;
  rxfn : (Cstruct.t -> Packet.t option) -> Packet.t Deferred.t;
  timerfn : unit -> unit Deferred.t;
  cleanfn : unit -> unit Deferred.t;
}

val resolve :
  ?alloc:(unit -> Cstruct.t) ->
  ?dnssec:bool ->
  (module Protocol.CLIENT) ->
  commfn ->
  Packet.q_class ->
  Packet.q_type ->
  Name.t -> Packet.t Deferred.Or_error.t

val gethostbyname :
  ?alloc:(unit -> Cstruct.t) ->
  ?q_class:Packet.q_class ->
  ?q_type:Packet.q_type ->
  commfn ->
  string ->
  Ipaddr.t list Deferred.Or_error.t
