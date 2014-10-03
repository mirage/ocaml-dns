(*
 * Copyright (c) 2014 marklrh <marklrh@gmail.com>
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

type result = Answer of DP.t | Error of exn
type commfn = {
  txfn : Dns.Buf.t -> unit Async_kernel.Deferred.t;
  rxfn : (Dns.Buf.t -> Dns.Packet.t option) -> DP.t Async_kernel.Deferred.t;
  timerfn : unit -> unit Async_kernel.Deferred.t;
  cleanfn : unit -> unit Async_kernel.Deferred.t;
}
val stdout_writer : unit -> Async_unix.Writer.t
val stderr_writer : unit -> Async_unix.Writer.t
val message : string -> unit
val warn : string -> unit
val nchoose_split :
  'a Async_kernel.Deferred.t list ->
  ('a list * 'a Async_kernel.Deferred.t list) Async_kernel.Deferred.t
val send_req :
  ('a -> 'b Async_kernel.Deferred.t) ->
  (unit -> unit Async_kernel.Deferred.t) ->
  'a -> int -> unit Async_kernel.Deferred.t
val send_pkt :
  (module Dns.Protocol.CLIENT) ->
  commfn -> DP.t -> DP.t Async_kernel.Deferred.t
val resolve :
  (module Dns.Protocol.CLIENT) ->
  ?dnssec:bool ->
  commfn ->
  DP.q_class ->
  DP.q_type -> Dns.Name.domain_name -> DP.t Async_kernel.Deferred.t
val gethostbyname :
  ?q_class:DP.q_class ->
  ?q_type:DP.q_type ->
  commfn ->
  string ->
  (Ipaddr.V4.t, Ipaddr.V6.t) Ipaddr.v4v6 list Async_kernel.Deferred.t
