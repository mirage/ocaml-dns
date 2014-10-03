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
val buflen : int
val ns : string
val port : int
val stderr_writer : unit -> Async_unix.Writer.t
val log_warn : string -> unit
val sockaddr : string -> int -> Async.Std.Socket.Address.Inet.t
val sockaddr_to_string : [< Async.Std.Socket.Address.t ] -> string
val active_sock_exn :
  string ->
  int ->
  [ `Interrupted
  | `Ok of
      ([ `Active ], Async.Std.Socket.Address.Inet.t)
      Async_extra.Import.Socket.t ]
  Async_kernel.Deferred.t
val timerfn : unit -> unit Async_kernel.Deferred.t
val cleanfn :
  ([< `Active | `Bound | `Passive | `Unconnected ],
   [< Async.Std.Socket.Address.t ])
  Async_extra.Import.Socket.t -> unit -> unit Async_kernel.Deferred.t
val connect_to_resolver :
  string -> int -> Async_dns_resolver.commfn Async_kernel.Deferred.t
val resolve :
  (module Dns.Protocol.CLIENT) ->
  ?dnssec:bool ->
  string ->
  int ->
  DP.q_class ->
  DP.q_type -> Dns.Name.domain_name -> DP.t Async_kernel.Deferred.t
val gethostbyname :
  ?server:string ->
  ?dns_port:int ->
  ?q_class:DP.q_class ->
  ?q_type:DP.q_type ->
  string ->
  (Ipaddr.V4.t, Ipaddr.V6.t) Ipaddr.v4v6 list Async_kernel.Deferred.t
