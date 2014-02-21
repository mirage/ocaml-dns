(*
 * Copyright (c) 2011-2014 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
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

open Dns_server

(** Given a source address and a port, return a bound file descriptor and
    source sockaddr suitable for passing to the [listen] functions *)
val bind_fd :
  address:string -> port:int -> (Lwt_unix.file_descr * Lwt_unix.sockaddr) Lwt.t

val eventual_process_of_zonefile : string -> Dns.Packet.t process Lwt.t

(** General listening function for DNS servers. Pass in the [fd] and
    [src] from calling [bind_fd] and supply a [processor] which
    deserializes the wire format, generates a DNS response packet,
    and serializes it into the wire format
*)
val listen :
  fd:Lwt_unix.file_descr -> src:Lwt_unix.sockaddr
  -> processor:(module PROCESSOR) -> unit Lwt.t

val serve_with_processor :
  address:string -> port:int -> processor:(module PROCESSOR) -> unit Lwt.t

val serve_with_zonebuf :
  address:string -> port:int -> zonebuf:string -> unit Lwt.t

val serve_with_zonefile :
  address:string -> port:int -> zonefile:string -> unit Lwt.t

