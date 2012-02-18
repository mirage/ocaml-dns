(*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
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

(** Given a source address and a port, return a bound file descriptor
  * and source sockaddr suitable for passing to the [listen] functions
  *)
val bind_fd : address:string -> port:int -> (Lwt_unix.file_descr * Lwt_unix.sockaddr) Lwt.t

(** DNS responder function.
  * @param src Server sockaddr
  * @param dst Client sockaddr 
  * @param Query packet
  * @return Answer packet
  *)
type dnsfn = src:Lwt_unix.sockaddr -> dst:Lwt_unix.sockaddr -> Dns.Packet.dns -> Dns.Packet.dns Lwt.t

(** General listening function for dynamic DNS servers.  Pass in the [fd] and [src] from
  * calling [bind_fd] and supply a [dnsfn] which responds with a response DNS packet
  *)
val listen : fd:Lwt_unix.file_descr -> src:Lwt_unix.sockaddr -> dnsfn:dnsfn -> unit Lwt.t

val listen_with_zonebuf : address:string -> port:int -> zonebuf:string -> mode:[ `none ] -> unit Lwt.t

val listen_with_zonefile : address:string -> port:int -> zonefile:string -> unit Lwt.t

