(*
 * Copyright (c) 2015 Anil Madhavapeddy <anil.madhavapeddy@unikernel.com>
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

open Lwt.Infix

let bind_fd ?src () =
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  match src with
  | Some (address, port) ->
    let sa = Unix.ADDR_INET (Ipaddr_unix.V4.to_inet_addr address, port) in
    Lwt_unix.bind fd sa;
    Lwt.return fd
  | None -> Lwt.return fd

let init ?src () =
  bind_fd ?src () >>= fun fd ->
  let (module Transport) = (module struct
    let alloc () = Dns.Buf.create 4096
    let sleep = Lwt_unix.sleep
    let write (ip, port) buf =
      let dst = Unix.ADDR_INET (Ipaddr_unix.V4.to_inet_addr ip, port) in
      Lwt_bytes.sendto fd buf 0 (Dns.Buf.length buf) [] dst
      >>= fun _ -> Lwt.return_unit
  end : Mdns_responder.TRANSPORT) in
  let module R = Mdns_responder.Make(Transport) in
  Lwt.return ((module R : Mdns_responder.RESPONDER), fd)
