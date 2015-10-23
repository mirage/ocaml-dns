(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
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

open Lwt

let load_file path =
  let ch = open_in path in
  let n = in_channel_length ch in
  let data = Bytes.create n in
  really_input ch data 0 n;
  close_in ch;
  data

let bufsz = 4096

let ipaddr_of_sockaddr =
  function
  | Unix.ADDR_UNIX _ -> Lwt.fail (Failure "Unix domain sockets not supported")
  | Unix.ADDR_INET (ip,port) -> Lwt.return (Ipaddr_unix.of_inet_addr ip, port)

let listen ~fd ~src ~processor processor =
  let cont = ref true in
  let bufs = Lwt_pool.create 64 (fun () -> Lwt.return (Dns.Buf.create bufsz)) in
  ipaddr_of_sockaddr src
  >>= fun src ->
  let rec loop () =
    if not !cont then Lwt.return_unit
    else
      Lwt_pool.use bufs
        (fun buf ->
           Lwt_bytes.recvfrom fd buf 0 bufsz []
           >>= fun (len, dst) ->
           ipaddr_of_sockaddr dst
           >>= fun dst' ->
           processor ~src ~dst:dst' buf
           >>= fun _ -> return_unit
        )
      >>= fun () ->
      loop ()
  in
  Lwt.async loop;
  let t, u = Lwt.task () in
  Lwt.on_cancel t (fun () -> cont := false);
  t

let t =
  let src = Ipaddr.V4.localhost, 5353 in
  Mdns_responder_unix.init ~src () >>= fun ((module M : Mdns_responder.RESPONDER), fd) ->
  let zf = load_file "test_mdns.zone" in
  let t = M.of_zonebuf zf in
  let ann_t = M.announce ~repeat:5 t in
  prerr_endline "announce started";
  return ()

let _ = Lwt_main.run t
