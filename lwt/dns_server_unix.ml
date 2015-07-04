(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2013-2015 David Sheets <sheets@alum.mit.edu>
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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
open Dns_server

let sp = Printf.sprintf

let bind_fd ~address ~port =
  let src =
    Lwt.catch (fun () ->
      (* should this be lwt hent = Lwt_lib.gethostbyname addr ? *)
      let hent = Unix.gethostbyname address in
      Lwt.return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), port)))
      (fun exn ->
         let err = sp "cannot resolve %s: %s" address (Printexc.to_string exn) in
         Lwt.fail (Failure err))
  in
  src >|= fun src ->
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let () = Lwt_unix.bind fd src in
  (fd, src)

let eventual_process_of_zonefiles zonefiles =
  Lwt_list.map_s (fun zonefile ->
    let lines = Lwt_io.lines_of_file zonefile in
    let buf = Buffer.create 1024 in
    Lwt_stream.iter (fun l ->
      Buffer.add_string buf l;
      Buffer.add_char buf '\n') lines
    >|= fun () ->
    Buffer.contents buf
  ) zonefiles
  >|= process_of_zonebufs

let bufsz = 4096

let ipaddr_of_sockaddr =
  function
  | Unix.ADDR_UNIX _ -> Lwt.fail (Failure "Unix domain sockets not supported")
  | Unix.ADDR_INET (ip,port) -> Lwt.return (Ipaddr_unix.of_inet_addr ip, port)

let listen ~fd ~src ~processor =
  let cont = ref true in
  let bufs = Lwt_pool.create 64 (fun () -> Lwt.return (Dns.Buf.create bufsz)) in
  ipaddr_of_sockaddr src
  >>= fun src ->
  let loop () =
    if not !cont then Lwt.return_unit
    else
      Lwt_pool.use bufs
        (fun buf ->
           Lwt_bytes.recvfrom fd buf 0 bufsz []
           >>= fun (len, dst) ->
           (* TODO Process in a background thread; should be a bounded queue *)
           Lwt.async (fun () ->
               ipaddr_of_sockaddr dst
               >>= fun dst' ->
               process_query buf len buf src dst' processor >>= function
               | None -> Lwt.return_unit
               | Some buf ->
                   Lwt_bytes.sendto fd buf 0 (Dns.Buf.length buf) [] dst
                   >>= fun _ -> Lwt.return_unit);
           Lwt.return_unit)
  in
  loop () >>= fun () ->
  let t, u = Lwt.task () in
  Lwt.on_cancel t (fun () -> cont := false);
  t

let serve_with_processor ~address ~port ~processor =
  bind_fd ~address ~port
  >>= fun (fd, src) -> listen ~fd ~src ~processor

let serve_with_zonebufs ~address ~port ~zonebufs =
  let process = process_of_zonebufs zonebufs in
  let processor = (processor_of_process process :> (module PROCESSOR)) in
  serve_with_processor ~address ~port ~processor

let serve_with_zonefiles ~address ~port ~zonefiles =
  eventual_process_of_zonefiles zonefiles
  >>= fun process ->
  let processor = (processor_of_process process :> (module PROCESSOR)) in
  serve_with_processor ~address ~port ~processor

let serve_with_zonebuf ~address ~port ~zonebuf =
  serve_with_zonebufs ~address ~port ~zonebufs:[zonebuf]

let serve_with_zonefile ~address ~port ~zonefile =
  serve_with_zonefiles ~address ~port ~zonefiles:[zonefile]
