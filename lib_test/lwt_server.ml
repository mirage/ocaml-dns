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
open Dns_server

let t =
  try_lwt
  lwt zonebuf =
     let lines = Lwt_io.lines_of_file "test.zone" in
     let buf = Buffer.create 1024 in
     lwt () = Lwt_stream.iter (fun l -> Buffer.add_string buf l; Buffer.add_char buf '\n') lines in
     return (Buffer.contents buf)
  in
  let spec = {
     zonebuf;
     port=5354;
     address="0.0.0.0";
     mode=`none;
  } in
    listen spec
  with exn ->
    Printf.eprintf "exn: %s\n%!" (Printexc.to_string exn);
    return ()

let _ = Lwt_unix.run t
