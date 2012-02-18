(*
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>
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
open Printf

module DL = Loader
module DQ = Query
module DR = RR
module DP = Packet

type dnsfn = fd:Lwt_unix.file_descr -> src:Lwt_unix.sockaddr -> dst:Lwt_unix.sockaddr -> Dns.Packet.dns -> unit Lwt.t

let bind_fd ~address ~port =
  lwt src = try_lwt
    (* should this be lwt hent = Lwt_lib.gethostbyname addr ? *)
    let hent = Unix.gethostbyname address in
    return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), port))
  with _ ->
    raise_lwt (Failure ("cannot resolve " ^ address))
  in
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let () = Lwt_unix.bind fd src in
  return (fd,src)

let listen ~fd ~src ~dnsfn =
  let cont = ref true in
  let bufs = Lwt_pool.create 64 (fun () -> return (String.make 1024 '\000')) in
  let _ =
    let names = Hashtbl.create 64 in
    while_lwt !cont do
      Lwt_pool.use bufs (fun buf ->
        lwt len, dst = Lwt_unix.recvfrom fd buf 0 (String.length buf) [] in
        let bits = buf, 0, (len*8) in
        (* TODO exception handler *)
        let packet = DP.parse_dns names bits in
        dnsfn ~fd ~src ~dst packet
      )
    done
  in
  let t,u = Lwt.task () in
  Lwt.on_cancel t
    (fun () ->
       Printf.eprintf "listen: canceled\n%!";
       cont := false
    );
  Printf.eprintf "listen: done\n%!";
  t

let listen_with_zonebuf ~address ~port ~zonebuf ~mode =
  Zone.load_zone [] zonebuf;
  lwt fd, src = bind_fd ~address ~port in
  let dnstrie = DL.(state.db.trie) in
  let get_answer qname qtype id =
    let qname = List.map String.lowercase qname in  
    let ans = DQ.answer_query qname qtype dnstrie in
    let detail = DP.(build_detail { qr=`Answer; opcode=`Query; 
      aa=ans.DQ.aa; tc=false; rd=false; ra=false; rcode=ans.DQ.rcode;  })      
    in
    let questions = [ DP.({ q_name=qname; q_type=qtype; q_class=`IN }) ] in
    DP.({ id; detail; questions; answers=ans.DQ.answer; 
          authorities=ans.DQ.authority; additionals=ans.DQ.additional; 
    })
  in
  let (dnsfn:dnsfn) =
    match mode with
    |`none ->
      (fun ~fd ~src ~dst d ->
         let open DP in
         let q = List.hd d.questions in
         let r = get_answer q.q_name q.q_type d.id in
         let buf, boff, blen = marshal r in
         let _ = Lwt_unix.sendto fd buf (boff/8) (blen/8) [] dst in
         return ()
      )
  in
  listen ~fd ~src ~dnsfn

let listen_with_zonefile ~address ~port ~zonefile =
  lwt zonebuf =
     let lines = Lwt_io.lines_of_file zonefile in
     let buf = Buffer.create 1024 in
     lwt () = Lwt_stream.iter (fun l -> Buffer.add_string buf l; Buffer.add_char buf '\n') lines in
     return (Buffer.contents buf)
  in
  listen_with_zonebuf ~address ~port ~zonebuf ~mode:`none

