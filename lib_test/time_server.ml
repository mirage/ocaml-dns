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

let time_rsrc_record () =
  let rr_name = ["time";"com"] in
  let rr_class = `IN in
  let rr_ttl = 100l in
  let time = string_of_float (Unix.gettimeofday ()) in
  let rr_rdata = `TXT [ "the"; "time"; "is"; time] in
  { DP.rr_name; rr_class; rr_ttl; rr_rdata }

let get_answer qname qtype id =
  let qname = List.map String.lowercase qname in  
  let answer = [ time_rsrc_record () ] in
  let ans = { DQ.rcode=`NoError; aa=true; authority=[]; additional=[]; answer } in
  let detail = 
    DP.(build_detail { qr=`Answer; opcode=`Query; 
                       aa=ans.DQ.aa; tc=false; rd=false; ra=false; 
                       rcode=ans.DQ.rcode;  
                     })      
  in
  let questions = [ DP.({ q_name=qname; q_type=qtype; q_class=`IN }) ] in
  DP.({ id; detail; questions;
        answers=ans.DQ.answer; 
        authorities=ans.DQ.authority; 
        additionals=ans.DQ.additional; 
      })

let send_answer fd ~src ~dst bits =
  let names = Hashtbl.create 8 in
  DP.(
    let d = parse_dns names bits in
    let q = List.hd d.questions in
    Printf.eprintf "query: %s\n%!" (DP.question_to_string q);
    let r = get_answer q.q_name q.q_type d.id in
    let buf,boff,blen = marshal r in
    let _ = Lwt_unix.sendto fd buf (boff/8) (blen/8) [] dst in
    return ()
  )

let listen (addr,port) =
  let build_sockaddr (addr, port) =
    try_lwt
      (* should this be lwt hent = Lwt_lib.gethostbyname addr ? *)
      let hent = Unix.gethostbyname addr in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), port))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ addr))
  in
  lwt src = build_sockaddr (addr, port) in
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let () = Lwt_unix.bind fd src in
  let cont = ref true in
  let bufs = Lwt_pool.create 64 (fun () -> return (String.make 1024 '\000')) in
  let _ =
    while_lwt !cont do
      Lwt_pool.use bufs (fun buf ->
        lwt len, dst = Lwt_unix.recvfrom fd buf 0 (String.length buf) [] in
        let bits = buf, 0, (len*8) in
        send_answer fd ~src ~dst bits
      )
    done
  in
  let t,u = Lwt.task () in
  Lwt.on_cancel t (fun () ->
     Printf.eprintf "listen: canceled\n%!";
    cont := false);
  Printf.eprintf "listen: done\n%!";
  t

let _ =
  Lwt_main.run (listen ("0.0.0.0",5354))
