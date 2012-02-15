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

module DL = Dnsloader
module DQ = Dnsquery
module DR = Dnsrr
module DP = Dnspacket

let dnstrie = DL.(state.db.trie)

let get_answer qname qtype id =
  let qname = List.map String.lowercase qname in  
  let ans = DQ.answer_query qname qtype dnstrie in
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

(* Space leaking hash table cache, always grows *)
module Leaking_cache = Hashtbl.Make (struct
  type t = string list * DP.q_type
  let equal (a:t) (b:t) = a = b
  let hash = Hashtbl.hash
end)

let cache = Leaking_cache.create 1
let get_answer_memo qname qtype id =
  let qargs = qname, qtype in
  let r =
    try
      Leaking_cache.find cache qargs
    with Not_found -> (
      let r = get_answer qname qtype id in
      Leaking_cache.add cache qargs r;
      r
    )
  in
  DP.({ r with id })

let no_memo fd ~src ~dst bits =
  let names = Hashtbl.create 8 in
  DP.(
    let d = parse_dns names bits in
    let q = List.hd d.questions in
    let r = get_answer q.q_name q.q_type d.id in
    let buf,boff,blen = marshal r in
    let _ = Lwt_unix.sendto fd buf (boff/8) (blen/8) [] dst in
    return ()
  )

let leaky fd ~src ~dst bits =
  let names = Hashtbl.create 8 in
  DP.(
    let d = DP.parse_dns names bits in
    let q = List.hd d.questions in
    let r = get_answer_memo q.q_name q.q_type d.id in
    let buf,boff,blen = marshal r in
    let _ = Lwt_unix.sendto fd buf (boff/8) (blen/8) [] dst in
    return ()
  )

type spec = {
  zonebuf: string;
  address: string;
  port: int;
  mode: [`leaky|`none];
}

let listen spec =
  Printf.eprintf "listen: start\n%!";
  Dnsserver.load_zone [] spec.zonebuf;
  let build_sockaddr (addr, port) =
    try_lwt
      (* should this be lwt hent = Lwt_lib.gethostbyname addr ? *)
      let hent = Unix.gethostbyname addr in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), port))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ spec.address))
  in
  lwt src = build_sockaddr (spec.address, spec.port) in
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let () = Lwt_unix.bind fd src in
  let cont = ref true in
  let bufs = Lwt_pool.create 64 (fun () -> return (String.make 1024 '\000')) in
  let iofn = match spec.mode with |`none -> no_memo |`leaky -> leaky in
  let _ =
    while_lwt !cont do
      Lwt_pool.use bufs (fun buf ->
        lwt len, dst = Lwt_unix.recvfrom fd buf 0 (String.length buf) [] in
        let bits = buf, 0, (len*8) in
        iofn fd ~src ~dst bits
      )
    done
  in
  let t,u = Lwt.task () in
  Lwt.on_cancel t (fun () ->
     Printf.eprintf "listen: canceled\n%!";
    cont := false);
  Printf.eprintf "listen: done\n%!";
  t
