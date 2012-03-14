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

module DL = Dns.Loader
module DQ = Dns.Query
module DR = Dns.RR
module DP = Dns.Packet

type dnsfn = src:Lwt_unix.sockaddr -> dst:Lwt_unix.sockaddr ->
  Dns.Packet.dns -> Dns.Query.query_answer option Lwt.t

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

let listen ~fd ~src ~(dnsfn:dnsfn) =
  let cont = ref true in
  let bufs = Lwt_pool.create 64 (fun () -> return (String.make 1024 '\000')) in
  let _ =
    let names = Hashtbl.create 64 in
    while_lwt !cont do
      Lwt_pool.use bufs (fun buf ->
        lwt len, dst = Lwt_unix.recvfrom fd buf 0 (String.length buf) [] in
        let bits = buf, 0, (len*8) in
        let query =
          try Some (DP.parse_dns names bits)
          with 
            | exn 
              -> (eprintf "dns parse exn: %s\n%!" (Printexc.to_string exn); 
                  None 
              )
        in
        match query with
        |None -> return ()
        |Some query -> begin
          lwt answer = dnsfn ~src ~dst query in
          match answer with
          |None -> return ()
          |Some answer ->
            let detail = DP.(build_detail { 
              qr=`Answer; opcode=`Query; aa=answer.DQ.aa;
              tc=false; rd=false; ra=false; rcode=answer.DQ.rcode 
            }) 
            in
            let response = DP.({ 
              id=query.id; detail; 
              questions=query.questions; 
              answers=answer.DQ.answer;
              authorities=answer.DQ.authority; 
              additionals=answer.DQ.additional }) 
            in
            let bits = 
              try Some (DP.marshal_dns response)
              with exn -> (
                eprintf "dns marshal exn: %s\n%!" (Printexc.to_string exn); 
                None 
              )
            in
            match bits with
              | None -> return ()
              | Some (buf, boff, blen) -> (
            (* TODO transmit queue, rather than ignoring result here *)
                let _ = Lwt_unix.sendto fd buf (boff/8) (blen/8) [] dst in
                return ()
              )
        end
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
  Dns.Zone.load_zone [] zonebuf;
  lwt fd, src = bind_fd ~address ~port in
  let dnstrie = DL.(state.db.trie) in
  let get_answer qname qtype id =
    let qname = List.map String.lowercase qname in  
    DQ.answer_query qname qtype dnstrie
  in
  let (dnsfn:dnsfn) =
    match mode with
    |`none ->
      (fun ~src ~dst d ->
         let open DP in
         let q = List.hd d.questions in
         let r = 
           try Some (get_answer q.q_name q.q_type d.id )
           with exn -> (
             eprintf "dns parse exn: %s\n%!" (Printexc.to_string exn); 
             None 
           )
         in
         return r
      )
  in
  listen ~fd ~src ~dnsfn

let listen_with_zonefile ~address ~port ~zonefile =
  lwt zonebuf =
     let lines = Lwt_io.lines_of_file zonefile in
     let buf = Buffer.create 1024 in
     lwt () = Lwt_stream.iter (fun l -> 
       Buffer.add_string buf l; Buffer.add_char buf '\n') lines 
     in
     return (Buffer.contents buf)
  in
  listen_with_zonebuf ~address ~port ~zonebuf ~mode:`none

