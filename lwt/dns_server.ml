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

module DQ = Dns.Query
module DR = Dns.RR
module DP = Dns.Packet

type 'a process =
  src:Lwt_unix.sockaddr -> dst:Lwt_unix.sockaddr -> 'a ->
  Dns.Packet.t -> Dns.Query.query_answer option Lwt.t

module type PROCESSOR = sig
  type context

  val parse   : Buf.t -> (context * Dns.Packet.t) option
  val process : context process
  val marshal : Buf.t -> context -> Dns.Packet.t -> Buf.t option
end

let contain_exc l v =
  try
    Some (v ())
  with exn ->
    eprintf "dns %s exn: %s\n%!" l (Printexc.to_string exn);
    None

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

let process_query fd buf len src dst processor =
  let module Processor = (val processor : PROCESSOR) in
  match Processor.parse buf with
  |None -> return ()
  |Some (ctxt, query) -> begin
    lwt answer = Processor.process ~src ~dst ctxt query in
    match answer with
    |None -> return ()
    |Some answer ->
(*            let edns_rec =
              try
                List.find (fun rr -> ) query.additionals
              with Not_found -> []
            in *)
      let detail = DP.({
        qr=Response; opcode=Standard; aa=answer.DQ.aa;
        tc=false; rd=false; ra=false; rcode=answer.DQ.rcode
      })
      in
      let response = DP.({
        id=query.id; detail; questions=query.questions;
        answers=answer.DQ.answer;
        authorities=answer.DQ.authority;
        additionals=answer.DQ.additional;
      })
      in
      (* Lwt_bytes.unsafe_fill buf 0 (Lwt_bytes.length buf) '\x00'; *)
      match Processor.marshal buf ctxt response with
      | None -> return ()
      | Some buf ->
        (* TODO transmit queue, rather than ignoring result here *)
        let _ = Lwt_bytes.(sendto fd buf 0 (Dns.Buf.length buf) [] dst) in
        return ()
 end

module DNSProtocol = struct
  type context = unit
  let parse buf = contain_exc "parse" (fun () -> (), DP.parse buf)
  let marshal buf () response =
    contain_exc "marshal" (fun () -> DP.marshal buf response)
end

let processor_of_process process =
  let module P = struct
    include DNSProtocol

    let process = process
  end in
  (module P : PROCESSOR)

let process_of_zonebuf zonebuf =
  let db = Dns.Zone.load [] zonebuf in
  let dnstrie = db.Dns.Loader.trie in
  let get_answer qname qtype id =
    let qname = List.map String.lowercase qname in
    DQ.answer_query ~dnssec:true qname qtype dnstrie
  in
  fun ~src ~dst () d ->
    let open DP in
    (* TODO: FIXME so that 0 question queries don't crash the server *)
    let q = List.hd d.questions in
    let r =
      contain_exc "answer" (fun () -> get_answer q.q_name q.q_type d.id)
    in
    return r

let eventual_process_of_zonefile zonefile =
  let lines = Lwt_io.lines_of_file zonefile in
  let buf = Buffer.create 1024 in
  Lwt_stream.iter (fun l ->
    Buffer.add_string buf l; Buffer.add_char buf '\n') lines
  >>= fun () -> return (process_of_zonebuf (Buffer.contents buf))

let bufsz = 4096
let listen ~fd ~src ~processor =
  let cont = ref true in
  let bufs = Lwt_pool.create 64 (fun () -> return (Dns.Buf.create bufsz)) in
  let _ =
    while_lwt !cont do
      Lwt_pool.use bufs (fun buf ->
        lwt len, dst = Lwt_bytes.(recvfrom fd buf 0 bufsz []) in
	  return (Lwt.ignore_result
                    (process_query fd buf len src dst processor))
     )
    done
  in
  let t,u = Lwt.task () in
  Lwt.on_cancel t
    (fun () -> Printf.eprintf "listen: cancelled\n%!"; cont := false);
  Printf.eprintf "listen: done\n%!";
  t

let serve_with_processor ~address ~port ~processor =
  bind_fd ~address ~port
  >>= fun (fd, src) -> listen ~fd ~src ~processor

let serve_with_zonebuf ~address ~port ~zonebuf =
  serve_with_processor ~address ~port
    ~processor:(processor_of_process (process_of_zonebuf zonebuf))

let serve_with_zonefile ~address ~port ~zonefile =
  eventual_process_of_zonefile zonefile
  >>= fun process ->
  serve_with_processor ~address ~port ~processor:(processor_of_process process)
