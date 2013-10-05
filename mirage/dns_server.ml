(*
 * Copyright (c) 2005-2013 Anil Madhavapeddy <anil@recoil.org>
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

let port = 53

type 'a process =
  src:Net.Datagram.UDPv4.src -> dst:Net.Datagram.UDPv4.dst -> 'a
  -> Dns.Query.answer option Lwt.t

module type PROCESSOR = sig
  include Dns.Protocol.SERVER
  val process : context process
end

type 'a processor = (module PROCESSOR with type context = 'a)

let process_query mgr processor src dst buf =
  let module Processor = (val processor : PROCESSOR) in
  match Processor.parse buf with
  |None -> return ()
  |Some ctxt -> begin
    lwt answer = Processor.process ~src ~dst ctxt in
    match answer with
    |None -> return ()
    |Some answer ->
      let query = Processor.query_of_context ctxt in
      let response = Dns.Query.response_of_answer query answer in
      match Processor.marshal buf ctxt response with
      | None -> return ()
      | Some buf -> Net.Datagram.UDPv4.send mgr ~src dst buf
 end

let processor_of_process process : Dns.Packet.t processor =
  let module P = struct
    include Dns.Protocol.Server

    let process = process
  end in
  (module P)

let process_of_zonebuf zonebuf =
  let db = Dns.Zone.load [] zonebuf in
  let dnstrie = db.Dns.Loader.trie in
  let get_answer qname qtype id =
    let qname = List.map String.lowercase qname in
    Dns.Query.answer ~dnssec:true qname qtype dnstrie
  in
  fun ~src ~dst d ->
    let open DP in
    (* TODO: FIXME so that 0 question queries don't crash the server *)
    let q = List.hd d.questions in
    let r =
      Dns.Protocol.contain_exc "answer"
        (fun () -> get_answer q.q_name q.q_type d.id)
    in
    return r

let bufsz = 4096
let listen ?(mode=`none) ?(origin=[]) ~zb mgr src ~processor =
  Net.Datagram.UDPv4.(recv mgr src
    (match mode with
      |`none -> process_query mgr processor src
    )
  )

  (*
let serve_with_zonebuf ~mgr ~address ~port ~zonebuf =
  let process = process_of_zonebuf zonebuf in
  let processor = (processor_of_process process :> (module PROCESSOR)) in
  serve_with_processor ~address ~port ~processor
*)
