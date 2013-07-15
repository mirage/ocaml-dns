(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2013 Heidi Howard
 * Copyright (c) 2013 Anil Madhavapeddy <anil@recoil.org>
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

open Core.Std
open Async.Std
open Dns.Name
open Dns.Operators
open Dns.Resolvconf

module DP = Dns.Packet
module DN = Dns.Name

let debug_active = ref true
let debug x = if !debug_active then (printf "[debug] %s \n" x)

let buflen = 4096
let ns = "8.8.8.8"
let port = 53

let id = ref 0xDEAD

let get_id () =
  let i = !id in
  incr id;
  i

let build_query  q_class q_type q_name = 
  DP.(
    let detail = { qr=Query; opcode=Standard;
                   aa=true; tc=false; rd=true; ra=false; rcode=NoError; } in
    let additionals = [] in
    let question = { q_name; q_type; q_class } in 
    { id=get_id (); detail; questions=[question]; 
      answers=[]; authorities=[]; additionals; 
    }
  )


let rec rcv_query reader q :DP.t Deferred.t =
  let names = Caml.Hashtbl.create 8 in
  let buf = String.create (16 * 1024) in
  (Reader.read reader ~len:(16 * 1024) buf )
  >>= (fun x -> 
      let r = DP.parse names (Cstruct.of_string buf) in 
      (*  debug (DP.to_string r); *)
      if (r.DP.id = q.DP.id) then return r
      else
        rcv_query reader q )


let send_pkt (server:string) (dns_port:int) pkt =
  debug ("sending DNS query to "^server^" port: "^(Caml.string_of_int dns_port));
  let buf = Cstruct.create 4096 in
  let pkt_cstruct = DP.marshal buf pkt in
  let pkt_string = String.create (16 * 1024) in
  Cstruct.blit_to_string pkt_cstruct 0 pkt_string 0 (Cstruct.len pkt_cstruct);
  Tcp.with_connection (Tcp.to_host_and_port server dns_port)
    (fun s r w -> 
       let peername = Socket.getpeername s in
       let sockname = Socket.getsockname s in
       debug ("socket establisted between "^(Unix_syscalls.Socket.Address.to_string peername)^" to "^(Unix_syscalls.Socket.Address.to_string sockname));
       Writer.write w pkt_string;
       Writer.flushed w 
       >>= (fun _ ->  with_timeout (Time.Span.create ~sec:5 () ) (rcv_query r pkt) ))


let resolve (server:string) (dns_port:int)  (q_class:DP.q_class)
    (q_type:DP.q_type) (q_name:DN.domain_name) =
  let query = build_query q_class q_type q_name in
  send_pkt server dns_port query 

let default_configuration_file = "/etc/resolv.conf"

let get_resolvers ?(file=default_configuration_file) () =
  let warn x = prerr_endline (Printf.sprintf "resolvconf in file %s: %s" file x) in
  Reader.open_file file
  >>= fun rd -> Reader.lines rd
  |> Pipe.filter_map ~f:(fun l -> prerr_endline l; map_line l)
  |> Pipe.filter_map ~f:(fun line ->
    try Some (KeywordValue.of_string line)
    with
      | KeywordValue.Unknown x -> warn ("unknown keyword: " ^ x); None
      | OptionsValue.Unknown x -> warn ("unknown option: " ^ x); None
      | LookupValue.Unknown x  -> warn ("unknown lookup option: " ^ x); None
    )
  |> Pipe.to_list

let resolve (res_config: KeywordValue.t List.t)  q_class q_type q_name =
  match choose_server res_config with
  | Some (server,dns_port) -> resolve server dns_port q_class q_type q_name
  | None -> assert false (* TODO *)
