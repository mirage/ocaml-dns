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

let buflen =  (16 * 1064)

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

let send_pkt (server:string) (dns_port:int) pkt =
  debug ("sending DNS query to "^server^" port: "^(Caml.string_of_int dns_port));
  let buf = Cstruct.create 4096 in
  let pkt_cstruct = DP.marshal buf pkt in
  let pkt_string = String.create (16 * 1024) in
  let addr = `Inet (Unix.Inet_addr.of_string server, dns_port) in
  Cstruct.blit_to_string pkt_cstruct 0 pkt_string 0 (Cstruct.len pkt_cstruct);
  Udp.bind_any ()
  >>| (fun sock -> Udp.sendto_sync ()
		   |> Or_error.map ~f:(fun sendto_sync ->
       (fun fd buf addr ->
          match sendto_sync fd buf addr with
          | `Not_ready -> assert false
          | `Ok -> Deferred.unit)))


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
