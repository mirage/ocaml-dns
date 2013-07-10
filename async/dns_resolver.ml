(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
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
open Printf
open Dns.Name
open Dns.Operators

module DP = Dns.Packet

let buflen = 4096
let ns = "8.8.8.8"
let port = 53

let id = ref 0xDEAD

let get_id () =
    let i = !id in
    incr id;
    i

let log_info s = eprintf "INFO: %s\n%!" s
let log_debug s = eprintf "DEBUG: %s\n%!" s
let log_warn s = eprintf "WARN: %s\n%!" s

type resolver_config = {
 servers : (string * int) list;
 search_domains : string list;
}

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


let rec rcv_query reader q =
  let names = Caml.Hashtbl.create 8 in
  let buf = String.create (16 * 1024) in
  (Reader.read reader ~len:(16 * 1024) buf )
  >>| (fun x -> 
    let r = DP.parse names (Cstruct.of_string buf) in 
    if (r.DP.id = q.DP.id) then r
    else
      rcv_query reader q )
			    

let send_pkt (server:string) (dns_port:int) pkt =
 let ofd = outfd "0.0.0.0" 0 in
 let buf = Cstruct.create 4096 in
 let q = DP.marshal buf pkt in
      let (socket,reader,writer) = Tcp.connect (Tcp.to_host_and_port addr port) in 
      Writer.write writer q.to_string; 
      with_timeout (Time.Span.create ~sec:5) (rcv_query reader pkt) 


let resolve
    (server:string) (dns_port:int) 
    (q_class:DP.q_class) (q_type:DP.q_type) 
    (q_name:domain_name) =
      let query = build_query q_class q_type q_name in
      log_info (sprintf "query: %s\n%!" (DP.to_string query));
      send_pkt server dns_port query 

let default_configuration_file = "/etc/resolv.conf"

let get_resolvers ?(file=default_configuration_file) () =
    Unix_syscalls.with_file ~mode:[`Rdonly]  file ~f:(fun fd ->
      let warn x = prerr_endline (Printf.sprintf "resolvconf in file %s: %s" file x) in
      let reader = Reader.create fd in
      let rec input_lines (res : string list ) : string list Deferred.t = 
        Reader.read_line reader
	>>= function 
	  | `Ok x -> input_lines (x::res)
	  | `Eof ->  return res  in
      input_lines []
        >>| List.filter_map ~f:map_line
        >>| List.filter_map ~f:(fun line ->
        try Some (KeywordValue.of_string line)
        with
        | KeywordValue.Unknown x -> warn ("unknown keyword: " ^ x); None
        | OptionsValue.Unknown x -> warn ("unknown option: " ^ x); None
        | LookupValue.Unknown x  -> warn ("unknown lookup option: " ^ x); None
      ))


let get_config () : resolver_config Deferred.t = 
  let t = get_resolvers () in
  let servers = (t >>| all_servers) in 
  let search_domains = (t >>| search_domains t) in
  { servers; search_domain } 

let resolve (t: resolver_config)  q_class q_type q_name =
  match t.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ -> resolve server dns_port q_class q_type q_name
