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

open Lwt
open Printf
open Dns.Name
open Dns.Operators

module DP = Dns.Packet

exception Dns_resolve_timeout

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

let build_query ?(dnssec=false) q_class q_type q_name = 
  DP.(
    let detail = { qr=Query; opcode=Standard;
                   aa=true; tc=false; rd=true; ra=false; rcode=NoError; }
    in
    let additionals = 
      if dnssec then 
        [ ( {
          name=[]; cls=RR_IN; ttl=0l;
          rdata=(EDNS0(1500, 0, true, []));} ) ]
      else
        []
    in
    let question = { q_name; q_type; q_class } in 
    { id=get_id (); detail; questions=[question]; 
      answers=[]; authorities=[]; additionals; 
    }
  )

let sockaddr addr port = 
  Lwt_unix.(ADDR_INET (Unix.inet_addr_of_string addr, port))

let sockaddr_to_string = Lwt_unix.(function
  | ADDR_INET (a,p) -> sprintf "%s/%d" (Unix.string_of_inet_addr a) p
  | ADDR_UNIX s -> s ^ "/UNIX"
  )

let outfd addr port = 
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 17) in 
  Lwt_unix.(bind fd (sockaddr addr port));
  fd

let txbuf fd dst buf =
  Lwt_bytes.sendto fd buf 0 (Cstruct.len buf) [] dst

let rxbuf fd len = 
  let buf = Lwt_bytes.create len in
  lwt (len, sa) = Lwt_bytes.recvfrom fd buf 0 len [] in
  return (buf, sa)

let rec send_req ofd dst q = function
  | 0 -> raise Dns_resolve_timeout
  | count ->
      lwt _ = txbuf ofd dst q in
      lwt _ = Lwt_unix.sleep 5.0 in
      printf "retrying query for %d times\n%!" (4-count); 
        send_req ofd dst q (count - 1)

let rec rcv_query ofd q =
  lwt (buf,sa) = rxbuf ofd buflen in
  let names = Hashtbl.create 8 in
  let r = DP.parse names buf in 
    if (r.DP.id = q.DP.id) then
      return r
    else
      rcv_query ofd q 

let send_pkt (server:string) (dns_port:int) pkt =
 let ofd = outfd "0.0.0.0" 0 in
 let buf = Lwt_bytes.create 4096 in
 let q = DP.marshal buf pkt in
  try_lwt
      let dst = sockaddr server dns_port in 
      let ret = ref None in 
      lwt _ =
        pick [
          (send_req ofd dst q 4);
          (lwt r = rcv_query ofd pkt in 
            return (ret := Some(r))) ]
      in
        match !ret with
        | None -> raise Dns_resolve_timeout
        | Some r -> return r 
    with exn -> 
      log_warn (sprintf "%s\n%!" (Printexc.to_string exn));
      fail exn

let resolve
    ?(dnssec=false)
    (server:string) (dns_port:int) 
    (q_class:DP.q_class) (q_type:DP.q_type) 
    (q_name:domain_name) =
    try_lwt
      let q = build_query ~dnssec q_class q_type q_name in
      log_info (sprintf "query: %s\n%!" (DP.to_string q));
      send_pkt server dns_port q 
   with exn -> 
      log_warn (sprintf "%s\n%!" (Printexc.to_string exn));
      fail exn 

let gethostbyname
    ?(server:string = ns) ?(dns_port:int = port) 
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    name =
  let open DP in
  let domain = string_to_domain_name name in
  resolve server dns_port q_class q_type domain >|= fun r ->
  List.fold_left (fun a x -> match x.rdata with |A ip -> ip::a |_ -> a) [] r.answers |>
  List.rev

let gethostbyaddr 
    ?(server:string = ns) ?(dns_port:int = port) 
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
    addr 
    = 
  let addr = for_reverse addr in
  log_info (sprintf "gethostbyaddr: %s" (domain_name_to_string addr));
  let open DP in
  resolve server dns_port q_class q_type addr >|= fun r ->
  List.fold_left (fun a x -> match x.rdata with |PTR n -> (domain_name_to_string n)::a |_->a) [] r.answers |>
  List.rev

open Dns.Resolvconf

module type RESOLVER = sig
  val servers : (string * int) list
  val search_domains : string list
end

type config = [
  | `Resolv_conf
  | `Static of (string * int) list * string list
]

type t = (module RESOLVER)

module Resolv_conf = struct
  let default_configuration_file = "/etc/resolv.conf"

  let get_resolvers ?(file=default_configuration_file) () =
    Lwt_io.with_file ~mode:Lwt_io.input file (fun ic ->
      (* Read lines and filter out whitespace/blanks *)
      let lines = Lwt_stream.filter_map map_line (Lwt_io.read_lines ic) in
      let warn x = prerr_endline (Printf.sprintf "resolvconf in file %s: %s" file x) in
      (* Parse remaining lines *)
      Lwt_stream.(to_list (filter_map (fun line ->
        try Some (KeywordValue.of_string line)
        with
        | KeywordValue.Unknown x -> warn ("unknown keyword: " ^ x); None
        | OptionsValue.Unknown x -> warn ("unknown option: " ^ x); None
        | LookupValue.Unknown x  -> warn ("unknown lookup option: " ^ x); None
      ) lines))
    )

  let create () =
    lwt t = get_resolvers () in
    return
    (module (struct
      let servers = all_servers t
      let search_domains = search_domains t
     end) : RESOLVER)
end

module Static = struct
  let create ?(servers=["8.8.8.8",53]) ?(search_domains=[]) () =
    (module (struct
      let servers = servers
      let search_domains = search_domains
     end) : RESOLVER)
end

let create ?(config=`Resolv_conf) () =
  match config with
  |`Static (servers, search_domains) ->
     return (Static.create ~servers ~search_domains ())
  |`Resolv_conf -> Resolv_conf.create ()


let gethostbyname t ?q_class ?q_type q_name =
  let module R = (val t :RESOLVER ) in
  match R.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ -> gethostbyname ~server ~dns_port ?q_class ?q_type q_name

let gethostbyaddr t ?q_class ?q_type q_name =
  let module R = (val t :RESOLVER ) in
  match R.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ -> gethostbyaddr ~server ~dns_port ?q_class ?q_type q_name

let send_pkt t pkt =
  let module R = (val t :RESOLVER ) in
  match R.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ -> send_pkt server dns_port pkt

let resolve t ?(dnssec=false) q_class q_type q_name =
  let module R = (val t :RESOLVER ) in
  match R.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ -> resolve ~dnssec server dns_port q_class q_type q_name
