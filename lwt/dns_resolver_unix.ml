(*
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2013 David Sheets <sheets@alum.mit.edu>
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
open Dns.Protocol
open Dns_resolver

module DP = Dns.Packet

let buflen = 4096
let ns = "8.8.8.8"
let port = 53

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

let connect_to_resolver server port =
  let dst = sockaddr server port in
  let ofd = outfd "0.0.0.0" 0 in
  let txfn buf =
    Lwt_bytes.sendto ofd buf 0 (Dns.Buf.length buf) [] dst 
    >>= fun _ -> return_unit in
  let rec rxfn f =
    let buf = Dns.Buf.create buflen in
    Lwt_bytes.recvfrom ofd buf 0 buflen []
    >>= fun (len, sa) ->
    let buf = Dns.Buf.sub buf 0 len in
    match f buf with
    | None -> rxfn f
    | Some r -> return r
  in
  txfn, rxfn

let resolve client
    ?(dnssec=false)
    (server:string) (dns_port:int)
    (q_class:DP.q_class) (q_type:DP.q_type)
    (q_name:domain_name) =
   let commfn = connect_to_resolver server dns_port in
   resolve client ~dnssec commfn q_class q_type q_name

let gethostbyname
    ?(server:string = ns) ?(dns_port:int = port)
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    name =
   let commfn = connect_to_resolver server dns_port in
   gethostbyname ~q_class ~q_type commfn name

let gethostbyaddr
    ?(server:string = ns) ?(dns_port:int = port)
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
    addr
    =
   let commfn = connect_to_resolver server dns_port in
   gethostbyaddr ~q_class ~q_type commfn addr

open Dns.Resolvconf

type t = {
  client : (module CLIENT);
  servers : (string * int) list;
  search_domains : string list;
}

type config = [
  | `Resolv_conf of string
  | `Static of (string * int) list * string list
]

module Resolv_conf = struct
  let default_file = "/etc/resolv.conf"

  let get_resolvers ?(file=default_file) () =
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

  let create client ?(file=default_file) () =
    lwt t = get_resolvers ~file () in
    return {
      client;
      servers = all_servers t;
      search_domains = search_domains t;
    }
end

module Static = struct
  let create client ?(servers=["8.8.8.8",53]) ?(search_domains=[]) () =
    { client; servers; search_domains }
end

let create
    ?(client=(module Dns.Protocol.Client : CLIENT))
    ?(config=`Resolv_conf Resolv_conf.default_file) () =
  match config with
  |`Static (servers, search_domains) ->
     return (Static.create client ~servers ~search_domains ())
  |`Resolv_conf file -> Resolv_conf.create client ~file ()

let gethostbyname t ?q_class ?q_type q_name =
  match t.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    gethostbyname ~server ~dns_port ?q_class ?q_type q_name

let gethostbyaddr t ?q_class ?q_type q_name =
  match t.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    gethostbyaddr ~server ~dns_port ?q_class ?q_type q_name

let resolve t ?(dnssec=false) q_class q_type q_name =
  match t.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    resolve t.client ~dnssec server dns_port q_class q_type q_name
