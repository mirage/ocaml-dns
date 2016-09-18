(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
 * Copyright (c) 2013-2014 David Sheets <sheets@alum.mit.edu>
 * Copyright (c) 2014 Anil Madhavapeddy <anil@recoil.org>
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

open Lwt.Infix
open Printf
open Dns
open Operators
open Protocol
open Dns_resolver

module DP = Packet

let log_warn s = eprintf "WARN: %s\n%!" s

type protocol = [
  | `Tcp
  | `Udp
  | `Automatic
]

let buflen = 4096
let ns = Ipaddr.of_string_exn "8.8.8.8"
let port = 53

let sockaddr addr port =
  Lwt_unix.(ADDR_INET (Ipaddr_unix.to_inet_addr addr, port))

let sockaddr_to_string = Lwt_unix.(function
  | ADDR_INET (a,p) -> sprintf "%s/%d" (Unix.string_of_inet_addr a) p
  | ADDR_UNIX s -> s ^ "/UNIX"
  )

let cleanfn ofd () =
  Lwt.catch (fun () ->
      Lwt_unix.close ofd
    ) (fun e ->
      log_warn (sprintf "%s\n%!" (Printexc.to_string e));
      Lwt.return_unit
    )

let udp_commfn server port =
  let dst = sockaddr server port in
  let ofd = Lwt_unix.(socket PF_INET SOCK_DGRAM 17) in
  Lwt_unix.(bind ofd (sockaddr Ipaddr.(V4 V4.any) 0));
  let cleanfn = cleanfn ofd in
  let timerfn () = Lwt_unix.sleep 5.0 in
  let txfn buf =
    Lwt_bytes.sendto ofd buf 0 (Dns.Buf.length buf) [] dst
    >>= fun _ -> Lwt.return_unit in
  let rec rxfn f =
    let buf = Dns.Buf.create buflen in
    Lwt_bytes.recvfrom ofd buf 0 buflen []
    >>= fun (len, sa) ->
    let buf = Dns.Buf.sub buf 0 len in
    match f buf with
    | None -> rxfn f
    | Some r -> Lwt.return r
  in
  Lwt.return { txfn; rxfn; timerfn; cleanfn }

let tcp_commfn server port =
  let dst = sockaddr server port in
  let ofd = Lwt_unix.(socket PF_INET SOCK_STREAM 0) in
  Lwt.catch
    (fun () ->
      Lwt_unix.connect ofd dst
    ) (fun e ->
      Lwt_unix.close ofd
      >>= fun () ->
      Lwt.fail e
    )
  >>= fun () ->
  let cleanfn = cleanfn ofd in
  let timerfn () = Lwt_unix.sleep 5.0 in
  (* RFC 1035 4.2.2 TCP Usage: 2 byte length field *)
  let header = Cstruct.create 2 in
  let txfn buf =
    Cstruct.BE.set_uint16 header 0 (Dns.Buf.length buf);
    Lwt_cstruct.(complete (write ofd) header)
    >>= fun () ->
    let payload = Cstruct.of_bigarray buf in
    Lwt_cstruct.(complete (write ofd) payload)
    >>= fun () ->
    Lwt.return_unit in
  let rec rxfn f =
    Lwt_cstruct.(complete (read ofd) header)
    >>= fun () ->
    let length = Cstruct.BE.get_uint16 header 0 in
    let buf = Dns.Buf.create length in
    let payload = Cstruct.of_bigarray buf in
    Lwt_cstruct.(complete (read ofd) payload)
    >>= fun () ->
    match f buf with
    | None -> rxfn f
    | Some r -> Lwt.return r
  in
  Lwt.return { txfn; rxfn; timerfn; cleanfn }

let commfn = function
  | `Tcp -> tcp_commfn
  | `Udp -> udp_commfn
  | `Automatic -> udp_commfn (* FIXME: need to switch between UDP and TCP *)

let resolve client
    ?(dnssec=false)
    protocol server dns_port
    (q_class:DP.q_class) (q_type:DP.q_type)
    (q_name:Name.t) =
   commfn protocol server dns_port
   >>= fun commfn ->
   resolve client ~dnssec commfn q_class q_type q_name

let gethostbyname
    ?(protocol = `Automatic) ?(server = ns) ?(dns_port = port)
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    name =
  commfn protocol server dns_port
  >>= fun commfn ->
  gethostbyname ~q_class ~q_type commfn name

let gethostbyaddr
    ?(protocol = `Automatic) ?(server = ns) ?(dns_port = port)
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
    addr
    =
  commfn protocol server dns_port
  >>= fun commfn ->
  gethostbyaddr ~q_class ~q_type commfn addr

open Dns.Resolvconf

type t = {
  client : (module CLIENT);
  servers : (Ipaddr.t * int) list;
  search_domains : string list;
  protocol: protocol;
}

type config = [
  | `Resolv_conf of string
  | `Static of (Ipaddr.t * int) list * string list
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

  let create client protocol ?(file=default_file) () =
    get_resolvers ~file ()
    >|= fun t ->
    { client; servers = all_servers t; search_domains = search_domains t; protocol }

end

module Static = struct
  let create client protocol ?(servers=[ns,port]) ?(search_domains=[]) () =
    { client; servers; search_domains; protocol }
end

let create
    ?(client=(module Dns.Protocol.Client : CLIENT))
    ?(config=`Resolv_conf Resolv_conf.default_file)
    ?(protocol=`Automatic) () =
  match config with
  |`Static (servers, search_domains) ->
     Lwt.return (Static.create client protocol ~servers ~search_domains ())
  |`Resolv_conf file -> Resolv_conf.create client protocol ~file ()

let gethostbyname t ?q_class ?q_type q_name =
  match t.servers with
  |[] -> Lwt.fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    gethostbyname ~protocol:t.protocol ~server ~dns_port ?q_class ?q_type q_name

let gethostbyaddr t ?q_class ?q_type q_name =
  match t.servers with
  |[] -> Lwt.fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    gethostbyaddr ~protocol:t.protocol ~server ~dns_port ?q_class ?q_type q_name

let resolve t ?(dnssec=false) q_class q_type q_name =
  match t.servers with
  |[] -> Lwt.fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    resolve t.client ~dnssec t.protocol server dns_port q_class q_type q_name
