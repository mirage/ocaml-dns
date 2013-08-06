(*
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

module DP = Dns.Packet

exception Dns_resolve_timeout
exception Dns_resolve_error of exn list

type result = Answer of DP.t | Error of exn

let buflen = 4096
let ns = "8.8.8.8"
let port = 53

module type RESOLVER = sig
  type context

  val get_id : unit -> int

  val marshal : DP.t -> (context * Dns.Buf.t) list
  val parse : context -> Dns.Buf.t -> DP.t option

  val timeout : context -> exn
end

module DNSProtocol : RESOLVER = struct
  type context = int

  (* TODO: XXX FIXME SECURITY EXPLOIT HELP: random enough? *)
  let get_id () =
    Random.self_init ();
    Random.int (1 lsl 16)

  let marshal q = [q.DP.id, DP.marshal (Dns.Buf.create 4096) q]
  let parse id buf =
    let pkt = DP.parse buf in
    if pkt.DP.id = id then Some pkt else None

  let timeout _id = Dns_resolve_timeout
end

let log_info s = eprintf "INFO: %s\n%!" s
let log_debug s = eprintf "DEBUG: %s\n%!" s
let log_warn s = eprintf "WARN: %s\n%!" s

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
  Lwt_bytes.sendto fd buf 0 (Dns.Buf.length buf) [] dst

let rxbuf fd len =
  let buf = Dns.Buf.create len in
  lwt (len, sa) = Lwt_bytes.recvfrom fd buf 0 len [] in
  return (buf, sa)

let rec send_req ofd dst q = function
  | 0 -> return ()
  | count ->
      lwt _ = txbuf ofd dst q in
      lwt _ = Lwt_unix.sleep 5.0 in
      printf "retrying query for %d times\n%!" (4-count);
      send_req ofd dst q (count - 1)

let rec rcv_query ofd f =
  lwt (buf,sa) = rxbuf ofd buflen in
  match f buf with Some r -> return r | None -> rcv_query ofd f

let send_pkt resolver server dns_port pkt =
  let module R = (val resolver : RESOLVER) in
  let dst = sockaddr server dns_port in
  let cqpl = R.marshal pkt in
  let resl = List.map (fun (ctxt,q) ->
    (* make a new socket for each request flavor *)
    let ofd = outfd "0.0.0.0" 0 in
    (* start the requests in parallel and run them until success or timeout*)
    let t, w = Lwt.wait () in
    async (fun () -> pick [
      (send_req ofd dst q 4
       >>= fun () -> return (wakeup w (Error (R.timeout ctxt))));
      (catch
         (fun () ->
           rcv_query ofd (R.parse ctxt)
           >>= fun r -> return (wakeup w (Answer r))
         )
         (fun exn -> return (wakeup w (Error exn)))
      )
    ]);
    t
  ) cqpl in
  (* return an answer or all the errors if no request succeeded *)
  let rec select errors = function
    | [] -> fail (Dns_resolve_error errors)
    | ts ->
      nchoose_split ts
      >>= fun (rs, ts) ->
      let rec find_answer errors = function
        | [] -> select errors ts
        | (Answer a)::_ -> return a
        | (Error e)::r -> find_answer (e::errors) r
      in
      find_answer errors rs
  in select [] resl

let resolve resolver
    ?(dnssec=false)
    (server:string) (dns_port:int)
    (q_class:DP.q_class) (q_type:DP.q_type)
    (q_name:domain_name) =
    try_lwt
      let id = (let module R = (val resolver : RESOLVER) in R.get_id ()) in
      let q = Dns.Query.create ~id ~dnssec q_class q_type q_name in
      log_info (sprintf "query: %s\n%!" (DP.to_string q));
      send_pkt resolver server dns_port q
   with exn ->
      log_warn (sprintf "%s\n%!" (Printexc.to_string exn));
      fail exn

let gethostbyname
    ?(server:string = ns) ?(dns_port:int = port)
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    name =
  let open DP in
  let domain = string_to_domain_name name in
  resolve (module DNSProtocol) server dns_port q_class q_type domain
  >|= fun r ->
    List.fold_left (fun a x ->
      match x.rdata with |A ip -> ip::a |_ -> a
    ) [] r.answers
   |> List.rev

let gethostbyaddr
    ?(server:string = ns) ?(dns_port:int = port)
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
    addr
    =
  let addr = for_reverse addr in
  log_info (sprintf "gethostbyaddr: %s" (domain_name_to_string addr));
  let open DP in
  resolve (module DNSProtocol) server dns_port q_class q_type addr
  >|= fun r ->
    List.fold_left (fun a x ->
      match x.rdata with |PTR n -> (domain_name_to_string n)::a |_->a
    ) [] r.answers
   |> List.rev

open Dns.Resolvconf

type t = {
  resolver : (module RESOLVER);
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

  let create resolver ?(file=default_file) () =
    lwt t = get_resolvers ~file () in
    return {
      resolver;
      servers = all_servers t;
      search_domains = search_domains t;
    }
end

module Static = struct
  let create resolver ?(servers=["8.8.8.8",53]) ?(search_domains=[]) () =
    { resolver; servers; search_domains }
end

let create
    ?(resolver=(module DNSProtocol : RESOLVER))
    ?(config=`Resolv_conf Resolv_conf.default_file) () =
  match config with
  |`Static (servers, search_domains) ->
     return (Static.create resolver ~servers ~search_domains ())
  |`Resolv_conf file -> Resolv_conf.create resolver ~file ()

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

let send_pkt t pkt =
  match t.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    send_pkt t.resolver server dns_port pkt

let resolve t ?(dnssec=false) q_class q_type q_name =
  match t.servers with
  |[] -> fail (Failure "No resolvers available")
  |(server,dns_port)::_ ->
    resolve t.resolver ~dnssec server dns_port q_class q_type q_name
