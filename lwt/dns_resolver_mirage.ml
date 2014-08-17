(*
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

open Lwt
open Printf
open Dns.Name
open Dns.Operators
open Dns.Protocol
open Dns_resolver

module DP = Dns.Packet

let default_ns = Ipaddr.V4.of_string_exn "8.8.8.8"
let default_port = 53

module Make(Time:V1_LWT.TIME)(S:V1_LWT.STACKV4) = struct

  type endp = Ipaddr.V4.t * int

  type t = {
    s: S.t;
    res: (endp, Dns_resolver.commfn) Hashtbl.t;
  }

  let create s =
    let res = Hashtbl.create 3 in
    { s; res }

  let connect_to_resolver {s; res} ((dest_ip,dest_port) as endp) =
    let udp = S.udpv4 s in
    try
      Hashtbl.find res endp
    with Not_found ->
      let timerfn () = Time.sleep 5.0 in
      let mvar = Lwt_mvar.create_empty () in
      (* TODO: test that port is free. Needs more functions exposed in tcpip *)
      let source_port = Random.int 65300 + 1024 in
      let callback ~src ~dst ~src_port buf = Lwt_mvar.put mvar buf in
      let cleanfn () = return () in
      S.listen_udpv4 s ~port:source_port callback;
      let rec txfn buf =
        Cstruct.of_bigarray buf |>
        S.UDPV4.write ~source_port ~dest_ip ~dest_port udp in
      let rec rxfn f =
        Lwt_mvar.take mvar
        >>= fun buf ->
        match f (Dns.Buf.of_cstruct buf) with
        | None -> rxfn f
        | Some packet -> return packet
      in
      let commfn = { txfn; rxfn; timerfn; cleanfn } in
      Hashtbl.add res endp commfn;
      commfn

  let resolve client
      ?(dnssec=false)
      s server dns_port
      (q_class:DP.q_class) (q_type:DP.q_type)
      (q_name:domain_name) =
    let commfn = connect_to_resolver s (server,dns_port) in
    resolve client ~dnssec commfn q_class q_type q_name

  let gethostbyname
      s ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
      name =
    let commfn = connect_to_resolver s (server,dns_port) in
    gethostbyname ~q_class ~q_type commfn name

  let gethostbyaddr
      s ?(server = default_ns) ?(dns_port = default_port)
      ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
      addr =
    let commfn = connect_to_resolver s (server,dns_port) in
    gethostbyaddr ~q_class ~q_type commfn addr

end
