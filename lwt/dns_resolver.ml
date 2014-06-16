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

module DP = Dns.Packet

type result = Answer of DP.t | Error of exn

type commfn =
  (Dns.Buf.t -> unit Lwt.t) *
  ((Dns.Buf.t -> Dns.Packet.t option) -> DP.t Lwt.t) * 
  (unit -> unit Lwt.t)

let log_info s = eprintf "INFO: %s\n%!" s
let log_debug s = eprintf "DEBUG: %s\n%!" s
let log_warn s = eprintf "WARN: %s\n%!" s

let rec send_req txfn timerfn q = function
  | 0 -> return ()
  | count ->
      txfn q >>= fun _ ->
      timerfn () >>= fun () ->
      printf "retrying query for %d times\n%!" (4-count);
      send_req txfn timerfn q (count - 1)

let send_pkt client (txfn,rxfn,timerfn) pkt =
  let module R = (val client : CLIENT) in
  let cqpl = R.marshal pkt in
  let resl = List.map (fun (ctxt,q) ->
    (* make a new socket for each request flavor *)
    (* start the requests in parallel and run them until success or timeout*)
    let t, w = Lwt.wait () in
    async (fun () -> pick [
      (send_req txfn timerfn q 4
       >>= fun () -> return (wakeup w (Error (R.timeout ctxt))));
      (catch
         (fun () ->
           rxfn (R.parse ctxt)
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

let resolve client
    ?(dnssec=false)
    (commfn:commfn)
    (q_class:DP.q_class) (q_type:DP.q_type)
    (q_name:domain_name) =
    try_lwt
      let id = (let module R = (val client : CLIENT) in R.get_id ()) in
      let q = Dns.Query.create ~id ~dnssec q_class q_type q_name in
      log_info (sprintf "query: %s\n%!" (DP.to_string q));
      send_pkt client commfn q
   with exn ->
      log_warn (sprintf "%s\n%!" (Printexc.to_string exn));
      fail exn

let gethostbyname
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    commfn
    name =
  let open DP in
  let domain = string_to_domain_name name in
  resolve (module Dns.Protocol.Client) commfn q_class q_type domain
  >|= fun r ->
    List.fold_left (fun a x ->
      match x.rdata with |A ip -> ip::a |_ -> a
    ) [] r.answers
   |> List.rev

let gethostbyaddr
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_PTR)
    commfn
    addr
    =
  let addr = for_reverse addr in
  log_info (sprintf "gethostbyaddr: %s" (domain_name_to_string addr));
  let open DP in
  resolve (module Dns.Protocol.Client) commfn q_class q_type addr
  >|= fun r ->
    List.fold_left (fun a x ->
      match x.rdata with |PTR n -> (domain_name_to_string n)::a |_->a
    ) [] r.answers
   |> List.rev
