(*
 * Copyright (c) 2014 marklrh <marklrh@gmail.com>
 * Copyright (c) 2016 Vincent Bernardoff <vb@luminar.eu.org>
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

open Core_kernel
open Async

open Dns
open Protocol

module DP = Packet

type result = Answer of DP.t | Err of exn

type commfn = {
  log : Log.t option;
  txfn    : Cstruct.t -> unit Deferred.t;
  rxfn    : (Cstruct.t -> Packet.t option) -> DP.t Deferred.t;
  timerfn : unit -> unit Deferred.t;
  cleanfn : unit -> unit Deferred.t;
}

let nchoose_split l =
  let fold_f (rs, ts) cur =
    match Deferred.peek cur with
    | Some v -> (v :: rs), ts
    | None -> rs, (cur :: ts)
  in
  List.fold_left l ~init:([], []) ~f:fold_f

let rec send_req txfn timerfn q = function
  | 0 -> Deferred.unit
  | count -> begin
      txfn q >>= fun _ ->
      timerfn () >>= fun () ->
      send_req txfn timerfn q (count - 1)
    end

let send_pkt ?alloc client { log; txfn; rxfn; timerfn; _ } pkt =
  let module R = (val client: CLIENT ) in
  let cqpl = R.marshal ?alloc pkt in
  let resl = List.map cqpl ~f:begin fun (ctxt, q) -> Deferred.any [
      ((send_req txfn timerfn q 4) >>| fun () -> (Err (R.timeout ctxt)));
      (try_with (fun () -> rxfn (R.parse ctxt)) >>| function
        | Ok r -> (Answer r)
        | Error exn -> (Err exn)
      )
    ]
    end
  in
  let rec select errors = function
    | [] ->
      raise (Dns_resolve_error errors)
    | ts ->
      let (rs, ts) = nchoose_split ts in
      Option.iter log ~f:(fun log -> Log.debug log "select");
      let rec find_answer errors = function
        | [] ->
          Clock_ns.after @@ Time_ns.Span.of_int_sec 1 >>= fun () ->
          select errors ts
        | (Answer a) ::  _ -> return a
        | (Err e) :: r -> find_answer (e :: errors) r
      in
      find_answer errors rs
  in select [] resl

let resolve ?alloc ?(dnssec = false) client commfn q_class q_type q_name =
  Monitor.try_with_or_error begin fun () ->
    let id = (let module R = (val client: CLIENT ) in R.get_id ()) in
    let q = Dns.Query.create ~id ~dnssec q_class q_type q_name in
    send_pkt ?alloc client commfn q
  end >>| fun r ->
  don't_wait_for (commfn.cleanfn ());
  r

let gethostbyname ?alloc ?(q_class=DP.Q_IN) ?(q_type=DP.Q_A) commfn name =
  let open DP in
  let domain = Name.of_string name in
  resolve ?alloc (module Dns.Protocol.Client) commfn q_class q_type domain >>|
  Or_error.map ~f:begin fun r ->
    List.fold_right r.answers ~init:[] ~f:begin fun x a ->
      match x.rdata with
      | A ip -> (Ipaddr.V4 ip) :: a
      | AAAA ip -> (Ipaddr.V6 ip) :: a
      | _ -> a
    end
  end
