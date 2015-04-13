(*
 * Copyright (c) 2014 marklrh <marklrh@gmail.com>
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

open Core_kernel.Std
open Async_kernel.Std

open Dns
open Operators
open Protocol

module DP = Packet

type result = Answer of DP.t | Err of exn

type commfn = {
  txfn    : Buf.t -> unit Deferred.t;
  rxfn    : (Buf.t -> Packet.t option) -> DP.t Deferred.t;
  timerfn : unit -> unit Deferred.t;
  cleanfn : unit -> unit Deferred.t;
}

(*
TODO: move to a Unix module, since library should not write to stdout
    
let stdout_writer () = Lazy.force Writer.stdout
let stderr_writer () = Lazy.force Writer.stderr

let message s = Writer.write (stdout_writer ()) s
let warn s = Writer.write (stderr_writer ()) (Printf.sprintf "WARN: %s\n%!" s)
*)

let nchoose_split l = 
  let fold_f (rs, ts) cur =
    match Deferred.peek cur with
    | Some v -> (v :: rs), ts
    | None -> rs, (cur :: ts)
  in
  return (List.fold_left l ~init:([], []) ~f:fold_f)

let rec send_req txfn timerfn q =
  function
  | 0 -> return ()
  | count -> begin
      txfn q >>= fun _ ->
      timerfn () >>= fun () ->
      send_req txfn timerfn q (count - 1)
    end

let send_pkt client ({ txfn; rxfn; timerfn; cleanfn }) pkt =
  let module R = (val client: CLIENT ) in
  let cqpl = R.marshal pkt in
  let resl = List.map cqpl ~f:(fun (ctxt, q) ->
    Deferred.any [
      ((send_req txfn timerfn q 4) >>= fun () -> 
        return (Err (R.timeout ctxt)));
      (try_with (fun () -> rxfn (R.parse ctxt))
        >>| function
        | Ok r -> (Answer r)
        | Error exn -> (Err exn))
      ]) in
  let rec select errors = function
    | [] -> raise (Dns_resolve_error errors)
    | ts ->
      nchoose_split ts
      >>= fun (rs, ts) ->
      let rec find_answer errors = function
        | [] -> select errors ts
        | (Answer a) ::  _ -> return a
        | (Err e) :: r -> find_answer (e :: errors) r
      in
      find_answer errors rs
  in select [] resl

let resolve client
    ?(dnssec = false)
    (commfn : commfn)
    (q_class : DP.q_class) (q_type : DP.q_type)
    (q_name : Name.t) =
  (try_with (fun () ->
    let id = (let module R = (val client: CLIENT ) in R.get_id ()) in
    let q = Dns.Query.create ~id ~dnssec q_class q_type q_name in
    send_pkt client commfn q)) >>| 
  (function
    | Ok r -> don't_wait_for (commfn.cleanfn ()); r
    | Error exn -> don't_wait_for (commfn.cleanfn ()); raise exn)


let gethostbyname
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    commfn
    name =
  let open DP in
  let domain = Name.of_string name in
  resolve (module Dns.Protocol.Client) commfn q_class q_type domain
  >>| fun r ->
  List.fold_left r.answers ~f:(fun a x ->
    match x.rdata with
    | A ip -> (Ipaddr.V4 ip) :: a
    | AAAA ip -> (Ipaddr.V6 ip) :: a
    | _ -> a
    ) ~init:[] |> List.rev

