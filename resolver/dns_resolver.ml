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
open Uri_IP
open Printf
open Dns.Name
open Dns.Operators

module DP = Dns.Packet

let buflen = 1514
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

let build_query q_class q_type q_name = 
  let detail = DP.(build_detail { 
    qr=DP.(`Query); opcode=DP.(`Query);
    aa=true; tc=false; rd=true; ra=false; rcode=DP.(`NoError); })
  in
  let question = DP.({ q_name; q_type; q_class }) in 
  DP.({ id=get_id (); detail; questions=[question]; 
        answers=[]; authorities=[]; additionals=[]; 
      })

let sockaddr addr port = 
  Lwt_unix.(ADDR_INET (Unix.inet_addr_of_string addr, port))

let sockaddr_to_string = Lwt_unix.(function
  | ADDR_INET (a,p) -> sprintf "%s/%d" (Unix.string_of_inet_addr a) p
  | ADDR_UNIX s -> s ^ "/UNIX"
  )

let outfd addr port = 
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 17) in 
  let _ = Lwt_unix.(bind fd (sockaddr addr port)) in
  fd

let txbuf fd dst buf =
  lwt len = Lwt_unix.sendto fd buf 0 (String.length buf) [] dst in
  log_debug (sprintf "txbuf: len:%d" len);
  return(len)

let rxbuf fd len = 
  let buf = String.create len in
  lwt _ = Lwt_unix.wait_read fd in 
  lwt (len, sa) = Lwt_unix.recvfrom fd buf 0 len [] in
  log_debug (sprintf "rxbuf: len:%d" len);
  return (Bitstring.bitstring_of_string buf, sa)

let resolve
    ?(server:string = ns)
    ?(q_class:DP.q_class = `IN)
    ?(q_type:DP.q_type = `ANY) 
    (q_name:domain_name) 
    =

  let ofd = outfd "0.0.0.0" 0 in
  (try_lwt
      let q = build_query q_class q_type q_name in
      log_info (sprintf "query: %s\n%!" (DP.dns_to_string q));
      let q = q |> DP.marshal_dns |> Bitstring.string_of_bitstring in
      let dst = sockaddr server port in 
      txbuf ofd dst q
   with 
     | exn -> (log_warn (sprintf "%s\n%!" (Printexc.to_string exn)); fail exn)
  ) >> (
       lwt (buf,sa) = rxbuf ofd buflen in 
       let names = Hashtbl.create 8 in
       let r = DP.parse_dns names buf in 
       log_info (sprintf "response:%s sa:%s" 
                   (DP.dns_to_string r) (sockaddr_to_string sa));
       return r
   )
(*
  ;
  (* make the thread cancellable, and return it *)
  let t,u = Lwt.task () in
  Lwt.on_cancel t (fun () -> eprintf "resolve: cancelled\n%!";);
  eprintf "resolve: done\n%!";
  t
  Lwt.on_failure t (fun e -> 
    eprintf "resolve: exception: %s\n%!" (Printexc.to_string e)
  );
*)

let gethostbyname name = 
  let domain = string_to_domain_name name in
  lwt r = resolve ~q_class:DP.(`IN) ~q_type:DP.(`A) domain in 
  return (DP.(r.answers ||> (fun x -> match x.rr_rdata with 
    |`A ip -> Some ip
    | _ -> None
    )) 
    |> List.fold_left (fun a -> function Some x -> x :: a | None -> a) []
    |> List.rev
  )

let gethostbyaddr addr = 
  let addr = for_reverse addr in
  log_info (sprintf "gethostbyaddr: %s" (domain_name_to_string addr));

  lwt r = resolve ~q_class:DP.(`IN) ~q_type:DP.(`PTR) addr in
  return (DP.(r.answers ||> (fun x -> match x.rr_rdata with 
    |`PTR n -> Some n
    | _ -> None
    )) 
    |> List.fold_left (fun a -> function 
        | Some n -> (domain_name_to_string n) :: a
        | None -> a) []
    |> List.rev
  )
