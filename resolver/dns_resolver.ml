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

let port = 5335

let ns = "127.0.0.1"
let id = ref 0xDEAD
let get_id () =
    let i = !id in
    incr id;
    i

let pr s = eprintf "XXX: %s\n%!" s

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

let outfd addr port = 
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 17) in 
  let _ = Lwt_unix.(bind fd (sockaddr addr port)) in
  fd

let txbuf fd dst buf =
  lwt len = Lwt_unix.sendto fd buf 0 (String.length buf) [] dst in
  return(len)

let resolve
    ?(server:string = ns)
    ?(q_class:DP.q_class = `IN)
    ?(q_type:DP.q_type = `ANY) 
    (q_name:domain_name) 
    =

  let ofd = outfd "0.0.0.0" 0 in
  (try_lwt
      let q = build_query q_class q_type q_name in
      printf "query: %s\n%!" (DP.dns_to_string q);
      
      let q = q |> DP.marshal_dns |> Bitstring.string_of_bitstring in
      let dst = sockaddr server port in 
      txbuf ofd dst q
   with 
     | exn -> (eprintf "EXN: TX: %s\n%!" (Printexc.to_string exn); fail exn)
  ) >>= (fun len -> 
    eprintf "TX: len:%d\n%!" len; 

    let buf = String.create 1514 in 
    lwt _ = Lwt_unix.wait_read ofd in 
    lwt (len, sa) = Lwt_unix.recvfrom ofd buf 0 1514 [] in     
    eprintf "RX: len:%d\n%!" len;
    
    let r =
      let names = Hashtbl.create 64 in
      DP.parse_dns names (Bitstring.bitstring_of_string buf)
    in 
    printf "response; %s\n%!" (DP.dns_to_string r);
    return r
   )
(*
  ;
  (* make the thread cancellable, and return it *)
  let t,u = Lwt.task () in
  Lwt.on_cancel t (fun () -> eprintf "resolve: cancelled\n%!";);
  Lwt.on_failure t (fun e -> 
    eprintf "resolve: exception: %s\n%!" (Printexc.to_string e)
  );
  eprintf "resolve: done\n%!";
  t
*)

let gethostbyname name = 
  let domain = string_to_domain_name name in
  lwt r = resolve ~q_class:DP.(`IN) ~q_type:DP.(`A) domain in 

  return DP.(r.answers ||> (fun x -> match x.rr_rdata with 
      |`A ip -> Some ip
      | _ -> None 
    ) |> List.filter (function Some _ -> true | None -> false)
    ||> (function Some i -> i | None -> raise (Failure "XXX"))
  )

let gethostbyaddr addr = 
  return "DEADBEEF"
