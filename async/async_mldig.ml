(*
 * Copyright (c) 2005-2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2005 David Scott <djs@fraserresearch.org>
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

open Core.Std
open Async.Std
open Async_dns_resolver
open Printf
open Dns.Name
open Dns.Packet
open Uri

let debug_active = ref false
let debug x = if !debug_active then (printf "[debug] %s \n" x)
let warn x y = (printf "%s warning: %s\n" x y)
let error x y = (printf "%s error: %s \n" x y)

let print_timeout () =
  printf ";; connection timed out; no servers could be reached\n%!";
  exit 1

let print_section s = printf ";; %s SECTION:\n" (String.uppercase s)

let print_answers p =
    printf ";; global options: \n";
    let { detail; id; questions; answers; authorities; additionals } = p in
    let if_flag a b = if a then None else Some b in
    let flags = [
      (match detail.qr with |Query -> None |Response -> Some "qr");
      (if_flag detail.aa "aa");
      (if_flag detail.tc "tc");
      (if_flag detail.rd "rd");
      (if_flag detail.ra "ra");
    ] in
    let flags = String.concat ~sep:" " (List.fold_left ~f:(fun a ->
      function |None -> a |Some x -> x :: a) ~init:[] flags) in
    printf ";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n" 
      (String.uppercase (opcode_to_string detail.opcode))
      (String.uppercase (rcode_to_string detail.rcode)) id;
    let al = List.length in
    printf ";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n"
      flags (al questions) (al answers) (al authorities) (al additionals);
    if al questions > 0 then begin
      print_section "question";
      List.iter ~f:(fun q -> printf ";%-23s %-8s %-8s %s\n"
        (String.concat ~sep:"." q.q_name) ""
        (q_class_to_string q.q_class)
        (q_type_to_string q.q_type)
      ) questions;
      print_newline ();
    end;
    let print_rr rr = printf "%-24s %-8lu %-8s %-8s %s\n" 
        (String.concat ~sep:"." rr.name) rr.ttl (rr_class_to_string rr.cls) in
    List.iter ~f:(fun (nm,ob) ->
      if al ob > 0 then print_section nm;
      List.iter ~f:(fun rr ->
        match rr.rdata with
        |A ip-> print_rr rr "A" (Uri_IP.ipv4_to_string ip);
        |SOA (n1,n2,a1,a2,a3,a4,a5) ->
          print_rr rr "SOA"
            (sprintf "%s %s %lu %lu %lu %lu %lu" (String.concat ~sep:"." n1)
              (String.concat ~sep:"." n2) a1 a2 a3 a4 a5);
        |MX (pref,host) -> 
          print_rr rr "MX" (sprintf "%d %s" pref (String.concat ~sep:"." host));
        |CNAME a -> print_rr rr "CNAME" (String.concat ~sep:"." a)
        |NS a -> print_rr rr "NS" (String.concat ~sep:"." a)
        |_ -> printf "unknown\n"
      ) ob;
      if al ob > 0 then print_newline ()
    ) ["answer",answers; "authority",authorities; "additional",additionals]
  
open Cmdliner

let run domain :unit =
    let q_type =  Q_A in
    let q_class =  Q_IN in
    let domain = string_to_domain_name domain in
    Async_dns_resolver.get_resolvers ()
    >>= (fun resolvers -> Async_dns_resolver.resolve resolvers q_class q_type domain)
    >>> (function | `Result p -> (print_answers p ; Caml.exit 0) 
		  | `Timeout -> printf ":("; Caml.exit 1  )


let () =
  Command.async_basic
    ~summary:"Start an dns resquest"
    Command.Spec.(
      empty
      +> flag "-domain" (optional_with_default "www.bbc.co.uk" string)
        ~doc:" Domain to query (default www.bbc.co.uk)"
    )
    (fun uppercase domain () -> run ~domain)
  |> Command.run

