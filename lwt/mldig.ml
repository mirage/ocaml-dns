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

open Printf
open Dns.Packet

let debug_active = ref false
let debug x = if !debug_active then prerr_endline (sprintf "[debug] %s" x)
let warn x y = prerr_endline (sprintf "%s warning: %s" x y)
let error x y = prerr_endline (sprintf "%s error: %s" x y); exit(1)

let got_alrm = ref false

let print_timeout () =
  printf ";; connection timed out; no servers could be reached\n%!";
  exit 1

let print_error e = printf ";; read error: %s\n" (Unix.error_message e)
let print_section s = printf ";; %s SECTION:\n" (String.uppercase s)

let print_answers p =
    printf ";; global options: \n";
    let uc = String.uppercase in
    let onl () = print_newline () in
    let bitfn a b = if a then None else Some b in
    let { detail; id; questions; answers; authorities; additionals } = p in
    let flags = [
      (match detail.qr with
       |Query -> None
       |Response -> Some "qr");
      (bitfn detail.aa "aa");
      (bitfn detail.tc "tc");
      (bitfn detail.rd "rd");
      (bitfn detail.ra "ra");
    ] in
    let flags = String.concat " " 
      (List.fold_left (fun a -> function |None -> a |Some x -> x :: a) [] flags) in
    printf ";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n" 
      (uc (opcode_to_string detail.opcode))
      (uc (rcode_to_string detail.rcode)) id;
    let al = List.length in
    printf ";; flags: %s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n\n"
      flags (al questions) (al answers) (al authorities) (al additionals);
    if al questions > 0 then begin
      print_section "question";
      List.iter (fun q -> printf ";%-23s %-8s %-8s %s\n"
        (String.concat "." q.q_name) ""
        (q_class_to_string q.q_class)
        (q_type_to_string q.q_type)
      ) questions;
      onl ();
    end;
    let print_rr a d e =
      printf "%-24s %-8lu %-8s %-8s %s\n" 
        (String.concat "." a.name) a.ttl (rr_class_to_string a.cls) d e in
    List.iter (fun (nm,ob) ->
      if al ob > 0 then print_section nm;
      List.iter (fun rr ->
        match rr.rdata with
        |A ip-> print_rr rr "A" (Uri_IP.ipv4_to_string ip);
        |SOA (n1,n2,a1,a2,a3,a4,a5) ->
          print_rr rr "SOA"
            (sprintf "%s %s %lu %lu %lu %lu %lu" (String.concat "." n1)
              (String.concat "." n2) a1 a2 a3 a4 a5);
        |MX (pref,host) -> 
          print_rr rr "MX" (sprintf "%d %s" pref (String.concat "." host));
        |CNAME a -> print_rr rr "CNAME" (String.concat "." a)
        |NS a -> print_rr rr "NS" (String.concat "." a)
        |_ -> printf "unknown\n"
      ) ob;
      if al ob > 0 then onl ()
    ) ["answer",answers; "authority",authorities; "additional",additionals]
  
open Lwt
 
let t =
  lwt res = Dns_resolver.create () in
  let (module Res) = res in
  let (server,dest_port) =
    match Res.servers with 
    | [] -> None,53 
    |(s,p)::_ -> (Some s),p in
  let server = ref server in
  let dest_port = ref dest_port in
  let args = ref [] in
  let qty = ref Q_A in
  let qcl = ref Q_IN in
  let timeout = ref 2 in
  let notimpl x = warn "dig" ("Command-line option \"" ^ x ^ "\" is not supported.") in
  let spec = [
    "-b", Arg.String (fun x -> notimpl "-b"), "set source IP of query";
    "-c", Arg.String (fun x -> notimpl "-c"), "set query class (default IN)";
    "-f", Arg.String (fun x -> notimpl "-f"), "read batched requests from file";
    "-k", Arg.String (fun x -> notimpl "-k"), "sign outgoing queries";
    "-p", Arg.Set_int dest_port, (sprintf "set destination port number (default %d)" !dest_port);
    "-t", Arg.String (fun x -> notimpl "-t"), "set query type (default to A unless -x is set)";
    "-x", Arg.String (fun x -> notimpl "-x"), "do reverse lookup";
    "-y", Arg.String (fun x -> notimpl "-y"), "key to sign request";
    "-v", Arg.Unit (fun () -> debug_active := true), "turn on debug output";
  ] in
    
  let anon_arg x = 
    if String.length x > 1 && (x.[0] = '@') then begin
      server := Some (String.sub x 1 (String.length x - 1))
    end else begin
      match string_to_q_type (String.uppercase x) with
      |None -> begin
        match string_to_q_class (String.uppercase x) with
        |None ->
          args := !args @ [x];
          debug (sprintf "Setting HOSTNAME = %s" x);
        |Some cl ->
          qcl := cl;
          debug (sprintf "Setting CLASS = %s" (q_class_to_string !qcl));
        end
      |Some ty -> begin
        qty := ty;
        debug (sprintf "Setting TYPE = %s" (q_type_to_string !qty));
      end
    end
  in
  Arg.parse spec anon_arg "generate and send DNS queries";
  if !args = [] then error "dig" "Must specify at least one hostname to resolve.";
  if List.length !args > 1 then error "dig" "Only one name can be resolved at a time.";
  printf ";; <<>> MLDiG 1.0 <<>>\n"; (* TODO put query domains from Sys.argv here *)
  match !server with
  |None -> error "dig" "Must specify a DNS resolver (with @<hostname>)"
  |Some x -> 
    debug (sprintf "Querying DNS server %s" x);
    let domain = Dns.Name.string_to_domain_name (List.hd !args) in
    let _ = Lwt_unix.sleep (float_of_int !timeout) >|= print_timeout in
    Dns_resolver.resolve res !qcl !qty domain >|= print_answers

let _ = Lwt_main.run t
