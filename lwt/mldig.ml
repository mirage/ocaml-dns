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
open Dns.Name
open Dns.Packet

let debug_active = ref false
let debug x = if !debug_active then prerr_endline (sprintf "[debug] %s" x)
let warn x y = prerr_endline (sprintf "%s warning: %s" x y)
let error x y = prerr_endline (sprintf "%s error: %s" x y); exit(1)

let print_timeout () =
  printf ";; connection timed out; no servers could be reached\n%!";
  exit 1

let print_error e = printf ";; read error: %s\n" (Unix.error_message e)
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
    let flags = String.concat " " (List.fold_left (fun a ->
      function |None -> a |Some x -> x :: a) [] flags) in
    printf ";; ->>HEADER<<- opcode: %s, status: %s, id: %u\n"
      (String.uppercase (opcode_to_string detail.opcode))
      (String.uppercase (rcode_to_string detail.rcode)) id;
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
      print_newline ();
    end;
    let print_rr rr = printf "%-24s %-8lu %-8s %-8s %s\n"
        (String.concat "." rr.name) rr.ttl (rr_class_to_string rr.cls) in
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
      if al ob > 0 then print_newline ()
    ) ["answer",answers; "authority",authorities; "additional",additionals]

open Lwt
open Cmdliner

let dig res server source_ip dest_port q_class q_type args =
  let timeout = 5 (* matches dig *) in
  (* Fold over args to determine overrides for q_class/type *)
  let (server, q_class, q_type, domains) = List.fold_left (
    fun (server, q_class, q_type, domains) arg ->
      (* Args beginning with @ decide the server *)
      if String.length arg > 1 && (arg.[0] = '@') then begin
        (* TODO: check for port? *)
        let server = String.sub arg 1 (String.length arg -1) in
        (Some server, q_class, q_type, domains)
      end else begin
        (* See if the argument is a query class or type *)
        let arg = String.uppercase arg in
        let q_type' = string_to_q_type arg in
        let q_class' = string_to_q_class arg in
        match q_type', q_class' with
        |None, None -> (server, q_class, q_type, arg::domains)
        |Some q_type, None -> (server, q_class, q_type, domains)
        |None, Some q_class -> (server, q_class, q_type, domains)
        |Some q_type, Some q_class -> (server, q_class, q_type, domains)
      end
  ) (server, q_class, q_type, []) args in
  let domains = match domains with |[] -> ["."] |_ -> domains in
  printf ";; <<>> MLDiG 1.0 <<>>\n"; (* TODO put query domains from Sys.argv here *)
 match server with
  |None -> error "dig" "Must specify a DNS resolver (with @<hostname>)"
  |Some x ->
    debug (sprintf "Querying DNS server %s" x);
    let domain = string_to_domain_name (List.hd domains) in
    let _ = Lwt_unix.sleep (float_of_int timeout) >|= print_timeout in
    Dns_resolver.resolve res q_class q_type domain >|= print_answers

let t =
  lwt res = Dns_resolver.create () in
  let (default_server, default_dest_port) =
    match res.Dns_resolver.servers with
    |[] -> None,53
    |(s,p)::_ -> (Some s),p in
  let source_ip =
    Arg.(value & opt string "0.0.0.0" & info ["b"] ~docv:"SOURCE_IP"
      ~doc:"set source IP of query") in
  let dest_port =
    Arg.(value & opt int default_dest_port & info ["p";"port"] ~docv:"DEST_PORT"
      ~doc:"set destination port number") in
  let q_class =
    (fun x -> match string_to_q_class x with |None -> `Error "" |Some x -> `Ok x),
    (fun f a -> Format.pp_print_string f (q_class_to_string a)) in
  let q_class = Arg.(value & opt q_class Q_IN & info ["c";"qclass"]  ~docv:"QCLASS") in
  let q_type =
    (fun x -> match string_to_q_type x with |None -> `Error "" |Some x -> `Ok x),
    (fun f a -> Format.pp_print_string f (q_type_to_string a)) in
  let q_type = Arg.(value & opt q_type Q_A &  info ["t";"qtype"] ~docv:"QTYPE") in
  let args = Arg.(non_empty & pos_all string [] & info [] ~docv:"ARGS") in
  let info =
    let doc = "DNS lookup utility" in
    let man = [ `S "BUGS"; `P "Email bug reports to <cl-mirage@lists.cl.cam.ac.uk>."] in
    Term.info "mldig" ~version:"1.0.0" ~doc ~man
  in
  let cmd_t = Term.(pure
    (dig res default_server) $
    source_ip $
    dest_port $
    q_class $
    q_type $ args) in
  match Term.eval (cmd_t, info) with `Ok x -> x |_ -> exit 1

let _ = Lwt_main.run t
