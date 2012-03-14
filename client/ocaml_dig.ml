open Lwt
open Printf
open Re_str

module DP = Dns.Packet

let ns = ref "8.8.8.8"
let domain = ref "google.com"
let rr_type = ref DP.(`A)

let usage () = 
  eprintf "Usage: %s <node-name> <node-ip> <node-signalling-port>\n%!" 
    Sys.argv.(0); 
  exit 1

let _ =
  ignore(
    try
      ns := Sys.argv.(1);
      domain := Sys.argv.(2);
      rr_type := DP.string_to_q_type Sys.argv.(3);
    with exn -> (
      eprintf "EXN: %s\n%!" (Printexc.to_string exn);
      usage()
    )
  );
  
  try
    let ns_fd = 
      let ns_fd = Unix.(socket PF_INET SOCK_DGRAM 0) in
      let src = Unix.ADDR_INET(Unix.inet_addr_any, 25000) in 
      Unix.bind ns_fd src;
      ns_fd
    in
    
    let detail = DP.({
      qr=DP.(`Query); opcode=DP.(`Query);
      aa=true; tc=false; rd=true; ra=false; rcode=DP.(`NoError);
    })
    in
    let question = DP.({ 
      q_name  = Re_str.split (Re_str.regexp "\\.") !domain;
      q_type  = !rr_type; 
      q_class = DP.(`IN);
    }) 
    in 
    let packet = DP.({
      id=0xBEEF; detail=(DP.build_detail detail);
      questions=[question]; answers=[]; authorities=[]; additionals=[];
    }) 
    in 
    let data = Bitstring.string_of_bitstring (DP.marshal_dns packet) in
    let dst = Unix.ADDR_INET((Unix.inet_addr_of_string !ns), 53) in
    let _ = Unix.sendto ns_fd data 0 (String.length data) [] dst in
    let buf = 
      let buf = String.create 1514 in
      let (len, _) = Unix.recvfrom ns_fd buf 0 1514 [] in
      String.sub buf 0 len
    in
    let lbl = Hashtbl.create 64 in
    let reply = (DP.parse_dns lbl (Bitstring.bitstring_of_string buf)) in
    printf "dns reply: \n%s\n%!" (DP.dns_to_string reply);
    return () 
  with
    | exn -> (
      eprintf "Exception caught: %s\n%!" (Printexc.to_string exn);
      raise exn
    )
