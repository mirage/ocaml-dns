open Printf
open Lwt
open Dns.Packet
open Re_str

let ns = ref "8.8.8.8"
let domain = ref "google.com"
let rr_type = ref (Dns.Packet.q_type_of_int 1)

let usage () = (eprintf 
    "Usage: %s <node-name> <node-ip> <node-signalling-port>\n%!" 
    Sys.argv.(0); exit 1)

let _ =
  (try ns := Sys.argv.(1) with _ -> usage ());
  (try domain := Sys.argv.(2) with _ -> usage ());
  (try rr_type := (Dns.Packet.q_type_of_string Sys.argv.(3)) with _ -> usage());
  try
  let ns_fd = (Unix.(socket PF_INET SOCK_DGRAM 0)) in
  let src = Unix.ADDR_INET(Unix.inet_addr_any, 25000) in 
    Unix.bind ns_fd src;
    let detail = Dns.Packet.({qr=(qr_of_bool false); opcode=(opcode_of_int 0);
            aa=true; tc=false; rd=true; ra=false; rcode=(rcode_of_int 0);}) in
    let question = Dns.Packet.({ q_name=(Re_str.split (Re_str.regexp "\.") !domain);
        q_type=(!rr_type); q_class=(Dns.Packet.q_class_of_int 0);}) in 
    let packet = Dns.Packet.({id=1;detail=(Dns.Packet.build_detail detail);
    questions=[question]; answers=[]; authorities=[]; additionals=[];}) in 
    let data = Bitstring.string_of_bitstring (Dns.Packet.marshal packet) in
    let dst = Unix.ADDR_INET((Unix.inet_addr_of_string !ns),53) in
    let _ = Unix.sendto ns_fd data 0 (String.length data) [] dst in
    let buf = (String.create 1500) in
    let (len, _) = Unix.recvfrom ns_fd buf 0 1500 [] in
    let lbl = Hashtbl.create 64 in
    let reply = (Dns.Packet.parse_dns lbl (Bitstring.bitstring_of_string (String.sub buf 0 len))) in
      Printf.printf "dns reply: \n%s\n%!" (Dns.Packet.dns_to_string reply);
      return () 
  with exn -> Printf.printf "Exception caught!!\n%!"; raise exn
