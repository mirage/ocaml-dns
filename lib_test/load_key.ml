open Packet
open Printf

(* replicate examples from rfc 5702 *)

let _ = 
  let (alg, key) = Sec.load_key "lib_test/test-2.txt" in  
  let rr = Packet.({name=(Name.string_to_domain_name "www.example.net.");
                    cls=RR_IN; ttl=3600l; 
                    rdata=(A (Uri_IP.string_to_ipv4 "192.0.2.91"));}) in
  let _ = printf "signing record %s\n%!" (rr_to_string rr) in 
  let signed_rr = Sec.sign_records
    ~inception:(946684800l) ~expiration:(1893456000l) alg key 9033 
    (Name.string_to_domain_name "example.net.") [rr] in 
  let _ = printf "resulting rrsig %s\n%!" (rr_to_string signed_rr) in
    printf "Key loaded successfully.\n%!"
