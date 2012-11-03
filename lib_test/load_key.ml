open Packet
open Printf

(* replicate examples from rfc 5702 *)

let _ = 
  let (alg, key) = Sec.load_key "lib_test/rsa-sha256-test.private" in  
  let rr = Packet.({name=(Name.string_to_domain_name "www.example.net.");
                    cls=RR_IN; ttl=3600l; 
                    rdata=(A (Uri_IP.string_to_ipv4 "192.0.2.91"));}) in
  let _ = printf "signing record %s\n%!" (rr_to_string rr) in 
  let signed_rr = Sec.sign_records
    ~inception:(946684800l) ~expiration:(1893456000l) alg key 9033 
    (Name.string_to_domain_name "example.net.") [rr] in 
  let _ = printf "resulting rrsig %s\n%!" (rr_to_string signed_rr) in

  (*
   *  www.example.net. 3600  IN  RRSIG  (A 8 3 3600 20300101000000
   *                       20000101000000 9033 example.net. kRCOH6u7l0QGy9qpC9
   *                       l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncriShZNz85mwlMgNEa
   *                       cFYK/lPtPiVYP4bwg==);{id = 9033}
   * *)


  let rr_dnskey = Packet.({name=(Name.string_to_domain_name "example.net.");
                           cls=RR_IN; ttl=3600l;
                           rdata=(Sec.get_dnssec_key alg key)}) in
  let _ = printf "used key %s\n%!" (rr_to_string rr_dnskey) in
  let (alg, key) = Sec.load_key "lib_test/rsa-sha512-test.private" in  
  let signed_rr = Sec.sign_records
    ~inception:(946684800l) ~expiration:(1893456000l) alg key 3740 
    (Name.string_to_domain_name "example.net.") [rr] in 
  let _ = printf "resulting rrsig %s\n%!" (rr_to_string signed_rr) in
(*
 *
 *   www.example.net. 3600  IN  RRSIG  (A 10 3 3600 20300101000000
                    20000101000000 3740 example.net. tsb4wnjRUDnB1BUi+t
                    6TMTXThjVnG+eCkWqjvvjhzQL1d0YRoOe0CbxrVDYd0xDtsuJRa
                    eUw1ep94PzEWzr0iGYgZBWm/zpq+9fOuagYJRfDqfReKBzMweOL
                    DiNa8iP5g9vMhpuv6OPlvpXwm9Sa9ZXIbNl1MBGk0fthPgxdDLw
                    =);{id = 3740}
 * *)
    printf "Key loaded successfully.\n%!"
