open Packet
open Printf

(* replicate examples from rfc 5702 *)
(*
 *bill.example.com.       86400   IN A    192.168.0.3
 *                       86400   RRSIG   A 8 3 86400 20121201163932 (
 *                                       20121101163932 45195 example.com.
 *                                       YUnn6K9izGheb//HwDFG+3DopLYw/2Y7kaIH
 *                                       lCIHWRrBrr7c8CZzpbkEQW+F9DAL7hfGF+90
 *                                       7nRRiFnxA9BH2ypfM4vX9Gw5SUpZ2cWmBXhz
 *                                       5EkBlTxDeZsvEQixYwbhh8m/quj9NkFYh9an
 *                                       EYTnSU9sdx1U0auTpx3XpOOn5Tw= )
 * *)
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
