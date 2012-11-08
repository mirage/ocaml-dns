open Packet
open Printf
open Lwt

(* replicate examples from rfc 5702 *)

lwt _ = 
  let (alg, key) = Sec.load_rsa_key "lib_test/rsa-sha256-test.private" in  
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

  let rdata_dnskey = Sec.get_dnskey_rr alg key in
  let rr_dnskey = Packet.({name=(Name.string_to_domain_name "example.net.");
                           cls=RR_IN; ttl=3600l;
                           rdata=rdata_dnskey}) in
  let _ = printf "used key %s {tag : %d}\n%!" (rr_to_string rr_dnskey)
            (Sec.get_dnskey_tag rdata_dnskey)
  in
  let rdata_ds = Sec.get_ds_rr rr_dnskey.name Packet.SHA1 
                  rdata_dnskey in 

  let (alg, key) = Sec.load_rsa_key "lib_test/rsa-sha512-test.private" in  
  let rr_ds = Packet.({name=(Name.string_to_domain_name "example.net.");
                           cls=RR_IN; ttl=3600l;rdata=rdata_ds}) in
  let _ = printf "ds record %s\n%!" (rr_to_string rr_ds) in 
   
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
  let rr_dnskey = Packet.({name=(Name.string_to_domain_name "example.net.");
                           cls=RR_IN; ttl=3600l;
                           rdata=(Sec.get_dnskey_rr alg key)}) in
  let _ = printf "used key %s\n tag : %d\n%!" (rr_to_string rr_dnskey) 
            (Sec.get_dnskey_tag (Sec.get_dnskey_rr alg key)) in
(*
 *   example.net.    3600  IN  DNSKEY  (256 3 10 AwEAAdHoNTOW+et86KuJOWRD
                   p1pndvwb6Y83nSVXXyLA3DLroROUkN6X0O6pnWnjJQujX/AyhqFD
                   xj13tOnD9u/1kTg7cV6rklMrZDtJCQ5PCl/D7QNPsgVsMu1J2Q8g
                   pMpztNFLpPBz1bWXjDtaR7ZQBlZ3PFY12ZTSncorffcGmhOL
                   );{id = 3740 (zsk), size = 1024b}
 *)


  let _ = printf "\n\n---------------Test resolver---------------\n%!" in 
  lwt resolver = Dns_resolver.create () in 
  lwt st = Sec.init_dnssec ~resolver:(Some resolver) () in  
  
  lwt p = Dns_resolver.resolve resolver Packet.Q_IN Packet.Q_DNSKEY 
            (Name.string_to_domain_name ".") in
  let rec add_root_dnskey = function
    | [] -> ()
    | hd :: tl -> 
        let _ = Sec.add_anchor st hd in
          add_root_dnskey tl 
  in 
  let _ = add_root_dnskey p.Packet.answers in 
  lwt p = Sec.resolve st Packet.Q_IN Packet.Q_SOA
            (Name.string_to_domain_name "www.nlnetlabs.nl.") in

  let _ = printf "verifying %s\n%!" (Sec.dnssec_result_to_string p) in
    return (printf "Key loaded successfully.\n%!")
