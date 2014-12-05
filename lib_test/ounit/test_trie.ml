
open OUnit2
open Printf

module H = Dns.Hashcons
open Dns.Name
open Dns.Trie
open Dns.RR

let load_test_zone path =
  let ch = open_in path in
  let n = in_channel_length ch in
  let data = String.create n in
  really_input ch data 0 n;
  close_in ch;
  let db = Dns.Loader.new_db () in
  let db = Dns.Zone.load ~db [] data in
  db.Dns.Loader.trie

let tests =
  "Trie" >:::
  [
    "lookup" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_dns.zone" in

        let name = string_to_domain_name "mail.d1.signpo.st." in
        match lookup (canon2key name) trie ~mdns:false with
        | `Found (sec, node, zonehead) -> (* Name has RRs, and we own it. *)
          assert_equal false sec;
          (* Verify the A record *)
          assert_equal name node.owner.H.node;
          assert_equal 1 (List.length node.rrsets);
          let a = List.hd node.rrsets in
          assert_equal (Int32.of_int 172800) a.ttl;
          begin 
            match a.rdata with
            | A ips ->
              assert_equal 1 (List.length ips);
              assert_equal "127.0.0.94" (ips |> List.hd |> Ipaddr.V4.to_string)
            | _ -> assert_failure "Not A"
          end;

          (* Verify the SOA record *)
          assert_equal "d1.signpo.st" (domain_name_to_string zonehead.owner.H.node);
          assert_equal ~printer:string_of_int 3 (List.length zonehead.rrsets);
          let soa = List.nth zonehead.rrsets 1 in
          assert_equal (Int32.of_int 604800) soa.ttl;
          begin
            match soa.rdata with
            | SOA soas ->
              assert_equal 1 (List.length soas);
              let (master, rp, serial, refresh, retry, expiry, min) = List.hd soas in
              assert_equal "ns0.d1.signpo.st" (domain_name_to_string master.owner.H.node);
              (* Warning: the first dot is part of the first label *)
              assert_equal "john.doe.d1.signpo.st" (domain_name_to_string rp.owner.H.node);
              assert_equal ~msg:"refresh" (Int32.of_int 3600) refresh;
              assert_equal ~msg:"retry" (Int32.of_int 1800) retry;
              assert_equal ~msg:"expiry" (Int32.of_int 3024000) expiry;
              assert_equal ~msg:"min" (Int32.of_int 1800) min;
            | _ -> assert_failure "Not SOA"
          end
        | _ -> assert_failure "Not found"
      );

    "lookup-mdns" >:: (fun test_ctxt ->
        let trie = load_test_zone "test_mdns.zone" in

        let name = string_to_domain_name "fake1.local." in
        match lookup (canon2key name) trie ~mdns:true with
        | `Found (sec, node, zonehead) -> (* Name has RRs, and we own it. *)
          begin 
            assert_equal false sec;
            assert_equal name node.owner.H.node;
            assert_equal 1 (List.length node.rrsets);
            let a = List.hd node.rrsets in
            assert_equal (Int32.of_int 4500) a.ttl;
            match a.rdata with
            | A ips ->
              assert_equal 1 (List.length ips);
              assert_equal "127.0.0.94" (ips |> List.hd |> Ipaddr.V4.to_string)
            | _ -> assert_failure "Not A"
          end
        | _ -> assert_failure "Not found";
      );

  ]

