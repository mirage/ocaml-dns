
open OUnit2
open Printf

open Dns.Packet
open Dns.Name
module Q = Dns.Query

let tests =
  "Query" >:::
  [
    "answer-dns" >:: (fun test_ctxt ->
        let trie = Test_trie.load_test_zone "test_dns.zone" in
        let name = string_to_domain_name "mail.d1.signpo.st." in
        let answer = Q.answer ~dnssec:false ~mdns:false name Q_A trie in
        assert_equal NoError answer.Q.rcode;
        assert_equal true answer.Q.aa;
        assert_equal 1 (List.length answer.Q.answer);
        assert_equal ~printer:string_of_int 5 (List.length answer.Q.authority);
        assert_equal ~printer:string_of_int 1 (List.length answer.Q.additional);

        (* Verify the A record *)
        begin 
          let a = List.hd answer.Q.answer in
          assert_equal name a.name;
          assert_equal (Int32.of_int 172800) a.ttl;
          match a.rdata with
          | A ip ->
            assert_equal ~printer:(fun s -> s) "127.0.0.94" (ip |> Ipaddr.V4.to_string)
          | _ -> assert_failure "Not A"
        end;

        (* Verify the authority records *)
        (* Unfortunately the order of records is non-deterministic so we build a sorted list first *)
        let names = ["ns.isp.net"; "ns0.d1.signpo.st"; "ns2.isp.net"; "ns3.isp.net"; "ns4.isp.net"] in
        let rec get_ns_list rrs rest =
            begin
              match rrs with
              | [] -> rest;
              | ns::tl ->
                begin
                  assert_equal ~msg:"name" ~printer:(fun s -> s) "d1.signpo.st" (domain_name_to_string ns.name);
                  assert_equal ~msg:"cls" RR_IN ns.cls;
                  assert_equal ~msg:"flush" false ns.flush;
                  assert_equal ~msg:"ttl" ~printer:Int32.to_string (Int32.of_int 604800) ns.ttl;
                  match ns.rdata with
                  | NS name ->
                    get_ns_list tl ((domain_name_to_string name) :: rest)
                  | _ -> assert_failure "Authority not A";
                end
            end in
        let ns_list = get_ns_list answer.Q.authority [] in
        let ns_sorted = List.sort String.compare ns_list in
        let rec dump_str_l l =
          match l with
          | [] -> ""
          | hd::tl -> hd ^ "; " ^ (dump_str_l tl) in
        assert_equal ~printer:dump_str_l names ns_sorted;

        (* Verify the additional record *)
        begin
          let ns = List.hd answer.Q.additional in
          assert_equal ~msg:"name" "ns0.d1.signpo.st" (domain_name_to_string ns.name);
          assert_equal ~msg:"cls" RR_IN ns.cls;
          assert_equal ~msg:"flush" false ns.flush;
          assert_equal ~msg:"ttl" (Int32.of_int 172800) ns.ttl;
          match ns.rdata with
          | A addr -> assert_equal ~msg:"A" ~printer:(fun s -> s) "127.0.0.94" (Ipaddr.V4.to_string addr)
          | _ -> assert_failure "Authority not A";
        end

      );
  ]

