open Dns

let ds_root =
  (* from https://data.iana.org/root-anchors/root-anchors.xml *)
  Ds.{ key_tag = 20326 ; algorithm = Dnskey.RSA_SHA256 ; digest_type = Ds.SHA256 ;
       digest = Cstruct.of_hex "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D" }

let dnskey_root =
  (* from "dig +dnssec dnskey ." *)
  Cstruct.of_hex {|
 d6d0 8180 0001 0003 0000 0001 0000 3000
 0100 0030 0001 0002 311f 0108 0100 0308
 0301 0001 b286 2a4a 9cd5 502f 42be 3c88
 f7fd 35dd fd7f 7dfb 322b 6083 1174 001f
 642c a44d 4aea bd8e 8384 3c2f d1e8 f0ff
 e254 f352 6b3c 53da 0ff9 a885 d2b5 42da
 b18e 2927 4e2f 13c7 44b0 376a 678c 153d
 bfdd b995 085b 11b2 7d37 2154 dd37 9554
 01f7 338e a8e6 034b 7d34 cedb 6cde 6857
 3b90 2f73 f517 241b d6ae 875f 8335 aa0f
 a1b4 c344 77d3 dd94 f2cc 15ca d483 97dc
 62d4 ebda 5955 90ed 57a3 7940 76b8 e69b
 17c6 788c 909e c929 c0fc 96f3 c279 dbb0
 c4ca d9a0 3e8e 4acc b058 2cca 0bd9 0e35
 3cad 2e97 4aec ef23 7e83 9206 e0b9 c939
 c8de c35c ab98 75eb a7f3 b3ae 9b0e e059
 2272 e7d8 b7fc a07d 02a4 4f91 d86e bff2
 1607 9901 f685 f349 d8c9 cef0 8036 3139
 e1dd 8919 0000 3000 0100 0231 1f01 0801
 0103 0803 0100 01ac ffb4 09bc c939 f831
 f7a1 e5ec 88f7 a592 55ec 5304 0be4 3202
 7390 a4ce 896d 6f90 86f3 c5e1 77fb fe11
 8163 aaec 7af1 462c 4794 5944 c4e2 c026
 be5e 98bb cded 2597 8272 e1e3 e079 c509
 4d57 3f0e 83c9 2f02 b32d 3513 b155 0b82
 6929 c80d d0f9 2cac 966d 1776 9fd5 867b
 647c 3f38 029a bdc4 8152 eb8f 2071 59ec
 c5d2 32c7 c153 7c79 f4b7 ac28 ff11 682f
 2168 1bf6 d6ab a555 032b f6f9 f036 beb2
 aaa5 b377 8d6e ebfb a6bf 9ea1 91be 4ab0
 caea 759e 2f77 3a1f 9029 c73e cb8d 5735
 b932 1db0 85f1 b8e2 d803 8fe2 9419 9254
 8cee 0d67 dd45 47e1 1dd6 3af9 c9fc 1c54
 66fb 684c f009 d719 7c2c f79e 792a b501
 e6a8 a1ca 519a f2cb 9b5f 6367 e94c 0d47
 5024 5135 7be1 b500 002e 0001 0002 311f
 0113 0030 0800 0002 a300 6017 4480 5ffb
 9500 4f66 009c f945 600c 88fa 250d cad6
 6eef 529c 3307 6f47 5b9b 8d54 4fe8 7a7b
 13fa 3045 a2e1 1e13 8e37 8809 b1ec dfe1
 4a01 7aae f9c9 e0c1 9334 40da 9c03 ee0e
 9755 8fea b103 3d58 3bb3 4d84 095a abd2
 1838 f405 8179 6d2e 3cda 41fc 6373 7f2f
 2fe3 9500 9214 8942 6d38 c050 11d3 7586
 638b a7ac 403a a25a 4d92 cc1d fc64 bb31
 81ec b8df d264 8715 3332 1e79 db4c cb0a
 23a7 b99b 3d23 2d0a 2e8c b8b2 ced1 fc68
 908d c604 222d 3349 c5d9 5dc0 c1af 7a9d
 d870 7f04 bf7c 1763 037a c873 43f5 518a
 6c6c 6774 47dc 444d 3d2d 46ba b9a3 63f9
 9351 9c57 dc84 e3d4 2e7b 3c8d 9b82 eaef
 d5be ddca 9d73 2e99 9994 8cff db59 50c2
 f4f7 c044 8617 8e09 d589 810e 1798 a06e
 3819 8f51 5600 0029 2000 0000 8000 0000
|}

let ts_of_req = match Ptime.of_rfc3339 "2021-01-17T23:00:00Z" with
  | Ok (t, _, _) -> t
  | Error  _ -> assert false

let key =
  let cs = Cstruct.of_string
      (Base64.decode_exn (String.concat "" [
           "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7H";
           "rxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5";
           "LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpV";
           "UDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLY";
           "A4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2";
           "Nn6UwNR1AkUTV74bU=" ]))
  in
  let e = Mirage_crypto_pk.Z_extra.of_cstruct_be (Cstruct.sub cs 1 3)
  and n = Mirage_crypto_pk.Z_extra.of_cstruct_be (Cstruct.shift cs 4)
  in
  match Mirage_crypto_pk.Rsa.pub ~e ~n with
  | Ok p -> p
  | Error _ -> assert false

let test_root () =
  (* decode the reply *)
  match Packet.decode dnskey_root with
  | Error _ -> Alcotest.fail "couldn't decode dnskey reply"
  | Ok data ->
    match data.Packet.data with
    | `Answer (a, au) ->
      Alcotest.(check int (__LOC__ ^ " authority is empty") 0
                  (Domain_name.Map.cardinal au));
      (* in the answer section there should be: 2 dnskey and 1 rrsig *)
      Alcotest.(check int (__LOC__ ^ " answer has a single element") 1
                  (Domain_name.Map.cardinal a));
      begin
        match Domain_name.Map.find Domain_name.root a with
        | None -> Alcotest.fail (__LOC__ ^ " expected root in answer map")
        | Some rrs ->
          Alcotest.(check int (__LOC__ ^ " two rrsets in rrs") 2
                      (Rr_map.cardinal rrs));
          match Rr_map.find Rr_map.Dnskey rrs, Rr_map.find Rr_map.Rrsig rrs with
          | Some (_, dnskeys), Some (_, rrsigs) ->
            Alcotest.(check int (__LOC__ ^ " two dnskeys") 2
                        (Rr_map.Dnskey_set.cardinal dnskeys));
            Alcotest.(check int (__LOC__ ^ " one rrsig") 1
                        (Rr_map.Rrsig_set.cardinal rrsigs));
            let rrsig = Rr_map.Rrsig_set.choose rrsigs in
            let no_rrsig_rrmap = Rr_map.remove Rr_map.Rrsig rrs in
            let used_dnskey =
              Rr_map.Dnskey_set.(choose (filter (fun dnsk ->
                  Dnskey.F.mem `Secure_entry_point dnsk.Dnskey.flags) dnskeys))
            in
            begin
              match Dnssec.digest ds_root.Ds.digest_type Domain_name.root used_dnskey with
              | Error _ -> Alcotest.fail "bad digest"
              | Ok dgst ->
                Alcotest.(check bool (__LOC__ ^ " DS matches") true
                            (Cstruct.equal ds_root.Ds.digest dgst))
            end;
            begin
              match Dnssec.dnskey_to_pk used_dnskey with
              | Ok `RSA k ->
                Alcotest.(check bool (__LOC__ ^ " key successfully extracted") true
                            ((Z.equal key.Mirage_crypto_pk.Rsa.e k.Mirage_crypto_pk.Rsa.e) &&
                             (Z.equal key.Mirage_crypto_pk.Rsa.n k.Mirage_crypto_pk.Rsa.n)))
              | _ -> Alcotest.fail "bad dnssec key"
            end;
            begin
              match Dnssec.verify ts_of_req (`RSA key) Domain_name.root rrsig no_rrsig_rrmap with
              | Ok () -> ()
              | Error (`Msg m) ->
                Alcotest.failf "%s signature verification failed %s" __LOC__ m
            end
          | _ -> Alcotest.fail (__LOC__ ^ " expected dnskey and rrsig")
      end
    (* use the matching dnskey, verify its hash against the ds root *)
    (* verify the rrsig signature -> we used the ds (KSK) to verify the ZSK *)
    | _ ->
      Alcotest.fail "expected an answer"

let tests = [
  "root", `Quick, test_root ;
]

let () =
  Printexc.record_backtrace true;
  Alcotest.run "DNSSEC tests" [ "DNSSEC tests", tests ]

