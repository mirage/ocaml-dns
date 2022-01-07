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
          | Some ((_, dnskeys) as dnskey_rrs), Some (_, rrsigs) ->
            Alcotest.(check int (__LOC__ ^ " two dnskeys") 2
                        (Rr_map.Dnskey_set.cardinal dnskeys));
            Alcotest.(check int (__LOC__ ^ " one rrsig") 1
                        (Rr_map.Rrsig_set.cardinal rrsigs));
            let rrsig = Rr_map.Rrsig_set.choose rrsigs in
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
              match Dnssec.verify ts_of_req (`RSA key) Domain_name.root rrsig Dnskey dnskey_rrs with
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

let verify_dnssec ts algorithm zsk buf =
  print_endline "here";
  let dnskey = Dnskey.{ algorithm ; key = Cstruct.of_string (Base64.decode_exn zsk) ; flags = F.singleton `Zone } in
  print_endline "here";
  let dnskeys = Rr_map.Dnskey_set.singleton dnskey in
  match Dnssec.dnskey_to_pk dnskey with
  | Error _ -> Alcotest.fail "key decoding failed"
  | Ok key ->
    match Packet.decode buf with
    | Error _ -> Alcotest.fail "packet decoding failed"
    | Ok pkt ->
      let name = fst pkt.Packet.question in
      match pkt.Packet.data with
      | `Answer (answer, _) when not (Domain_name.Map.is_empty answer) ->
        begin
          if Domain_name.Map.cardinal answer <> 1 then
            Alcotest.fail "expected one element name_rr_map";
          let name, rrmap = Domain_name.Map.choose answer in
          let _, rrsigs = Rr_map.get Rrsig rrmap in
          if Rr_map.Rrsig_set.cardinal rrsigs <> 1 then
            Alcotest.fail "expected single rrsig" ;
          let rrsig = Rr_map.Rrsig_set.choose rrsigs in
          let left = Rr_map.remove Rrsig rrmap in
          if Rr_map.cardinal left <> 1 then
            Alcotest.fail "expected single element in rr_map";
          match Rr_map.min_binding left with
          | None -> assert false
          | Some (B (k, v)) ->
            match Dnssec.verify ts key name rrsig k v with
            | Ok () -> ()
            | Error _ -> Alcotest.fail "verification failed"
        end
      | `Answer (_, auth) ->
        begin
          match snd pkt.Packet.question with
          | `K K k ->
            begin match Dnssec.validate_no_data ts name dnskeys k auth with
              | Ok () -> ()
              | Error `Msg m ->
                Alcotest.fail ("dnssec no data " ^ m)
            end
          | _ -> assert false
        end
      | `Rcode_error (NXDomain, Query, Some (_answer, auth)) ->
        begin
          match Dnssec.validate_nsec_no_domain ts name dnskeys auth with
          | Ok () -> ()
          | Error `Msg m -> Alcotest.fail ("dnssec nxdomain verification: " ^ m)
        end
      | _ -> Alcotest.fail "expected an answer"

let test_ns_ripe () =
  let ts = Option.get (Ptime.of_date_time ((2021, 11, 24), ((17, 26, 00), 0)))
  and zsk = "1Ykt1gvvZyfCR3IculzIepOsrPDpL63hNCNEo+wEuBd93pV8gAwLjCZ/ZtgccdbnhhVN6OBD70pUbml9Y2zOSQ=="
  and algorithm = Dnskey.P256_SHA256
  and buf = Cstruct.of_hex {|
6a 1c 81 a0 00 01  00 06 00 00 00 01 04 72
69 70 65 03 6e 65 74 00  00 02 00 01 c0 0c 00 02
00 01 00 00 4f 33 00 0c  03 6e 73 34 05 61 70 6e
69 63 c0 11 c0 0c 00 02  00 01 00 00 4f 33 00 0d
03 6e 73 33 06 6c 61 63  6e 69 63 c0 11 c0 0c 00
02 00 01 00 00 4f 33 00  0d 05 72 69 72 6e 73 04
61 72 69 6e c0 11 c0 0c  00 02 00 01 00 00 4f 33
00 0e 03 6e 73 33 07 61  66 72 69 6e 69 63 c0 11
c0 0c 00 02 00 01 00 00  4f 33 00 10 05 6d 61 6e
75 73 07 61 75 74 68 64  6e 73 c0 0c c0 0c 00 2e
00 01 00 00 4f 33 00 5c  00 02 0d 02 00 01 51 80
61 af 37 b3 61 9c ad 9b  d9 23 04 72 69 70 65 03
6e 65 74 00 c3 76 38 b7  04 a5 a4 45 9d 51 cc c2
ca b7 3b eb 19 2d e1 be  39 8a 64 27 e9 50 90 fd
4f 17 96 78 46 da 46 63  39 ca db c7 e0 37 e5 d4
c9 91 77 1f 9b 6c c7 dc  64 76 ad 00 71 15 3c 84
dc 02 7d 0a 00 00 29 02  00 00 00 80 00 00 00
|}
  in
  verify_dnssec ts algorithm zsk buf

let test_ds_afnoc_af_mil () =
  let ts = Option.get (Ptime.of_date_time ((2021, 11, 24), ((17, 26, 00), 0)))
  and zsk = {|AwEAAckGwhxTnqLiHTZ+/UuMnkeZqU44ORmLQHfhr1egTcMRetYHcsd9fnmlzgpoIgz19aJvSyjTT1Bp4ofOwMzeusK6knYKjbP3R5Uz8Y5hhnb3VTTm2Js6IoK3g2yxggkZWfewy7J+ZuMxwRLOKnS6O7cDBx4jM3/d61/8i1Ium1ZXbKgIjfLyphD0mZaaQ1nBigK+ej6lMaR4ddHEd4VKCl9s3s6EanfE8zR/oU9igxNzhYTpqT348aFHy6ebZAt5kfvTWyEtXsxXAZt5jQk0tBmT8nf2n6+Z9Z+M8ZWQphNzZ2m3rTafRc04EpnIDD1ROawPa6beIBvTAMsMgrS4Cus=|}
  and algorithm = Dnskey.RSA_SHA256
  and buf = Cstruct.of_hex {|
8c ae 81 a0 00 01  00 05 00 00 00 01 05 61
66 6e 6f 63 02 61 66 03  6d 69 6c 00 00 2b 00 01
c0 0c 00 2b 00 01 00 00  01 cf 00 24 d1 a7 08 02
73 08 1a b8 e5 26 0a 0c  c2 78 fd 06 21 8d 9e ad
da b7 95 52 00 cb ec 3f  88 3d a0 27 d2 06 6f 08
c0 0c 00 2b 00 01 00 00  01 cf 00 24 72 ac 08 02
c7 d2 59 06 9b 2d 96 32  db 7a 55 c4 b2 c2 83 6f
06 45 4f a5 07 1d 72 f8  ad 68 2b 6a 68 07 97 10
c0 0c 00 2b 00 01 00 00  01 cf 00 18 72 ac 08 01
76 ed e5 b6 7b 43 67 a7  08 3e 6f e3 e1 a4 dd e6
9a ed 3a 91 c0 0c 00 2b  00 01 00 00 01 cf 00 18
d1 a7 08 01 98 c0 2c 3c  76 8e 2b a8 ad 66 cb f2
39 6b ed aa 70 d6 17 6e  c0 0c 00 2e 00 01 00 00
01 cf 01 1a 00 2b 08 03  00 00 0e 10 61 a2 b0 64
61 9d 61 26 f4 a1 02 61  66 03 6d 69 6c 00 51 c8
5a 7d 11 9f 81 cb 5e 9f  5b 36 cb 91 fd a3 c7 a6
2e 57 ff b9 ac b9 83 ff  f1 b9 18 0e 28 9e f6 2b
59 70 81 d3 7c bd b1 b6  2d 09 34 5f 4a 42 13 4e
d8 e1 d8 ce 32 9f 42 3b  30 df f0 9c ec 4a 63 23
54 ea 7d 68 c8 18 b3 ef  59 9e 9c 42 83 3d 2c 02
15 01 21 8b 86 7c 97 9f  79 c9 5e f9 cb 11 ca d9
57 f0 21 94 27 ea f5 9e  90 1f 07 c7 13 c1 ef f4
d8 ff 00 5d 5e 1b 98 b0  b9 17 96 29 07 bc 1e f7
36 54 7e 2d 9e 54 76 44  2b c3 60 f3 0c e8 a9 40
1e 68 ec 22 ae 45 8d dd  a6 59 00 ac f3 07 0e 5a
37 37 7b 48 86 42 7b 86  5e d7 97 45 06 a2 00 70
00 a3 69 fe 5a 82 de 67  bf 33 33 fb b0 34 50 1d
6e 52 3e b9 99 17 34 c6  91 54 d4 cc d1 a4 a5 5f
c0 e1 b1 dd 27 5b df cb  27 f3 87 8c a9 a1 dc 15
a3 7b 0f c9 43 0f a6 0d  80 53 0a b9 be 1e 24 05
d6 6e 57 bb b9 b4 3e 61  d2 6d b0 ad ca f4 00 00
29 02 00 00 00 80 00 00  00|}
  in
  verify_dnssec ts algorithm zsk buf

let test_or_nsec_nxdomain () =
  let time = Option.get (Ptime.of_date_time ((2022, 01, 05), ((18, 00, 00), 00))) in
  let zsk = "AwEAAZym4HCWiTAAl2Mv1izgTyn9sKwgi5eBxpG29bVlefq/r+TGCtmUElvFyBWHRjvf9mBglIlTBRse22dvzNOI+cYrkjD6LOHuxMoc/d4WtXWKdviNmrtWF2GpjmDOI98gLd4BZ0U/lY847mJP9LypFABZcEn3zM3vce4Ee1A3upSlFQ2TFyJSD9HvMnP4XneFexBxV96RpLcy2O+u2W6ChIiDCjlrowPCcU3zXfXxyWy/VKM6TOa8gNf+aKaVkcv/eIh5er8rrsqAi9KT8O5hmhzYLkUOQEXVSRORV0RMt9l3JSwWxT1MebEDvtfBag3uo+mZwWSFlpc9kuzyWBd72Ec=" in
  let algorithm = Dnskey.RSA_SHA256 in
  let data = Cstruct.of_hex {|
 2d 15 81 a3 00 01  00 00 00 06 00 01 02 6f
                               72 00 00 01 00 01 00 00  06 00 01 00 01 51 7a 00
                               40 01 61 0c 72 6f 6f 74  2d 73 65 72 76 65 72 73
                               03 6e 65 74 00 05 6e 73  74 6c 64 0c 76 65 72 69
                               73 69 67 6e 2d 67 72 73  03 63 6f 6d 00 78 85 6e
                               84 00 00 07 08 00 00 03  84 00 09 3a 80 00 01 51
                               80 00 00 2e 00 01 00 01  51 7a 01 13 00 06 08 00
                               00 01 51 80 61 e6 49 50  61 d5 17 c0 26 47 00 3c
                               15 1f a2 98 fc 09 c1 da  e4 14 a2 14 c3 eb c5 89
                               84 e1 15 e1 d3 27 21 4b  68 ad cb 0c 90 87 9d ee
                               0c 8b 75 49 b7 a4 a8 25  96 b4 28 33 50 27 cf cd
                               7f 84 31 ad 1f 28 87 c6  74 53 1d 80 80 8e ad 98
                               df 5a 9b c1 6f 88 f3 3e  bc 71 b4 bb 49 21 a6 84
                               2f 6d 22 44 b9 74 43 83  a1 fe c0 bb 15 51 e7 5e
                               0c 4d 36 f4 01 44 b8 d3  c2 33 5c ad 58 30 09 67
                               4e 99 2f 43 38 9c 6a 6f  83 80 60 8e 04 65 b7 2a
                               0f 5a d6 8e 3c b4 b6 a7  de aa b4 32 ce ca ae 54
                               d2 58 c5 40 cc c5 f0 0e  c7 82 a2 da 1c b1 56 28
                               3f 49 95 22 d8 8b e9 23  9d 28 c9 c7 8b a6 fa fb
                               a9 ea ea 29 85 22 a6 80  2d 9f 15 96 3c 0f 8a a3
                               87 0a 8d 7a fc 22 9c dd  70 43 66 4e 88 84 66 64
                               d5 2a 29 42 6d c7 e2 fc  92 c0 3b d3 3f 08 ab bd
                               32 de 14 18 99 6c 07 21  8a 07 69 de d8 de 7e 23
                               14 26 29 04 77 1c 06 97  92 74 24 d3 d6 14 53 00
                               00 2f 00 01 00 01 51 7a  00 0e 03 61 61 61 00 00
                               07 22 00 00 00 00 03 80  00 00 2e 00 01 00 01 51
                               7a 01 13 00 2f 08 00 00  01 51 80 61 e6 49 50 61
                               d5 17 c0 26 47 00 38 b8  c7 be 89 2b 49 33 88 10
                               b7 1e bc fe c7 c5 4c 7d  1b e3 88 cf 55 7c bd 41
                               39 26 79 57 24 71 eb 2b  1a ba f0 8b 01 98 cd 3b
                               03 b1 b3 42 51 c0 0c 7a  7f 72 97 2f b1 b9 2b c4
                               b4 c1 e7 eb 7a 13 7c 1f  32 fc 43 3e f7 49 91 3b
                               4c 48 11 49 8e cc e1 5f  e5 44 80 d9 46 25 88 af
                               e5 1b a1 0d 57 95 96 d6  5e f0 ed bf e6 83 02 7d
                               24 32 97 e0 94 b5 ec 66  5b 89 56 06 54 b3 1c de
                               0d 96 7b ae bb 73 75 f9  f4 e5 7b fa eb b5 bd 3f
                               25 94 c0 e7 88 2e 23 7e  7d b4 f6 85 83 06 67 e4
                               5e 16 a0 ea 3b db 71 9e  e0 01 fa 3b aa 49 76 5f
                               44 64 d5 00 7a a1 aa 44  80 4b 16 84 8d 06 09 09
                               e0 bb a8 dd d6 1e f6 85  ad 49 bf bf d4 95 6f 5d
                               49 ea db 0c 44 ee 87 2d  36 36 bd 4e 7b a9 63 1b
                               ad 18 a8 e8 77 a4 2b 34  c7 a5 b7 63 d5 c6 97 e4
                               1b 5f 7c 19 ba d0 90 eb  f7 25 aa a5 a7 4b c2 84
                               95 44 3d d1 9b 33 04 6f  70 65 6e 00 00 2f 00 01
                               00 01 4e f3 00 10 06 6f  72 61 63 6c 65 00 00 06
                               20 00 00 00 00 13 c2 b4  00 2e 00 01 00 01 4e f3
                               01 13 00 2f 08 01 00 01  51 80 61 e6 49 50 61 d5
                               17 c0 26 47 00 79 3f 6b  0d b0 63 69 7d d5 82 5b
                               d1 a8 b5 7c 8b 00 50 95  9f 99 04 81 07 83 96 61
                               5f 67 ea 41 c6 54 d4 e1  39 29 9f a5 2f 04 aa e0
                               53 10 17 18 6c 64 d6 b7  fa e7 c7 48 89 d3 65 f0
                               47 db 1f ff b3 2b 53 75  41 c1 ff ed 36 35 aa 27
                               68 ee d1 9a bf ca 78 d0  9d ff 44 fd cb 0d 27 7c
                               f2 0e 95 74 c5 2c 29 ae  65 df 3b c0 df 53 5d fa
                               6a fe 08 2a e5 5f 35 95  fc f0 0e e1 d6 00 2e 95
                               78 a3 97 95 b5 9b 37 16  c2 5f e6 ca 65 8e ea 07
                               24 2e 48 b8 8f 25 14 98  7a f9 e9 c7 d4 79 5c 83
                               25 5a 9b 0d 86 b6 ff f5  df 33 d2 d1 c3 63 ab 13
                               e7 a4 da b3 60 88 45 12  68 cd 8e ee 82 e1 a6 b2
                               52 dd 88 3e e8 12 a6 71  b1 a1 ac 67 42 8f be 57
                               af 9f 22 6a da 7a 9b 31  29 8f 36 30 87 dc 75 f6
                               dd 72 d9 84 35 f3 79 23  be 9e ed 03 53 dd 8f ad
                               fe 15 06 9f a5 46 60 ac  a0 09 b1 67 51 f7 61 cd
                               6b 2e 9e 06 96 00 00 29  02 00 00 00 80 00 00 00
|}
  in
  verify_dnssec time algorithm zsk data

let test_zz_nsec_nodomain () =
  let time = Option.get (Ptime.of_date_time ((2022, 01, 07), ((18, 00, 00), 00))) in
  let zsk = "AwEAAZym4HCWiTAAl2Mv1izgTyn9sKwgi5eBxpG29bVlefq/r+TGCtmUElvFyBWHRjvf9mBglIlTBRse22dvzNOI+cYrkjD6LOHuxMoc/d4WtXWKdviNmrtWF2GpjmDOI98gLd4BZ0U/lY847mJP9LypFABZcEn3zM3vce4Ee1A3upSlFQ2TFyJSD9HvMnP4XneFexBxV96RpLcy2O+u2W6ChIiDCjlrowPCcU3zXfXxyWy/VKM6TOa8gNf+aKaVkcv/eIh5er8rrsqAi9KT8O5hmhzYLkUOQEXVSRORV0RMt9l3JSwWxT1MebEDvtfBag3uo+mZwWSFlpc9kuzyWBd72Ec=" in
  let algorithm = Dnskey.RSA_SHA256 in
  let data = Cstruct.of_hex {|
 95 20 81 83 00 01  00 00 00 06 00 01 02 7a
                               7a 00 00 01 00 01 00 00  06 00 01 00 00 af 98 00
                               40 01 61 0c 72 6f 6f 74  2d 73 65 72 76 65 72 73
                               03 6e 65 74 00 05 6e 73  74 6c 64 0c 76 65 72 69
                               73 69 67 6e 2d 67 72 73  03 63 6f 6d 00 78 85 6f
                               4c 00 00 07 08 00 00 03  84 00 09 3a 80 00 01 51
                               80 00 00 2e 00 01 00 00  af 98 01 13 00 06 08 00
                               00 01 51 80 61 e8 ec 50  61 d7 ba c0 26 47 00 96
                               55 e3 9d cf f8 d6 34 4a  7e 3a 4c fb 42 fa 98 c9
                               74 c8 e3 17 b3 07 0d c1  fc 4b f9 0e 83 60 36 60
                               41 23 a6 da 04 25 50 2c  e7 e4 0c 5c 54 d3 e0 8d
                               07 d3 bd 25 d7 65 83 2e  ce 01 ae 61 52 b5 5f 2e
                               0e 4e 0a 8f 5c d0 63 99  02 c9 16 01 8a 93 96 57
                               14 93 ac 5e ce 03 3d 7e  1b 21 da 1e 5b 62 e1 92
                               57 95 56 33 fa d1 41 65  bf df ba 1a b2 a5 65 86
                               eb f3 72 f4 94 81 08 7e  0e b1 df 43 30 85 49 82
                               98 dd b2 c4 c0 f6 8e 9a  ba d4 6e a7 93 b8 c1 d3
                               64 79 36 c2 ba 56 2b 2f  fd eb f7 c6 94 a9 be b5
                               04 20 8e a7 17 1e 73 a8  8d 12 8e 67 cb 54 a4 d6
                               e8 75 b1 ec c7 f6 c0 3a  64 07 df fa a2 1e 78 05
                               d7 25 4a 87 9c 23 9d ed  9b ba 74 56 ab 95 73 89
                               a0 6d 96 1a bb cf 54 cf  a5 82 d3 0f c6 28 11 df
                               39 70 67 61 9f c1 46 63  08 6f f7 f3 d1 69 cc 91
                               08 ef 9d d3 09 59 db de  fe 52 93 dd c2 55 03 00
                               00 2f 00 01 00 00 af 98  00 0e 03 61 61 61 00 00
                               07 22 00 00 00 00 03 80  00 00 2e 00 01 00 00 af
                               98 01 13 00 2f 08 00 00  01 51 80 61 e8 ec 50 61
                               d7 ba c0 26 47 00 7b f0  d6 1d 8d 74 74 b3 e2 a5
                               46 02 56 30 ac 89 4b da  1b 64 24 ea 14 72 98 c5
                               d7 4a 35 33 05 cd fc b8  bb 5b b5 94 0b ed 67 79
                               b9 be e2 69 ae 13 b9 96  fd 18 a3 39 fc 81 2a c8
                               cc 27 2c 29 29 ad a9 93  8a 56 f4 5a 82 c1 c7 c2
                               6d b7 9e a4 ca 65 93 a8  89 d5 a5 76 46 be ad 7e
                               d5 e7 64 73 d4 b1 84 d1  e4 9f ea 5b 6a 41 5e bc
                               2c b7 26 0e 77 e2 00 5e  11 42 19 9a e8 04 55 55
                               12 61 50 ca 9e ac 93 b9  32 af 41 cf 34 e7 27 f1
                               48 7a 1b ae fc 62 18 0d  6b f3 ec d4 8d 76 fc 34
                               37 12 83 20 da f7 ad 4f  32 65 e3 ca f4 a9 93 a0
                               9f 6e 38 4a 88 92 4e d0  6a 1c b9 98 bc af 97 55
                               21 29 f8 3a 02 3d a0 90  95 4d 39 4f 0d 62 d1 1a
                               2b f8 29 b0 b7 d8 14 43  d7 7f 8f 5a 3c 42 a0 d5
                               2d 8a 1e d0 97 0f f9 d4  70 87 43 20 5d fa eb 9f
                               96 d1 75 1a de f9 e7 72  c7 df 3d 3b b9 25 f9 d6
                               8a 62 29 c1 0a 75 02 7a  77 00 00 2f 00 01 00 00
                               af 96 00 09 00 00 06 20  00 00 00 00 03 c2 b4 00
                               2e 00 01 00 00 af 96 01  13 00 2f 08 01 00 01 51
                               80 61 e8 ec 50 61 d7 ba  c0 26 47 00 24 7b 16 4c
                               ea 88 a7 c5 15 c5 74 5f  d3 b2 67 19 c2 9a e6 bf
                               04 26 84 a5 c8 31 b0 bb  9f 5b fc b2 7e 74 c0 ee
                               64 49 f6 0c 1f b5 3f bf  c3 9b b0 dd ee 5d 7f 3f
                               02 0c e2 37 34 15 34 6a  30 8e 4a ba b3 00 cb 4b
                               12 04 c6 0b d1 3b 2a da  62 c1 68 4a ac 7b 6e 86
                               19 32 70 b7 53 92 2d 28  9e 63 97 e6 de 95 69 47
                               86 f4 e6 58 00 b0 71 42  41 64 38 bd 10 1c 23 19
                               a2 9f 2a 6b 00 e2 06 f1  e9 23 7a 41 fe d8 fd a9
                               1d 3b 48 8d 23 bf c7 bf  6d 12 41 d6 1d 1a f1 0a
                               31 9b 6e 09 90 77 86 e8  ac ed 3a 6d 3b a6 bb b0
                               a1 77 4c 7d ab 0c 65 43  4d d2 35 df 96 82 42 d3
                               31 c2 33 9a 85 9d fe 8e  29 7d 3f 6b 81 cb 75 04
                               7b a7 af 3a 2f 3e 30 d5  77 9b 84 b7 fa 4d 04 d8
                               09 fc cf b4 19 5d 92 6c  3b 5d 55 37 7e f9 bb 91
                               93 2b 15 02 42 1a 1a f4  06 00 d5 34 98 0d ef c1
                               f3 21 99 18 b3 5f 5d 1b  d8 4f f8 ca 00 00 29 20
                               00 00 00 80 00 00 00|}
  in
  verify_dnssec time algorithm zsk data

let test_aa_nsec_nodomain () =
  let time = Option.get (Ptime.of_date_time ((2022, 01, 07), ((18, 00, 00), 00))) in
  let zsk = "AwEAAZym4HCWiTAAl2Mv1izgTyn9sKwgi5eBxpG29bVlefq/r+TGCtmUElvFyBWHRjvf9mBglIlTBRse22dvzNOI+cYrkjD6LOHuxMoc/d4WtXWKdviNmrtWF2GpjmDOI98gLd4BZ0U/lY847mJP9LypFABZcEn3zM3vce4Ee1A3upSlFQ2TFyJSD9HvMnP4XneFexBxV96RpLcy2O+u2W6ChIiDCjlrowPCcU3zXfXxyWy/VKM6TOa8gNf+aKaVkcv/eIh5er8rrsqAi9KT8O5hmhzYLkUOQEXVSRORV0RMt9l3JSwWxT1MebEDvtfBag3uo+mZwWSFlpc9kuzyWBd72Ec=" in
  let algorithm = Dnskey.RSA_SHA256 in
  let data = Cstruct.of_hex {|
 eb a7 81 83 00 01  00 00 00 04 00 01 02 61
                               61 00 00 01 00 01 00 00  2f 00 01 00 00 af 06 00
                               0e 03 61 61 61 00 00 07  22 00 00 00 00 03 80 00
                               00 2e 00 01 00 00 af 06  01 13 00 2f 08 00 00 01
                               51 80 61 e8 ec 50 61 d7  ba c0 26 47 00 7b f0 d6
                               1d 8d 74 74 b3 e2 a5 46  02 56 30 ac 89 4b da 1b
                               64 24 ea 14 72 98 c5 d7  4a 35 33 05 cd fc b8 bb
                               5b b5 94 0b ed 67 79 b9  be e2 69 ae 13 b9 96 fd
                               18 a3 39 fc 81 2a c8 cc  27 2c 29 29 ad a9 93 8a
                               56 f4 5a 82 c1 c7 c2 6d  b7 9e a4 ca 65 93 a8 89
                               d5 a5 76 46 be ad 7e d5  e7 64 73 d4 b1 84 d1 e4
                               9f ea 5b 6a 41 5e bc 2c  b7 26 0e 77 e2 00 5e 11
                               42 19 9a e8 04 55 55 12  61 50 ca 9e ac 93 b9 32
                               af 41 cf 34 e7 27 f1 48  7a 1b ae fc 62 18 0d 6b
                               f3 ec d4 8d 76 fc 34 37  12 83 20 da f7 ad 4f 32
                               65 e3 ca f4 a9 93 a0 9f  6e 38 4a 88 92 4e d0 6a
                               1c b9 98 bc af 97 55 21  29 f8 3a 02 3d a0 90 95
                               4d 39 4f 0d 62 d1 1a 2b  f8 29 b0 b7 d8 14 43 d7
                               7f 8f 5a 3c 42 a0 d5 2d  8a 1e d0 97 0f f9 d4 70
                               87 43 20 5d fa eb 9f 96  d1 75 1a de f9 e7 72 c7
                               df 3d 3b b9 25 f9 d6 8a  62 29 c1 0a 75 00 00 06
                               00 01 00 00 af 06 00 40  01 61 0c 72 6f 6f 74 2d
                               73 65 72 76 65 72 73 03  6e 65 74 00 05 6e 73 74
                               6c 64 0c 76 65 72 69 73  69 67 6e 2d 67 72 73 03
                               63 6f 6d 00 78 85 6f 4c  00 00 07 08 00 00 03 84
                               00 09 3a 80 00 01 51 80  00 00 2e 00 01 00 00 af
                               06 01 13 00 06 08 00 00  01 51 80 61 e8 ec 50 61
                               d7 ba c0 26 47 00 96 55  e3 9d cf f8 d6 34 4a 7e
                               3a 4c fb 42 fa 98 c9 74  c8 e3 17 b3 07 0d c1 fc
                               4b f9 0e 83 60 36 60 41  23 a6 da 04 25 50 2c e7
                               e4 0c 5c 54 d3 e0 8d 07  d3 bd 25 d7 65 83 2e ce
                               01 ae 61 52 b5 5f 2e 0e  4e 0a 8f 5c d0 63 99 02
                               c9 16 01 8a 93 96 57 14  93 ac 5e ce 03 3d 7e 1b
                               21 da 1e 5b 62 e1 92 57  95 56 33 fa d1 41 65 bf
                               df ba 1a b2 a5 65 86 eb  f3 72 f4 94 81 08 7e 0e
                               b1 df 43 30 85 49 82 98  dd b2 c4 c0 f6 8e 9a ba
                               d4 6e a7 93 b8 c1 d3 64  79 36 c2 ba 56 2b 2f fd
                               eb f7 c6 94 a9 be b5 04  20 8e a7 17 1e 73 a8 8d
                               12 8e 67 cb 54 a4 d6 e8  75 b1 ec c7 f6 c0 3a 64
                               07 df fa a2 1e 78 05 d7  25 4a 87 9c 23 9d ed 9b
                               ba 74 56 ab 95 73 89 a0  6d 96 1a bb cf 54 cf a5
                               82 d3 0f c6 28 11 df 39  70 67 61 9f c1 46 63 08
                               6f f7 f3 d1 69 cc 91 08  ef 9d d3 09 59 db de fe
                               52 93 dd c2 55 03 00 00  29 20 00 00 00 80 00 00
                               00|}
  in
  verify_dnssec time algorithm zsk data

let test_a_se_nsec_nodata () =
  let time = Option.get (Ptime.of_date_time ((2022, 01, 05), ((18, 00, 00), 00))) in
  let zsk = "AwEAAd7Bd3v5oA7hpv1gdqBDDKVUIpu0cat4ps5IuuuDF48qo/hot3kz1TBfwFnyoQpzaaR+T5m5/42rhf9PWQ0y879yoAMur9afjPXPliMv6ZJ8QyXgS+Aj59kqRXHQJVX1JXyhpOz+jG3aVdcdMFC3HB9uQ9ivvsJQ1bJlS8t5Zw1rfhvCZ4T2FeLdfDUIthsXa5aBvkN98nDr5aD3iLUk5x2ZvELuTJAZFHNzemyviWUp9EWnXtJwvl2YrX53bGzHVA7kyRpeYf4N1OMFIEi0QDlyGUS540i3OSCLWFCu5c9YvMIfOouqUV//yyy0mjVb2BWZQDtrZ+BuMmWfOEYlAb8=" in
  let algorithm = Dnskey.RSA_SHA256 in
  let data = Cstruct.of_hex {|
9b f5 81 a0 00 01  00 00 00 04 00 01 02 73
                               65 00 00 01 00 01 c0 0c  00 06 00 01 00 00 07 03
                               00 40 12 63 61 74 63 68  65 72 2d 69 6e 2d 74 68
                               65 2d 72 79 65 03 6e 69  63 c0 0c 10 72 65 67 69
                               73 74 72 79 2d 64 65 66  61 75 6c 74 c0 33 78 85
                               6e 95 00 00 07 08 00 00  07 08 00 0d 2f 00 00 00
                               1c 20 c0 0c 00 2e 00 01  00 00 07 03 01 16 00 06
                               08 01 00 02 a3 00 61 e7  3f 43 61 d5 b5 05 75 3f
                               02 73 65 00 09 8b 9c c5  47 a5 3c 8c 3a 1c e3 22
                               27 e6 9d 01 16 df 26 47  32 74 95 37 43 5d 4c 2f
                               65 97 a5 a4 d3 1c 41 36  64 59 2e e5 72 46 a9 fb
                               b3 26 7d f5 43 f8 51 bc  45 b1 ca 2f ab d5 cf 93
                               48 e7 26 21 6a 43 99 3e  a5 5e 3f b1 15 25 a5 0a
                               70 c5 21 6f 0b 9b 68 04  0c 77 15 28 18 30 86 fd
                               22 91 c7 52 73 a6 69 e4  e2 47 da 85 d2 da ce b3
                               b4 f1 6a c4 a7 88 ea d0  09 f8 ca 4e 3d 77 9b ac
                               06 24 bb d6 73 4a be 2d  20 15 55 bb 3b e9 32 9e
                               7a d9 da a3 f1 88 fc c5  5b 4a a7 0c ed 17 e0 d9
                               4b d5 56 f5 80 e7 66 9b  81 3f 30 27 bf fd 6a 88
                               27 e3 15 b5 14 c5 30 4a  be 04 d8 17 67 40 9b 1c
                               6b 07 11 fd 97 69 0d 8f  db e8 55 fa 86 4c d0 58
                               d3 07 1a fe ad 38 2a f5  dc d4 66 b6 fc 63 96 d2
                               82 60 09 90 3d 3c 73 c3  7e b9 5a e8 48 7e aa 82
                               55 51 87 58 fb 87 53 e5  82 1c ed 5e 48 e2 f0 97
                               28 af 6a a7 c0 0c 00 2f  00 01 00 00 1c 1b 00 0f
                               01 30 02 73 65 00 00 07  22 00 80 00 00 03 80 c0
                               0c 00 2e 00 01 00 00 1c  1b 01 16 00 2f 08 01 00
                               00 1c 20 61 e6 9d 55 61  d4 0f 1d 75 3f 02 73 65
                               00 65 47 9e bc 2c 4e 1e  3b 40 d5 a1 9b 2d 50 20
                               9d ae 5b 1e bd 99 6c b1  52 01 ab 8e eb a4 96 f2
                               76 61 20 ca 73 9c 95 73  ce 41 1b 63 41 ee 02 15
                               40 be 71 3c 6d df ba b2  8c 33 8c f3 6f 32 cf e5
                               c2 7d 37 7e 6e d4 24 df  d3 f9 ff 3c ee 27 3a 5e
                               e4 30 fd 3a 6c 5e 6e 48  83 9e 24 e9 77 a3 8c d3
                               f2 d6 b7 5f 4e 00 33 dc  d8 92 2c d3 72 41 04 5c
                               fb a7 b3 f0 55 f3 87 51  27 38 8d b7 57 fa 5f 10
                               cc ba 1b c1 69 c8 48 63  92 57 2f a5 69 4f df 19
                               de 2c a2 4b 06 43 e4 b0  94 74 b7 4b 46 14 c3 71
                               98 f6 c7 63 fe 8b 30 98  f7 dd c9 f6 b1 bb aa d0
                               a9 d4 4b 0f 16 84 21 a7  da e6 e6 0b 77 ae 90 d5
                               c2 23 d7 00 4f c8 f4 04  28 e4 00 4d 97 d4 c8 3b
                               47 cb a3 b2 b7 99 c7 95  8b 18 a1 30 92 43 f2 94
                               d3 ee 13 fa b0 39 bb 15  b9 cd 0d c8 31 7b a7 8f
                               e2 c1 d5 51 33 4a 9b 85  4e d6 fb f1 78 c5 79 27
                               11 00 00 29 02 00 00 00  80 00 00 00
|}
  in
  verify_dnssec time algorithm zsk data

let test_a_de_nsec3 () =
  let time = Option.get (Ptime.of_date_time ((2022, 01, 06), ((18, 00, 00), 00))) in
  let zsk = "AwEAAb5nVvUWjtX2ViEJxEovyniL+kTxSatSTxdSVwpZq2f1ryPPl0Yo4my/aQCdkuNPJmVeCOzL4Ebokp/5MfCfYLcHp7xl8saHALSvSMemsDkLUSgGWkefRNOv3It8nrbSibDthexuwtMkdN39z+LIcS4fNob/K+KUvZA6+Z+UfK65" in
  let algorithm = Dnskey.RSA_SHA256 in
  let data = Cstruct.of_hex {|
a7 27 81 80 00 01  00 00 00 06 00 01 01 61
                               02 64 65 00 00 2b 00 01  c0 0e 00 06 00 01 00 00
                               0d f1 00 28 01 66 03 6e  69 63 c0 0e 03 69 74 73
                               05 64 65 6e 69 63 c0 0e  61 d7 25 d0 00 00 1c 20
                               00 00 1c 20 00 36 ee 80  00 00 1c 20 c0 0e 00 2e
                               00 01 00 00 0d f1 00 96  00 06 08 01 00 01 51 80
                               61 e9 9a bd 61 d7 10 a5  e0 dc 02 64 65 00 04 f7
                               0b a6 78 bb 22 5a b4 a0  40 a0 43 52 a1 85 8b 92
                               f2 ef b5 ae 1a 99 2a a8  3b 6e 8b e6 b7 94 98 07
                               b3 b0 c3 55 4b e5 52 3f  5b 70 0f 83 8a 32 3f f7
                               90 80 a2 c7 bd 28 db 73  6c 2f 9e 36 ea c7 87 e3
                               5e b2 32 b9 56 1c 05 80  bf 87 63 6f 3b 54 bb 7c
                               c0 59 7f dc 2e c1 ac a0  e4 81 ed aa b9 68 73 7c
                               7b 3a a8 f6 47 f5 53 a4  e3 99 67 5a eb c8 81 cc
                               ac ac 73 f3 c8 11 f4 f9  cb 1e 94 6e f0 4b 20 6c
                               65 6e 69 35 35 62 62 65  70 74 73 64 6e 31 34 32
                               6f 71 6c 64 70 37 38 69  37 6b 6d 34 6d 71 33 c0
                               68 00 2e 00 01 00 00 0d  f1 00 96 00 32 08 02 00
                               00 1c 20 61 e8 3e 9f 61  d5 b4 87 e0 dc 02 64 65
                               00 71 22 04 1f e8 b4 a8  8e 4f f4 24 6c a6 66 98
                               26 96 7f 5e e4 ba af 7e  0d b7 0f f8 0b 67 c6 6c
                               f9 c3 64 bd 73 8a e5 9a  10 d0 1e 19 83 d0 a2 9c
                               0e b5 7d 68 33 65 4e 74  6a 2d 01 a4 b5 2b 07 87
                               8a 96 9a 25 74 64 35 6c  69 5b ad ae e2 f8 ae 57
                               45 3e 12 f9 c0 f5 83 58  9d b1 d4 5d 99 4c a3 4d
                               03 3e 99 6c 7a e8 37 0a  59 6c f3 c9 fd a2 01 d8
                               dd 3e 75 11 c6 41 b5 52  3c 6a 1f 72 b7 3e 96 46
                               de c0 ec 00 32 00 01 00  00 0d f1 00 2a 01 01 00
                               0f 08 ca 12 b7 4a db 90  59 1a 14 ab af 3e fe 9a
                               af 77 23 12 d5 4e e2 76  6d bf a1 2f 89 fd e7 00
                               06 40 00 00 00 00 02 20  74 6a 6c 62 37 71 62 6f
                               6a 76 6d 6c 66 31 73 36  67 64 72 69 72 75 37 76
                               73 6d 73 31 6c 67 31 36  c1 2b 00 2e 00 01 00 00
                               0d f1 00 96 00 32 08 02  00 00 1c 20 61 e3 84 74
                               61 d0 fa 5c e0 dc 02 64  65 00 67 4b e6 fd 1a 52
                               a9 61 55 08 a7 f3 40 ad  82 ca ef c5 fb 51 ac 6d
                               4e 1e 97 89 71 cc a3 93  88 88 e3 5c cc 8b a5 e4
                               47 39 dc ac ee ee 59 a3  d6 d1 a9 df f1 47 56 b9
                               59 69 28 77 65 46 6b 23  eb 55 9b ef 0d f1 c6 55
                               7c e8 d7 1d 26 78 98 d3  12 a4 a9 57 0a ee 13 10
                               0b e6 20 fb 06 06 72 0d  b8 d3 b0 5b e1 dc 5f 4f
                               0f 75 34 04 24 a8 4e b3  d8 2c f4 43 9e f2 11 ee
                               8f 29 a6 6a 15 f9 e0 95  5e 2f c1 e5 00 32 00 01
                               00 00 0d f1 00 2b 01 01  00 0f 08 ca 12 b7 4a db
                               90 59 1a 14 ec ea f9 e7  7f 65 b9 d8 88 83 cd a4
                               94 7f 5d 9a 73 09 1f dc  00 07 22 00 00 00 00 02
                               90 00 00 29 10 00 00 00  80 00 00 00
|}
  in
  verify_dnssec time algorithm zsk data

let tests = [
  "root", `Quick, test_root ;
  "ns for ripe.net", `Quick, test_ns_ripe ;
  "ds for afnoc.af.mil", `Quick, test_ds_afnoc_af_mil ;
  "nxdomain for or (nsec)", `Quick, test_or_nsec_nxdomain ;
  "nxdomain for zz (nsec)", `Quick, test_zz_nsec_nodomain ;
  "nxdomain for aa (nsec)", `Quick, test_aa_nsec_nodomain ;
  "nodata for a se (nsec)", `Quick, test_a_se_nsec_nodata ;
  "nodata for a.de (nsec3)", `Quick, test_a_de_nsec3 ;
]

let () =
  Printexc.record_backtrace true;
  Alcotest.run "DNSSEC tests" [ "DNSSEC tests", tests ]

