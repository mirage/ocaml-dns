
let ip =
  let module M = struct
    type t = Ipaddr.V4.t
    let pp = Ipaddr.V4.pp
    let equal a b = Ipaddr.V4.compare a b = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let ipset = Alcotest.(slist ip Ipaddr.V4.compare)

let p_cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

module Make_query_tests = struct
  let produces_same_output () =
    let rng = fun x -> Cstruct.create(x) in
    let name:'a Domain_name.t = Domain_name.of_string_exn "example.com" in
    let actual, _state = Dns_client.make_query rng `Tcp name Dns.Rr_map.A in
    let expected = Cstruct.of_hex
        "00 1d 00 00 01 00 00 01  00 00 00 00 00 00 07 65
        78 61 6d 70 6c 65 03 63  6f 6d 00 00 01 00 01" in
    Alcotest.check p_cs "produces cool stuff" expected actual

  let tests = [
    "produces same output", `Quick, produces_same_output;
    "fails on unspported query_type", `Quick, produces_same_output;
  ]
end

module Parse_response_tests = struct
  let unpacks_response () =
    (* Bytes 3, 4 are set to `00 00` - these represent query ID *)
    let ipv4_buf = Cstruct.of_hex
      "00 77 00 00 81 80 00 01  00 01 00 02 00 02 03 66
       6f 6f 03 63 6f 6d 00 00  01 00 01 c0 0c 00 01 00
       01 00 00 02 2a 00 04 17  17 56 2c c0 0c 00 02 00
       01 00 01 87 ae 00 10 03  6e 73 31 09 64 69 67 69
       6d 65 64 69 61 c0 10 c0  0c 00 02 00 01 00 01 87
       ae 00 06 03 6e 73 32 c0  39 c0 35 00 01 00 01 00
       02 40 8a 00 04 17 15 f2  58 c0 51 00 01 00 01 00
       02 40 8a 00 04 17 15 f3  77" in

    (* This `rng` generates zeros, used for the query ID above *)
    let rng = fun x -> Cstruct.create(x) in
    let name:'a Domain_name.t = Domain_name.of_string_exn "foo.com" in
    let _actual, state = Dns_client.make_query rng `Tcp name Dns.Rr_map.A in
    match Dns_client.parse_response state ipv4_buf with
    | `Ok _ -> () (* TODO: Alcotest TESTABLE for this return value *)
    | `Msg _ -> ignore(failwith "error")
    | `Partial -> ignore(failwith "error, partial")

  let fails_to_unpack_mismatched () =
    (* TODO: It is possible to use crowbar here, to generate the ipv4_buf *)

    (* Bytes 3, 4 are set to `aa aa` - these represent query ID *)
    let ipv4_buf = Cstruct.of_hex
      "00 77 aa aa 81 80 00 01  00 01 00 02 00 02 03 66
       6f 6f 03 63 6f 6d 00 00  01 00 01 c0 0c 00 01 00
       01 00 00 02 2a 00 04 17  17 56 2c c0 0c 00 02 00
       01 00 01 87 ae 00 10 03  6e 73 31 09 64 69 67 69
       6d 65 64 69 61 c0 10 c0  0c 00 02 00 01 00 01 87
       ae 00 06 03 6e 73 32 c0  39 c0 35 00 01 00 01 00
       02 40 8a 00 04 17 15 f2  58 c0 51 00 01 00 01 00
       02 40 8a 00 04 17 15 f3  77" in

    (* This `rng` generates zeros, used for the query ID above *)
    let rng = fun x -> Cstruct.create(x) in
    let name:'a Domain_name.t = Domain_name.of_string_exn "foo.com" in
    let _actual, state = Dns_client.make_query rng `Tcp name Dns.Rr_map.A in
    match Dns_client.parse_response state ipv4_buf with
    | `Ok _ -> failwith "should have rejected mismatched input" (* TODO: Alcotest TESTABLE for this return value *)
    | `Msg _ -> ()
    | `Partial -> failwith "should have rejected mismatched input"

  let tests = [
      "unpacks some kind of response", `Quick, unpacks_response;
      "fails to unpack response with mismatching query ID", `Quick, fails_to_unpack_mismatched;
  ]
end

let tests = [
    "make_query tests", Make_query_tests.tests;
    "parse_response tests", Parse_response_tests.tests;
]

let () = Alcotest.run "DNS client tests" tests
