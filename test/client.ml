
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
    let actual, _state = Dns_client.Pure.make_query rng `Tcp name Dns.Rr_map.A in
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
    let _actual, state = Dns_client.Pure.make_query rng `Tcp name Dns.Rr_map.A in
    match Dns_client.Pure.parse_response state ipv4_buf with
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
    let _actual, state = Dns_client.Pure.make_query rng `Tcp name Dns.Rr_map.A in
    match Dns_client.Pure.parse_response state ipv4_buf with
    | `Ok _ -> failwith "should have rejected mismatched input" (* TODO: Alcotest TESTABLE for this return value *)
    | `Msg _ -> ()
    | `Partial -> failwith "should have rejected mismatched input"

  let tests = [
      "unpacks some kind of response", `Quick, unpacks_response;
      "fails to unpack response with mismatching query ID", `Quick, fails_to_unpack_mismatched;
  ]
end

(* {!Transport} provides the implementation of the underlying flow
   that is in turn used by {!Dns_client.Make} to provide the
   blocking Unix convenience module:
*)

type debug_info = Cstruct.t list ref
let default_debug_info =
  ref []

module Transport : Dns_client.S
  with type flow = debug_info
   and type io_addr = debug_info
   and type stack = unit
   and type +'a io = 'a
= struct
  type io_addr = debug_info
  type ns_addr = [`TCP | `UDP] * io_addr
  type stack = unit
  type flow = debug_info
  type t = int -> Cstruct.t
  type +'a io = 'a

  let create
      ?(rng = Cstruct.create)
      ?nameserver:_ () =
    rng

  let nameserver _ = `TCP,  default_debug_info
  let rng x = x

  let bind a b = b a
  let lift v = v

  open Rresult

  let close _ = ()

  let connect ?nameserver:ns _ =
    match ns with
    | None -> Ok default_debug_info
    | Some(_, mock_responses) -> Ok mock_responses

  let send _ _ =
    Ok ()

  let recv (mock_responses:flow) =
    (* let cool = (Cstruct.of_string "hello") in
    Fmt.epr "dnsclient unix recv: %a\n%!"
            Cstruct.hexdump_pp cool; *)
    match !mock_responses with
      | [] -> failwith("nothing to recv")
      | hd::tail -> mock_responses := tail; Ok hd
end

(* Now that we have our {!Transport} implementation we can include the logic
   that goes on top of it: *)
include Dns_client.Make(Transport)

module Gethostbyname_tests = struct
  let foo_com_is_valid () =
    let domain_name = Domain_name.(of_string_exn "foo.com" |> host_exn) in
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
    let clock () = 0L in
    let t = create ~clock () in
    let ns = `TCP, ref [ipv4_buf] in
    match gethostbyname t domain_name ~nameserver:ns with
    | Ok _ip -> ()
    | Error _ -> failwith "foo.com should have been returned"

  let tests = [
    "foo.com is valid", `Quick, foo_com_is_valid;
  ]
end

module Getaddrinfo_tests = struct
  let supports_mx_packets () =
    let domain_name = Domain_name.(of_string_exn "google.com" |> host_exn) in
    (* a google.com MX record - bytes 3,4 are set to the query ID 00 00 *)
    let ipv4_buf = Cstruct.of_hex
      "02 1e 00 00 81 80 00 01  00 05 00 04 00 0f 06 67
      6f 6f 67 6c 65 03 63 6f  6d 00 00 0f 00 01 c0 0c
      00 0f 00 01 00 00 02 58  00 11 00 1e 04 61 6c 74
      32 05 61 73 70 6d 78 01  6c c0 0c c0 0c 00 0f 00
      01 00 00 02 58 00 04 00  0a c0 2f c0 0c 00 0f 00
      01 00 00 02 58 00 09 00  28 04 61 6c 74 33 c0 2f
      c0 0c 00 0f 00 01 00 00  02 58 00 09 00 14 04 61
      6c 74 31 c0 2f c0 0c 00  0f 00 01 00 00 02 58 00
      09 00 32 04 61 6c 74 34  c0 2f c0 0c 00 02 00 01
      00 00 ad 8c 00 06 03 6e  73 31 c0 0c c0 0c 00 02
      00 01 00 00 ad 8c 00 06  03 6e 73 34 c0 0c c0 0c
      00 02 00 01 00 00 ad 8c  00 06 03 6e 73 33 c0 0c
      c0 0c 00 02 00 01 00 00  ad 8c 00 06 03 6e 73 32
      c0 0c c0 2f 00 01 00 01  00 00 00 e0 00 04 6c b1
      77 1b c0 6c 00 01 00 01  00 00 00 0d 00 04 ac d9
      c2 1b 04 41 4c 54 32 c0  2f 00 01 00 01 00 00 00
      0d 00 04 6c b1 61 1b c0  81 00 01 00 01 00 00 00
      e0 00 04 6c b1 08 1a c0  94 00 01 00 01 00 03 8b
      b6 00 04 d8 ef 20 0a c0  ca 00 01 00 01 00 03 8f
      54 00 04 d8 ef 22 0a c0  b8 00 01 00 01 00 03 8b
      b6 00 04 d8 ef 24 0a c0  a6 00 01 00 01 00 03 97
      5d 00 04 d8 ef 26 0a c0  2f 00 1c 00 01 00 00 00
      f9 00 10 2a 00 14 50 40  13 0c 01 00 00 00 00 00
      00 00 1b c0 6c 00 1c 00  01 00 00 00 f9 00 10 24
      04 68 00 40 03 0c 04 00  00 00 00 00 00 00 1b 04
      41 4c 54 33 c0 2f 00 1c  00 01 00 00 01 1b 00 10
      26 07 f8 b0 40 0e 0c 00  00 00 00 00 00 00 00 1b
      c0 94 00 1c 00 01 00 02  64 96 00 10 20 01 48 60
      48 02 00 32 00 00 00 00  00 00 00 0a c0 ca 00 1c
      00 01 00 04 54 3a 00 10  20 01 48 60 48 02 00 34
      00 00 00 00 00 00 00 0a  c0 b8 00 1c 00 01 00 01
      79 ea 00 10 20 01 48 60  48 02 00 36 00 00 00 00
      00 00 00 0a c0 a6 00 1c  00 01 00 01 d1 ba 00 10
      20 01 48 60 48 02 00 38  00 00 00 00 00 00 00 0a" in

    let clock () = 0L in
    let mock_state = create ~clock () in
    let ns = `TCP, ref [ipv4_buf] in
    match getaddrinfo mock_state Dns.Rr_map.Mx domain_name ~nameserver:ns with
    | Ok (_ttl, mx_set) ->
      let make_mx_record (preference, domain_name) =
        Dns.Mx.{
          preference;
          mail_exchange = Domain_name.host_exn @@ Domain_name.of_string_exn domain_name
        } in

      (* assert this is Google MX *)
      Alcotest.(check bool __LOC__ true @@ Dns.Rr_map.Mx_set.equal mx_set @@ Dns.Rr_map.Mx_set.of_list @@
        List.map make_mx_record [
          (10, "aspmx.l.google.com");
          (20, "alt1.aspmx.l.google.com");
          (30, "alt2.aspmx.l.google.com");
          (40, "alt3.aspmx.l.google.com");
          (50, "alt4.aspmx.l.google.com")
        ])
    | Error _ -> failwith "foo.com should have been returned"

  let fails_on_partial_udp_packet () =
    let domain_name = Domain_name.(of_string_exn "google.com" |> host_exn) in
    (* A partial google.com MX record
       first two bytes identify this as a TCP packet - dropped here
       bytes 3,4 are set to the query ID 00 00
     *)
    let udp_buf = Cstruct.of_hex
      "     00 00 81 80 00 01  00 05 00 04 00 0f 06 67
      6f 6f 67 6c 65 03 63 6f  " in
    let clock () = 0L in
    let mock_state = create ~clock () in
    let ns = `UDP, ref [udp_buf] in
    match getaddrinfo mock_state Dns.Rr_map.Mx domain_name ~nameserver:ns with
    | Ok (_, _) ->
      failwith("Should have reported the Truncated UDP packet")
    | Error `Msg actual ->
      let expected = "Truncated UDP response" in
      Alcotest.(check string "reports the truncated UDP packet failure" expected actual)

  let tests = [
    "supports_mx_packets", `Quick, supports_mx_packets;
    "a partial UDP response packet fails", `Quick, fails_on_partial_udp_packet;
  ]
end

let tests = [
    "make_query tests", Make_query_tests.tests;
    "parse_response tests", Parse_response_tests.tests;
    "gethostbyname tests", Gethostbyname_tests.tests;
    "getaddrinfo tests", Getaddrinfo_tests.tests;
]

let () = Alcotest.run "DNS client tests" tests
