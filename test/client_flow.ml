(* {!Uflow} provides the implementation of the underlying flow
   that is in turn used by {!Dns_client_flow.Make} to provide the
   blocking Unix convenience module:
*)

type debug_info = Cstruct.t list ref
let default_debug_info =
  ref []

module Uflow : Dns_client_flow.S
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

(* Now that we have our {!Uflow} implementation we can include the logic
   that goes on top of it: *)
include Dns_client_flow.Make(Uflow)

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
    let t = Uflow.create () in
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
    let mock_state = Uflow.create () in
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

  let tests = [
    "supports_mx_packets", `Quick, supports_mx_packets;
  ]
end


(* list of well-known inputs *)
(* new connection: THESE  responses are expected *)
(* you will recv the next thing in the list of inputs *)

let tests = [
    "gethostbyname tests", Gethostbyname_tests.tests;
    "getaddrinfo tests", Getaddrinfo_tests.tests;
]

let () = Alcotest.run "DNS client flow tests" tests
