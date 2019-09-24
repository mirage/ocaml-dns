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
      ?(nameserver = `TCP, default_debug_info) () =
    rng

  let nameserver _ = `TCP,  default_debug_info
  let rng x = x

  let bind a b = b a
  let lift v = v

  open Rresult

  let close socket = ()

  let connect ?nameserver:ns t =
    match ns with
    | None -> Ok default_debug_info
    | Some(_, mock_responses) -> Ok mock_responses

  let send (socket:flow) (tx:Cstruct.t) =
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
  let gethostbyname_for_foo_com_is_valid () =
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
    "foo.com is valid", `Quick, gethostbyname_for_foo_com_is_valid;
  ]
end


(* list of well-known inputs *)
(* new connection: THESE  responses are expected *)
(* you will recv the next thing in the list of inputs *)

let tests = [
    "gethostbyname tests", Gethostbyname_tests.tests;
]

let () = Alcotest.run "DNS client flow tests" tests
