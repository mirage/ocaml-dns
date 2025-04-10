(* (c) 2017 Hannes Mehnert, all rights reserved *)

let cs =
  let module M = struct
    type t = string
    let pp = Ohex.pp
    let equal = String.equal
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let msg =
  let module M = struct
    type t = [ `Msg of string ]
    let pp ppf = function `Msg str -> Fmt.string ppf str
    let equal _ _ = true
    end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let key =
  match Base64.decode "GSnQJ+fHuzwj5yKzCOkXdISyGQXBUxMrjEjL4Kr1WIs=" with
  | Error _ -> assert false
  | Ok x -> x

let key_name = Domain_name.of_string_exn "mykey.bla.example"

let of_h = Ohex.decode

let tsig ?(fudge = 300) algorithm signed =
  let fudge = Ptime.Span.of_int_s fudge in
  let signed =
    match Ptime.of_float_s signed with
    | None -> assert false
    | Some x -> x
  in
  match Dns.Tsig.tsig ~algorithm ~signed ~fudge () with
  | None -> assert false
  | Some x -> x

let example0 () =
  let buf = of_h {__|62 d7 28 00 00 01 00 00  00 02 00 00 07 65 78 61
                     6d 70 6c 65 03 63 6f 6d  00 00 06 00 01 03 66 6f
                     6f c0 0c 00 ff 00 ff 00  00 00 00 00 00 03 62 61
                     72 c0 0c 00 01 00 01 00  00 01 2c 00 04 01 02 03
                     04|__}
  and now = 1506887417.
  and mac = of_h {__|bf 5d 77 ba 97 ba 7b 95  9e 1b 0d 95 64 a7 5b a6
                     95 bf 24 15 3b 9d a2 1b  bf 6f ae 61 9d 0f 28 a1|__}
  in
  Alcotest.(check cs "tsig is the same" mac
              (Dns_tsig.compute_tsig key_name (tsig Dns.Tsig.SHA256 now) ~key buf))

let example1 () =
  let buf = of_h {__|4c 56 28 00 00 01 00 00  00 01 00 00 07 45 78 41
                     6d 50 6c 45 03 63 6f 6d  00 00 06 00 01 03 66 6f
                     6f 07 65 78 61 6d 70 6c  65 c0 14 00 ff 00 ff 00
                     00 00 00 00 00|__}
  and now = 1506887742.
  and mac = of_h {__|70 67 ae 70 9e fd 22 9e  ce d9 65 25 8a db 8c 96
                     10 95 80 89 a7 ee 4f bb  13 81 e7 38 e3 a0 78 80|__}
  in
  Alcotest.(check cs "tsig is the same" mac
              (Dns_tsig.compute_tsig key_name (tsig Dns.Tsig.SHA256 now) ~key buf))

let example2 () =
  let buf = of_h {__|76 8a 28 00 00 01 00 00  00 01 00 00 07 65 78 61
                     6d 70 6c 65 00 00 06 00  01 03 66 6f 6f c0 0c 00
                     ff 00 ff 00 00 00 00 00  00|__}
  and now = 1506888104.
  and mac = of_h {__|e7 76 e6 df 4e 73 14 c8  eb ba 4c c7 a5 39 b3 93
                     a7 df 6d de 47 b6 fa cc  81 c8 47 29 20 77 40 44|__}
  in
  Alcotest.(check cs "tsig is the same" mac
              (Dns_tsig.compute_tsig key_name (tsig Dns.Tsig.SHA256 now) ~key buf))


let tsig_tests = [
  "example0", `Quick, example0 ;
  "example1", `Quick, example1 ;
  "example2", `Quick, example2 ;
]


let tests = [
  "Tsig example", tsig_tests ;
]

let () = Alcotest.run "DNS name tests" tests
