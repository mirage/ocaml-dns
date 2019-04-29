(* (c) 2017 Hannes Mehnert, all rights reserved *)
open Dns
open Astring

open Packet

let of_hex s =
  let hexchar = function
    | 'a' .. 'f' as x -> int_of_char x - 0x57
    | '0' .. '9' as x -> int_of_char x - 0x30
    | _ -> invalid_arg "unknown char"
  in
  let cs = Cstruct.create (succ (String.length s) / 2) in
  let idx, part =
    String.fold_left (fun (i, part) c ->
        if Char.Ascii.is_white c then
          (i, part)
        else match part with
          | None -> (i, Some (hexchar c lsl 4))
          | Some data -> Cstruct.set_uint8 cs i (data lor hexchar c) ; (succ i, None))
      (0, None) s
  in
  (match part with None -> () | Some _ -> invalid_arg "missing a hex char") ;
  Cstruct.sub cs 0 idx

let n_of_s = Domain_name.of_string_exn

let p_cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let p_err =
  let module M = struct
    type t = err
    let pp = pp_err
    let equal a b = match a, b with
      | `Not_implemented _, `Not_implemented _
      | `Leftover _, `Leftover _
      | `Malformed _, `Malformed _
      | `Partial, `Partial
      | `Bad_edns_version _, `Bad_edns_version _ -> true
      | _ -> false
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

module Packet = struct
  let t_ok =
    let module M = Packet in
    (module Packet: Alcotest.TESTABLE with type t = M.t)

  let bad_query () =
    let cs = of_hex "0000 0000 0001 0000 0000 0000 0000 0100 02" in
    Alcotest.(check (result t_ok p_err) "query with bad class"
                (Error (`Not_implemented (0, "BadClass 2")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0100 03" in
    Alcotest.(check (result t_ok p_err) "query with unsupported class"
                (Error (`Not_implemented (0, "UnsupportedClass 0")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0000 01" in
    let res =
      let i = match Rr_map.I.of_int 0 with
        | Error _ -> Alcotest.fail "expected ok"
        | Ok i -> i
      in
      let header = (0, Flags.singleton `Recursion_desired)
      and question = Question.create Domain_name.root (Unknown i)
      and data = `Query
      in
      Packet.create header question data
    in
    Alcotest.(check (result t_ok p_err) "question with unsupported typ"
                (Ok res) (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 2100 01" in
    Alcotest.(check (result t_ok p_err) "question with bad SRV"
                (Error (`Malformed (0, "BadContent")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0102 0000 0200 01" in
    Alcotest.(check (result t_ok p_err) "question with bad hostname"
                (Error (`Malformed (0, "BadContent")))
                (decode cs))

  let regression0 () =
    let data = of_hex
        {___|d4 e4 85 83 00 01 00 00 00 01 00 00 01 36 02 31
             36 03 31 35 30 03 31 33 38 07 69 6e 2d 61 64 64
             72 04 61 72 70 61 00 00 0c 00 01 03 31 35 30 03
             31 33 38 07 49 4e 2d 41 44 44 52 04 41 52 50 41
             00 00 06 00 01 00 00 2a 30 00 3f 05 43 4f 4e 31
             52 04 4e 49 50 52 03 4d 49 4c 00 13 44 41 4e 49
             45 4c 2e 57 2e 4b 4e 4f 50 50 53 2e 43 49 56 04
             4d 41 49 4c c0 56 78 39 c3 d1 00 00 2a 30 00 00
             03 84 00 12 75 00 00 00 2a 30|___}
    in
    let flags = Flags.(add `Authoritative (add `Recursion_desired (singleton `Recursion_available)))
    and content =
      let soa = {
      Soa.nameserver = n_of_s "CON1R.NIPR.MIL" ;
      hostmaster =
        Domain_name.of_strings_exn ~hostname:false
          ["DANIEL.W.KNOPPS.CIV" ; "MAIL" ; "MIL" ] ;
      serial = 0x7839c3d1l ; refresh = 0x2a30l ; retry = 0x384l ;
      expiry = 0x127500l ; minimum = 0x2a30l
    } in
      Domain_name.Map.empty,
      Name_rr_map.singleton (n_of_s "150.138.in-addr.arpa") Soa soa
    in
    let res =
      create (0xD4E4, flags)
        (Question.create (n_of_s "6.16.150.138.in-addr.arpa") Ptr)
        (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some content))
    in
    Alcotest.(check (result t_ok p_err) "regression 0 decodes"
                (Ok res) (decode data))

  let regression1 () =
    let data = of_hex {___|83 d9 01 00 00 01 00 00 00 00 00 00 04 6b 65 79
                           73 06 72 69 73 65 75 70 03 6e 65 74 00 00 1c 00
                           01|___}
    in
    let flags = Flags.singleton `Recursion_desired in
    let res =
      create (0x83D9, flags)
        (Question.create (n_of_s "keys.riseup.net") Aaaa) `Query
    in
    Alcotest.(check (result t_ok p_err) "regression 1 decodes"
                (Ok res) (decode data))

  let regression2 () =
    let data = of_hex {___|ae 00 84 03 00 01 00 00 00 01 00 00 04 6e 65 77
                           73 03 62 62 63 03 6e 65 74 02 75 6b 00 00 02 00
                           01 03 62 62 63 03 6e 65 74 02 75 6b 00 00 06 00
                           01 00 00 0e 10 00 34 03 32 31 32 02 35 38 03 32
                           33 30 03 32 30 30 00 04 62 6f 66 68 03 62 62 63
                           02 63 6f 02 75 6b 00 59 5c bd ce 00 01 51 80 00
                           01 51 80 00 01 51 80 00 00 01 2c|___}
    in
    let flags = Flags.singleton `Authoritative
    and content =
      let soa = {
        Soa.nameserver = n_of_s ~hostname:false "212.58.230.200" ;
        hostmaster = n_of_s "bofh.bbc.co.uk" ;
        serial = 0x595cbdcel ; refresh = 0x00015180l ; retry = 0x00015180l ;
        expiry = 0x00015180l ; minimum = 0x0000012cl
      } in
      (Domain_name.Map.empty,
       Name_rr_map.singleton (n_of_s "bbc.net.uk") Soa soa)
    in
    let res = create (0xAE00, flags)
        (Question.create (n_of_s "news.bbc.net.uk") Ns)
        (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some content))
    in
    Alcotest.(check (result t_ok p_err) "regression 2 decodes"
                (Ok res) (decode data))

  let regression3 () =
    let data = of_hex {___|e213 8180 0001
        0001 0000 0001 0366 6f6f 0363 6f6d 0000
        0f00 01c0 0c00 0f00 0100 0002 2c00 0b03
        e801 3001 3001 3001 3000 0000 2901 c2 00
        0000 0000 00|___}
    in
    let flags = Flags.(add `Recursion_desired (singleton `Recursion_available))
    and question =
      Question.create (Domain_name.of_string_exn ~hostname:false "foo.com") Mx
    and answer =
      let mx = {
        Mx.preference = 1000 ;
        mail_exchange = Domain_name.of_string_exn ~hostname:false "0.0.0.0"
      } in
      Name_rr_map.singleton (Domain_name.of_string_exn "foo.com")
        Mx (556l, Rr_map.Mx_set.singleton mx)
    and edns = Edns.create ~payload_size:450 ()
    in
    let res = create ~edns (0xe213, flags) question
        (`Answer (answer, Domain_name.Map.empty))
    in
    Alcotest.(check (result t_ok p_err) "regression 4 decodes"
                (Ok res) (decode data))

  (* still not sure whether to allow this or not... -- since the resolver code
     now knows about SRV records (and drops _foo._tcp), this shouldn't appear *)
  let regression4 () =
    let data = of_hex {___|9f ca 84 03 00 01 00 00  00 01 00 01 04 5f 74 63
                           70 04 6b 65 79 73 06 72  69 73 65 75 70 03 6e 65
                           74 00 00 02 00 01 c0 16  00 06 00 01 00 00 01 2c
                           00 2b 07 70 72 69 6d 61  72 79 c0 16 0a 63 6f 6c
                           6c 65 63 74 69 76 65 c0  16 78 48 8b 04 00 00 1c
                           20 00 00 0e 10 00 12 75  00 00 00 01 2c 00 00 29
                           10 00 00 00 00 00 00 00|___}
    in
    let question =
      Question.create (Domain_name.of_string_exn ~hostname:false "_tcp.keys.riseup.net") Ns
    and authority =
      let soa = { Soa.nameserver = Domain_name.of_string_exn "primary.riseup.net" ;
                  hostmaster = Domain_name.of_string_exn "collective.riseup.net" ;
                  serial = 0x78488b04l ; refresh = 0x1c20l ; retry = 0x0e10l ;
                  expiry = 0x127500l ; minimum = 0x012cl }
      in
      Name_rr_map.singleton (Domain_name.of_string_exn "riseup.net") Soa soa
    and edns = Edns.create ~payload_size:4096 ()
    in
    let res =
      create ~edns (0x9FCA, Flags.empty) question
        (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (Name_rr_map.empty, authority)))
    in
    Alcotest.(check (result t_ok p_err) "regression 4 decodes"
                (Ok res) (decode data))

  let regression5 () =
    (* this is what bbc returns me (extra bytes) since it doesn't like EDNS *)
    let data = of_hex {___|5b 12 84 01 00 01 00 00  00 00 00 00 03 6e 73 34
                           03 62 62 63 03 6e 65 74  02 75 6b 00 00 02 00 01
                           00 00 29 05 cc 00 00 00  00 00 00|___}
    in
    let flags = Flags.singleton `Authoritative
    and question =
      Question.create (Domain_name.of_string_exn "ns4.bbc.net.uk") Ns
    in
    let res = create (0x5B12, flags) question
        (`Rcode_error (Rcode.FormErr, Opcode.Query, None))
    in
    Alcotest.(check (result t_ok p_err) "regression 5 decodes"
                (Ok res) (decode data))

  let regression6 () =
    let data = of_hex {|00 03 00 00 00 b5 00 00  00 00 00 00 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 03 66 6f 6f 02
                        6d 79 06 64 6f 6d 61 69  6e 00 00 01 00 01 03 66
                        6f 6f 02 6d 79 06 64 6f  6d 61 69 6e 00 00 01 00
                        01 03 66 6f 6f 02 6d 79  06 64 6f 6d 61 69 6e 00
                        00 01 00 01 03 66 6f 6f  02 6d 79 06 64 6f 6d 61
                        69 6e 00 00 01 00 01 03  66 6f 6f 02 6d 79 06 64
                        6f 6d 61 69 6e 00 00 01  00 01 03 66 6f 6f 02 6d
                        79 06 64 6f 6d 61 69 6e  00 00 01 00 01 03 66 6f
                        6f 02 6d 79 06 64 6f 6d  61 69 6e 00 00 01 00 01
                        03 66 6f 6f 02 6d 79 06  64 6f 6d 61 69 6e 00 00
                        01 00 01 03 66 6f 6f 02  6d 79 06 64 6f 6d 61 69
                        6e 00 00 01 00 01 03 66  6f 6f 02 6d 79 06 64 6f
                        6d 61 69 6e 00 00 01 00  01 03 66 6f 6f 02 6d 79
                        06 64 6f 6d 61 69 6e 00  00 01 00 01 03 66 6f 6f
                        02 6d 79 06 64 6f 6d 61  69 6e 00 00 01 00 01 03
                        66 6f 6f 02 6d 79 06 64  6f 6d 61 69 6e 00 00 01
                        00 01 03 66 6f 6f 02 6d  79 06 64 6f 6d 61 69 6e
                        00 00 01 00 01 03 66 6f  6f 02 6d 79 06 64 6f 6d
                        61 69 6e 00 00 01 00 01  03 66 6f 6f 02 6d 79 06
                        64 6f 6d 61 69 6e 00 00  01 00 01 |}
    in
    match decode data with
    | Error _ -> ()
    | Ok _ -> Alcotest.fail "got ok, expected to fail with multiple questions"

  let regression7 () =
    (* encoding a remove_single in an update frame lead to wrong rdlength (off by 2) *)
    let header = 0xAE00, Flags.empty
    and update =
      let up =
        Domain_name.Map.singleton
          (n_of_s "www.example.com")
          [ Update.Remove_single Rr_map.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost))) ]
      in
      (Domain_name.Map.empty, up)
    and zone = Question.create (n_of_s "example.com") Soa
    in
    let res = create header zone (`Update update) in
    let encoded = fst @@ encode `Udp res in
    Cstruct.hexdump encoded;
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result t_ok p_err) "regression 7 decode encode works"
                (Ok res) (decode @@ encoded))

  let regression8 () =
    (* encoding a exists_data in an update frame lead to wrong rdlength (off by 2) *)
    let header = 0xAE00, Flags.empty
    and prereq =
      let pre =
        Domain_name.Map.singleton (n_of_s "www.example.com")
          [ Update.Exists_data Rr_map.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost)))]
      in
      (pre, Domain_name.Map.empty)
    and zone = Question.create (n_of_s "example.com") Soa
    in
    let res = create header zone (`Update prereq) in
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result t_ok p_err) "regression 8 decode encode works"
                (Ok res) (decode @@ fst @@ encode `Udp res))

  let regression9 () =
    (* from ednscomp.isc.org *)
    let data = Cstruct.of_hex {|
a8 6c 00 00 00 01 00 00  00 00 00 01 04 6e 71 73
62 02 69 6f 00 00 01 00  01 00 00 29 10 00 00 00
00 00 00 1c 00 03 00 00  00 08 00 04 00 01 00 00
00 0a 00 08 c8 9a 2a f8  aa 77 31 af 00 09 00 00
|}
    in
    let header = 0xa86c, Flags.empty
    and question = Question.create (n_of_s "nqsb.io") A
    and edns =
      let extensions = [
        Edns.Nsid Cstruct.empty ;
        Edns.Extension (8, Cstruct.of_hex "00 01 00 00") ;
        Edns.Cookie (Cstruct.of_hex "c8 9a 2a f8 aa 77 31 af") ;
        Edns.Extension (9, Cstruct.empty)
      ] in
      Edns.create ~payload_size:4096 ~extensions ()
    in
    let res = create ~edns header question `Query in
    Alcotest.(check (result t_ok p_err) "regression 9 decodes"
                (Ok res) (decode data))

  let regression10 () =
    (* ERR [application] decode error (from 141.1.1.1:53)
       not implemented at 305: unsupported RR typ ISDN for *)
    let data = Cstruct.of_hex {|
10 92 81 80 00 01 00 0d  00 00 00 0d 03 63 63 63
02 64 65 00 00 ff 00 01  c0 0c 00 06 00 01 00 00
1b 9e 00 2a 02 6e 73 03  68 61 6d c0 0c 0a 68 6f
73 74 6d 61 73 74 65 72  c0 0c 78 57 fa 94 00 00
a8 c0 00 00 1c 20 00 24  ea 00 00 01 51 80 c0 0c
00 02 00 01 00 00 1b 9e  00 09 02 6e 73 03 62 65
72 c0 0c c0 0c 00 02 00  01 00 00 1b 9e 00 02 c0
24 c0 0c 00 02 00 01 00  00 1b 9e 00 09 02 6e 73
03 76 69 65 c0 0c c0 0c  00 02 00 01 00 00 1b 9e
00 11 05 73 2d 64 6e 73  05 69 72 7a 34 32 03 6e
65 74 00 c0 0c 00 0f 00  01 00 00 1b 9e 00 0b 00
05 06 6e 6f 6d 61 69 6c  c0 0c c0 0c 00 0f 00 01
00 00 1b 9e 00 09 00 0a  04 6d 61 69 6c c0 0c c0
0c 00 0f 00 01 00 00 1b  9e 00 0c 00 17 07 6e 6f
6d 61 69 6c 32 c0 0c c0  0c 00 0f 00 01 00 00 1b
9e 00 0c 00 2a 07 6e 6f  6d 61 69 6c 33 c0 0c c0
0c 00 01 00 01 00 00 1b  9e 00 04 c3 36 a4 27 c0
0c 00 1c 00 01 00 00 1b  9e 00 10 20 01 06 7c 20
a0 00 02 00 00 01 64 00  00 00 39 c0 0c 00 14 00
01 00 00 1b 9e 00 0c 0b  34 39 34 30 34 30 31 38
30 31 30 c0 0c 00 10 00  01 00 00 1b 9e 00 26 25
43 68 61 6f 73 20 43 6f  6d 70 75 74 65 72 20 43
6c 75 62 2c 20 48 61 6d  62 75 72 67 2c 20 47 65
72 6d 61 6e 79 c0 5a 00  01 00 01 00 00 0d d8 00
04 c3 36 a4 24 c0 24 00  01 00 01 00 00 0d d8 00
04 d4 0c 37 4d c0 7d 00  01 00 01 00 00 0d d8 00
04 92 ff 39 e4 c0 b1 00  01 00 01 00 00 1b 9e 00
04 d4 0c 37 41 c0 c8 00  01 00 01 00 00 1b 9e 00
04 d4 0c 37 42 c0 dd 00  01 00 01 00 00 1b 9e 00
04 d4 0c 37 41 c0 5a 00  1c 00 01 00 00 06 d0 00
10 20 01 06 7c 20 a0 00  02 00 00 01 64 00 00 00
36 c0 24 00 1c 00 01 00  00 06 d0 00 10 2a 00 14
b0 42 00 30 00 00 23 00  55 00 00 00 77 c0 7d 00
1c 00 01 00 00 06 d0 00  10 2a 02 01 b8 00 10 00
31 00 00 00 00 00 00 02  28 c0 b1 00 1c 00 01 00
00 1b 9e 00 10 2a 00 14  b0 42 00 30 00 00 23 00
55 00 00 00 65 c0 c8 00  1c 00 01 00 00 1b 9e 00
10 2a 00 14 b0 42 00 30  00 00 23 00 55 00 00 00
66 c0 f5 00 1c 00 01 00  00 1b 9e 00 10 2a 00 14
b0 42 00 30 00 00 23 00  55 00 00 00 65 00 00 29
20 00 00 00 00 00 00 00
|}
    in
    let header = 0x1092, Flags.(add `Recursion_available (singleton `Recursion_desired))
    and question = n_of_s "ccc.de", `Any
    and an, additional =
      let isdn = match Rr_map.I.of_int 20 with Ok x -> x | Error _ -> Alcotest.fail "expected unexpected" in
      let ip s = Rr_map.Ipv4_set.singleton (Ipaddr.V4.of_string_exn s)
      and ip6 s = Rr_map.Ipv6_set.singleton (Ipaddr.V6.of_string_exn s)
      in
      Domain_name.Map.singleton (n_of_s "ccc.de")
        (Rr_map.add Soa {
            Soa.nameserver = n_of_s "ns.ham.ccc.de" ; hostmaster = n_of_s "hostmaster.ccc.de" ;
            serial = 2019031700l ; refresh = 43200l ; retry = 7200l ; expiry = 2419200l ;
            minimum = 86400l }
            (Rr_map.add Ns (7070l, Domain_name.Set.of_list [
                 n_of_s "ns.vie.ccc.de" ; n_of_s "ns.ham.ccc.de" ;
                 n_of_s "ns.ber.ccc.de" ; n_of_s "s-dns.irz42.net"
               ])
                (Rr_map.add Mx (7070l, Rr_map.Mx_set.of_list [
                     { preference = 5 ; mail_exchange = n_of_s "nomail.ccc.de" } ;
                     { preference = 10 ; mail_exchange = n_of_s "mail.ccc.de" } ;
                     { preference = 23 ; mail_exchange = n_of_s "nomail2.ccc.de" } ;
                     { preference = 42 ; mail_exchange = n_of_s "nomail3.ccc.de" }
                   ])
                    (Rr_map.add A (7070l, ip "195.54.164.39")
                       (Rr_map.add Aaaa (7070l, ip6 "2001:67c:20a0:2:0:164:0:39")
                          (Rr_map.add Txt (7070l, Rr_map.Txt_set.singleton "Chaos Computer Club, Hamburg, Germany")
                             (Rr_map.singleton (Unknown isdn) (7070l, Rr_map.Txt_set.singleton Cstruct.(to_string (of_hex "0B3439343034303138303130")))))))))),
      Domain_name.Map.add (n_of_s "mail.ccc.de")
        (Rr_map.add Aaaa (7070l, ip6 "2a00:14b0:4200:3000:23:55:0:66")
           (Rr_map.singleton A (7070l, ip "212.12.55.66")))
        (Domain_name.Map.add (n_of_s "nomail.ccc.de")
           (Rr_map.add A (7070l, ip "212.12.55.65")
              (Rr_map.singleton Aaaa (7070l, ip6 "2a00:14b0:4200:3000:23:55:0:65")))
           (Domain_name.Map.add (n_of_s "nomail2.ccc.de")
              (Rr_map.singleton A (7070l, ip "212.12.55.65"))
              (Domain_name.Map.add (n_of_s "nomail3.ccc.de") (Rr_map.singleton Aaaa (7070l, ip6 "2a00:14b0:4200:3000:23:55:0:65"))
                 (Domain_name.Map.add (n_of_s "ns.ber.ccc.de")
                    (Rr_map.add A (3544l, ip "195.54.164.36")
                       (Rr_map.singleton Aaaa (1744l, ip6 "2001:67c:20a0:2:0:164:0:36")))
                    (Domain_name.Map.add (n_of_s "ns.ham.ccc.de")
                       (Rr_map.add A (3544l, ip "212.12.55.77")
                          (Rr_map.singleton Aaaa (1744l, ip6 "2a00:14b0:4200:3000:23:55:0:77")))
                       (Domain_name.Map.singleton (n_of_s "ns.vie.ccc.de")
                          (Rr_map.add A (3544l, ip "146.255.57.228")
                             (Rr_map.singleton Aaaa (1744l, ip6 "2a02:1b8:10:31::228")))))))))
    and edns =
      Edns.create ~payload_size:8192 ()
    in
    let res = create ~additional ~edns header question (`Answer (an, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "regression 9 decodes"
                (Ok res) (decode data))

  let code_tests = [
    "bad query", `Quick, bad_query ;
    "regression0", `Quick, regression0 ;
    "regression1", `Quick, regression1 ;
    "regression2", `Quick, regression2 ;
    "regression3", `Quick, regression3 ;
    (* "regression4", `Quick, regression4 ; *)
    "regression5", `Quick, regression5 ;
    "regression6", `Quick, regression6 ;
    "regression7", `Quick, regression7 ;
    "regression8", `Quick, regression8 ;
    "regression9", `Quick, regression9 ;
    "regression10", `Quick, regression10 ;
  ]
end

let tests = [
  "Packet decode", Packet.code_tests ;
]

let () = Alcotest.run "DNS name and packet tests" tests
