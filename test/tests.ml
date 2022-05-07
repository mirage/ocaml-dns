(* (c) 2017 Hannes Mehnert, all rights reserved *)
open Dns
open Packet

let n_of_s = Domain_name.of_string_exn

let p_cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

let p_err =
  let module M = struct
    type t = err
    let pp = pp_err
    let equal a b = match a, b with
      | `Not_implemented _, `Not_implemented _
      | `Malformed _, `Malformed _
      | `Partial, `Partial
      | `Bad_edns_version _, `Bad_edns_version _ -> true
      | `Leftover (off, _), `Leftover (off', _) -> off = off'
      | _ -> false
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

module Packet = struct
  let t_ok =
    let module M = Packet in
    (module Packet: Alcotest.TESTABLE with type t = M.t)

  let bad_query () =
    let cs = Cstruct.of_hex "0000 0000 0001 0000 0000 0000 0000 0100 02" in
    Alcotest.(check (result t_ok p_err) "query with bad class"
                (Error (`Not_implemented (0, "BadClass 2")))
                (decode cs)) ;
    let cs = Cstruct.of_hex "0000 0100 0001 0000 0000 0000 0000 0100 03" in
    Alcotest.(check (result t_ok p_err) "query with unsupported class"
                (Error (`Not_implemented (0, "UnsupportedClass 0")))
                (decode cs)) ;
    let cs = Cstruct.of_hex "0000 0100 0001 0000 0000 0000 0000 0000 01" in
    let header = (0, Flags.singleton `Recursion_desired) in
    let res =
      let i = match Rr_map.I.of_int 0 with
        | Error _ -> Alcotest.fail "expected ok"
        | Ok i -> i
      in
      let question = Question.create Domain_name.root (Unknown i)
      and data = `Query
      in
      Packet.create header question data
    in
    Alcotest.(check (result t_ok p_err) "question with unsupported typ"
                (Ok res) (decode cs)) ;
    let cs = Cstruct.of_hex "0000 0100 0001 0000 0000 0000 0000 2100 01" in
    let r =
      let question = Question.create Domain_name.root Srv in
      Packet.create header question `Query
    in
    Alcotest.(check (result t_ok p_err) "question with SRV ()"
                (Ok r) (decode cs)) ;
    let cs = Cstruct.of_hex "0000 0100 0001 0000 0000 0000 0102 0000 0200 01" in
    let r =
      let name = Domain_name.of_string_exn "\002." in
      let question = Question.create name Ns in
      Packet.create header question `Query
    in
    Alcotest.(check (result t_ok p_err) "question with name that is not a hostname"
                (Ok r) (decode cs))

  let regression0 () =
    let data = Cstruct.of_hex
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
        Domain_name.of_strings_exn ["DANIEL.W.KNOPPS.CIV" ; "MAIL" ; "MIL" ] ;
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
    let data = Cstruct.of_hex
        {___|83 d9 01 00 00 01 00 00 00 00 00 00 04 6b 65 79
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
    let data = Cstruct.of_hex
        {___|ae 00 84 03 00 01 00 00 00 01 00 00 04 6e 65 77
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
        Soa.nameserver = n_of_s "212.58.230.200" ;
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
    let data = Cstruct.of_hex
        {___|e213 8180 0001
             0001 0000 0001 0366 6f6f 0363 6f6d 0000
             0f00 01c0 0c00 0f00 0100 0002 2c00 0b03
             e801 3001 3001 3001 3000 0000 2901 c2 00
             0000 0000 00|___}
    in
    let flags = Flags.(add `Recursion_desired (singleton `Recursion_available))
    and question =
      Question.create (Domain_name.of_string_exn "foo.com") Mx
    and answer =
      let mx = {
        Mx.preference = 1000 ;
        mail_exchange = Obj.magic (Domain_name.of_string_exn "0.0.0.0")
      } in
      Name_rr_map.singleton (Domain_name.of_string_exn "foo.com")
        Mx (556l, Rr_map.Mx_set.singleton mx)
    and edns = Edns.create ~payload_size:450 ()
    in
    let res = create ~edns (0xe213, flags) question
        (`Answer (answer, Domain_name.Map.empty))
    in
    Alcotest.(check (result t_ok p_err) "regression 3 decodes"
                (Ok res) (decode data))

  (* still not sure whether to allow this or not... -- since the resolver code
     now knows about SRV records (and drops _foo._tcp), this shouldn't appear *)
  let regression4 () =
    let data = Cstruct.of_hex
        {___|9f ca 84 03 00 01 00 00  00 01 00 01 04 5f 74 63
             70 04 6b 65 79 73 06 72  69 73 65 75 70 03 6e 65
             74 00 00 02 00 01 c0 16  00 06 00 01 00 00 01 2c
             00 2b 07 70 72 69 6d 61  72 79 c0 16 0a 63 6f 6c
             6c 65 63 74 69 76 65 c0  16 78 48 8b 04 00 00 1c
             20 00 00 0e 10 00 12 75  00 00 00 01 2c 00 00 29
             10 00 00 00 00 00 00 00|___}
    in
    let question =
      Question.create (Domain_name.of_string_exn "_tcp.keys.riseup.net") Ns
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
      create ~edns (0x9FCA, Flags.singleton `Authoritative) question
        (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (Name_rr_map.empty, authority)))
    in
    Alcotest.(check (result t_ok p_err) "regression 4 decodes"
                (Ok res) (decode data))

  let regression5 () =
    (* this is what bbc returns me (extra bytes) since it doesn't like EDNS *)
    let data = Cstruct.of_hex
        {___|5b 12 84 01 00 01 00 00  00 00 00 00 03 6e 73 34
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
    let data = Cstruct.of_hex
        {|00 03 00 00 00 b5 00 00  00 00 00 00 03 66 6f 6f
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
          [ Update.Remove_single Rr_map.(B (A, (0l, Ipaddr.V4.Set.singleton Ipaddr.V4.localhost))) ]
      in
      (Domain_name.Map.empty, up)
    and zone = Question.create (n_of_s "example.com") Soa
    in
    let res = create header zone (`Update update) in
    let encoded = fst @@ encode `Udp res in
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result t_ok p_err) "regression 7 decode encode works"
                (Ok res) (decode @@ encoded))

  let regression8 () =
    (* encoding a exists_data in an update frame lead to wrong rdlength (off by 2) *)
    let header = 0xAE00, Flags.empty
    and prereq =
      let pre =
        Domain_name.Map.singleton (n_of_s "www.example.com")
          [ Update.Exists_data Rr_map.(B (A, (0l, Ipaddr.V4.Set.singleton Ipaddr.V4.localhost)))]
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
      let ip s = Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn s)
      and ip6 s = Ipaddr.V6.Set.singleton (Ipaddr.V6.of_string_exn s)
      in
      Domain_name.Map.singleton (n_of_s "ccc.de")
        (Rr_map.add Soa {
            Soa.nameserver = n_of_s "ns.ham.ccc.de" ; hostmaster = n_of_s "hostmaster.ccc.de" ;
            serial = 2019031700l ; refresh = 43200l ; retry = 7200l ; expiry = 2419200l ;
            minimum = 86400l }
            (Rr_map.add Ns (7070l, Domain_name.Host_set.of_list
                              (List.map Domain_name.host_exn [
                                  n_of_s "ns.vie.ccc.de" ; n_of_s "ns.ham.ccc.de" ;
                                  n_of_s "ns.ber.ccc.de" ; n_of_s "s-dns.irz42.net"
                                ]))
                (Rr_map.add Mx (7070l, Rr_map.Mx_set.of_list [
                     { preference = 5 ; mail_exchange = Domain_name.host_exn (n_of_s "nomail.ccc.de") } ;
                     { preference = 10 ; mail_exchange = Domain_name.host_exn (n_of_s "mail.ccc.de") } ;
                     { preference = 23 ; mail_exchange = Domain_name.host_exn (n_of_s "nomail2.ccc.de") } ;
                     { preference = 42 ; mail_exchange = Domain_name.host_exn (n_of_s "nomail3.ccc.de") }
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

  let regression11 () =
    (* here we have an overlong text record (>255 bytes) which should be encoded into a single RR! *)
    let data = Cstruct.of_hex {|
d0 55 81 80 00 01 00 01 00 00 00 01 0c 61 72 63
2d 32 30 31 36 30 38 31 36 0a 5f 64 6f 6d 61 69
6e 6b 65 79 06 67 6f 6f 67 6c 65 03 63 6f 6d 00
00 10 00 01 c0 0c 00 10 00 01 00 00 00 33 01 93
aa 6b 3d 72 73 61 3b 20 70 3d 4d 49 49 42 49 6a
41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51
45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67
4b 43 41 51 45 41 31 4c 7a 74 70 78 73 37 79 55
78 51 45 73 62 44 46 68 6a 4d 63 39 6b 5a 56 5a
75 35 50 2f 43 4f 59 45 55 49 58 34 42 33 39 49
4c 34 53 58 41 62 76 34 76 69 49 6c 54 39 45 36
46 36 69 5a 6d 54 68 31 67 6f 37 2b 39 57 51 4c
79 77 77 67 77 6a 58 4d 4a 78 2f 44 7a 30 52 67
4d 6f 50 65 79 70 35 4e 52 79 34 6c 33 32 30 44
50 59 69 62 4e 71 56 4d 57 61 35 e7 69 51 32 57
69 49 6d 51 43 30 65 6e 31 4f 39 75 68 4c 4c 76
7a 61 53 5a 4a 30 33 66 76 47 6d 43 6f 39 6a 4d
6f 30 47 77 4b 7a 4c 4e 65 31 34 78 4d 67 6e 2f
70 78 32 4c 35 4e 2f 33 49 4b 6c 4b 58 34 62 71
55 41 4a 54 55 74 38 4c 39 39 33 5a 6c 57 7a 76
67 4d 6e 53 46 53 74 38 42 2b 65 75 53 4b 53 72
74 41 69 6f 70 64 79 34 72 31 79 4f 34 65 4e 35
67 6f 42 41 53 72 47 57 30 65 4c 51 63 31 6c 59
6f 75 4e 76 43 72 63 54 51 70 6f 73 34 2f 47 45
41 71 69 47 7a 70 71 75 65 4a 4c 6d 42 66 4f 4f
34 63 6c 4e 76 56 76 70 50 6b 76 51 73 32 42 48
77 39 49 39 4c 6d 49 6a 61 4d 78 54 4e 47 78 6b
47 42 52 61 50 33 75 74 44 69 4b 58 58 71 75 31
4b 2b 4c 52 7a 6c 30 48 43 4e 53 64 51 49 44 41
51 41 42 00 00 29 20 00 00 00 00 00 00 00
|}
    in
    let host = n_of_s "arc-20160816._domainkey.google.com" in
    let flags = Flags.(add `Recursion_desired (singleton `Recursion_available))
    and question = Question.create host Txt
    and content =
      Domain_name.Map.singleton host
        (Rr_map.singleton Txt (51l, Rr_map.Txt_set.singleton "k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Lztpxs7yUxQEsbDFhjMc9kZVZu5P/COYEUIX4B39IL4SXAbv4viIlT9E6F6iZmTh1go7+9WQLywwgwjXMJx/Dz0RgMoPeyp5NRy4l320DPYibNqVMWa5iQ2WiImQC0en1O9uhLLvzaSZJ03fvGmCo9jMo0GwKzLNe14xMgn/px2L5N/3IKlKX4bqUAJTUt8L993ZlWzvgMnSFSt8B+euSKSrtAiopdy4r1yO4eN5goBASrGW0eLQc1lYouNvCrcTQpos4/GEAqiGzpqueJLmBfOO4clNvVvpPkvQs2BHw9I9LmIjaMxTNGxkGBRaP3utDiKXXqu1K+LRzl0HCNSdQIDAQAB"))
    and edns =
      Edns.create ~payload_size:8192 ()
    in
    let header = 0xD055, flags in
    let res = create ~edns header question (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "regression 11 decodes"
                (Ok res) (decode data)) ;
    (* manually moved the length field a bit further *)
    let data' = Cstruct.of_hex {|
d0 55 81 80 00 01 00 01 00 00 00 01 0c 61 72 63
2d 32 30 31 36 30 38 31 36 0a 5f 64 6f 6d 61 69
6e 6b 65 79 06 67 6f 6f 67 6c 65 03 63 6f 6d 00
00 10 00 01 c0 0c 00 10 00 01 00 00 00 33 01 93
ff 6b 3d 72 73 61 3b 20 70 3d 4d 49 49 42 49 6a
41 4e 42 67 6b 71 68 6b 69 47 39 77 30 42 41 51
45 46 41 41 4f 43 41 51 38 41 4d 49 49 42 43 67
4b 43 41 51 45 41 31 4c 7a 74 70 78 73 37 79 55
78 51 45 73 62 44 46 68 6a 4d 63 39 6b 5a 56 5a
75 35 50 2f 43 4f 59 45 55 49 58 34 42 33 39 49
4c 34 53 58 41 62 76 34 76 69 49 6c 54 39 45 36
46 36 69 5a 6d 54 68 31 67 6f 37 2b 39 57 51 4c
79 77 77 67 77 6a 58 4d 4a 78 2f 44 7a 30 52 67
4d 6f 50 65 79 70 35 4e 52 79 34 6c 33 32 30 44
50 59 69 62 4e 71 56 4d 57 61 35 69 51 32 57
69 49 6d 51 43 30 65 6e 31 4f 39 75 68 4c 4c 76
7a 61 53 5a 4a 30 33 66 76 47 6d 43 6f 39 6a 4d
6f 30 47 77 4b 7a 4c 4e 65 31 34 78 4d 67 6e 2f
70 78 32 4c 35 4e 2f 33 49 4b 6c 4b 58 34 62 71
55 41 4a 54 55 74 38 4c 39 39 33 5a 6c 57 7a 76
67 92 4d 6e 53 46 53 74 38 42 2b 65 75 53 4b 53 72
74 41 69 6f 70 64 79 34 72 31 79 4f 34 65 4e 35
67 6f 42 41 53 72 47 57 30 65 4c 51 63 31 6c 59
6f 75 4e 76 43 72 63 54 51 70 6f 73 34 2f 47 45
41 71 69 47 7a 70 71 75 65 4a 4c 6d 42 66 4f 4f
34 63 6c 4e 76 56 76 70 50 6b 76 51 73 32 42 48
77 39 49 39 4c 6d 49 6a 61 4d 78 54 4e 47 78 6b
47 42 52 61 50 33 75 74 44 69 4b 58 58 71 75 31
4b 2b 4c 52 7a 6c 30 48 43 4e 53 64 51 49 44 41
51 41 42 00 00 29 20 00 00 00 00 00 00 00
|} in
    Alcotest.(check p_cs "regression 11 encode works"
                data' (fst @@ encode `Tcp res));
    Alcotest.(check (result t_ok p_err) "regression 11 encoded decodes well"
                (Ok res) (decode data'))

  let regression12 () =
    let data = {|
  7b a2 80 09 00 01 00 00 00 00 00 01 00 00
  06 00 01 03 31 34 37 02 37 35 02 33 34 03 32 31
  30 03 31 39 34 03 31 35 30 03 31 36 38 03 31 35
  36 09 5f 74 72 61 6e 73 66 65 72 00 00 fa 00 ff
  00 00 00 00 00 43 0b 68 6d 61 63 2d 73 68 61 32
  35 36 00 00 00 5f f3 22 3b 01 2c 00 20 b1 40 50
  19 fd 27 49 c3 90 77 d3 a2 87 38 ed a0 eb 2f e8
  eb c4 12 03 f1 25 ad fa 5b 4a 17 83 5e 7b a2 00
  12 00 06 00 00 5f f3 23 71
|} in
    let header = 0x7BA2, Flags.empty in
    let question = Question.create Domain_name.root Soa in
    let r = `Rcode_error (Rcode.NotAuth, Opcode.Query, None) in
    let tsig =
      let of_ts s = match Ptime.of_rfc3339 s with
          Ok (ts, _, _) -> ts
        | Error _ -> Alcotest.fail "bad ts"
      in
      let mac = Cstruct.of_hex {|
  b1 40 50 19 fd 27 49 c3  90 77 d3 a2 87 38 ed a0
  eb 2f e8 eb c4 12 03 f1  25 ad fa 5b 4a 17 83 5e
|}
      and signed = of_ts "2021-01-04T14:12:11-00:00"
      and other = of_ts "2021-01-04T14:17:21-00:00"
      and fudge = Ptime.Span.of_int_s 300
      in
      let tsig =
        match
          Tsig.tsig ~algorithm:Tsig.SHA256
            ~signed ~fudge ~mac ~original_id:0x7BA2
            ~error:Rcode.BadTime ~other ()
        with
        | Some ts -> ts
        | None -> Alcotest.fail "bad tsig"
      in
      n_of_s "147.75.34.210.194.150.168.156._transfer",
      tsig, 17
    in
    let res = create ~tsig header question r in
    Alcotest.(check (result t_ok p_err) "regression 12 decodes"
                (Ok res) (decode (Cstruct.of_hex data)))

  let a_success () =
    let data = Cstruct.of_hex {|ac 8f 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 01 00 01 c0 0c
                          00 01 00 01 00 00 0d c9  00 04 c1 1e 28 8a|}
    in
    let host = n_of_s "robur.coop" in
    let header = 0xac8f, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and q = Question.create host A
    in
    let content = Domain_name.Map.singleton host
       (Rr_map.singleton A (3600l, Ipaddr.V4.(Set.singleton (of_string_exn "193.30.40.138"))))
    in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "A decodes" (Ok res) (decode data))

  let a_leftover () =
    let data = Cstruct.of_hex {|ac 8f 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 01 00 01 c0 0c
                          00 01 00 01 00 00 0d c9  00 04 c1 1e 28 8a 9b|}
    in
    let host = n_of_s "robur.coop" in
    let header = 0xac8f, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and q = Question.create host A
    in
    let content = Domain_name.Map.singleton host
       (Rr_map.singleton A (3600l, Ipaddr.V4.(Set.singleton (of_string_exn "193.30.40.138"))))
    in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "A decodes" (Ok res) (decode data))

  let a_fail_partial () =
    let data = Cstruct.of_hex {|ac 8f 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 01 00 01 c0 0c
                          00 01 00 01 00 00 0d c9  00 04 c1 1e 28|}
    in
    Alcotest.(check (result t_ok p_err) "short A decodes" (Error `Partial) (decode data))

  let a_fail_leftover_inner () =
    let data = Cstruct.of_hex {|ac 8f 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 01 00 01 c0 0c
                          00 01 00 01 00 00 0d c9  00 05 c1 1e 28 8a 9b|}
    in
    Alcotest.(check (result t_ok p_err) "A decode failure (rdata leftover)"
      (Error (`Leftover (44, "rdata"))) (decode data))

  let a_fail_partial_inner () =
    let data = Cstruct.of_hex {|ac 8f 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 01 00 01 c0 0c
                          00 01 00 01 00 00 0d c9  00 03 c1 1e 28 8a|}
    in
    Alcotest.(check (result t_ok p_err) "A decode failure (rdata partial)" (Error `Partial) (decode data))

  let ns_success () =
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 10  00 11 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 06 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  06 03 6e 73 36 c0 2c|}
    in
    let host = n_of_s "robur.coop" in
    let header = 0x3158, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and q = Question.create host Ns
    in
    let h s = Domain_name.host_exn (n_of_s s) in
    let content = Domain_name.Map.singleton host
       (Rr_map.singleton Ns (3600l,
          Domain_name.Host_set.(add (h "ns6.mehnert.org")
            (add (h "ns2.mehnert.org") (singleton (h "ns3.mehnert.org"))))))
    in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "NS decodes" (Ok res) (decode data))

  let ns_fail_partial () =
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 10  00 11 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 06 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  06 03 6e 73 36 c0|}
    in
    Alcotest.(check (result t_ok p_err) "Ns decode failure (partial)"
      (Error `Partial) (decode data))

  let ns_fail_leftover_inner () =
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 10  00 12 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 06 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  06 03 6e 73 36 c0 2c|}
    in
    Alcotest.(check (result t_ok p_err) "Ns decode failure (rdata leftover)"
      (Error (`Leftover (57, "rdata"))) (decode data));
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 10  00 11 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 07 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  06 03 6e 73 36 c0 2c|}
    in
    Alcotest.(check (result t_ok p_err) "Ns decode failure (rdata leftover)"
      (Error (`Leftover (75, "rdata"))) (decode data));
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 10  00 11 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 06 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  07 03 6e 73 36 c0 2c 00|}
    in
    Alcotest.(check (result t_ok p_err) "Ns decode failure (rdata leftover)"
      (Error (`Leftover (93, "rdata"))) (decode data))

  let ns_fail_partial_inner () =
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 10  00 10 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 06 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  06 03 6e 73 36 c0 2c|}
    in
    Alcotest.(check (result t_ok p_err) "Ns decode failure (rdata partial)"
      (Error `Partial) (decode data));
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 11  00 10 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 05 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  06 03 6e 73 36 c0 2c|}
    in
    Alcotest.(check (result t_ok p_err) "Ns decode failure (rdata partial)"
      (Error `Partial) (decode data));
    let data = Cstruct.of_hex {|
                          31 58 81 80 00 01  00 03 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 02 00 01 c0 0c
                          00 02 00 01 00 00 0e 11  00 10 03 6e 73 32 07 6d
                          65 68 6e 65 72 74 03 6f  72 67 00 c0 0c 00 02 00
                          01 00 00 0e 10 00 06 03  6e 73 33 c0 2c c0 0c 00
                          02 00 01 00 00 0e 10 00  05 03 6e 73 36 c0 2c|}
    in
    Alcotest.(check (result t_ok p_err) "Ns decode failure (rdata partial)"
      (Error `Partial) (decode data))

  let cname_success () =
    let data = Cstruct.of_hex {|58 ca 81 80 00 01  00 01 00 00 00 00 03 77
                          77 77 0a 74 61 67 65 73  73 63 68 61 75 02 64 65
                          00 00 05 00 01 c0 0c 00  05 00 01 00 00 00 aa 00
                          1f 03 77 77 77 0a 74 61  67 65 73 73 63 68 61 75
                          02 64 65 07 65 64 67 65  6b 65 79 03 6e 65 74 00|}
    in
    let host = n_of_s "www.tagesschau.de" in
    let header = 0x58ca, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and q = Question.create host Cname
    in
    let content = Domain_name.Map.singleton host
       (Rr_map.singleton Cname (170l, n_of_s "www.tagesschau.de.edgekey.net"))
    in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "Cname decodes" (Ok res) (decode data))

  let cname_fail_partial () =
    let data = Cstruct.of_hex {|58 ca 81 80 00 01  00 01 00 00 00 00 03 77
                          77 77 0a 74 61 67 65 73  73 63 68 61 75 02 64 65
                          00 00 05 00 01 c0 0c 00  05 00 01 00 00 00 aa 00
                          1f 03 77 77 77 0a 74 61  67 65 73 73 63 68 61 75
                          02 64 65 07 65 64 67 65  6b 65 79 03 6e 65 74|}
    in
    Alcotest.(check (result t_ok p_err) "Cname decode failure partial"
      (Error `Partial) (decode data))

  let cname_fail_leftover_inner () =
    let data = Cstruct.of_hex {|58 ca 81 80 00 01  00 01 00 00 00 00 03 77
                          77 77 0a 74 61 67 65 73  73 63 68 61 75 02 64 65
                          00 00 05 00 01 c0 0c 00  05 00 01 00 00 00 aa 00
                          1f 03 77 77 77 0a 74 61  67 65 73 73 63 68 61 75
                          02 64 65 07 65 64 67 65  6b 65 79 02 6e 65 00 00|}
    in
    Alcotest.(check (result t_ok p_err) "Cname decode failure (rdata leftover)"
      (Error (`Leftover (77, ""))) (decode data))

  let cname_fail_partial_inner () =
    let data = Cstruct.of_hex {|58 ca 81 80 00 01  00 01 00 00 00 00 03 77
                          77 77 0a 74 61 67 65 73  73 63 68 61 75 02 64 65
                          00 00 05 00 01 c0 0c 00  05 00 01 00 00 00 aa 00
                          1e 03 77 77 77 0a 74 61  67 65 73 73 63 68 61 75
                          02 64 65 07 65 64 67 65  6b 65 79 03 6e 65 74 00|}
    in
    Alcotest.(check (result t_ok p_err) "Cname decode failure (rdata partial)"
      (Error `Partial) (decode data))

  let soa_success () =
    let data = Cstruct.of_hex
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
        Domain_name.of_strings_exn ["DANIEL.W.KNOPPS.CIV" ; "MAIL" ; "MIL" ] ;
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
    Alcotest.(check (result t_ok p_err) "soa decodes"
                (Ok res) (decode data))

  let soa_fail_partial () =
    (*  missing one byte for the SOA (minimum) *)
    let data = Cstruct.of_hex
        {___|d4 e4 85 83 00 01 00 00 00 01 00 00 01 36 02 31
             36 03 31 35 30 03 31 33 38 07 69 6e 2d 61 64 64
             72 04 61 72 70 61 00 00 0c 00 01 03 31 35 30 03
             31 33 38 07 49 4e 2d 41 44 44 52 04 41 52 50 41
             00 00 06 00 01 00 00 2a 30 00 3e 05 43 4f 4e 31
             52 04 4e 49 50 52 03 4d 49 4c 00 13 44 41 4e 49
             45 4c 2e 57 2e 4b 4e 4f 50 50 53 2e 43 49 56 04
             4d 41 49 4c c0 56 78 39 c3 d1 00 00 2a 30 00 00
             03 84 00 12 75 00 00 00 2a|___}
    in
    Alcotest.(check (result t_ok p_err) "soa fails partial"
                (Error `Partial) (decode data))

  let soa_fail_leftover_inner () =
    let data = Cstruct.of_hex
        {___|d4 e4 85 83 00 01 00 00 00 01 00 00 01 36 02 31
             36 03 31 35 30 03 31 33 38 07 69 6e 2d 61 64 64
             72 04 61 72 70 61 00 00 0c 00 01 03 31 35 30 03
             31 33 38 07 49 4e 2d 41 44 44 52 04 41 52 50 41
             00 00 06 00 01 00 00 2a 30 00 40 05 43 4f 4e 31
             52 04 4e 49 50 52 03 4d 49 4c 00 13 44 41 4e 49
             45 4c 2e 57 2e 4b 4e 4f 50 50 53 2e 43 49 56 04
             4d 41 49 4c c0 56 78 39 c3 d1 00 00 2a 30 00 00
             03 84 00 12 75 00 00 00 2a 30 00|___}
    in
    Alcotest.(check (result t_ok p_err) "soa fails (rdata leftover)"
                (Error (`Leftover (138, ""))) (decode data))

  let soa_fail_partial_inner () =
    (*  missing one byte for the SOA (minimum) *)
    let data = Cstruct.of_hex
        {___|d4 e4 85 83 00 01 00 00 00 01 00 00 01 36 02 31
             36 03 31 35 30 03 31 33 38 07 69 6e 2d 61 64 64
             72 04 61 72 70 61 00 00 0c 00 01 03 31 35 30 03
             31 33 38 07 49 4e 2d 41 44 44 52 04 41 52 50 41
             00 00 06 00 01 00 00 2a 30 00 3e 05 43 4f 4e 31
             52 04 4e 49 50 52 03 4d 49 4c 00 13 44 41 4e 49
             45 4c 2e 57 2e 4b 4e 4f 50 50 53 2e 43 49 56 04
             4d 41 49 4c c0 56 78 39 c3 d1 00 00 2a 30 00 00
             03 84 00 12 75 00 00 00 2a 30|___}
    in
    Alcotest.(check (result t_ok p_err) "soa fails (rdata partial)"
                (Error `Partial) (decode data))

  let ptr_success () =
    let data = Cstruct.of_hex {|1f 71 81 80 00 01  00 01 00 00 00 00 01 31
                          01 31 01 31 01 31 07 69  6e 2d 61 64 64 72 04 61
                          72 70 61 00 00 0c 00 01  c0 0c 00 0c 00 01 00 00
                          02 cf 00 11 03 6f 6e 65  03 6f 6e 65 03 6f 6e 65
                          03 6f 6e 65 00|}
    in
    let host = n_of_s "1.1.1.1.in-addr.arpa" in
    let header = 0x1f71, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      Name_rr_map.singleton host Ptr (719l, n_of_s "one.one.one.one" |> Domain_name.host_exn)
    in
    let q = Question.create host Ptr in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "ptr decodes"
                (Ok res) (decode data))

  let ptr_fail_partial () =
    let data = Cstruct.of_hex {|1f 71 81 80 00 01  00 01 00 00 00 00 01 31
                          01 31 01 31 01 31 07 69  6e 2d 61 64 64 72 04 61
                          72 70 61 00 00 0c 00 01  c0 0c 00 0c 00 01 00 00
                          02 cf 00 11 03 6f 6e 65  03 6f 6e 65 03 6f 6e 65
                          03 6f 6e 65|}
    in
    Alcotest.(check (result t_ok p_err) "ptr fails partial"
                (Error `Partial) (decode data))

  let ptr_fail_leftover_inner () =
    let data = Cstruct.of_hex {|1f 71 81 80 00 01  00 01 00 00 00 00 01 31
                          01 31 01 31 01 31 07 69  6e 2d 61 64 64 72 04 61
                          72 70 61 00 00 0c 00 01  c0 0c 00 0c 00 01 00 00
                          02 cf 00 12 03 6f 6e 65  03 6f 6e 65 03 6f 6e 65
                          03 6f 6e 65 00 01|}
    in
    Alcotest.(check (result t_ok p_err) "ptr fails (rdata leftover)"
                (Error (`Leftover (67, ""))) (decode data))

  let ptr_fail_partial_inner () =
    let data = Cstruct.of_hex {|1f 71 81 80 00 01  00 01 00 00 00 00 01 31
                          01 31 01 31 01 31 07 69  6e 2d 61 64 64 72 04 61
                          72 70 61 00 00 0c 00 01  c0 0c 00 0c 00 01 00 00
                          02 cf 00 11 03 6f 6e 65  03 6f 6e 65 03 6f 6e 65
                          03 6f 6e 65|}
    in
    Alcotest.(check (result t_ok p_err) "ptr fails (rdata partial)"
                (Error `Partial) (decode data))


  let mx_success () =
    let data = Cstruct.of_hex {|85 5a 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 0f 00 01 c0 0c
                          00 0f 00 01 00 00 0e 10  00 0f 00 0a 02 6d 78 05
                          72 6f 62 75 72 02 69 6f  00|}
    in
    let host = n_of_s "robur.coop" in
    let header = 0x855a, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      Name_rr_map.singleton host Mx
        (3600l, Rr_map.Mx_set.singleton { preference = 10 ; mail_exchange = n_of_s "mx.robur.io" |> Domain_name.host_exn })
    in
    let q = Question.create host Mx in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "mx decodes"
                (Ok res) (decode data))

  let mx_fail_partial () =
    let data = Cstruct.of_hex {|85 5a 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 0f 00 01 c0 0c
                          00 0f 00 01 00 00 0e 10  00 0f 00 0a 02 6d 78 05
                          72 6f 62 75 72 02 69 6f|}
    in
    Alcotest.(check (result t_ok p_err) "mx fails partial"
                (Error `Partial) (decode data))

  let mx_fail_leftover_inner () =
    let data = Cstruct.of_hex {|85 5a 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 0f 00 01 c0 0c
                          00 0f 00 01 00 00 0e 10  00 10 00 0a 02 6d 78 05
                          72 6f 62 75 72 02 69 6f  00 00|}
    in
    Alcotest.(check (result t_ok p_err) "mx fails (rdata leftover)"
                (Error (`Leftover (55, ""))) (decode data))

  let mx_fail_partial_inner () =
    let data = Cstruct.of_hex {|85 5a 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 0f 00 01 c0 0c
                          00 0f 00 01 00 00 0e 10  00 0e 00 0a 02 6d 78 05
                          72 6f 62 75 72 02 69 6f  00|}
    in
    Alcotest.(check (result t_ok p_err) "mx fails (rdata partial)"
                (Error `Partial) (decode data))

  let txt_success () =
    let data = Cstruct.of_hex {|a9 f3 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 10 00 01 c0 0c
                          00 10 00 01 00 00 0e 10  00 0f 0e 76 3d 73 70 66
                          31 20 6d 78 20 2d 61 6c  6c|}
    in
    let host = n_of_s "robur.coop" in
    let header = 0xa9f3, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      Name_rr_map.singleton host Txt
        (3600l, Rr_map.Txt_set.singleton "v=spf1 mx -all")
    in
    let q = Question.create host Txt in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "txt decodes"
                (Ok res) (decode data))

  let txt_fail_partial () =
    let data = Cstruct.of_hex {|a9 f3 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 10 00 01 c0 0c
                          00 10 00 01 00 00 0e 10  00 0f 0e 76 3d 73 70 66
                          31 20 6d 78 20 2d 61 6c  |}
    in
    Alcotest.(check (result t_ok p_err) "txt fails partial"
                (Error `Partial) (decode data))

  let txt_fail_partial_inner () =
    let data = Cstruct.of_hex {|a9 f3 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 10 00 01 c0 0c
                          00 10 00 01 00 00 0e 10  00 10 0e 76 3d 73 70 66
                          31 20 6d 78 20 2d 61 6c  6c 01|}
    in
    Alcotest.(check (result t_ok p_err) "txt fails (rdata partial)"
                (Error `Partial) (decode data))

  let aaaa_success () =
    let data = Cstruct.of_hex {|c1 a8 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 1c 00 01 c0 0c
                          00 1c 00 01 00 00 0e 10  00 10 2a 0f 7c c7 7c c7
                          7c 40 00 00 00 00 00 00  01 38|}
    in
    let host = n_of_s "robur.coop" in
    let header = 0xc1a8, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      Name_rr_map.singleton host Aaaa
        (3600l, Ipaddr.V6.Set.singleton (Ipaddr.V6.of_string_exn "2a0f:7cc7:7cc7:7c40::138"))
    in
    let q = Question.create host Aaaa in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "aaaa decodes"
                (Ok res) (decode data))

  let aaaa_fail_partial () =
    let data = Cstruct.of_hex {|c1 a8 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 1c 00 01 c0 0c
                          00 1c 00 01 00 00 0e 10  00 10 2a 0f 7c c7 7c c7
                          7c 40 00 00 00 00 00 00  01|}
    in
    Alcotest.(check (result t_ok p_err) "aaaa fails partial"
                (Error `Partial) (decode data))

  let aaaa_fail_leftover_inner () =
    let data = Cstruct.of_hex {|c1 a8 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 1c 00 01 c0 0c
                          00 1c 00 01 00 00 0e 10  00 11 2a 0f 7c c7 7c c7
                          7c 40 00 00 00 00 00 00  01 38 00|}
    in
    Alcotest.(check (result t_ok p_err) "aaaa fails (rdata leftover)"
                (Error (`Leftover (56, ""))) (decode data))

  let aaaa_fail_partial_inner () =
    let data = Cstruct.of_hex {|c1 a8 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 00 1c 00 01 c0 0c
                          00 1c 00 01 00 00 0e 10  00 08 2a 0f 7c c7 7c c7
                          7c 40 00 00 00 00 00 00  01 38|}
    in
    Alcotest.(check (result t_ok p_err) "aaaa fails (rdata partial)"
                (Error `Partial) (decode data))

  let srv_success () =
    let data = Cstruct.of_hex {|03 ad 81 80 00 01  00 03 00 00 00 00 0c 5f
                          78 6d 70 70 2d 73 65 72  76 65 72 04 5f 74 63 70
                          06 6a 61 62 62 65 72 03  63 63 63 02 64 65 00 00
                          21 00 01 c0 0c 00 21 00  01 00 00 1a 55 00 1d 00
                          0a 00 00 14 95 07 6a 61  62 62 65 72 64 06 6a 61
                          62 62 65 72 03 63 63 63  02 64 65 00 c0 0c 00 21
                          00 01 00 00 1a 55 00 22  00 1e 00 00 14 95 0c 6a
                          61 62 62 65 72 64 2d 69  70 76 36 06 6a 61 62 62
                          65 72 03 63 63 63 02 64  65 00 c0 0c 00 21 00 01
                          00 00 1a 55 00 22 00 1f  00 00 14 95 0c 6a 61 62
                          62 65 72 64 2d 69 70 76  34 06 6a 61 62 62 65 72
                          03 63 63 63 02 64 65 00|}
    in
    let host = n_of_s "_xmpp-server._tcp.jabber.ccc.de" in
    let header = 0x03ad, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let srv1 = { Srv.priority = 31 ; weight = 0 ; port = 5269 ; target = n_of_s "jabberd-ipv4.jabber.ccc.de" |> Domain_name.host_exn } in
      let srv2 = { srv1 with priority = 30 ; target = n_of_s "jabberd-ipv6.jabber.ccc.de" |> Domain_name.host_exn } in
      let srv3 = { srv1 with priority = 10 ; target = n_of_s "jabberd.jabber.ccc.de" |> Domain_name.host_exn } in
      Name_rr_map.singleton host Srv
        (6741l, Rr_map.Srv_set.(add srv1 (add srv2 (singleton srv3))))
    in
    let q = Question.create host Srv in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "srv decodes"
                (Ok res) (decode data))

  let srv_fail_partial () =
    let data = Cstruct.of_hex {|03 ad 81 80 00 01  00 03 00 00 00 00 0c 5f
                          78 6d 70 70 2d 73 65 72  76 65 72 04 5f 74 63 70
                          06 6a 61 62 62 65 72 03  63 63 63 02 64 65 00 00
                          21 00 01 c0 0c 00 21 00  01 00 00 1a 55 00 1d 00
                          0a 00 00 14 95 07 6a 61  62 62 65 72 64 06 6a 61
                          62 62 65 72 03 63 63 63  02 64 65 00 c0 0c 00 21
                          00 01 00 00 1a 55 00 22  00 1e 00 00 14 95 0c 6a
                          61 62 62 65 72 64 2d 69  70 76 36 06 6a 61 62 62
                          65 72 03 63 63 63 02 64  65 00 c0 0c 00 21 00 01
                          00 00 1a 55 00 22 00 1f  00 00 14 95 0c 6a 61 62
                          62 65 72 64 2d 69 70 76  34 06 6a 61 62 62 65 72
                          03 63 63 63 02 64 65|}
    in
    Alcotest.(check (result t_ok p_err) "srv fails partial"
                (Error `Partial) (decode data))

  let srv_fail_leftover_inner () =
    let data = Cstruct.of_hex {|03 ad 81 80 00 01  00 03 00 00 00 00 0c 5f
                          78 6d 70 70 2d 73 65 72  76 65 72 04 5f 74 63 70
                          06 6a 61 62 62 65 72 03  63 63 63 02 64 65 00 00
                          21 00 01 c0 0c 00 21 00  01 00 00 1a 55 00 1e 00
                          0a 00 00 14 95 07 6a 61  62 62 65 72 64 06 6a 61
                          62 62 65 72 03 63 63 63  02 64 65 00 00 c0 0c 00 21
                          00 01 00 00 1a 55 00 22  00 1e 00 00 14 95 0c 6a
                          61 62 62 65 72 64 2d 69  70 76 36 06 6a 61 62 62
                          65 72 03 63 63 63 02 64  65 00 c0 0c 00 21 00 01
                          00 00 1a 55 00 22 00 1f  00 00 14 95 0c 6a 61 62
                          62 65 72 64 2d 69 70 76  34 06 6a 61 62 62 65 72
                          03 63 63 63 02 64 65 00|}
    in
    Alcotest.(check (result t_ok p_err) "srv fails (rdata leftover)"
                (Error (`Leftover (90, ""))) (decode data))

  let srv_fail_partial_inner () =
    let data = Cstruct.of_hex {|03 ad 81 80 00 01  00 03 00 00 00 00 0c 5f
                          78 6d 70 70 2d 73 65 72  76 65 72 04 5f 74 63 70
                          06 6a 61 62 62 65 72 03  63 63 63 02 64 65 00 00
                          21 00 01 c0 0c 00 21 00  01 00 00 1a 55 00 1d 00
                          0a 00 00 14 95 07 6a 61  62 62 65 72 64 06 6a 61
                          62 62 65 72 03 63 63 63  02 64 65 00 c0 0c 00 21
                          00 01 00 00 1a 55 00 22  00 1e 00 00 14 95 0c 6a
                          61 62 62 65 72 64 2d 69  70 76 36 06 6a 61 62 62
                          65 72 03 63 63 63 02 64  65 00 c0 0c 00 21 00 01
                          00 00 1a 55 00 20 00 1f  00 00 14 95 0c 6a 61 62
                          62 65 72 64 2d 69 70 76  34 06 6a 61 62 62 65 72
                          03 63 63 63 02 64|}
    in
    Alcotest.(check (result t_ok p_err) "srv fails (rdata partial)"
                (Error `Partial) (decode data))

  let sshfp_success () =
    let data = Cstruct.of_hex {|98 e5 81 80 00 01  00 06 00 00 00 00 0f 72
                          65 64 70 69 6c 6c 6c 69  6e 70 72 6f 30 31 04 72
                          69 6e 67 05 6e 6c 6e 6f  67 03 6e 65 74 00 00 2c
                          00 01 c0 0c 00 2c 00 01  00 00 02 58 00 16 03 01
                          3e 46 ce cd 98 60 42 e5  06 26 57 52 31 a4 a1 55
                          cb 0e e5 ca c0 0c 00 2c  00 01 00 00 02 58 00 22
                          03 02 20 cf e8 d9 06 a4  c3 8a bb be 8f 5d 04 c2
                          ca b8 a0 0c 8a 80 3b 51  e2 52 a1 58 5f 73 90 98
                          b0 2b c0 0c 00 2c 00 01  00 00 02 58 00 22 02 02
                          8a 07 b9 7b 96 d8 26 a7  d4 d4 03 42 4b 97 a8 cc
                          db 77 10 5b 52 7b e7 d7  be 83 5d 02 fd b9 cd 58
                          c0 0c 00 2c 00 01 00 00  02 58 00 16 01 01 5f ca
                          08 7a 7c 3e be bb c8 9b  22 9a 05 af d4 50 d0 8c
                          f9 b3 c0 0c 00 2c 00 01  00 00 02 58 00 22 01 02
                          cd b4 cd af 77 34 df 34  3f d5 67 e0 ca b9 2f d6
                          ac 5f 27 54 bf ef 79 78  26 df d4 bc f9 0f 0b af
                          c0 0c 00 2c 00 01 00 00  02 58 00 16 02 01 61 3f
                          38 9a 36 cf 33 b6 7d 9b  d6 9e 38 17 85 b2 75 e1
                          01 cd|}
    in
    let host = n_of_s "redpilllinpro01.ring.nlnog.net" in
    let header = 0x98e5, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let one = { Sshfp.algorithm = Ecdsa ; typ = SHA256 ; fingerprint = Cstruct.of_hex "20CFE8D906A4C38ABBBE8F5D04C2CAB8A00C8A803B51E252A1585F739098B02B" } in
      let two = { Sshfp.algorithm = Ecdsa ; typ = SHA1 ; fingerprint = Cstruct.of_hex "3E46CECD986042E50626575231A4A155CB0EE5CA" } in
      let three = { Sshfp.algorithm = Dsa ; typ = SHA256 ; fingerprint = Cstruct.of_hex "8A07B97B96D826A7D4D403424B97A8CCDB77105B527BE7D7BE835D02FDB9CD58" } in
      let four = { Sshfp.algorithm = Dsa ; typ = SHA1 ; fingerprint = Cstruct.of_hex "613F389A36CF33B67D9BD69E381785B275E101CD" } in
      let five = { Sshfp.algorithm = Rsa ; typ = SHA256 ; fingerprint = Cstruct.of_hex "CDB4CDAF7734DF343FD567E0CAB92FD6AC5F2754BFEF797826DFD4BCF90F0BAF" } in
      let six = { Sshfp.algorithm = Rsa ; typ = SHA1 ; fingerprint = Cstruct.of_hex "5FCA087A7C3EBEBBC89B229A05AFD450D08CF9B3" } in
      Name_rr_map.singleton host Sshfp
        (600l, Rr_map.Sshfp_set.(add one (add two (add three (add four (add five (singleton six)))))))
    in
    let q = Question.create host Sshfp in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "sshfp decodes"
                (Ok res) (decode data))

  let sshfp_fail_partial () =
    let data = Cstruct.of_hex {|98 e5 81 80 00 01  00 06 00 00 00 00 0f 72
                          65 64 70 69 6c 6c 6c 69  6e 70 72 6f 30 31 04 72
                          69 6e 67 05 6e 6c 6e 6f  67 03 6e 65 74 00 00 2c
                          00 01 c0 0c 00 2c 00 01  00 00 02 58 00 16 03 01
                          3e 46 ce cd 98 60 42 e5  06 26 57 52 31 a4 a1 55
                          cb 0e e5 ca c0 0c 00 2c  00 01 00 00 02 58 00 22
                          03 02 20 cf e8 d9 06 a4  c3 8a bb be 8f 5d 04 c2
                          ca b8 a0 0c 8a 80 3b 51  e2 52 a1 58 5f 73 90 98
                          b0 2b c0 0c 00 2c 00 01  00 00 02 58 00 22 02 02
                          8a 07 b9 7b 96 d8 26 a7  d4 d4 03 42 4b 97 a8 cc
                          db 77 10 5b 52 7b e7 d7  be 83 5d 02 fd b9 cd 58
                          c0 0c 00 2c 00 01 00 00  02 58 00 16 01 01 5f ca
                          08 7a 7c 3e be bb c8 9b  22 9a 05 af d4 50 d0 8c
                          f9 b3 c0 0c 00 2c 00 01  00 00 02 58 00 22 01 02
                          cd b4 cd af 77 34 df 34  3f d5 67 e0 ca b9 2f d6
                          ac 5f 27 54 bf ef 79 78  26 df d4 bc f9 0f 0b af
                          c0 0c 00 2c 00 01 00 00  02 58 00 16 02 01 61 3f
                          38 9a 36 cf 33 b6 7d 9b  d6 9e 38 17 85 b2 75 e1
                          01|}
    in
    Alcotest.(check (result t_ok p_err) "sshfp fails partial"
                (Error `Partial) (decode data))

  let sshfp_fail_partial_inner () =
    let data = Cstruct.of_hex {|98 e5 81 80 00 01  00 06 00 00 00 00 0f 72
                          65 64 70 69 6c 6c 6c 69  6e 70 72 6f 30 31 04 72
                          69 6e 67 05 6e 6c 6e 6f  67 03 6e 65 74 00 00 2c
                          00 01 c0 0c 00 2c 00 01  00 00 02 58 00 16 03 01
                          3e 46 ce cd 98 60 42 e5  06 26 57 52 31 a4 a1 55
                          cb 0e e5 ca c0 0c 00 2c  00 01 00 00 02 58 00 22
                          03 02 20 cf e8 d9 06 a4  c3 8a bb be 8f 5d 04 c2
                          ca b8 a0 0c 8a 80 3b 51  e2 52 a1 58 5f 73 90 98
                          b0 2b c0 0c 00 2c 00 01  00 00 02 58 00 22 02 02
                          8a 07 b9 7b 96 d8 26 a7  d4 d4 03 42 4b 97 a8 cc
                          db 77 10 5b 52 7b e7 d7  be 83 5d 02 fd b9 cd 58
                          c0 0c 00 2c 00 01 00 00  02 58 00 16 01 01 5f ca
                          08 7a 7c 3e be bb c8 9b  22 9a 05 af d4 50 d0 8c
                          f9 b3 c0 0c 00 2c 00 01  00 00 02 58 00 22 01 02
                          cd b4 cd af 77 34 df 34  3f d5 67 e0 ca b9 2f d6
                          ac 5f 27 54 bf ef 79 78  26 df d4 bc f9 0f 0b af
                          c0 0c 00 2c 00 01 00 00  02 58 00 00|}
    in
    Alcotest.(check (result t_ok p_err) "sshfp fails (rdata partial)"
                (Error `Partial) (decode data))

  let tlsa_success () =
    let data = Cstruct.of_hex {|e1 bf 81 80 00 01  00 04 00 00 00 00 0c 5f
                          6c 65 74 73 65 6e 63 72  79 70 74 04 5f 74 63 70
                          05 72 6f 62 75 72 04 63  6f 6f 70 00 00 34 00 01
                          c0 0c 00 34 00 01 00 00  0e 10 05 1d 00 00 00 30
                          82 05 16 30 82 02 fe a0  03 02 01 02 02 11 00 91
                          2b 08 4a cf 0c 18 a7 53  f6 d6 2e 25 a7 5f 5a 30
                          0d 06 09 2a 86 48 86 f7  0d 01 01 0b 05 00 30 4f
                          31 0b 30 09 06 03 55 04  06 13 02 55 53 31 29 30
                          27 06 03 55 04 0a 13 20  49 6e 74 65 72 6e 65 74
                          20 53 65 63 75 72 69 74  79 20 52 65 73 65 61 72
                          63 68 20 47 72 6f 75 70  31 15 30 13 06 03 55 04
                          03 13 0c 49 53 52 47 20  52 6f 6f 74 20 58 31 30
                          1e 17 0d 32 30 30 39 30  34 30 30 30 30 30 30 5a
                          17 0d 32 35 30 39 31 35  31 36 30 30 30 30 5a 30
                          32 31 0b 30 09 06 03 55  04 06 13 02 55 53 31 16
                          30 14 06 03 55 04 0a 13  0d 4c 65 74 27 73 20 45
                          6e 63 72 79 70 74 31 0b  30 09 06 03 55 04 03 13
                          02 52 33 30 82 01 22 30  0d 06 09 2a 86 48 86 f7
                          0d 01 01 01 05 00 03 82  01 0f 00 30 82 01 0a 02
                          82 01 01 00 bb 02 15 28  cc f6 a0 94 d3 0f 12 ec
                          8d 55 92 c3 f8 82 f1 99  a6 7a 42 88 a7 5d 26 aa
                          b5 2b b9 c5 4c b1 af 8e  6b f9 75 c8 a3 d7 0f 47
                          94 14 55 35 57 8c 9e a8  a2 39 19 f5 82 3c 42 a9
                          4e 6e f5 3b c3 2e db 8d  c0 b0 5c f3 59 38 e7 ed
                          cf 69 f0 5a 0b 1b be c0  94 24 25 87 fa 37 71 b3
                          13 e7 1c ac e1 9b ef db  e4 3b 45 52 45 96 a9 c1
                          53 ce 34 c8 52 ee b5 ae  ed 8f de 60 70 e2 a5 54
                          ab b6 6d 0e 97 a5 40 34  6b 2b d3 bc 66 eb 66 34
                          7c fa 6b 8b 8f 57 29 99  f8 30 17 5d ba 72 6f fb
                          81 c5 ad d2 86 58 3d 17  c7 e7 09 bb f1 2b f7 86
                          dc c1 da 71 5d d4 46 e3  cc ad 25 c1 88 bc 60 67
                          75 66 b3 f1 18 f7 a2 5c  e6 53 ff 3a 88 b6 47 a5
                          ff 13 18 ea 98 09 77 3f  9d 53 f9 cf 01 e5 f5 a6
                          70 17 14 af 63 a4 ff 99  b3 93 9d dc 53 a7 06 fe
                          48 85 1d a1 69 ae 25 75  bb 13 cc 52 03 f5 ed 51
                          a1 8b db 15 02 03 01 00  01 a3 82 01 08 30 82 01
                          04 30 0e 06 03 55 1d 0f  01 01 ff 04 04 03 02 01
                          86 30 1d 06 03 55 1d 25  04 16 30 14 06 08 2b 06
                          01 05 05 07 03 02 06 08  2b 06 01 05 05 07 03 01
                          30 12 06 03 55 1d 13 01  01 ff 04 08 30 06 01 01
                          ff 02 01 00 30 1d 06 03  55 1d 0e 04 16 04 14 14
                          2e b3 17 b7 58 56 cb ae  50 09 40 e6 1f af 9d 8b
                          14 c2 c6 30 1f 06 03 55  1d 23 04 18 30 16 80 14
                          79 b4 59 e6 7b b6 e5 e4  01 73 80 08 88 c8 1a 58
                          f6 e9 9b 6e 30 32 06 08  2b 06 01 05 05 07 01 01
                          04 26 30 24 30 22 06 08  2b 06 01 05 05 07 30 02
                          86 16 68 74 74 70 3a 2f  2f 78 31 2e 69 2e 6c 65
                          6e 63 72 2e 6f 72 67 2f  30 27 06 03 55 1d 1f 04
                          20 30 1e 30 1c a0 1a a0  18 86 16 68 74 74 70 3a
                          2f 2f 78 31 2e 63 2e 6c  65 6e 63 72 2e 6f 72 67
                          2f 30 22 06 03 55 1d 20  04 1b 30 19 30 08 06 06
                          67 81 0c 01 02 01 30 0d  06 0b 2b 06 01 04 01 82
                          df 13 01 01 01 30 0d 06  09 2a 86 48 86 f7 0d 01
                          01 0b 05 00 03 82 02 01  00 85 ca 4e 47 3e a3 f7
                          85 44 85 bc d5 67 78 b2  98 63 ad 75 4d 1e 96 3d
                          33 65 72 54 2d 81 a0 ea  c3 ed f8 20 bf 5f cc b7
                          70 00 b7 6e 3b f6 5e 94  de e4 20 9f a6 ef 8b b2
                          03 e7 a2 b5 16 3c 91 ce  b4 ed 39 02 e7 7c 25 8a
                          47 e6 65 6e 3f 46 f4 d9  f0 ce 94 2b ee 54 ce 12
                          bc 8c 27 4b b8 c1 98 2f  a2 af cd 71 91 4a 08 b7
                          c8 b8 23 7b 04 2d 08 f9  08 57 3e 83 d9 04 33 0a
                          47 21 78 09 82 27 c3 2a  c8 9b b9 ce 5c f2 64 c8
                          c0 be 79 c0 4f 8e 6d 44  0c 5e 92 bb 2e f7 8b 10
                          e1 e8 1d 44 29 db 59 20  ed 63 b9 21 f8 12 26 94
                          93 57 a0 1d 65 04 c1 0a  22 ae 10 0d 43 97 a1 18
                          1f 7e e0 e0 86 37 b5 5a  b1 bd 30 bf 87 6e 2b 2a
                          ff 21 4e 1b 05 c3 f5 18  97 f0 5e ac c3 a5 b8 6a
                          f0 2e bc 3b 33 b9 ee 4b  de cc fc e4 af 84 0b 86
                          3f c0 55 43 36 f6 68 e1  36 17 6a 8e 99 d1 ff a5
                          40 a7 34 b7 c0 d0 63 39  35 39 75 6e f2 ba 76 c8
                          93 02 e9 a9 4b 6c 17 ce  0c 02 d9 bd 81 fb 9f b7
                          68 d4 06 65 b3 82 3d 77  53 f8 8e 79 03 ad 0a 31
                          07 75 2a 43 d8 55 97 72  c4 29 0e f7 c4 5d 4e c8
                          ae 46 84 30 d7 f2 85 5f  18 a1 79 bb e7 5e 70 8b
                          07 e1 86 93 c3 b9 8f dc  61 71 25 2a af df ed 25
                          50 52 68 8b 92 dc e5 d6  b5 e3 da 7d d0 87 6c 84
                          21 31 ae 82 f5 fb b9 ab  c8 89 17 3d e1 4c e5 38
                          0e f6 bd 2b bd 96 81 14  eb d5 db 3d 20 a7 7e 59
                          d3 e2 f8 58 f9 5b b8 48  cd fe 5c 4f 16 29 fe 1e
                          55 23 af c8 11 b0 8d ea  7c 93 90 17 2f fd ac a2
                          09 47 46 3f f0 e9 b0 b7  ff 28 4d 68 32 d6 67 5e
                          1e 69 a3 93 b8 f5 9d 8b  2f 0b d2 52 43 a6 6f 32
                          57 65 4d 32 81 df 38 53  85 5d 7e 5d 66 29 ea b8
                          dd e4 95 b5 cd b5 56 12  42 cd c4 4e c6 25 38 44
                          50 6d ec ce 00 55 18 fe  e9 49 64 d4 4e ca 97 9c
                          b4 5b c0 73 a8 ab b8 47  c2 c0 0c 00 34 00 01 00
                          00 0e 10 05 67 00 00 00  30 82 05 60 30 82 04 48
                          a0 03 02 01 02 02 10 40  01 77 21 37 d4 e9 42 b8
                          ee 76 aa 3c 64 0a b7 30  0d 06 09 2a 86 48 86 f7
                          0d 01 01 0b 05 00 30 3f  31 24 30 22 06 03 55 04
                          0a 13 1b 44 69 67 69 74  61 6c 20 53 69 67 6e 61
                          74 75 72 65 20 54 72 75  73 74 20 43 6f 2e 31 17
                          30 15 06 03 55 04 03 13  0e 44 53 54 20 52 6f 6f
                          74 20 43 41 20 58 33 30  1e 17 0d 32 31 30 31 32
                          30 31 39 31 34 30 33 5a  17 0d 32 34 30 39 33 30
                          31 38 31 34 30 33 5a 30  4f 31 0b 30 09 06 03 55
                          04 06 13 02 55 53 31 29  30 27 06 03 55 04 0a 13
                          20 49 6e 74 65 72 6e 65  74 20 53 65 63 75 72 69
                          74 79 20 52 65 73 65 61  72 63 68 20 47 72 6f 75
                          70 31 15 30 13 06 03 55  04 03 13 0c 49 53 52 47
                          20 52 6f 6f 74 20 58 31  30 82 02 22 30 0d 06 09
                          2a 86 48 86 f7 0d 01 01  01 05 00 03 82 02 0f 00
                          30 82 02 0a 02 82 02 01  00 ad e8 24 73 f4 14 37
                          f3 9b 9e 2b 57 28 1c 87  be dc b7 df 38 90 8c 6e
                          3c e6 57 a0 78 f7 75 c2  a2 fe f5 6a 6e f6 00 4f
                          28 db de 68 86 6c 44 93  b6 b1 63 fd 14 12 6b bf
                          1f d2 ea 31 9b 21 7e d1  33 3c ba 48 f5 dd 79 df
                          b3 b8 ff 12 f1 21 9a 4b  c1 8a 86 71 69 4a 66 66
                          6c 8f 7e 3c 70 bf ad 29  22 06 f3 e4 c0 e6 80 ae
                          e2 4b 8f b7 99 7e 94 03  9f d3 47 97 7c 99 48 23
                          53 e8 38 ae 4f 0a 6f 83  2e d1 49 57 8c 80 74 b6
                          da 2f d0 38 8d 7b 03 70  21 1b 75 f2 30 3c fa 8f
                          ae dd da 63 ab eb 16 4f  c2 8e 11 4b 7e cf 0b e8
                          ff b5 77 2e f4 b2 7b 4a  e0 4c 12 25 0c 70 8d 03
                          29 a0 e1 53 24 ec 13 d9  ee 19 bf 10 b3 4a 8c 3f
                          89 a3 61 51 de ac 87 07  94 f4 63 71 ec 2e e2 6f
                          5b 98 81 e1 89 5c 34 79  6c 76 ef 3b 90 62 79 e6
                          db a4 9a 2f 26 c5 d0 10  e1 0e de d9 10 8e 16 fb
                          b7 f7 a8 f7 c7 e5 02 07  98 8f 36 08 95 e7 e2 37
                          96 0d 36 75 9e fb 0e 72  b1 1d 9b bc 03 f9 49 05
                          d8 81 dd 05 b4 2a d6 41  e9 ac 01 76 95 0a 0f d8
                          df d5 bd 12 1f 35 2f 28  17 6c d2 98 c1 a8 09 64
                          77 6e 47 37 ba ce ac 59  5e 68 9d 7f 72 d6 89 c5
                          06 41 29 3e 59 3e dd 26  f5 24 c9 11 a7 5a a3 4c
                          40 1f 46 a1 99 b5 a7 3a  51 6e 86 3b 9e 7d 72 a7
                          12 05 78 59 ed 3e 51 78  15 0b 03 8f 8d d0 2f 05
                          b2 3e 7b 4a 1c 4b 73 05  12 fc c6 ea e0 50 13 7c
                          43 93 74 b3 ca 74 e7 8e  1f 01 08 d0 30 d4 5b 71
                          36 b4 07 ba c1 30 30 5c  48 b7 82 3b 98 a6 7d 60
                          8a a2 a3 29 82 cc ba bd  83 04 1b a2 83 03 41 a1
                          d6 05 f1 1b c2 b6 f0 a8  7c 86 3b 46 a8 48 2a 88
                          dc 76 9a 76 bf 1f 6a a5  3d 19 8f eb 38 f3 64 de
                          c8 2b 0d 0a 28 ff f7 db  e2 15 42 d4 22 d0 27 5d
                          e1 79 fe 18 e7 70 88 ad  4e e6 d9 8b 3a c6 dd 27
                          51 6e ff bc 64 f5 33 43  4f 02 03 01 00 01 a3 82
                          01 46 30 82 01 42 30 0f  06 03 55 1d 13 01 01 ff
                          04 05 30 03 01 01 ff 30  0e 06 03 55 1d 0f 01 01
                          ff 04 04 03 02 01 06 30  4b 06 08 2b 06 01 05 05
                          07 01 01 04 3f 30 3d 30  3b 06 08 2b 06 01 05 05
                          07 30 02 86 2f 68 74 74  70 3a 2f 2f 61 70 70 73
                          2e 69 64 65 6e 74 72 75  73 74 2e 63 6f 6d 2f 72
                          6f 6f 74 73 2f 64 73 74  72 6f 6f 74 63 61 78 33
                          2e 70 37 63 30 1f 06 03  55 1d 23 04 18 30 16 80
                          14 c4 a7 b1 a4 7b 2c 71  fa db e1 4b 90 75 ff c4
                          15 60 85 89 10 30 54 06  03 55 1d 20 04 4d 30 4b
                          30 08 06 06 67 81 0c 01  02 01 30 3f 06 0b 2b 06
                          01 04 01 82 df 13 01 01  01 30 30 30 2e 06 08 2b
                          06 01 05 05 07 02 01 16  22 68 74 74 70 3a 2f 2f
                          63 70 73 2e 72 6f 6f 74  2d 78 31 2e 6c 65 74 73
                          65 6e 63 72 79 70 74 2e  6f 72 67 30 3c 06 03 55
                          1d 1f 04 35 30 33 30 31  a0 2f a0 2d 86 2b 68 74
                          74 70 3a 2f 2f 63 72 6c  2e 69 64 65 6e 74 72 75
                          73 74 2e 63 6f 6d 2f 44  53 54 52 4f 4f 54 43 41
                          58 33 43 52 4c 2e 63 72  6c 30 1d 06 03 55 1d 0e
                          04 16 04 14 79 b4 59 e6  7b b6 e5 e4 01 73 80 08
                          88 c8 1a 58 f6 e9 9b 6e  30 0d 06 09 2a 86 48 86
                          f7 0d 01 01 0b 05 00 03  82 01 01 00 0a 73 00 6c
                          96 6e ff 0e 52 d0 ae dd  8c e7 5a 06 ad 2f a8 e3
                          8f bf c9 0a 03 15 50 c2  e5 6c 42 bb 6f 9b f4 b4
                          4f c2 44 88 08 75 cc eb  07 9b 14 62 6e 78 de ec
                          27 ba 39 5c f5 a2 a1 6e  56 94 70 10 53 b1 bb e4
                          af d0 a2 c3 2b 01 d4 96  f4 c5 20 35 33 f9 d8 61
                          36 e0 71 8d b4 b8 b5 aa  82 45 95 c0 f2 a9 23 28
                          e7 d6 a1 cb 67 08 da a0  43 2c aa 1b 93 1f c9 de
                          f5 ab 69 5d 13 f5 5b 86  58 22 ca 4d 55 e4 70 67
                          6d c2 57 c5 46 39 41 cf  8a 58 83 58 6d 99 fe 57
                          e8 36 0e f0 0e 23 aa fd  88 97 d0 e3 5c 0e 94 49
                          b5 b5 17 35 d2 2e bf 4e  85 ef 18 e0 85 92 eb 06
                          3b 6c 29 23 09 60 dc 45  02 4c 12 18 3b e9 fb 0e
                          de dc 44 f8 58 98 ae ea  bd 45 45 a1 88 5d 66 ca
                          fe 10 e9 6f 82 c8 11 42  0d fb e9 ec e3 86 00 de
                          9d 10 e3 38 fa a4 7d b1  d8 e8 49 82 84 06 9b 2b
                          e8 6b 4f 01 0c 38 77 2e  f9 dd e7 39 c0 0c 00 34
                          00 01 00 00 0e 10 06 2f  03 00 00 30 82 06 28 30
                          82 05 10 a0 03 02 01 02  02 12 04 09 7c 41 de ea
                          77 a0 69 44 37 dc 69 e0  a3 83 4f 5b 30 0d 06 09
                          2a 86 48 86 f7 0d 01 01  0b 05 00 30 32 31 0b 30
                          09 06 03 55 04 06 13 02  55 53 31 16 30 14 06 03
                          55 04 0a 13 0d 4c 65 74  27 73 20 45 6e 63 72 79
                          70 74 31 0b 30 09 06 03  55 04 03 13 02 52 33 30
                          1e 17 0d 32 31 31 31 30  37 32 33 35 33 32 32 5a
                          17 0d 32 32 30 32 30 35  32 33 35 33 32 31 5a 30
                          15 31 13 30 11 06 03 55  04 03 13 0a 72 6f 62 75
                          72 2e 63 6f 6f 70 30 82  02 22 30 0d 06 09 2a 86
                          48 86 f7 0d 01 01 01 05  00 03 82 02 0f 00 30 82
                          02 0a 02 82 02 01 00 96  91 31 29 a2 12 3b 13 13
                          a2 b7 cc 36 fc 16 a2 e7  a1 0b ad 87 dc 84 7e 26
                          b5 44 f7 0d 30 60 33 b4  12 d9 de 0f 4a df d0 08
                          5a 5d b5 9c 2b 40 38 d9  f3 46 54 e7 ba fd d1 3f
                          c7 f3 76 4d 88 5c e6 31  99 29 24 86 ed 95 99 f4
                          d4 49 2a 5a dc 4b db 62  43 c7 2e e7 1a b8 19 b3
                          1d bd e7 0b ca 51 38 82  f7 20 d3 5d c4 e4 41 34
                          38 25 91 7c d9 de 39 5e  20 1d 24 ed a7 43 76 da
                          6a 68 7b 3a 11 43 a0 ab  ad 66 4f 8a 69 c6 de 3d
                          a0 a1 6d 65 0d 80 27 6b  7f db 82 76 38 93 20 44
                          01 87 3a 2a a9 0f f4 80  7a 90 a6 d9 3b fe 74 57
                          e9 f6 41 48 0e ad 4d 69  4c 4f 80 e7 15 9b c8 95
                          8c 27 c3 8d 57 33 f5 0d  d0 ee e8 9b 00 f4 0e 66
                          d5 d4 97 96 c1 e2 96 13  f6 66 90 57 9e 9a 81 36
                          f6 4a 74 74 bf 00 bf 6a  81 ce 48 0b 83 de 90 27
                          55 80 56 74 92 44 1a da  2e 52 9d 68 07 0d 7a c3
                          97 9e 3e 6d 03 65 68 18  b0 41 27 7e cf b6 96 0a
                          4f 7f 43 79 3f 2d 40 69  0f 71 21 f8 f1 ad 65 2d
                          19 76 cd 64 6f f1 56 f6  ed 08 c3 b2 1c bf 07 22
                          65 44 70 24 f9 74 fb 57  8a 33 a8 c5 0b a5 85 9c
                          98 7a 86 71 81 0a c4 f1  f7 a7 95 f6 36 06 81 77
                          a1 0c 67 98 7a c8 a4 11  60 c7 19 ea 23 23 b7 35
                          fd d9 51 27 f7 94 21 be  80 4a e0 eb 9d 1c 6e 20
                          5f 5b 99 f1 3d 4f 89 af  ce fe c7 af 75 c7 c2 88
                          c6 e3 60 1e 11 e9 cd 02  db db d6 77 ed 2d 58 a0
                          06 5c bf 8d 29 04 03 24  fd ef 4e 31 73 b9 b6 03
                          0e ce ba 8b 54 c1 60 78  0e 70 1a 53 45 de 06 ba
                          59 fe cd 81 c4 65 e9 18  a1 c5 85 5c ac a1 b1 1a
                          5b 29 d3 11 de aa 75 b7  d8 ef 4a 92 64 36 d8 e5
                          19 86 59 50 18 ec c6 9d  df 69 b7 fa cc e5 e7 18
                          e4 27 7f e0 00 c9 e5 4d  2f f0 75 49 2a b6 60 a8
                          77 1d 8f a3 a4 f9 73 29  2c e9 85 46 2f d4 45 72
                          f6 e5 14 66 46 e3 91 02  03 01 00 01 a3 82 02 53
                          30 82 02 4f 30 0e 06 03  55 1d 0f 01 01 ff 04 04
                          03 02 05 a0 30 1d 06 03  55 1d 25 04 16 30 14 06
                          08 2b 06 01 05 05 07 03  01 06 08 2b 06 01 05 05
                          07 03 02 30 0c 06 03 55  1d 13 01 01 ff 04 02 30
                          00 30 1d 06 03 55 1d 0e  04 16 04 14 55 e7 90 35
                          fe 74 5b 6b e5 ca a8 dd  5f 53 82 86 b2 3c 09 c8
                          30 1f 06 03 55 1d 23 04  18 30 16 80 14 14 2e b3
                          17 b7 58 56 cb ae 50 09  40 e6 1f af 9d 8b 14 c2
                          c6 30 55 06 08 2b 06 01  05 05 07 01 01 04 49 30
                          47 30 21 06 08 2b 06 01  05 05 07 30 01 86 15 68
                          74 74 70 3a 2f 2f 72 33  2e 6f 2e 6c 65 6e 63 72
                          2e 6f 72 67 30 22 06 08  2b 06 01 05 05 07 30 02
                          86 16 68 74 74 70 3a 2f  2f 72 33 2e 69 2e 6c 65
                          6e 63 72 2e 6f 72 67 2f  30 23 06 03 55 1d 11 04
                          1c 30 1a 82 0c 2a 2e 72  6f 62 75 72 2e 63 6f 6f
                          70 82 0a 72 6f 62 75 72  2e 63 6f 6f 70 30 4c 06
                          03 55 1d 20 04 45 30 43  30 08 06 06 67 81 0c 01
                          02 01 30 37 06 0b 2b 06  01 04 01 82 df 13 01 01
                          01 30 28 30 26 06 08 2b  06 01 05 05 07 02 01 16
                          1a 68 74 74 70 3a 2f 2f  63 70 73 2e 6c 65 74 73
                          65 6e 63 72 79 70 74 2e  6f 72 67 30 82 01 04 06
                          0a 2b 06 01 04 01 d6 79  02 04 02 04 81 f5 04 81
                          f2 00 f0 00 76 00 41 c8  ca b1 df 22 46 4a 10 c6
                          a1 3a 09 42 87 5e 4e 31  8b 1b 03 eb eb 4b c7 68
                          f0 90 62 96 06 f6 00 00  01 7c fd 09 12 ca 00 00
                          04 03 00 47 30 45 02 21  00 e8 f7 7f 83 2d 24 c2
                          29 0f f7 bb 07 67 7a e8  8b 0a c2 c3 8b 96 ac c7
                          ad cd bf 73 84 78 29 1e  64 02 20 10 5f d7 9c 34
                          ed bc f8 28 ee 51 7a 5d  5d 2c c6 00 07 a6 1c a2
                          90 5b 63 66 23 43 18 cb  cd 3d 73 00 76 00 29 79
                          be f0 9e 39 39 21 f0 56  73 9f 63 a5 77 e5 be 57
                          7d 9c 60 0a f8 f9 4d 5d  26 5c 25 5d c7 84 00 00
                          01 7c fd 09 12 9e 00 00  04 03 00 47 30 45 02 20
                          3a 16 29 28 f0 cd b6 36  7d 14 80 a1 5b 58 95 26
                          f5 97 9c ce 94 cc 44 7b  f6 57 8b 6b de 49 a8 36
                          02 21 00 c7 30 ff 24 79  9c 05 36 62 ca 7a 6b ad
                          d6 d4 de 80 80 cb 4a ef  44 d5 6b da bb 95 87 2c
                          8e e7 bd 30 0d 06 09 2a  86 48 86 f7 0d 01 01 0b
                          05 00 03 82 01 01 00 78  ee 1c bf 34 f4 4e 3f ca
                          14 3f ba db 36 d5 1e b0  d7 fa 75 f5 c7 4e de fb
                          37 73 80 7f 9c 55 5a 15  4a 70 21 a1 42 e7 9c 24
                          34 0d c6 6b 0d 2d ec fc  3c e2 9e e7 cc 05 fb 57
                          0d b1 f8 9e 6f fb fc 95  20 18 5e 02 72 7b 8f df
                          01 e3 fe 8e a2 13 35 a5  ae ff 3d 86 fd 98 9d 33
                          7f 75 2d 16 89 61 a0 34  be 5e a9 28 83 a5 38 25
                          08 46 db e6 5c 84 62 8b  09 f4 9a 2e ad b3 24 c4
                          01 18 df d6 6d d7 cb 96  72 64 09 b6 2b 87 76 cf
                          36 43 93 1c a3 c2 fc a8  99 94 0a 0e c4 ae 2e 04
                          66 0a d2 0d 4e b3 eb 27  f0 db 14 35 25 89 d0 2b
                          a1 b4 8a 9d b2 6f 21 01  da 93 d3 b2 52 c9 2c ca
                          97 d8 20 7d a1 2f 87 95  90 cb 3c c5 56 a9 d5 9a
                          9f 46 fe fe e2 3c bf 2c  7c 53 02 72 fc a2 25 87
                          81 68 d5 eb 31 f4 12 19  e9 21 0c 9c 90 91 4d 85
                          db 50 c2 44 df a0 10 6a  53 cc 8f 80 cb ff 78 11
                          7d a2 54 5d 8d df 79 c0  0c 00 34 00 01 00 00 0e
                          10 04 97 03 ff 00 30 82  04 90 30 82 02 78 02 01
                          00 30 15 31 13 30 11 06  03 55 04 03 0c 0a 72 6f
                          62 75 72 2e 63 6f 6f 70  30 82 02 22 30 0d 06 09
                          2a 86 48 86 f7 0d 01 01  01 05 00 03 82 02 0f 00
                          30 82 02 0a 02 82 02 01  00 96 91 31 29 a2 12 3b
                          13 13 a2 b7 cc 36 fc 16  a2 e7 a1 0b ad 87 dc 84
                          7e 26 b5 44 f7 0d 30 60  33 b4 12 d9 de 0f 4a df
                          d0 08 5a 5d b5 9c 2b 40  38 d9 f3 46 54 e7 ba fd
                          d1 3f c7 f3 76 4d 88 5c  e6 31 99 29 24 86 ed 95
                          99 f4 d4 49 2a 5a dc 4b  db 62 43 c7 2e e7 1a b8
                          19 b3 1d bd e7 0b ca 51  38 82 f7 20 d3 5d c4 e4
                          41 34 38 25 91 7c d9 de  39 5e 20 1d 24 ed a7 43
                          76 da 6a 68 7b 3a 11 43  a0 ab ad 66 4f 8a 69 c6
                          de 3d a0 a1 6d 65 0d 80  27 6b 7f db 82 76 38 93
                          20 44 01 87 3a 2a a9 0f  f4 80 7a 90 a6 d9 3b fe
                          74 57 e9 f6 41 48 0e ad  4d 69 4c 4f 80 e7 15 9b
                          c8 95 8c 27 c3 8d 57 33  f5 0d d0 ee e8 9b 00 f4
                          0e 66 d5 d4 97 96 c1 e2  96 13 f6 66 90 57 9e 9a
                          81 36 f6 4a 74 74 bf 00  bf 6a 81 ce 48 0b 83 de
                          90 27 55 80 56 74 92 44  1a da 2e 52 9d 68 07 0d
                          7a c3 97 9e 3e 6d 03 65  68 18 b0 41 27 7e cf b6
                          96 0a 4f 7f 43 79 3f 2d  40 69 0f 71 21 f8 f1 ad
                          65 2d 19 76 cd 64 6f f1  56 f6 ed 08 c3 b2 1c bf
                          07 22 65 44 70 24 f9 74  fb 57 8a 33 a8 c5 0b a5
                          85 9c 98 7a 86 71 81 0a  c4 f1 f7 a7 95 f6 36 06
                          81 77 a1 0c 67 98 7a c8  a4 11 60 c7 19 ea 23 23
                          b7 35 fd d9 51 27 f7 94  21 be 80 4a e0 eb 9d 1c
                          6e 20 5f 5b 99 f1 3d 4f  89 af ce fe c7 af 75 c7
                          c2 88 c6 e3 60 1e 11 e9  cd 02 db db d6 77 ed 2d
                          58 a0 06 5c bf 8d 29 04  03 24 fd ef 4e 31 73 b9
                          b6 03 0e ce ba 8b 54 c1  60 78 0e 70 1a 53 45 de
                          06 ba 59 fe cd 81 c4 65  e9 18 a1 c5 85 5c ac a1
                          b1 1a 5b 29 d3 11 de aa  75 b7 d8 ef 4a 92 64 36
                          d8 e5 19 86 59 50 18 ec  c6 9d df 69 b7 fa cc e5
                          e7 18 e4 27 7f e0 00 c9  e5 4d 2f f0 75 49 2a b6
                          60 a8 77 1d 8f a3 a4 f9  73 29 2c e9 85 46 2f d4
                          45 72 f6 e5 14 66 46 e3  91 02 03 01 00 01 a0 36
                          30 34 06 09 2a 86 48 86  f7 0d 01 09 0e 31 27 30
                          25 30 23 06 03 55 1d 11  04 1c 30 1a 82 0a 72 6f
                          62 75 72 2e 63 6f 6f 70  82 0c 2a 2e 72 6f 62 75
                          72 2e 63 6f 6f 70 30 0d  06 09 2a 86 48 86 f7 0d
                          01 01 0b 05 00 03 82 02  01 00 61 48 df c1 bf 34
                          8f ee ef e6 f2 e6 df 2d  28 e3 38 8e 6d b2 fb 9a
                          34 30 36 20 19 81 2d 4a  e0 35 68 78 4f f2 07 7b
                          84 a1 08 d7 4a 0d a5 6c  e3 12 af 25 d7 de 7b f3
                          8f b0 15 d1 95 7d 0b bf  e3 a3 84 37 2d 48 bd 3c
                          77 f0 65 a5 e6 8f 5d 7b  d2 05 2b 1e a8 e0 71 39
                          e0 4d f4 d5 df 42 f5 5d  b2 c4 5e 4f 9f 66 86 24
                          9a 99 aa 7d f9 bc 08 48  4a 49 50 11 a0 11 a6 c5
                          00 1c c9 73 30 e9 04 b3  4e 84 65 38 56 58 bd 53
                          05 be c9 19 d0 f1 74 04  87 a9 62 89 63 fa 5f a5
                          84 98 5b 75 f1 b7 18 14  a7 78 4c a2 d1 2e a8 0f
                          a8 00 7d 03 ca bd 15 06  a9 e0 02 f7 35 33 14 ec
                          73 03 d4 36 07 09 69 26  41 61 12 6e 86 88 88 24
                          2e 81 41 35 29 b1 f5 19  ae aa 72 d1 0d 83 09 05
                          cd 0b 75 f2 33 d9 cc e8  d7 e4 ac 74 30 ec 6f 16
                          3a bb c6 2a f6 be 65 8d  61 2e ee f4 98 d7 2e 7c
                          c1 1e d5 0a c7 60 87 58  c8 01 93 41 40 54 2f b2
                          d8 51 11 bf 23 38 0f e9  63 63 0c 0f f7 1a d4 2b
                          ad 01 c2 28 86 76 d2 18  bb 10 e1 55 ca 21 15 7f
                          fe 6b 6f 63 c7 a1 e3 46  bb e8 24 2e 84 cb 9f 03
                          f3 e7 34 a5 63 56 95 3d  79 06 5e 00 c6 5d c6 89
                          6a a5 de a9 f0 2d 76 5b  7b 42 2f 08 25 94 6f 18
                          d8 0d 3d 6f b9 18 fc 19  1d 8b 56 50 ce 78 af e8
                          4d e0 4a e7 65 f4 15 09  11 b3 40 51 9d a9 b9 50
                          f3 0b e8 7d 30 ff ed 43  6a 28 1b e7 93 29 90 1f
                          9f 33 3c 95 ce 9a 8e 9f  b0 1b b8 58 4a 5e 87 b4
                          d2 c8 6d 2d 35 42 14 87  23 a3 e1 ec 44 d9 10 cf
                          0a 76 4b f8 ee 97 23 3c  f6 c8 9f 6a ee dd 72 e6
                          b9 c0 f8 1a 64 fa 68 1e  28 8e 8b 44 e7 04 7c d8
                          8e 1f c9 97 7e 62 57 39  38 cb 4b f0 88 ec c2 d0
                          bd 9d 34 25 ba fb 35 e5  36 8d b9 4b 10 70 15 52
                          a5 7d d9 96 bc 67 09 54  0d 15 c5 2a b0 0d 0b f7
                          67 c6 4a 30 2f 37 36 78  1d 34|}
    in
    let host = n_of_s "_letsencrypt._tcp.robur.coop" in
    let header = 0xe1bf, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let tlsa1 = { Tlsa.cert_usage = Domain_issued_certificate ; selector = Private ; matching_type = No_hash ; data = Cstruct.of_hex "308204903082027802010030153113301106035504030C0A726F6275722E636F6F7030820222300D06092A864886F70D01010105000382020F003082020A028202010096913129A2123B1313A2B7CC36FC16A2E7A10BAD87DC847E26B544F70D306033B412D9DE0F4ADFD0085A5DB59C2B4038D9F34654E7BAFDD13FC7F3764D885CE63199292486ED9599F4D4492A5ADC4BDB6243C72EE71AB819B31DBDE70BCA513882F720D35DC4E441343825917CD9DE395E201D24EDA74376DA6A687B3A1143A0ABAD664F8A69C6DE3DA0A16D650D80276B7FDB82763893204401873A2AA90FF4807A90A6D93BFE7457E9F641480EAD4D694C4F80E7159BC8958C27C38D5733F50DD0EEE89B00F40E66D5D49796C1E29613F66690579E9A8136F64A7474BF00BF6A81CE480B83DE90275580567492441ADA2E529D68070D7AC3979E3E6D03656818B041277ECFB6960A4F7F43793F2D40690F7121F8F1AD652D1976CD646FF156F6ED08C3B21CBF072265447024F974FB578A33A8C50BA5859C987A8671810AC4F1F7A795F636068177A10C67987AC8A41160C719EA2323B735FDD95127F79421BE804AE0EB9D1C6E205F5B99F13D4F89AFCEFEC7AF75C7C288C6E3601E11E9CD02DBDBD677ED2D58A0065CBF8D29040324FDEF4E3173B9B6030ECEBA8B54C160780E701A5345DE06BA59FECD81C465E918A1C5855CACA1B11A5B29D311DEAA75B7D8EF4A926436D8E51986595018ECC69DDF69B7FACCE5E718E4277FE000C9E54D2FF075492AB660A8771D8FA3A4F973292CE985462FD44572F6E5146646E3910203010001A036303406092A864886F70D01090E3127302530230603551D11041C301A820A726F6275722E636F6F70820C2A2E726F6275722E636F6F70300D06092A864886F70D01010B050003820201006148DFC1BF348FEEEFE6F2E6DF2D28E3388E6DB2FB9A3430362019812D4AE03568784FF2077B84A108D74A0DA56CE312AF25D7DE7BF38FB015D1957D0BBFE3A384372D48BD3C77F065A5E68F5D7BD2052B1EA8E07139E04DF4D5DF42F55DB2C45E4F9F6686249A99AA7DF9BC08484A495011A011A6C5001CC97330E904B34E8465385658BD5305BEC919D0F1740487A9628963FA5FA584985B75F1B71814A7784CA2D12EA80FA8007D03CABD1506A9E002F7353314EC7303D436070969264161126E868888242E81413529B1F519AEAA72D10D830905CD0B75F233D9CCE8D7E4AC7430EC6F163ABBC62AF6BE658D612EEEF498D72E7CC11ED50AC7608758C801934140542FB2D85111BF23380FE963630C0FF71AD42BAD01C2288676D218BB10E155CA21157FFE6B6F63C7A1E346BBE8242E84CB9F03F3E734A56356953D79065E00C65DC6896AA5DEA9F02D765B7B422F0825946F18D80D3D6FB918FC191D8B5650CE78AFE84DE04AE765F4150911B340519DA9B950F30BE87D30FFED436A281BE79329901F9F333C95CE9A8E9FB01BB8584A5E87B4D2C86D2D3542148723A3E1EC44D910CF0A764BF8EE97233CF6C89F6AEEDD72E6B9C0F81A64FA681E288E8B44E7047CD88E1FC9977E62573938CB4BF088ECC2D0BD9D3425BAFB35E5368DB94B10701552A57DD996BC6709540D15C52AB00D0BF767C64A302F3736781D34" } in
      let tlsa2 = { Tlsa.cert_usage = Domain_issued_certificate ; selector = Full_certificate ; matching_type = No_hash ; data = Cstruct.of_hex "3082062830820510A003020102021204097C41DEEA77A0694437DC69E0A3834F5B300D06092A864886F70D01010B05003032310B300906035504061302555331163014060355040A130D4C6574277320456E6372797074310B3009060355040313025233301E170D3231313130373233353332325A170D3232303230353233353332315A3015311330110603550403130A726F6275722E636F6F7030820222300D06092A864886F70D01010105000382020F003082020A028202010096913129A2123B1313A2B7CC36FC16A2E7A10BAD87DC847E26B544F70D306033B412D9DE0F4ADFD0085A5DB59C2B4038D9F34654E7BAFDD13FC7F3764D885CE63199292486ED9599F4D4492A5ADC4BDB6243C72EE71AB819B31DBDE70BCA513882F720D35DC4E441343825917CD9DE395E201D24EDA74376DA6A687B3A1143A0ABAD664F8A69C6DE3DA0A16D650D80276B7FDB82763893204401873A2AA90FF4807A90A6D93BFE7457E9F641480EAD4D694C4F80E7159BC8958C27C38D5733F50DD0EEE89B00F40E66D5D49796C1E29613F66690579E9A8136F64A7474BF00BF6A81CE480B83DE90275580567492441ADA2E529D68070D7AC3979E3E6D03656818B041277ECFB6960A4F7F43793F2D40690F7121F8F1AD652D1976CD646FF156F6ED08C3B21CBF072265447024F974FB578A33A8C50BA5859C987A8671810AC4F1F7A795F636068177A10C67987AC8A41160C719EA2323B735FDD95127F79421BE804AE0EB9D1C6E205F5B99F13D4F89AFCEFEC7AF75C7C288C6E3601E11E9CD02DBDBD677ED2D58A0065CBF8D29040324FDEF4E3173B9B6030ECEBA8B54C160780E701A5345DE06BA59FECD81C465E918A1C5855CACA1B11A5B29D311DEAA75B7D8EF4A926436D8E51986595018ECC69DDF69B7FACCE5E718E4277FE000C9E54D2FF075492AB660A8771D8FA3A4F973292CE985462FD44572F6E5146646E3910203010001A38202533082024F300E0603551D0F0101FF0404030205A0301D0603551D250416301406082B0601050507030106082B06010505070302300C0603551D130101FF04023000301D0603551D0E0416041455E79035FE745B6BE5CAA8DD5F538286B23C09C8301F0603551D23041830168014142EB317B75856CBAE500940E61FAF9D8B14C2C6305506082B0601050507010104493047302106082B060105050730018615687474703A2F2F72332E6F2E6C656E63722E6F7267302206082B060105050730028616687474703A2F2F72332E692E6C656E63722E6F72672F30230603551D11041C301A820C2A2E726F6275722E636F6F70820A726F6275722E636F6F70304C0603551D20044530433008060667810C0102013037060B2B0601040182DF130101013028302606082B06010505070201161A687474703A2F2F6370732E6C657473656E63727970742E6F726730820104060A2B06010401D6790204020481F50481F200F000760041C8CAB1DF22464A10C6A13A0942875E4E318B1B03EBEB4BC768F090629606F60000017CFD0912CA0000040300473045022100E8F77F832D24C2290FF7BB07677AE88B0AC2C38B96ACC7ADCDBF738478291E640220105FD79C34EDBCF828EE517A5D5D2CC60007A61CA2905B6366234318CBCD3D730076002979BEF09E393921F056739F63A577E5BE577D9C600AF8F94D5D265C255DC7840000017CFD09129E000004030047304502203A162928F0CDB6367D1480A15B589526F5979CCE94CC447BF6578B6BDE49A836022100C730FF24799C053662CA7A6BADD6D4DE8080CB4AEF44D56BDABB95872C8EE7BD300D06092A864886F70D01010B0500038201010078EE1CBF34F44E3FCA143FBADB36D51EB0D7FA75F5C74EDEFB3773807F9C555A154A7021A142E79C24340DC66B0D2DECFC3CE29EE7CC05FB570DB1F89E6FFBFC9520185E02727B8FDF01E3FE8EA21335A5AEFF3D86FD989D337F752D168961A034BE5EA92883A538250846DBE65C84628B09F49A2EADB324C40118DFD66DD7CB96726409B62B8776CF3643931CA3C2FCA899940A0EC4AE2E04660AD20D4EB3EB27F0DB14352589D02BA1B48A9DB26F2101DA93D3B252C92CCA97D8207DA12F879590CB3CC556A9D59A9F46FEFEE23CBF2C7C530272FCA225878168D5EB31F41219E9210C9C90914D85DB50C244DFA0106A53CC8F80CBFF78117DA2545D8DDF79" } in
      let tlsa3 = { Tlsa.cert_usage =CA_constraint ; selector = Full_certificate; matching_type = No_hash ; data = Cstruct.of_hex "3082056030820448A00302010202104001772137D4E942B8EE76AA3C640AB7300D06092A864886F70D01010B0500303F31243022060355040A131B4469676974616C205369676E617475726520547275737420436F2E311730150603550403130E44535420526F6F74204341205833301E170D3231303132303139313430335A170D3234303933303138313430335A304F310B300906035504061302555331293027060355040A1320496E7465726E65742053656375726974792052657365617263682047726F7570311530130603550403130C4953524720526F6F7420583130820222300D06092A864886F70D01010105000382020F003082020A0282020100ADE82473F41437F39B9E2B57281C87BEDCB7DF38908C6E3CE657A078F775C2A2FEF56A6EF6004F28DBDE68866C4493B6B163FD14126BBF1FD2EA319B217ED1333CBA48F5DD79DFB3B8FF12F1219A4BC18A8671694A66666C8F7E3C70BFAD292206F3E4C0E680AEE24B8FB7997E94039FD347977C99482353E838AE4F0A6F832ED149578C8074B6DA2FD0388D7B0370211B75F2303CFA8FAEDDDA63ABEB164FC28E114B7ECF0BE8FFB5772EF4B27B4AE04C12250C708D0329A0E15324EC13D9EE19BF10B34A8C3F89A36151DEAC870794F46371EC2EE26F5B9881E1895C34796C76EF3B906279E6DBA49A2F26C5D010E10EDED9108E16FBB7F7A8F7C7E50207988F360895E7E237960D36759EFB0E72B11D9BBC03F94905D881DD05B42AD641E9AC0176950A0FD8DFD5BD121F352F28176CD298C1A80964776E4737BACEAC595E689D7F72D689C50641293E593EDD26F524C911A75AA34C401F46A199B5A73A516E863B9E7D72A712057859ED3E5178150B038F8DD02F05B23E7B4A1C4B730512FCC6EAE050137C439374B3CA74E78E1F0108D030D45B7136B407BAC130305C48B7823B98A67D608AA2A32982CCBABD83041BA2830341A1D605F11BC2B6F0A87C863B46A8482A88DC769A76BF1F6AA53D198FEB38F364DEC82B0D0A28FFF7DBE21542D422D0275DE179FE18E77088AD4EE6D98B3AC6DD27516EFFBC64F533434F0203010001A382014630820142300F0603551D130101FF040530030101FF300E0603551D0F0101FF040403020106304B06082B06010505070101043F303D303B06082B06010505073002862F687474703A2F2F617070732E6964656E74727573742E636F6D2F726F6F74732F647374726F6F74636178332E703763301F0603551D23041830168014C4A7B1A47B2C71FADBE14B9075FFC4156085891030540603551D20044D304B3008060667810C010201303F060B2B0601040182DF130101013030302E06082B060105050702011622687474703A2F2F6370732E726F6F742D78312E6C657473656E63727970742E6F7267303C0603551D1F043530333031A02FA02D862B687474703A2F2F63726C2E6964656E74727573742E636F6D2F445354524F4F544341583343524C2E63726C301D0603551D0E0416041479B459E67BB6E5E40173800888C81A58F6E99B6E300D06092A864886F70D01010B050003820101000A73006C966EFF0E52D0AEDD8CE75A06AD2FA8E38FBFC90A031550C2E56C42BB6F9BF4B44FC244880875CCEB079B14626E78DEEC27BA395CF5A2A16E5694701053B1BBE4AFD0A2C32B01D496F4C5203533F9D86136E0718DB4B8B5AA824595C0F2A92328E7D6A1CB6708DAA0432CAA1B931FC9DEF5AB695D13F55B865822CA4D55E470676DC257C5463941CF8A5883586D99FE57E8360EF00E23AAFD8897D0E35C0E9449B5B51735D22EBF4E85EF18E08592EB063B6C29230960DC45024C12183BE9FB0EDEDC44F85898AEEABD4545A1885D66CAFE10E96F82C811420DFBE9ECE38600DE9D10E338FAA47DB1D8E8498284069B2BE86B4F010C38772EF9DDE739" } in
      let tlsa4 = { Tlsa.cert_usage = CA_constraint ; selector = Full_certificate ; matching_type = No_hash ; data = Cstruct.of_hex "30820516308202FEA003020102021100912B084ACF0C18A753F6D62E25A75F5A300D06092A864886F70D01010B0500304F310B300906035504061302555331293027060355040A1320496E7465726E65742053656375726974792052657365617263682047726F7570311530130603550403130C4953524720526F6F74205831301E170D3230303930343030303030305A170D3235303931353136303030305A3032310B300906035504061302555331163014060355040A130D4C6574277320456E6372797074310B300906035504031302523330820122300D06092A864886F70D01010105000382010F003082010A0282010100BB021528CCF6A094D30F12EC8D5592C3F882F199A67A4288A75D26AAB52BB9C54CB1AF8E6BF975C8A3D70F4794145535578C9EA8A23919F5823C42A94E6EF53BC32EDB8DC0B05CF35938E7EDCF69F05A0B1BBEC094242587FA3771B313E71CACE19BEFDBE43B45524596A9C153CE34C852EEB5AEED8FDE6070E2A554ABB66D0E97A540346B2BD3BC66EB66347CFA6B8B8F572999F830175DBA726FFB81C5ADD286583D17C7E709BBF12BF786DCC1DA715DD446E3CCAD25C188BC60677566B3F118F7A25CE653FF3A88B647A5FF1318EA9809773F9D53F9CF01E5F5A6701714AF63A4FF99B3939DDC53A706FE48851DA169AE2575BB13CC5203F5ED51A18BDB150203010001A382010830820104300E0603551D0F0101FF040403020186301D0603551D250416301406082B0601050507030206082B0601050507030130120603551D130101FF040830060101FF020100301D0603551D0E04160414142EB317B75856CBAE500940E61FAF9D8B14C2C6301F0603551D2304183016801479B459E67BB6E5E40173800888C81A58F6E99B6E303206082B0601050507010104263024302206082B060105050730028616687474703A2F2F78312E692E6C656E63722E6F72672F30270603551D1F0420301E301CA01AA0188616687474703A2F2F78312E632E6C656E63722E6F72672F30220603551D20041B30193008060667810C010201300D060B2B0601040182DF13010101300D06092A864886F70D01010B0500038202010085CA4E473EA3F7854485BCD56778B29863AD754D1E963D336572542D81A0EAC3EDF820BF5FCCB77000B76E3BF65E94DEE4209FA6EF8BB203E7A2B5163C91CEB4ED3902E77C258A47E6656E3F46F4D9F0CE942BEE54CE12BC8C274BB8C1982FA2AFCD71914A08B7C8B8237B042D08F908573E83D904330A472178098227C32AC89BB9CE5CF264C8C0BE79C04F8E6D440C5E92BB2EF78B10E1E81D4429DB5920ED63B921F81226949357A01D6504C10A22AE100D4397A1181F7EE0E08637B55AB1BD30BF876E2B2AFF214E1B05C3F51897F05EACC3A5B86AF02EBC3B33B9EE4BDECCFCE4AF840B863FC0554336F668E136176A8E99D1FFA540A734B7C0D063393539756EF2BA76C89302E9A94B6C17CE0C02D9BD81FB9FB768D40665B3823D7753F88E7903AD0A3107752A43D8559772C4290EF7C45D4EC8AE468430D7F2855F18A179BBE75E708B07E18693C3B98FDC6171252AAFDFED255052688B92DCE5D6B5E3DA7DD0876C842131AE82F5FBB9ABC889173DE14CE5380EF6BD2BBD968114EBD5DB3D20A77E59D3E2F858F95BB848CDFE5C4F1629FE1E5523AFC811B08DEA7C9390172FFDACA20947463FF0E9B0B7FF284D6832D6675E1E69A393B8F59D8B2F0BD25243A66F3257654D3281DF3853855D7E5D6629EAB8DDE495B5CDB5561242CDC44EC6253844506DECCE005518FEE94964D44ECA979CB45BC073A8ABB847C2" } in
      Name_rr_map.singleton host Tlsa
        (3600l, Rr_map.Tlsa_set.(add tlsa1 (add tlsa2 (add tlsa3 (singleton tlsa4)))))
    in
    let q = Question.create host Tlsa in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "tlsa decodes"
                (Ok res) (decode data))

  let caa_success () =
    let data = Cstruct.of_hex {|2b 9b 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 01 01 00 01 c0 0c
                          01 01 00 01 00 00 0e 10  00 16 80 05 69 73 73 75
                          65 6c 65 74 73 65 6e 63  72 79 70 74 2e 6f 72 67|}
    in
    let host = n_of_s "robur.coop" in
    let header = 0x2b9b, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let one = { Caa.critical = true ; tag = "issue" ; value = [ "letsencrypt.org" ] } in
      Name_rr_map.singleton host Caa
        (3600l, Rr_map.Caa_set.singleton one)
    in
    let q = Question.create host Caa in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "caa decodes"
                (Ok res) (decode data))

  let caa_fail_partial () =
    let data = Cstruct.of_hex {|2b 9b 81 80 00 01  00 01 00 00 00 00 05 72
                          6f 62 75 72 04 63 6f 6f  70 00 01 01 00 01 c0 0c
                          01 01 00 01 00 00 0e 10  00 16 80 05 69 73 73 75
                          65 6c 65 74 73 65 6e 63  72 79 70 74 2e 6f 72|}
    in
    Alcotest.(check (result t_ok p_err) "caa fails partial"
                (Error `Partial) (decode data))


  let dnskey_success () =
    let data = Cstruct.of_hex {| 58 1d 81 80 00 01  00 03 00 00 00 00 04 63
                          6f 6f 70 00 00 30 00 01  c0 0c 00 30 00 01 00 00
                          0d bd 00 88 01 00 03 08  03 01 00 01 b0 16 c5 b1
                          c0 a1 ea c9 9d 1c ae 3d  38 32 21 e4 c3 77 5c 0b
                          fa e2 c0 cd ed c5 6d 37  0e af a0 53 5c 28 6b d3
                          d5 82 54 7f db 42 5f 03  d3 11 e7 76 70 27 4b 22
                          03 69 30 25 a4 8f d6 ea  9d 2c db ac 7d ce c2 a8
                          fc 86 85 29 1f ab f9 ce  c0 b3 ee 30 d5 22 61 44
                          01 24 ff 6d 87 4f 9e d4  75 88 94 b0 f7 52 59 f5
                          dd 79 3e dd 64 ea e7 0c  be 16 37 f8 75 48 0d 47
                          8c 8f 0f d0 9f c0 18 b1  55 6e 41 55 c0 0c 00 30
                          00 01 00 00 0d bd 01 08  01 01 03 08 03 01 00 01
                          ca cf de 90 a8 08 b4 0f  11 ee c1 ca 55 13 43 65
                          97 a6 db d8 03 6a fa 1a  61 09 f4 aa 2a 0f 18 77
                          fd 59 35 4a dc b8 e2 bd  c6 b4 80 86 83 f2 5c cb
                          5b fc 5f ce 4b 60 0c 6d  c4 1c fe 0e 64 cb 30 78
                          5b f0 cb 53 bf 5f 3b a3  bc e1 37 6b 9d eb b8 3d
                          29 66 47 9c 6e 8d 1b a6  76 a9 20 97 6a c9 f8 bf
                          24 e2 50 69 24 03 a1 5f  c2 e4 45 29 72 3a 20 24
                          6e 76 df f3 97 88 5b 74  32 f2 de df e6 ef a3 3e
                          1e ab d2 e2 74 dc 6d ac  b8 7a b9 d2 7d 63 5d f7
                          2c 83 be 26 6f 67 50 2e  47 e2 94 98 e6 0c bf cf
                          ee 1a 98 1c 0f 0c 1a 2e  1f 79 45 a8 f5 7b bb a4
                          ab 6a da fc e4 f4 c6 48  36 81 a0 7d 7a 1b 11 80
                          ab f1 0d 22 54 0f 13 cd  c8 41 e3 3a c1 18 2d c2
                          28 9b b0 38 1b 5a 1a ed  5d 16 93 57 b7 88 02 f1
                          da 7f 4d 44 56 fa 7a 3b  7b 3e f9 dd 1f ec df c3
                          df f4 5d 0d b5 03 e3 f5  84 db 42 fe 32 e3 ae 85
                          c0 0c 00 30 00 01 00 00  0d bd 00 88 01 00 03 08
                          03 01 00 01 dd 67 34 bc  81 f1 b2 92 5c a6 af a2
                          99 93 d9 48 94 8b cc 0f  c4 81 7c 8d f2 85 23 68
                          27 fd 2f 9f 37 fb 92 b8  34 0b cc d3 c8 36 e7 14
                          d7 17 7f 6d 78 0c f9 90  43 59 f8 7f 3d 90 f0 a6
                          aa 30 1b 5b 84 61 1b 3c  bf d4 ee ba 21 d2 45 a6
                          d6 a5 77 fe f7 e2 cd 87  a8 7b da 6e c5 7c e3 86
                          87 a4 ae 6c f4 1b ac 0e  8e 0a ca fb 77 3d 76 b4
                          de 2d 10 09 cd 92 95 24  0d 7d 2f 0a dd 02 4b ce
                          9f 23 f8 0d|}
    in
    let host = n_of_s "coop" in
    let header = 0x581d, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and keys =
      let key1 =
        let b64 = "AwEAAcrP3pCoCLQPEe7BylUTQ2WXptvYA2r6GmEJ9KoqDxh3/Vk1Sty44r3GtICGg/Jcy1v8X85LYAxtxBz+DmTLMHhb8MtTv187o7zhN2ud67g9KWZHnG6NG6Z2qSCXasn4vyTiUGkkA6FfwuRFKXI6ICRudt/zl4hbdDLy3t/m76M+HqvS4nTcbay4ernSfWNd9yyDviZvZ1AuR+KUmOYMv8/uGpgcDwwaLh95Raj1e7ukq2ra/OT0xkg2gaB9ehsRgKvxDSJUDxPNyEHjOsEYLcIom7A4G1oa7V0Wk1e3iALx2n9NRFb6ejt7PvndH+zfw9/0XQ21A+P1hNtC/jLjroU=" in
        Dnskey.({
          flags = F.add `Zone (F.singleton `Secure_entry_point) ;
          algorithm = RSA_SHA256 ;
          key = Cstruct.of_string (Base64.decode_exn b64)})
      and key2 =
        let b64 = "AwEAAbAWxbHAoerJnRyuPTgyIeTDd1wL+uLAze3FbTcOr6BTXChr09WCVH/bQl8D0xHndnAnSyIDaTAlpI/W6p0s26x9zsKo/IaFKR+r+c7As+4w1SJhRAEk/22HT57UdYiUsPdSWfXdeT7dZOrnDL4WN/h1SA1HjI8P0J/AGLFVbkFV" in
        Dnskey.({
          flags = F.singleton `Zone ;
          algorithm = RSA_SHA256 ;
          key = Cstruct.of_string (Base64.decode_exn b64)})
      and key3 =
        let b64 = "AwEAAd1nNLyB8bKSXKavopmT2UiUi8wPxIF8jfKFI2gn/S+fN/uSuDQLzNPINucU1xd/bXgM+ZBDWfh/PZDwpqowG1uEYRs8v9TuuiHSRabWpXf+9+LNh6h72m7FfOOGh6SubPQbrA6OCsr7dz12tN4tEAnNkpUkDX0vCt0CS86fI/gN" in
        Dnskey.({
          flags = F.singleton `Zone ;
          algorithm = RSA_SHA256 ;
          key = Cstruct.of_string (Base64.decode_exn b64)})
      in
      Name_rr_map.singleton host Dnskey
        (3517l, Rr_map.Dnskey_set.(add key3 (add key2 (singleton key1))))
    in
    let q = Question.create host Dnskey in
    let res = create header q (`Answer (keys, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "dnskey decodes"
                (Ok res) (decode data))

  let ds_success () =
    let data = Cstruct.of_hex {|04 1f 81 80 00 01  00 02 00 00 00 00 04 63
                          6f 6f 70 00 00 2b 00 01  c0 0c 00 2b 00 01 00 01
                          31 c3 00 18 26 e9 08 01  f9 37 0f ae af 0b 84 64
                          b7 c8 80 21 36 a0 3f c9  6d 8f f2 00 c0 0c 00 2b
                          00 01 00 01 31 c3 00 24  26 e9 08 02 74 64 84 9b
                          6c 08 38 40 30 d1 35 d1  56 55 96 91 db 98 80 4c
                          e1 da b9 89 14 47 ca 45  b5 94 ef 36|}
    in
    let host = n_of_s "coop" in
    let header = 0x041f, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let ds1 = Ds.{ key_tag = 9961 ; algorithm = Dnskey.RSA_SHA256 ; digest_type = SHA256 ; digest = Cstruct.of_hex "7464849B6C08384030D135D156559691DB98804CE1DAB9891447CA45B594EF36"}
      and ds2 = Ds.{ key_tag = 9961 ; algorithm = Dnskey.RSA_SHA256 ; digest_type = SHA1 ; digest = Cstruct.of_hex "F9370FAEAF0B8464B7C8802136A03FC96D8FF200" }
      in
      Name_rr_map.singleton host Ds
        (78275l, Rr_map.Ds_set.(add ds2 (singleton ds1)))
    in
    let q = Question.create host Ds in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "ds decodes"
                (Ok res) (decode data))

  let rrsig_success () =
    let data = Cstruct.of_hex {|6d ec 81 80 00 01  00 03 00 00 00 01 0a 63
                              6c 6f 75 64 66 6c 61 72  65 03 63 6f 6d 00 00 01
                              00 01 c0 0c 00 01 00 01  00 00 01 29 00 04 68 10
                              85 e5 c0 0c 00 01 00 01  00 00 01 29 00 04 68 10
                              84 e5 c0 0c 00 2e 00 01  00 00 01 29 00 62 00 01
                              0d 02 00 00 01 2c 61 ce  06 6f 61 cb 47 4f 86 c9
                              0a 63 6c 6f 75 64 66 6c  61 72 65 03 63 6f 6d 00
                              7c 4a c3 54 38 74 f0 0f  f4 db ed 58 7f e4 aa aa
                              0b bf bd 83 2a cc c1 f0  42 55 44 7b ad 43 9e 83
                              ba 58 0c 38 a3 7c 1a e7  13 fe bf 8e dd 39 6b 6d
                              c3 c2 06 9e 82 87 8e db  5c fa 88 82 b9 ee 5a c6
                              00 00 29 20 00 00 00 80  00 00 00|}
    in
    let host = n_of_s "cloudflare.com" in
    let header = 0x6DEC, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let of_d_t d t = Option.get (Ptime.of_date_time (d, t)) in
      let a = 297l, Ipaddr.V4.Set.(add (Ipaddr.V4.of_string_exn "104.16.133.229") (singleton (Ipaddr.V4.of_string_exn "104.16.132.229")))
      and rrsig =
        297l,
        Rr_map.Rrsig_set.singleton
          Rrsig.{ type_covered = 1 ; algorithm = Dnskey.P256_SHA256 ; label_count = 2 ; original_ttl = 300l ;
                  signature_expiration = of_d_t (2021, 12, 30) ((19, 20, 15), 0) ;
                  signature_inception = of_d_t (2021, 12, 28) ((17, 20, 15), 0) ;
                  key_tag = 34505 ;
                  signer_name = n_of_s "cloudflare.com" ;
                  signature = Cstruct.of_string (Base64.decode_exn "fErDVDh08A/02+1Yf+Sqqgu/vYMqzMHwQlVEe61DnoO6WAw4o3wa5xP+v47dOWttw8IGnoKHjttc+oiCue5axg==")
                }
      in
      Domain_name.Map.singleton host
        Rr_map.(add A a (singleton Rrsig rrsig))
    in
    let q = Question.create host A in
    let edns = Edns.create ~dnssec_ok:true ~payload_size:8192 () in
    let res = create ~edns header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "rrsig decodes"
                (Ok res) (decode data))

  let nsec_success () =
    let data = Cstruct.of_hex {|38 51 81 80 00 01  00 01 00 00 00 00 06 66
                          6f 6f 6f 6f 6f 0a 63 6c  6f 75 64 66 6c 61 72 65
                          03 63 6f 6d 00 00 2f 00  01 c0 0c 00 2f 00 01 00
                          00 01 2c 00 21 01 00 06  66 6f 6f 6f 6f 6f 0a 63
                          6c 6f 75 64 66 6c 61 72  65 03 63 6f 6d 00 00 06
                          00 00 00 00 00 03|}
    in
    let host = n_of_s "fooooo.cloudflare.com" in
    let header = 0x3851, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let nsec = Nsec.{ next_domain = n_of_s "\000.fooooo.cloudflare.com" ; types = Bit_map.(add 47 (singleton 46)) } in
      Name_rr_map.singleton host Nsec
        (300l, nsec)
    in
    let q = Question.create host Nsec in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "nsec decodes"
                (Ok res) (decode data));
    let encoded, _ = Packet.encode `Udp res in
    Alcotest.(check bool "nsec encodes" true (Cstruct.equal data encoded))

  let nsec_success2 () =
    let data = Cstruct.of_hex {|38 51 81 80 00 01  00 01 00 00 00 00 06 66
                          6f 6f 6f 6f 6f 0a 63 6c  6f 75 64 66 6c 61 72 65
                          03 63 6f 6d 00 00 2f 00  01 c0 0c 00 2f 00 01 00
                          00 01 2c 00 22 01 00 06  66 6f 6f 6f 6f 6f 0a 63
                          6c 6f 75 64 66 6c 61 72  65 03 63 6f 6d 00 00 07
                          22 00 00 00 00 03 80|}
    in
    let host = n_of_s "fooooo.cloudflare.com" in
    let header = 0x3851, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let types = Bit_map.of_list [ 2 ; 6 ; 46; 47; 48 ] in
      let nsec = Nsec.{ next_domain = n_of_s "\000.fooooo.cloudflare.com" ; types } in
      Name_rr_map.singleton host Nsec
        (300l, nsec)
    in
    let q = Question.create host Nsec in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    Alcotest.(check (result t_ok p_err) "nsec decodes"
                (Ok res) (decode data));
    let encoded, _ = Packet.encode `Udp res in
    Alcotest.(check bool "nsec encodes" true (Cstruct.equal data encoded))

  let nsec3_success () =
    let data = Cstruct.of_hex {|8f ab 81 83 00 01  00 00 00 06 00 01 03 61
                              61 61 05 73 73 68 66 70  03 6e 65 74 00 00 2b 00
                              01 c0 10 00 06 00 01 00  00 00 85 00 3b 03 6e 73
                              30 08 77 65 62 65 72 64  6e 73 02 64 65 00 09 77
                              65 62 6d 61 73 74 65 72  09 77 65 62 65 72 6e 65
                              74 7a c0 16 78 76 7b b8  00 00 0e 10 00 00 03 84
                              00 24 ea 00 00 00 00 b4  c0 10 00 2e 00 01 00 00
                              00 85 01 1d 00 06 0a 02  00 01 51 80 61 ef 45 ad
                              61 c7 aa 9d 79 4f 05 73  73 68 66 70 03 6e 65 74
                              00 35 dd 03 c0 75 e9 f0  8f a6 23 90 1a 4d 5c e1
                              52 2b ad 02 d3 d1 a5 43  52 8d f3 76 08 38 5e ec
                              23 b0 85 80 71 02 89 13  d4 7d 24 0e 29 39 64 51
                              2f f0 e0 30 c1 69 c6 0e  e0 fc 7e e5 08 b1 19 7b
                              b2 7e ff 28 0e 7c 45 cf  88 25 87 25 34 de cb 49
                              c9 58 39 c7 c7 80 cc f1  af 73 2d 6b d6 07 41 02
                              88 34 b5 89 b5 c6 99 f8  30 e0 b2 70 ca fb 43 c8
                              71 8e 8e d9 b6 0e 0d 0a  48 ef 89 a6 77 57 3c 08
                              e4 47 ec 40 70 40 95 0f  0d 4c e0 76 5d cb 36 48
                              02 82 5b 93 5a 84 c3 d6  c9 25 8e 22 99 11 5d 2c
                              03 72 f8 32 62 a0 e2 df  50 89 4a cf ac b9 d9 44
                              24 bd 80 5b cb b7 94 b0  40 e7 c3 65 ae 46 b9 00
                              d4 14 83 c8 73 1c 3a 5e  94 29 a5 5f 13 73 f9 ba
                              7c 7b 4e 18 82 a7 ea 12  0a bf e1 28 7d 67 24 70
                              76 af e8 f5 01 61 a7 f7  ba 11 f7 45 1e 49 be 19
                              63 2c 19 df 8a 83 57 ac  9d df 94 b7 5d 5d 0f 49
                              3c 20 31 44 53 4a 53 38  39 4c 4a 31 38 46 4a 56
                              4a 47 45 43 30 33 35 35  35 48 33 50 50 47 31 30
                              42 4c c0 10 00 32 00 01  00 00 00 85 00 36 01 00
                              00 14 10 7b 1a 90 a9 16  19 7e 45 d0 77 2a bc b6
                              44 11 56 14 88 02 6c d0  ec 9b ca b3 15 02 81 1b
                              fb 8e 8c 8d 35 6d d9 78  00 07 62 00 80 08 00 02
                              90 01 01 40 c1 8f 00 2e  00 01 00 00 00 85 01 1d
                              00 32 0a 03 00 00 00 b4  61 e0 10 7d 61 b8 79 58
                              79 4f 05 73 73 68 66 70  03 6e 65 74 00 47 c4 15
                              e8 2f 51 a8 d2 15 39 9f  09 fb 8e 8e 3d 69 01 dc
                              37 6f 7b 6c ae 5e 77 a0  c8 b6 72 36 73 63 e7 bb
                              c6 41 64 f1 14 15 6d 9b  79 a3 fc 12 65 5b ac b6
                              f3 49 7a 1b 83 09 67 ac  f4 f7 dc 66 dc c7 27 98
                              41 8b 2e 1f e9 58 15 01  49 b2 91 b1 fc 1d 19 e2
                              15 6c 3e ce 2b 2e ad 68  d9 f8 7d 7a 17 60 db 67
                              03 50 e8 83 d8 1b 59 f6  ee 9e 54 0e 98 5e f6 d8
                              3b e5 f6 a6 a2 b2 73 ef  f8 c2 4e e8 17 27 25 95
                              59 3f 2a a2 0c 79 74 6d  e4 12 34 83 29 f7 9e d6
                              ad ca 6f 6c b1 0f e2 ad  e4 3e e3 81 28 74 72 75
                              8a aa 7c da 25 52 e4 a0  56 8b aa f8 2a 08 25 24
                              d5 98 28 5f b9 30 22 79  ea 47 b8 4b 26 75 b0 c2
                              59 4d e9 12 87 ad 15 47  40 ac 36 ca 1b 13 d8 a9
                              9c 90 76 06 4f 91 0b d8  0b 4b 66 9b bc 39 5c 22
                              38 2c 2a 8f f1 fe ff 64  38 d4 48 ac fa 59 f0 e5
                              aa 05 7f 0e 92 8e 0d be  17 a7 21 34 47 20 48 30
                              31 36 50 4b 37 43 4a 46  35 42 36 35 38 32 47 34
                              44 56 4e 33 4b 43 48 4b  51 4d 52 4d 42 4f c0 10
                              00 32 00 01 00 00 00 85  00 32 01 00 00 14 10 7b
                              1a 90 a9 16 19 7e 45 d0  77 2a bc b6 44 11 56 14
                              dd 58 5c dc 28 6f 14 8e  f0 c9 23 cf 0e 43 30 ca
                              c1 00 1e b0 00 06 00 00  80 00 00 02 c3 1b 00 2e
                              00 01 00 00 00 85 01 1d  00 32 0a 03 00 00 00 b4
                              61 e0 25 40 61 b8 93 2b  79 4f 05 73 73 68 66 70
                              03 6e 65 74 00 1f 1d 69  09 b8 d4 7c c2 59 a9 4a
                              d7 f8 4b d8 27 2b b0 01  46 40 10 97 af be 81 6b
                              43 75 a6 44 3b c8 2a bc  34 99 66 1a 11 99 59 cc
                              22 a2 f0 f9 26 9b 12 e1  44 bc 97 82 12 92 6c 2d
                              d0 98 29 69 6b b3 68 8e  6d 5f 51 d3 dc 44 65 2f
                              cd b9 f1 34 a8 d3 08 0c  b8 14 32 8c 4c 8c bb b4
                              4e 55 cb d7 74 c3 80 b7  78 ec 34 8f ee d6 42 3e
                              f7 77 54 d4 8c 7d f1 4f  c8 82 b3 3a 50 21 68 cd
                              6a b5 37 cd 02 85 5c 7c  d6 b4 50 3f 68 47 43 98
                              86 b5 f7 f9 85 ee 25 01  84 65 df ec 67 e9 4f 0b
                              a3 67 62 f4 33 74 f9 7b  35 50 bb 92 6a 7b ee ca
                              ce 14 04 15 0b e0 e7 3f  8e 2b 4f da 50 9c 62 b4
                              e1 21 fa 4f 13 0d 2b 79  cc 78 91 ee f7 3e a6 c7
                              0f 9b 9d 8c c9 70 78 b4  f9 91 a8 13 32 ab 10 57
                              cb e3 a7 a0 c4 24 1b 1d  6a bf 4b 2e 47 e6 f2 37
                              63 fe 0f 95 8d a8 a7 1d  6b 3c d4 b7 47 2d 2e bb
                              30 f5 e5 16 20 00 00 29  20 00 00 00 80 00 00 00|}
    in
    let host = n_of_s "aaa.sshfp.net" in
    let header = 0x8fab, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and content =
      let of_d_t d t = Option.get (Ptime.of_date_time (d, t)) in
      let domain = n_of_s "sshfp.net" in
      let nsec3_1_host = n_of_s "1DSJS89LJ18FJVJGEC03555H3PPG10BL.sshfp.net" in
      let nsec3_2_host = n_of_s "H016PK7CJF5B6582G4DVN3KCHKQMRMBO.sshfp.net" in
      let soa = Soa.{ nameserver = n_of_s "ns0.weberdns.de" ; hostmaster = n_of_s "webmaster.webernetz.net" ;
                      serial = 2021030840l ; refresh = 3600l ; retry = 900l ; expiry = 2419200l ; minimum = 180l }
      and rrsig_soa =
        Rrsig.{ type_covered = 6 ; algorithm = Dnskey.RSA_SHA512 ; label_count = 2 ; original_ttl = 86400l ;
                signature_expiration = of_d_t (2022, 01, 25) ((00, 34, 53), 0) ;
                signature_inception = of_d_t (2021, 12, 25) ((23, 34, 53), 0) ;
                key_tag = 31055 ;
                signer_name = domain ;
                signature = Cstruct.of_string (Base64.decode_exn "Nd0DwHXp8I+mI5AaTVzhUiutAtPRpUNSjfN2CDhe7COwhYBxAokT1H0kDik5ZFEv8OAwwWnGDuD8fuUIsRl7sn7/KA58Rc+IJYclNN7LSclYOcfHgMzxr3Mta9YHQQKINLWJtcaZ+DDgsnDK+0PIcY6O2bYODQpI74mmd1c8CORH7EBwQJUPDUzgdl3LNkgCgluTWoTD1skljiKZEV0sA3L4MmKg4t9QiUrPrLnZRCS9gFvLt5SwQOfDZa5GuQDUFIPIcxw6XpQppV8Tc/m6fHtOGIKn6hIKv+EofWckcHav6PUBYaf3uhH3RR5JvhljLBnfioNXrJ3flLddXQ9JPA==")
              }
      and nsec3_1 =
        let types = Bit_map.of_list [1;2;6;16;28;46;48;51;257] in
        Nsec3.{ flags = None ; iterations = 20 ; salt = Cstruct.of_hex "7B1A90A916197E45D0772ABCB6441156" ; next_owner_hashed = Cstruct.of_hex "88026CD0EC9BCAB31502811BFB8E8C8D356DD978" ; types }
      and rrsig_nsec3_1 =
        Rrsig.{ type_covered = 50 ; algorithm = Dnskey.RSA_SHA512 ; label_count = 3 ; original_ttl = 180l ;
                signature_expiration = of_d_t (2022, 01, 13) ((11, 43, 57), 0) ;
                signature_inception = of_d_t (2021, 12, 14) ((11, 00, 40), 0) ;
                key_tag = 31055 ;
                signer_name = domain ;
                signature = Cstruct.of_string (Base64.decode_exn "R8QV6C9RqNIVOZ8J+46OPWkB3Ddve2yuXnegyLZyNnNj57vGQWTxFBVtm3mj/BJlW6y280l6G4MJZ6z099xm3McnmEGLLh/pWBUBSbKRsfwdGeIVbD7OKy6taNn4fXoXYNtnA1Dog9gbWfbunlQOmF722Dvl9qaisnPv+MJO6BcnJZVZPyqiDHl0beQSNIMp957WrcpvbLEP4q3kPuOBKHRydYqqfNolUuSgVouq+CoIJSTVmChfuTAieepHuEsmdbDCWU3pEoetFUdArDbKGxPYqZyQdgZPkQvYC0tmm7w5XCI4LCqP8f7/ZDjUSKz6WfDlqgV/DpKODb4XpyE0Rw==")
              }
      and nsec3_2 =
        let types = Bit_map.of_list [16;46] in
        Nsec3.{ flags = None ; iterations = 20 ; salt = Cstruct.of_hex "7B1A90A916197E45D0772ABCB6441156" ; next_owner_hashed = Cstruct.of_hex "DD585CDC286F148EF0C923CF0E4330CAC1001EB0" ; types }
      and rrsig_nsec3_2 =
        Rrsig.{ type_covered = 50 ; algorithm = Dnskey.RSA_SHA512 ; label_count = 3 ; original_ttl = 180l ;
                signature_expiration = of_d_t (2022, 01, 13) ((13, 12, 32), 0) ;
                signature_inception = of_d_t (2021, 12, 14) ((12, 50, 51), 0) ;
                key_tag = 31055 ;
                signer_name = domain ;
                signature = Cstruct.of_string (Base64.decode_exn "Hx1pCbjUfMJZqUrX+EvYJyuwAUZAEJevvoFrQ3WmRDvIKrw0mWYaEZlZzCKi8PkmmxLhRLyXghKSbC3QmClpa7Nojm1fUdPcRGUvzbnxNKjTCAy4FDKMTIy7tE5Vy9d0w4C3eOw0j+7WQj73d1TUjH3xT8iCszpQIWjNarU3zQKFXHzWtFA/aEdDmIa19/mF7iUBhGXf7GfpTwujZ2L0M3T5ezVQu5Jqe+7KzhQEFQvg5z+OK0/aUJxitOEh+k8TDSt5zHiR7vc+pscPm52MyXB4tPmRqBMyqxBXy+OnoMQkGx1qv0suR+byN2P+D5WNqKcdazzUt0ctLrsw9eUWIA==")
              }
      in
      Domain_name.Map.(
        add nsec3_2_host
          Rr_map.(add Nsec3 (133l, nsec3_2)
                    (singleton Rrsig (133l, Rr_map.Rrsig_set.singleton rrsig_nsec3_2)))
          (add nsec3_1_host
             Rr_map.(add Nsec3 (133l, nsec3_1)
                       (singleton Rrsig (133l, Rr_map.Rrsig_set.singleton rrsig_nsec3_1)))
             (singleton domain
                Rr_map.(add Soa soa (singleton Rrsig (133l, Rr_map.Rrsig_set.singleton rrsig_soa))))))
    in
    let q = Question.create host Ds in
    let edns = Edns.create ~dnssec_ok:true ~payload_size:8192 () in
    let res = create ~edns header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (Name_rr_map.empty, content))) in
    Alcotest.(check (result t_ok p_err) "nsec3 decodes"
                (Ok res) (decode data))

  let loc_packet_preamble =
    (* RFC1035 section 4.1 *)
    (* header *)
    "11 11 81 80 00 01 00 01 00 00 00 00" ^
    (* question *)
      (* example.com *)
        "07 65 78 61 6d 70 6c 65" ^ (* example *)
        "03" ^ (* dot *)
        "63 6f 6d" ^ (* com *)
        "00" ^ (* \0 - null terminated *)
      (* QTYPE = 29 = LOC *)
      "00 1d" ^
      (* QCLASS = IN `*)
      "00 01" ^
    (* answer *)
      "c0 0c" ^
        (* binary: 11000000 00001100
        first 2 11's indicate a pointer
        000000 00001100 = 12
        this gives the size of the header as an offer, pointing to the domain in the query
        *)
      "00 1d" ^ (* TYPE = LOC *)
      "00 01" ^ (* CLASS = IN *)
      "00 00 0e 10" ^ (* TTL = 3600s *)
      "00 10" (* RDLENGTH = 16 *)

  let loc_decode_helper data loc =
    let host = n_of_s "example.com" in
    let header = 0x1111, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and q = Question.create host Loc
    in
    let content =
      Domain_name.Map.singleton host (Rr_map.singleton Loc (3600l, Rr_map.Loc_set.singleton loc))
    in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    let _ = Format.printf "%a\n" Cstruct.hexdump_pp (fst @@ encode `Udp res) in
    let _ =
      Format.printf "%a\n" pp (match (decode data) with
      | Ok t -> t
      | Error _ -> raise (Failure "Failed to decode data"))
    in
    Alcotest.(check (result t_ok p_err) "Loc decodes" (Ok res) (decode data))
  
  let loc_decode () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
        (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "13" ^ (* size *)
        "13" ^ (* horizontal percision *)
        "13" ^ (* vertical percision *)
        "8b 34 0a c0" ^ (* lat *)
        "7f fa f3 08" ^ (* long *)
        "00 98 9f 18" (* alt *) 
    ) in
    let loc = Loc.parse ((52l, 12l, 40.), true) ((0l, 5l, 31.), false) 22. (10., 10., 10.) in
    loc_decode_helper data loc
  
  let loc_decode_min () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
      (* RDATA *)
      (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "00" ^ (* size *)
        "00" ^ (* horizontal percision *)
        "00" ^ (* vertical percision *)
        "80 00 00 00" ^ (* lat *)
        "80 00 00 00" ^ (* long *)
        "00 00 00 00" (* alt *)
    ) in
    let loc = Loc.parse ((0l, 0l, 0.), true) ((0l, 0l, 0.), true) ~-.100000.00 (0., 0., 0.) in
    loc_decode_helper data loc
  
  let loc_decode_min_negated () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
      (* RDATA *)
      (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "00" ^ (* size *)
        "00" ^ (* horizontal percision *)
        "00" ^ (* vertical percision *)
        "80 00 00 00" ^ (* lat *)
        "80 00 00 00" ^ (* long *)
        "00 00 00 00" (* alt *)
    ) in
    let loc = Loc.parse ((0l, 0l, 0.), false) ((0l, 0l, 0.), false) ~-.100000.00 (0., 0., 0.) in
    loc_decode_helper data loc

  let loc_decode_max () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
      (* RDATA *)
      (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "99" ^ (* size *)
        "99" ^ (* horizontal percision *)
        "99" ^ (* vertical percision *)
        "8c df e5 ff" ^ (* lat *)
        "73 20 1a 01" ^ (* long *)
        "ff ff ff ff" (* alt *)
    ) in
    let loc = Loc.parse ((59l, 59l, 59.999), true) ((59l, 59l, 59.999), false) 42849672.95 (90000000.00, 90000000.00, 90000000.00) in
    loc_decode_helper data loc

  let loc_decode_alt_signed_max_under () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
      (* RDATA *)
      (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "99" ^ (* size *)
        "99" ^ (* horizontal percision *)
        "99" ^ (* vertical percision *)
        "8c df e5 ff" ^ (* lat *)
        "73 20 1a 01" ^ (* long *)
        "7f ff ff ff" (* alt *)
    ) in
    let loc = Loc.parse ((59l, 59l, 59.999), true) ((59l, 59l, 59.999), false) 21374836.47 (90000000.00, 90000000.00, 90000000.00) in
    loc_decode_helper data loc
  
  let loc_decode_alt_signed_max () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
      (* RDATA *)
      (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "99" ^ (* size *)
        "99" ^ (* horizontal percision *)
        "99" ^ (* vertical percision *)
        "8c df e5 ff" ^ (* lat *)
        "73 20 1a 01" ^ (* long *)
        "80 00 00 00" (* alt *)
    ) in
    let loc = Loc.parse ((59l, 59l, 59.999), true) ((59l, 59l, 59.999), false) 21374836.48 (90000000.00, 90000000.00, 90000000.00) in
    loc_decode_helper data loc
  
  let loc_decode_alt_signed_max_over () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
      (* RDATA *)
      (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "99" ^ (* size *)
        "99" ^ (* horizontal percision *)
        "99" ^ (* vertical percision *)
        "8c df e5 ff" ^ (* lat *)
        "73 20 1a 01" ^ (* long *)
        "80 00 00 01" (* alt *)
    ) in
    let loc = Loc.parse ((59l, 59l, 59.999), true) ((59l, 59l, 59.999), false) 21374836.49 (90000000.00, 90000000.00, 90000000.00) in
    loc_decode_helper data loc
  
  let loc_leftover () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
        (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "13" ^ (* size *)
        "13" ^ (* horizontal percision *)
        "13" ^ (* vertical percision *)
        "8b 34 0a c0" ^ (* lat *)
        "7f fa f3 08" ^ (* long *)
        "00 98 9f 18 00" (* alt *) 
    ) in
    let loc = Loc.parse ((52l, 12l, 40.), true) ((0l, 5l, 31.), false) 22. (10., 10., 10.) in
    loc_decode_helper data loc

  let loc_leftover_inner () =
    let data = Cstruct.of_hex (
      (* RFC1035 section 4.1 *)
      (* header *)
      "11 11 81 80 00 01 00 01 00 00 00 00" ^
      (* question *)
        (* example.com *)
          "07 65 78 61 6d 70 6c 65" ^ (* example *)
          "03" ^ (* dot *)
          "63 6f 6d" ^ (* com *)
          "00" ^ (* \0 - null terminated *)
        (* QTYPE = 29 = LOC *)
        "00 1d" ^
        (* QCLASS = IN `*)
        "00 01" ^
      (* answer *)
        "c0 0c" ^
          (* binary: 11000000 00001100
          first 2 11's indicate a pointer
          000000 00001100 = 12
          this gives the size of the header as an offer, pointing to the domain in the query
          *)
        "00 1d" ^ (* TYPE = LOC *)
        "00 01" ^ (* CLASS = IN *)
        "00 00 0e 10" ^ (* TTL = 3600s *)
        "00 11" ^ (* RDLENGTH = 17 *)
        (* RDATA *)
        (* RFC1876 section 2 *)
          "00" ^ (* version *)
          "13" ^ (* size *)
          "13" ^ (* horizontal percision *)
          "13" ^ (* vertical percision *)
          "8b 34 0a c0" ^ (* lat *)
          "7f fa f3 08" ^ (* long *)
          "00 98 9f 18 00" (* alt *) 
    ) in
    let loc = Loc.parse ((52l, 12l, 40.), true) ((0l, 5l, 31.), false) 22. (10., 10., 10.) in
    loc_decode_helper data loc

  let loc_fail_partial () =
    let data = Cstruct.of_hex (
      loc_packet_preamble ^
      (* RDATA *)
      (* RFC1876 section 2 *)
        "00" ^ (* version *)
        "13" ^ (* size *)
        "13" ^ (* horizontal percision *)
        "13" ^ (* vertical percision *)
        "8b 34 0a c0" ^ (* lat *)
        "7f fa f3 08" ^ (* long *)
        "00 98 9f" (* alt *) 
    ) in
    Alcotest.(check (result t_ok p_err) "short LOC decodes" (Error `Partial) (decode data))

  let loc_fail_partial_inner () =
    let data = Cstruct.of_hex (
      (* RFC1035 section 4.1 *)
      (* header *)
      "11 11 81 80 00 01 00 01 00 00 00 00" ^
      (* question *)
        (* example.com *)
          "07 65 78 61 6d 70 6c 65" ^ (* example *)
          "03" ^ (* dot *)
          "63 6f 6d" ^ (* com *)
          "00" ^ (* \0 - null terminated *)
        (* QTYPE = 29 = LOC *)
        "00 1d" ^
        (* QCLASS = IN `*)
        "00 01" ^
      (* answer *)
        "c0 0c" ^
          (* binary: 11000000 00001100
          first 2 11's indicate a pointer
          000000 00001100 = 12
          this gives the size of the header as an offer, pointing to the domain in the query
          *)
        "00 1d" ^ (* TYPE = LOC *)
        "00 01" ^ (* CLASS = IN *)
        "00 00 0e 10" ^ (* TTL = 3600s *)
        "00 0f" ^ (* RDLENGTH = 15 *)
        (* RDATA *)
        (* RFC1876 section 2 *)
          "00" ^ (* version *)
          "13" ^ (* size *)
          "13" ^ (* horizontal percision *)
          "13" ^ (* vertical percision *)
          "8b 34 0a c0" ^ (* lat *)
          "7f fa f3 08" ^ (* long *)
          "00 98 9f" (* alt *)
    ) in
    Alcotest.(check (result t_ok p_err) "A decode failure (rdata partial)" (Error `Partial) (decode data))
              
  let loc_encode_helper loc =
    let host = n_of_s "example.com" in
    let header = 0x1111, Flags.(add `Recursion_desired (singleton `Recursion_available))
    and q = Question.create host Loc
    in
    let content =
      Domain_name.Map.singleton host (Rr_map.singleton Loc (3600l, Rr_map.Loc_set.singleton loc))
    in
    let res = create header q (`Answer (content, Name_rr_map.empty)) in
    let _ = Format.printf "%a" Cstruct.hexdump_pp (fst @@ encode `Udp res) in
    Alcotest.(check (result t_ok p_err) "Loc encodes" (Ok res) (decode @@ fst @@ encode `Udp res))
  
  let loc_encode_min () =
    let loc = Loc.parse ((0l, 0l, 0.), true) ((0l, 0l, 0.), true) ~-.100000.00 (0., 0., 0.) in
    loc_encode_helper loc
  
  let loc_encode_min_negated () =
    let loc = Loc.parse ((0l, 0l, 0.), false) ((0l, 0l, 0.), false) ~-.100000.00 (0., 0., 0.) in
    loc_encode_helper loc
  
  let loc_encode_max () =
    let loc = Loc.parse ((59l, 59l, 59.999), true) ((59l, 59l, 59.999), false) 42849672.95 (90000000., 90000000., 90000000.) in
    loc_encode_helper loc

  let code_tests = [
    "bad query", `Quick, bad_query ;
    "regression0", `Quick, regression0 ;
    "regression1", `Quick, regression1 ;
    "regression2", `Quick, regression2 ;
    (* "regression3", `Quick, regression3 ; *)
    "regression4", `Quick, regression4 ;
    "regression5", `Quick, regression5 ;
    "regression6", `Quick, regression6 ;
    "regression7", `Quick, regression7 ;
    "regression8", `Quick, regression8 ;
    "regression9", `Quick, regression9 ;
    "regression10", `Quick, regression10 ;
    "regression11", `Quick, regression11 ;
    "regression12", `Quick, regression12 ;
    "a success", `Quick, a_success ;
    "a leftover", `Quick, a_leftover ;
    "a fail partial", `Quick, a_fail_partial ;
    "a fail leftover inner", `Quick, a_fail_leftover_inner ;
    "a fail partial inner", `Quick, a_fail_partial_inner ;
    "ns success", `Quick, ns_success ;
    "ns fail partial", `Quick, ns_fail_partial ;
    "ns fail leftover inner", `Quick, ns_fail_leftover_inner ;
    "ns fail partial inner", `Quick, ns_fail_partial_inner ;
    "cname success", `Quick, cname_success ;
    "cname fail partial", `Quick, cname_fail_partial ;
    "cname fail leftover inner", `Quick, cname_fail_leftover_inner ;
    "cname fail partial inner", `Quick, cname_fail_partial_inner ;
    "soa success", `Quick, soa_success ;
    "soa fail partial", `Quick, soa_fail_partial ;
    "soa fail leftover inner", `Quick, soa_fail_leftover_inner ;
    "soa fail partial inner", `Quick, soa_fail_partial_inner ;
    "ptr success", `Quick, ptr_success ;
    "ptr fail partial", `Quick, ptr_fail_partial ;
    "ptr fail leftover inner", `Quick, ptr_fail_leftover_inner ;
    "ptr fail partial inner", `Quick, ptr_fail_partial_inner ;
    "mx success", `Quick, mx_success ;
    "mx fail partial", `Quick, mx_fail_partial ;
    "mx fail leftover inner", `Quick, mx_fail_leftover_inner ;
    "mx fail partial inner", `Quick, mx_fail_partial_inner ;
    "txt success", `Quick, txt_success ;
    "txt fail partial", `Quick, txt_fail_partial ;
    "txt fail partial inner", `Quick, txt_fail_partial_inner ;
    "aaaa success", `Quick, aaaa_success ;
    "aaaa fail partial", `Quick, aaaa_fail_partial ;
    "aaaa fail leftover inner", `Quick, aaaa_fail_leftover_inner ;
    "aaaa fail partial inner", `Quick, aaaa_fail_partial_inner ;
    "srv success", `Quick, srv_success ;
    "srv fail partial", `Quick, srv_fail_partial ;
    "srv fail leftover inner", `Quick, srv_fail_leftover_inner ;
    "srv fail partial inner", `Quick, srv_fail_partial_inner ;
    "sshfp success", `Quick, sshfp_success ;
    "sshfp fail partial", `Quick, sshfp_fail_partial ;
    "sshfp fail partial inner", `Quick, sshfp_fail_partial_inner ;
    "tlsa success", `Quick, tlsa_success ;
    "caa success", `Quick, caa_success ;
    "caa fail partial", `Quick, caa_fail_partial ;
    "dnskey success", `Quick, dnskey_success ;
    "ds success", `Quick, ds_success ;
    "rrsig success", `Quick, rrsig_success ;
    "nsec success", `Quick, nsec_success ;
    "nsec success 2", `Quick, nsec_success2 ;
    "nsec3 success", `Quick, nsec3_success ;
    "loc decode", `Quick, loc_decode ;
    "loc decode min", `Quick, loc_decode_min ;
    "loc decode min negated", `Quick, loc_decode_min_negated ;
    (* "loc decode max", `Quick, loc_decode_max ; *)
    "loc decode alt signed max under", `Quick, loc_decode_alt_signed_max_under ;
    "loc decode alt signed max", `Quick, loc_decode_alt_signed_max ;
    (* "loc decode alt signed max over", `Quick, loc_decode_alt_signed_max_over ; *)
    "loc leftover", `Quick, loc_leftover ;
    "loc leftover inner", `Quick, loc_leftover_inner ;
    "loc fail partial", `Quick, loc_fail_partial ;
    "loc fail partial inner", `Quick, loc_fail_partial_inner ;
    "loc encode min" , `Quick, loc_encode_min ;
    "loc encode min negated", `Quick, loc_encode_min_negated ;
    "loc encode max", `Quick, loc_encode_max ;
  ]
end

let tests = [
  "Packet decode", Packet.code_tests ;
]

let () = Alcotest.run "DNS name and packet tests" tests
