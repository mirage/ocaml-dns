(* (c) 2017 Hannes Mehnert, all rights reserved *)
open Udns
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
  let question_equal a b = Question.compare a b = 0

  let header_equal a b = Header.compare a b = 0

  let h_ok = Alcotest.testable Header.pp header_equal

  let q_ok =
    let module M = struct
      type t = res
      let pp = pp_res
      let equal = equal_res
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let basic_header () =
    let hdr = { Header.id = 1 ; query = true ; operation = Udns_enum.Query ;
                rcode = Udns_enum.NoError ; flags = Header.FS.empty }
    in
    let cs = Cstruct.create 12 in
    Header.encode cs hdr ;
    Alcotest.check p_cs "first encoded header is good"
      (of_hex "00 01 00 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "first encoded header can be decoded"
                (Ok hdr) (Header.decode cs)) ;
    let hdr' = { hdr with query = false ; rcode = Udns_enum.NXDomain } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "second encoded header' is good"
      (of_hex "00 01 80 03") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "second encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Authentic_data in
      { hdr with Header.operation = Udns_enum.Update ; flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "third encoded header' is good"
      (of_hex "00 01 28 20") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "third encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Truncation in
      { hdr with Header.flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "fourth encoded header' is good"
      (of_hex "00 01 02 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "fourth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Checking_disabled in
      { hdr with Header.flags } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "fifth encoded header' is good"
      (of_hex "00 01 00 10") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "fifth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    Alcotest.(check (result h_ok p_err) "header with bad opcode"
                (Error (`Not_implemented (0, "opcode 14")))
                (Header.decode (of_hex "0000 7000 0000 0000 0000 0000"))) ;
    Alcotest.(check (result h_ok p_err) "header with bad rcode"
                (Error (`Malformed (0, "rcode 14")))
                (Header.decode (of_hex "0000 000e 0000 0000 0000 0000"))) ;
    let hdr' =
      let flags = Header.FS.singleton `Authoritative in
      { hdr with Header.flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "sixth encoded header' is good"
      (of_hex "00 01 04 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "sixth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Recursion_desired in
      { hdr with Header.flags } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "seventh encoded header' is good"
      (of_hex "00 01 01 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "seventh encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.(add `Recursion_desired (singleton `Authoritative)) in
      { hdr with Header.flags }
    in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "eigth encoded header' is good"
      (of_hex "00 01 05 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "eigth encoded header can be decoded"
                (Ok hdr') (Header.decode cs)) ;
    let hdr' =
      let flags = Header.FS.singleton `Recursion_available in
      { hdr with Header.flags } in
    Header.encode cs hdr' ;
    Alcotest.check p_cs "nineth encoded header' is good"
      (of_hex "00 01 00 80") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "nineth encoded header can be decoded"
                (Ok hdr') (Header.decode cs))

  let bad_query () =
    let cs = of_hex "0000 0000 0001 0000 0000 0000 0000 0100 02" in
    Alcotest.(check (result q_ok p_err) "query with bad class"
                (Error (`Not_implemented (0, "BadClass 2")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0100 03" in
    Alcotest.(check (result q_ok p_err) "query with unsupported class"
                (Error (`Not_implemented (0, "UnsupportedClass 0")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 0000 01" in
    Alcotest.(check (result q_ok p_err) "question with unsupported typ"
                (Error (`Not_implemented (0, "typ 0")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0000 2100 01" in
    Alcotest.(check (result q_ok p_err) "question with bad SRV"
                (Error (`Malformed (0, "BadContent")))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0001 0000 0000 0000 0102 0000 0200 01" in
    Alcotest.(check (result q_ok p_err) "question with bad hostname"
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
    let header =
      let flags = Header.FS.(add `Authoritative (add `Recursion_desired (singleton `Recursion_available))) in
      { Header.id = 0xD4E4 ; query = false ; operation = Udns_enum.Query ;
        rcode = Udns_enum.NXDomain ; flags }
    and soa = {
      Soa.nameserver = n_of_s "CON1R.NIPR.MIL" ;
      hostmaster =
        Domain_name.of_strings_exn ~hostname:false
          ["DANIEL.W.KNOPPS.CIV" ; "MAIL" ; "MIL" ] ;
      serial = 0x7839c3d1l ; refresh = 0x2a30l ; retry = 0x384l ;
      expiry = 0x127500l ; minimum = 0x2a30l
    }
    in
    let res =
      header, (n_of_s "6.16.150.138.in-addr.arpa", Udns_enum.PTR),
      `Query (Domain_name.Map.empty,
              Domain_name.Map.singleton (n_of_s "150.138.in-addr.arpa")
                Rr_map.(singleton Soa soa)),
      Name_rr_map.empty, None, None
    in
    Alcotest.(check (result q_ok p_err) "regression 0 decodes"
                (Ok res) (decode data))

  let regression1 () =
    let data = of_hex {___|83 d9 01 00 00 01 00 00 00 00 00 00 04 6b 65 79
                           73 06 72 69 73 65 75 70 03 6e 65 74 00 00 1c 00
                           01|___}
    in
    let header =
      let flags = Header.FS.singleton `Recursion_desired in
      { Header.id = 0x83D9 ; query = true ; operation = Udns_enum.Query ;
        rcode = Udns_enum.NoError ; flags }
    in
    let res =
      header, (n_of_s "keys.riseup.net", Udns_enum.AAAA),
      `Query Packet.Query.empty, Name_rr_map.empty, None, None
    in
    Alcotest.(check (result q_ok p_err) "regression 1 decodes"
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
    let header =
      let rcode = Udns_enum.NXDomain
      and flags = Header.FS.singleton `Authoritative
      in
      { Header.query = false ; id = 0xAE00 ; operation = Udns_enum.Query ;
        rcode ; flags }
    and soa = {
      Soa.nameserver = n_of_s ~hostname:false "212.58.230.200" ;
      hostmaster = n_of_s "bofh.bbc.co.uk" ;
      serial = 0x595cbdcel ; refresh = 0x00015180l ; retry = 0x00015180l ;
      expiry = 0x00015180l ; minimum = 0x0000012cl
    } in
    let res =
      header, (n_of_s "news.bbc.net.uk", Udns_enum.NS),
      `Query (Domain_name.Map.empty,
              Domain_name.Map.singleton (n_of_s "bbc.net.uk")
                Rr_map.(singleton Soa soa)),
      Name_rr_map.empty, None, None
    in
    Alcotest.(check (result q_ok p_err) "regression 2 decodes"
                (Ok res) (decode data))

  let regression3 () =
    let data = of_hex {___|e213 8180 0001
        0001 0000 0001 0366 6f6f 0363 6f6d 0000
        0f00 01c0 0c00 0f00 0100 0002 2c00 0b03
        e801 3001 3001 3001 3000 0000 2901 c2 00
        0000 0000 00|___}
    in
    let header =
      let rcode = Udns_enum.NoError
      and flags = Header.FS.(add `Recursion_desired (singleton `Recursion_available))
      in
      { Header.query = false ; id = 0xe213 ; operation = Udns_enum.Query ;
        rcode ; flags }
    and question =
      (Domain_name.of_string_exn ~hostname:false "foo.com", Udns_enum.MX)
    and answer =
      let mx = {
        Mx.preference = 1000 ;
        mail_exchange = Domain_name.of_string_exn ~hostname:false "0.0.0.0"
      } in
      Domain_name.Map.singleton (Domain_name.of_string_exn "foo.com")
        Rr_map.(singleton Mx (556l, Mx_set.singleton mx))
    and edns = Edns.create ~payload_size:450 ()
    in
    let res =
      header, question, `Query (answer, Domain_name.Map.empty),
      Name_rr_map.empty, Some edns, None
    in
    Alcotest.(check (result q_ok p_err) "regression 4 decodes"
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
    let header =
      let rcode = Udns_enum.NXDomain in
      { Header.query = false ; id = 0x9FCA ; operation = Udns_enum.Query ;
        rcode ; flags = Header.FS.empty }
    and question =
      (Domain_name.of_string_exn ~hostname:false "_tcp.keys.riseup.net", Udns_enum.NS)
    and authority =
      let soa = { Soa.nameserver = Domain_name.of_string_exn "primary.riseup.net" ;
                  hostmaster = Domain_name.of_string_exn "collective.riseup.net" ;
                  serial = 0x78488b04l ; refresh = 0x1c20l ; retry = 0x0e10l ;
                  expiry = 0x127500l ; minimum = 0x012cl }
      in
      Domain_name.Map.singleton (Domain_name.of_string_exn "riseup.net")
        Rr_map.(singleton Soa soa)
    and edns = Edns.create ~payload_size:4096 ()
    in
    let res =
      header, question,
      `Query (Name_rr_map.empty, authority),
      Name_rr_map.empty, Some edns, None
    in
    Alcotest.(check (result q_ok p_err) "regression 4 decodes"
                (Ok res) (decode data))

  let regression5 () =
    (* this is what bbc returns me (extra bytes) since it doesn't like EDNS *)
    let data = of_hex {___|5b 12 84 01 00 01 00 00  00 00 00 00 03 6e 73 34
                           03 62 62 63 03 6e 65 74  02 75 6b 00 00 02 00 01
                           00 00 29 05 cc 00 00 00  00 00 00|___}
    in
    let header =
      let rcode = Udns_enum.FormErr
      and flags = Header.FS.singleton `Authoritative
      in
      { Header.query = false ; id = 0x5B12 ; operation = Udns_enum.Query ;
        rcode ; flags }
    and question =
      (Domain_name.of_string_exn "ns4.bbc.net.uk", Udns_enum.NS)
    in
    let res =
      header, question, `Query Query.empty,
      Name_rr_map.empty, None, None
    in
    Alcotest.(check (result q_ok p_err) "regression 5 decodes"
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
    let header =
      let rcode = Udns_enum.NoError in
      { Header.query = true ; id = 0xAE00 ; operation = Udns_enum.Update ;
        rcode ; flags = Header.FS.empty }
    and update =
      let up =
        Domain_name.Map.singleton
          (n_of_s "www.example.com")
          [ Packet.Update.Remove_single Rr_map.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost))) ]
      in
      (Domain_name.Map.empty, up)
    and zone = n_of_s "example.com", Udns_enum.SOA
    in
    let res =
      header, zone, `Update update,
      Name_rr_map.empty, None, None
    in
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result q_ok p_err) "regression 7 decode encode works"
                (Ok res)
                (decode @@ fst @@ Packet.encode `Udp header zone (`Update update)))

  let regression8 () =
    (* encoding a exists_data in an update frame lead to wrong rdlength (off by 2) *)
    let header =
      let rcode = Udns_enum.NoError in
      { Header.query = true ; id = 0xAE00 ; operation = Udns_enum.Update ;
        rcode ; flags = Header.FS.empty }
    and prereq =
      let pre =
        Domain_name.Map.singleton (n_of_s "www.example.com")
          [ Packet.Update.Exists_data Rr_map.(B (A, (0l, Ipv4_set.singleton Ipaddr.V4.localhost)))]
      in
      (pre, Domain_name.Map.empty)
    and zone = (n_of_s "example.com", Udns_enum.SOA)
    in
    let res = header, zone, `Update prereq, Name_rr_map.empty, None, None in
    (* encode followed by decode should lead to same data *)
    Alcotest.(check (result q_ok p_err) "regression 8 decode encode works"
                (Ok res)
                (decode @@ fst @@ Packet.encode `Udp header zone (`Update prereq)))

  let regression9 () =
    (* from ednscomp.isc.org *)
    let data = Cstruct.of_hex {|
a8 6c 00 00 00 01 00 00  00 00 00 01 04 6e 71 73
62 02 69 6f 00 00 01 00  01 00 00 29 10 00 00 00
00 00 00 1c 00 03 00 00  00 08 00 04 00 01 00 00
00 0a 00 08 c8 9a 2a f8  aa 77 31 af 00 09 00 00
|}
    in
    let header =
      { Header.query = true ; id = 0xa86c ; operation = Udns_enum.Query ;
                   rcode = Udns_enum.NoError ;
        flags = Header.FS.empty }
    and question = (n_of_s "nqsb.io", Udns_enum.A)
    and edns =
      let extensions = [
        Edns.Nsid Cstruct.empty ;
        Edns.Extension (8, Cstruct.of_hex "00 01 00 00") ;
        Edns.Cookie (Cstruct.of_hex "c8 9a 2a f8 aa 77 31 af") ;
        Edns.Extension (9, Cstruct.empty)
      ] in
      Edns.create ~payload_size:4096 ~extensions ()
    in
    let res =
      header, question, `Query Query.empty,
      Name_rr_map.empty, Some edns, None
    in
    Alcotest.(check (result q_ok p_err) "regression 9 decodes"
                (Ok res) (decode data))

  let code_tests = [
    "basic header", `Quick, basic_header ;
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
  ]
end

let tests = [
  "Packet decode", Packet.code_tests ;
]

let () = Alcotest.run "DNS name and packet tests" tests
