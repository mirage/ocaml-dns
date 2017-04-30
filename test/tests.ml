(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Astring

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

let n_of_s = Dns_name.of_string_exn

let p_cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

module Name = struct
  open Dns_name

  let p_err =
    let module M = struct
      type t = err
      let pp = pp_err
      let equal a b = match a, b with
        | `Partial, `Partial -> true
        | `TooLong, `TooLong -> true
        | `BadOffset a, `BadOffset b -> a = b
        | `BadTag a, `BadTag b -> a = b
        | `BadContent a, `BadContent b -> String.compare a b = 0
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let p_ok =
    let module M = struct
      type t = Dns_name.t * (Dns_name.t * int) IntMap.t * int
      let pp ppf (name, map, off) =
        Fmt.pf ppf "%a (map: %a) %d"
          pp name
          (Fmt.list ~sep:(Fmt.unit ";@ ")
             (Fmt.pair ~sep:(Fmt.unit "->") Fmt.int
                (Fmt.pair ~sep:(Fmt.unit " ") pp Fmt.int)))
          (IntMap.bindings map)
          off
      let equal (n, m, off) (n', m', off') =
        equal n n' && off = off' &&
        IntMap.equal
          (fun (nam, siz) (nam', siz') -> equal nam nam' && siz = siz')
          m m'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let p_msg =
    let module M = struct
      type t = [ `Msg of string ]
      let pp ppf (`Msg s) = Fmt.string ppf s
      let equal _ _ = true
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let p_name = Alcotest.testable pp equal

  let p_enc =
    let module M = struct
      type t = int DomMap.t * int
      let pp ppf (names, off) =
        Fmt.pf ppf "map: %a, off: %d"
          (Fmt.list ~sep:(Fmt.unit ";@ ")
             (Fmt.pair ~sep:(Fmt.unit "->") pp Fmt.int))
          (DomMap.bindings names)
          off
      let equal (m, off) (m', off') =
        off = off' &&
        DomMap.equal (fun off off' -> off = off') m m'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let basic_preds () =
    Alcotest.(check bool "root is_hostname" true (is_hostname root)) ;
    Alcotest.(check bool "root is no service" false (is_service root)) ;
    Alcotest.(check bool "_tcp.foo is no service" false
                (is_service (n_of_s ~hostname:false "_tcp.foo"))) ;
    Alcotest.(check bool "_._tcp.foo is no service" false
                (is_service (n_of_s ~hostname:false "_._tcp.foo"))) ;
    Alcotest.(check bool "foo._tcp.foo is no service" false
                (is_service (n_of_s ~hostname:false "foo._tcp.foo"))) ;
    Alcotest.(check bool "f_oo._tcp.foo is no service" false
                (is_service (n_of_s ~hostname:false "f_oo._tcp.foo"))) ;
    Alcotest.(check bool "foo_._tcp.foo is no service" false
                (is_service (n_of_s ~hostname:false "foo_._tcp.foo"))) ;
    Alcotest.(check bool "_xmpp-server._tcp.foo is a service" true
                (is_service (n_of_s ~hostname:false "_xmpp-server._tcp.foo"))) ;
    Alcotest.(check bool "_xmpp-server._tcp2.foo is no service" false
                (is_service (n_of_s ~hostname:false "_xmpp-server._tcp2.foo"))) ;
    Alcotest.(check bool "_xmpp_server._tcp.foo is no service" false
                (is_service (n_of_s ~hostname:false "_xmpp_server._tcp.foo"))) ;
    Alcotest.(check bool "_xmpp-server-server._tcp.foo is no service" false
                (is_service (n_of_s ~hostname:false "_xmpp_server-server._tcp.foo"))) ;
    Alcotest.(check bool "foo is no subdomain of foo.bar" false
                (sub ~subdomain:(n_of_s "foo") ~domain:(n_of_s "foo.bar")))

  let basic_name () =
    Alcotest.(check (result p_name p_msg) "prepend '_foo' to root is not valid"
                (Error (`Msg "")) (prepend root "_foo")) ;
    Alcotest.(check_raises "prepend_exn '_foo' to root raises"
                (Invalid_argument "invalid host name")
                (fun () -> ignore (prepend_exn root "_foo"))) ;
    Alcotest.(check (result p_name p_msg) "of_strings '_foo' ; 'bar' is not valid"
                (Error (`Msg "")) (of_strings [ "_foo" ; "bar" ])) ;
    Alcotest.(check_raises "of_strings_exn '_foo.bar' raises"
                (Invalid_argument "invalid host name")
                (fun () -> ignore (of_strings_exn [ "_foo" ; "bar" ]))) ;
    Alcotest.(check (result p_name p_msg) "of_string 'foo.bar' is valid"
                (Ok (n_of_s "foo.bar")) (of_string "foo.bar")) ;
    Alcotest.(check p_name "of_array 'foo.bar' is good"
                (n_of_s "foo.bar") (of_array [| "bar" ; "foo" |]))

  let simple () =
    let m =
      IntMap.add 0 (n_of_s "foo.com", 9)
        (IntMap.add 4 (n_of_s "com", 5)
           (IntMap.add 8 (root, 1) IntMap.empty))
    in
    Alcotest.(check (result p_ok p_err) "simple name decode test"
                (Ok (n_of_s "foo.com", m, 9))
                (decode IntMap.empty (Cstruct.of_string "\003foo\003com\000") 0)) ;
    Alcotest.(check (result p_ok p_err) "another simple name decode test"
                (Ok (n_of_s "foo.com", IntMap.add 9 (n_of_s "foo.com", 9) m, 11))
                (decode m (Cstruct.of_string "\003foo\003com\000\xC0\000") 9)) ;
    Alcotest.(check (result p_ok p_err) "a ptr added to the name decode test"
                (Ok (n_of_s "bar.foo.com",
                     IntMap.add 13 (n_of_s "foo.com", 9)
                       (IntMap.add 9 (n_of_s "bar.foo.com", 13) m),
                     15))
                (decode m (Cstruct.of_string "\003foo\003com\000\003bar\xC0\000") 9)) ;
    Alcotest.(check (result p_ok p_err) "a ptr with bar- added to the name decode test"
                (Ok (n_of_s "bar-.foo.com",
                     IntMap.add 14 (n_of_s "foo.com", 9)
                       (IntMap.add 9 (n_of_s "bar-.foo.com", 14) m),
                     16))
                (decode m (Cstruct.of_string "\003foo\003com\000\004bar-\xC0\000") 9)) ;
    let m =
      IntMap.add 0 (n_of_s "f23", 5) (IntMap.add 4 (root, 1) IntMap.empty)
    in
    Alcotest.(check (result p_ok p_err) "simple name decode test of f23"
                (Ok (n_of_s "f23", m, 5))
                (decode IntMap.empty (Cstruct.of_string "\003f23\000") 0)) ;
    let m = IntMap.add 0 (n_of_s ~hostname:false "23", 4)
        (IntMap.add 3 (root, 1) IntMap.empty)
    in
    Alcotest.(check (result p_ok p_err) "simple DNS name decode test of 23"
                (Ok (n_of_s ~hostname:false "23", m, 4))
                (decode ~hostname:false IntMap.empty
                   (Cstruct.of_string "\00223\000") 0))

  let encode () =
    let cs = Cstruct.create 30 in
    Alcotest.check p_enc "compressed encode of root is good"
      (DomMap.empty, 1) (encode DomMap.empty cs 0 root) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "00") (Cstruct.sub cs 0 1) ;
    Alcotest.check p_enc "uncompressed encode of root is good"
      (DomMap.empty, 1) (encode ~compress:false DomMap.empty cs 0 root) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "00") (Cstruct.sub cs 0 1) ;
    let map =
      DomMap.add (n_of_s "foo.bar") 0
        (DomMap.add (n_of_s "bar") 4 DomMap.empty)
    in
    Alcotest.check p_enc "encode of 'foo.bar' is good"
      (map, 9) (encode DomMap.empty cs 0 (n_of_s "foo.bar")) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "03 66 6f 6f 03 62 61 72 00")
      (Cstruct.sub cs 0 9) ;
    Alcotest.check p_enc "uncompressed encode of 'foo.bar' is good"
      (map, 9) (encode ~compress:false DomMap.empty cs 0 (n_of_s "foo.bar")) ;
    Alcotest.check p_cs "cstruct is good" (of_hex "03 66 6f 6f 03 62 61 72 00")
      (Cstruct.sub cs 0 9) ;
    let emap = DomMap.add (n_of_s "baz.foo.bar") 9 map in
    Alcotest.check p_enc "encode of 'baz.foo.bar' is good"
      (emap, 15) (encode map cs 9 (n_of_s "baz.foo.bar")) ;
    Alcotest.check p_cs "cstruct is good"
      (of_hex "03 66 6f 6f 03 62 61 72 00 03 62 61 7a c0 00")
      (Cstruct.sub cs 0 15) ;
    let map' =
      DomMap.add (n_of_s "baz.foo.bar") 9
        (DomMap.add (n_of_s "foo.bar") 13
           (DomMap.add (n_of_s "bar") 17 DomMap.empty))
    in
    Alcotest.check p_enc "uncompressed encode of 'baz.foo.bar' is good"
      (map', 22) (encode ~compress:false map cs 9 (n_of_s "baz.foo.bar")) ;
    Alcotest.check p_cs "cstruct is good"
      (of_hex "03 66 6f 6f 03 62 61 72 00 03 62 61 7a 03 66 6f 6f 03 62 61 72 00")
      (Cstruct.sub cs 0 22)

  let partial () =
    Alcotest.(check (result p_ok p_err) "partial domain name (bar)"
                (Error `Partial)
                (decode IntMap.empty (Cstruct.of_string "\003bar") 0));
    Alcotest.(check (result p_ok p_err) "partial domain name (one byte ptr)"
                (Error `Partial)
                (decode IntMap.empty (Cstruct.of_string "\xC0") 0)) ;
    Alcotest.(check (result p_ok p_err) "partial domain name (5foo)"
                (Error `Partial)
                (decode IntMap.empty (Cstruct.of_string "\005foo") 0))

  let bad_ptr () =
    Alcotest.(check (result p_ok p_err) "bad pointer in label"
                (Error (`BadOffset 10))
                (decode IntMap.empty (Cstruct.of_string "\xC0\x0A") 0)) ;
    Alcotest.(check (result p_ok p_err) "cyclic self-pointer in label"
                (Error (`BadOffset 0))
                (decode IntMap.empty (Cstruct.of_string "\xC0\x00") 0)) ;
    Alcotest.(check (result p_ok p_err) "cyclic self-pointer in label"
                (Error (`BadOffset 1))
                (decode IntMap.empty (Cstruct.of_string "\xC0\x01") 0))

  let bad_tag () =
    Alcotest.(check (result p_ok p_err) "bad tag (0x40) in label"
                (Error (`BadTag 0x40))
                (decode IntMap.empty (Cstruct.of_string "\x40") 0)) ;
    Alcotest.(check (result p_ok p_err) "bad tag (0x80) in label"
                (Error (`BadTag 0x80))
                (decode IntMap.empty (Cstruct.of_string "\x80") 0))

  let bad_content () =
    Alcotest.(check (result p_ok p_err) "bad content '-' in label"
                (Error (`BadContent "-"))
                (decode IntMap.empty (Cstruct.of_string "\001-\000") 0)) ;
    Alcotest.(check (result p_ok p_err) "bad content 'foo-+' in label"
                (Error (`BadContent "foo-+"))
                (decode IntMap.empty (Cstruct.of_string "\005foo-+\000") 0)) ;
    Alcotest.(check (result p_ok p_err) "bad content '23' in label"
                (Error (`BadContent "23"))
                (decode IntMap.empty (Cstruct.of_string "\00223\000") 0))

  let length () =
    let max = "s23456789012345678901234567890123456789012345678901234567890123" in
    let lst, _ = String.span ~max:61 max in
    let full = n_of_s (String.concat ~sep:"." [ max ; max ; max ; lst ]) in
    Alcotest.(check (result p_ok p_err) "longest allowed domain name"
                (Ok (full,
                     IntMap.add 0 (full, 255)
                       (IntMap.add 64 (n_of_s (String.concat ~sep:"." [ max ; max ; lst ]), 191)
                          (IntMap.add 128 (n_of_s (String.concat ~sep:"." [ max ; lst ]), 127)
                             (IntMap.add 192 (n_of_s lst, 63)
                                (IntMap.add 254 (root, 1) IntMap.empty)))),
                     255))
                (decode IntMap.empty
                   (Cstruct.of_string ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3D" ^ lst ^ "\000"))
                   0)) ;
    Alcotest.(check (result p_ok p_err) "domain name too long"
                (Error `TooLong)
                (decode IntMap.empty
                   (Cstruct.of_string ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3E" ^ lst ^ "1\000"))
                   0)) ;
    Alcotest.(check (result p_ok p_err) "domain name really too long"
                (Error `TooLong)
                (decode IntMap.empty
                   (Cstruct.of_string ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\000"))
                   0))

  let code_tests = [
    "basic predicates", `Quick, basic_preds ;
    "basic name stuff", `Quick, basic_name ;
    "simple decode", `Quick, simple ;
    "encode", `Quick, encode ;
    "partial", `Quick, partial ;
    "bad pointer", `Quick, bad_ptr ;
    "bad tag", `Quick, bad_tag ;
    "bad content", `Quick, bad_content ;
    "length checks", `Quick, length ;
  ]
end


module Packet = struct
  open Dns_packet

  let p_err =
    let module M = struct
      type t = [ Dns_name.err | `BadTTL of int32
               | `BadRRTyp of int | `DisallowedRRTyp of Dns_enum.rr_typ
               | `BadClass of int | `DisallowedClass of Dns_enum.clas | `UnsupportedClass of Dns_enum.clas
               | `BadOpcode of int | `UnsupportedOpcode of Dns_enum.opcode
               | `BadRcode of int
               | `BadProto of int | `BadAlgorithm of int | `BadCaaTag
               | `LeftOver | `InvalidTimestamp of int64
               | `InvalidAlgorithm of Dns_name.t
               | `NonZeroTTL of int32
               | `NonZeroRdlen of int | `InvalidZoneCount of int
               | `InvalidZoneRR of Dns_enum.rr_typ
               ]
      let pp = pp_err
      let equal a b = match a, b with
        | `Partial, `Partial -> true
        | `TooLong, `TooLong -> true
        | `BadOffset a, `BadOffset b -> a = b
        | `BadTag a, `BadTag b -> a = b
        | `BadContent a, `BadContent b -> String.compare a b = 0
        | `BadTTL a, `BadTTL b -> Int32.compare a b = 0
        | `BadRRTyp a, `BadRRTyp b -> a = b
        | `DisallowedRRTyp a, `DisallowedRRTyp b -> a = b
        | `BadClass a, `BadClass b -> a = b
        | `DisallowedClass a, `DisallowedClass b -> a = b
        | `UnsupportedClass a, `UnsupportedClass b -> a = b
        | `BadOpcode a, `BadOpcode b -> a = b
        | `BadRcode a, `BadRcode b -> a = b
        | `BadCaaTag, `BadCaaTag -> true
        | `LeftOver, `LeftOver -> true
        | `BadProto a, `BadProto b -> a = b
        | `BadAlgorithm a, `BadAlgorithm b -> a = b
        | `InvalidTimestamp a, `InvalidTimestamp b -> a = b
        | `InvalidAlgorithm a, `InvalidAlgorithm b -> Dns_name.equal a b
        | `NonZeroTTL a, `NonZeroTTL b -> a = b
        | `NonZeroRdlen a, `NonZeroRdlen b -> a = b
        | `InvalidZoneCount a, `InvalidZoneCount b -> a = b
        | `InvalidZoneRR a, `InvalidZoneRR b -> a = b
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let q_equal a b =
    Dns_name.compare a.q_name b.q_name = 0 &&
    compare a.q_type b.q_type = 0

  let header_equal a b =
    a.id = b.id &&
    a.query = b.query &&
    a.operation = b.operation &&
    a.authoritative = b.authoritative &&
    a.truncation = b.truncation &&
    a.recursion_desired = b.recursion_desired &&
    a.recursion_available = b.recursion_available &&
    a.authentic_data = b.authentic_data &&
    a.checking_disabled = b.checking_disabled &&
    a.rcode = b.rcode

  let h_ok = Alcotest.testable pp_header header_equal

  let q_ok =
    let module M = struct
      type t = Dns_packet.header * Dns_packet.query
      let pp = Fmt.(pair Dns_packet.pp_header Dns_packet.pp_query)
      let equal (ah, a) (bh, b) =
        header_equal ah bh &&
        List.length a.question = List.length b.question &&
        List.for_all (fun a -> List.exists (q_equal a) b.question) a.question &&
        List.length a.answer = List.length b.answer &&
        List.for_all (fun a -> List.exists (rr_equal a) b.answer) a.answer &&
        List.length a.authority = List.length b.authority &&
        List.for_all (fun a -> List.exists (rr_equal a) b.authority) a.authority &&
        List.length a.additional = List.length b.additional &&
        List.for_all (fun a -> List.exists (rr_equal a) b.additional) a.additional
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let basic_header () =
    let hdr = { id = 1 ; query = true ; operation = Dns_enum.Query ;
                authoritative = false ; truncation = false ;
                recursion_desired = false ; recursion_available = false ;
                authentic_data = false ; checking_disabled = false ;
                rcode = Dns_enum.NoError }
    in
    let cs = Cstruct.create 12 in
    encode_header cs hdr ;
    Alcotest.check p_cs "encoded header is good"
      (of_hex "00 01 00 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr) (decode_header cs)) ;
    let hdr' = { hdr with query = false ; rcode = Dns_enum.NXDomain } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 80 03") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs)) ;
    let hdr' = { hdr with operation = Dns_enum.Update ; authentic_data = true } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 28 20") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs)) ;
    let hdr' = { hdr with truncation = true } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 02 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs)) ;
    let hdr' = { hdr with checking_disabled = true } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 00 10") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs)) ;
    Alcotest.(check (result h_ok p_err) "header with bad opcode"
                (Error (`BadOpcode 14))
                (decode_header (of_hex "0000 7000 0000 0000 0000 0000"))) ;
    Alcotest.(check (result h_ok p_err) "header with bad rcode"
                (Error (`BadRcode 14))
                (decode_header (of_hex "0000 000e 0000 0000 0000 0000"))) ;
    let hdr' = { hdr with authoritative = true } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 04 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs)) ;
    let hdr' = { hdr with recursion_desired = true } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 01 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs)) ;
    let hdr' = { hdr with recursion_desired = true ; authoritative = true } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 05 00") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs)) ;
    let hdr' = { hdr with recursion_available = true } in
    encode_header cs hdr' ;
    Alcotest.check p_cs "encoded header' is good"
      (of_hex "00 01 00 80") (Cstruct.sub cs 0 4) ;
    Alcotest.(check (result h_ok p_err) "encoded header can be decoded"
                (Ok hdr') (decode_header cs))

  let decode cs =
    match decode cs with
    | Error e -> Error e
    | Ok ((header, `Query query), _) -> Ok (header, query)
    | Ok _ -> Error (`BadOpcode 10)

  let bad_query () =
    let cs = of_hex "0000 0000 0100 0000 0000 0000 0000 0100 02" in
    Alcotest.(check (result q_ok p_err) "query with bad class"
                (Error (`BadClass 2))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0100 0000 0000 0000 0000 0100 03" in
    Alcotest.(check (result q_ok p_err) "query with unsupported class"
                (Error (`UnsupportedClass Dns_enum.CHAOS))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0100 0000 0000 0000 0000 0000 01" in
    Alcotest.(check (result q_ok p_err) "question with unsupported typ"
                (Error (`BadRRTyp 0))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0100 0000 0000 0000 0000 2100 01" in
    Alcotest.(check (result q_ok p_err) "question with bad SRV"
                (Error (`BadContent ""))
                (decode cs)) ;
    let cs = of_hex "0000 0100 0100 0000 0000 0000 0102 0000 0200 01" in
    Alcotest.(check (result q_ok p_err) "question with bad hostname"
                (Error (`BadContent "\002"))
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
      { id = 0xD4E4 ; query = false ; operation = Dns_enum.Query ;
        authoritative = true ; truncation = false ;
        recursion_desired = true ; recursion_available = true ;
        authentic_data = false ; checking_disabled = false ;
        rcode = Dns_enum.NXDomain }
    in
    let soa = {
      nameserver = n_of_s "CON1R.NIPR.MIL" ;
      hostmaster =
        Dns_name.of_strings_exn ~hostname:false
          ["DANIEL.W.KNOPPS.CIV" ; "MAIL" ; "MIL" ] ;
      serial = 0x7839c3d1l ; refresh = 0x2a30l ; retry = 0x384l ;
      expiry = 0x127500l ; minimum = 0x2a30l
    }
    in
    Alcotest.(check (result q_ok p_err) "regression 0 decodes"
                (Ok (header, {
                     question = [{
                         q_name = n_of_s "6.16.150.138.in-addr.arpa" ;
                         q_type = Dns_enum.PTR
                       }] ;
                     answer = [] ;
                     authority = [{
                         name = n_of_s "150.138.in-addr.arpa" ;
                         ttl = 0x2a30l ;
                         rdata = SOA soa }];
                     additional = []}))
                (decode data))

  let regression1 () =
    let data = of_hex {___|83 d9 01 00 00 01 00 00 00 00 00 00 04 6b 65 79
                           73 06 72 69 73 65 75 70 03 6e 65 74 00 00 1c 00
                           01|___}
    in
    let header =
      { id = 0x83D9 ; query = true ; operation = Dns_enum.Query ;
        authoritative = false ; truncation = false ;
        recursion_desired = true ; recursion_available = false ;
        authentic_data = false ; checking_disabled = false ;
        rcode = Dns_enum.NoError }
    in
    Alcotest.(check (result q_ok p_err) "regression 1 decodes"
                (Ok (header, {
                     question = [{
                         q_name = n_of_s "keys.riseup.net" ;
                         q_type = Dns_enum.AAAA
                       }] ;
                     answer = [] ; authority = [] ; additional = []}))
                (decode data))

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
      let rcode = Dns_enum.NXDomain in
      { query = false ; id = 0xAE00 ; operation = Dns_enum.Query ;
        authoritative = true ; truncation = false ; recursion_desired = false ;
        recursion_available = false ; authentic_data = false ;
        checking_disabled = false ; rcode }
    in
    let soa = {
      nameserver = n_of_s ~hostname:false "212.58.230.200" ;
      hostmaster = n_of_s "bofh.bbc.co.uk" ;
      serial = 0x595cbdcel ; refresh = 0x00015180l ; retry = 0x00015180l ;
      expiry = 0x00015180l ; minimum = 0x0000012cl
    } in
    Alcotest.(check (result q_ok p_err) "regression 2 decodes"
                (Ok (header, {
                     question = [{
                         q_name = n_of_s "news.bbc.net.uk" ;
                         q_type = Dns_enum.NS
                       }] ;
                     authority = [{
                         name = n_of_s "bbc.net.uk" ;
                         ttl = 0x0E10l ;
                         rdata = SOA soa }] ;
                     answer = [] ; additional = []}))
                (decode data))

  let code_tests = [
    "basic header", `Quick, basic_header ;
    "bad query", `Quick, bad_query ;
    "regression0", `Quick, regression0 ;
    "regression1", `Quick, regression1 ;
    "regression2", `Quick, regression2 ;
  ]
end

let tests = [
  "Name code", Name.code_tests ;
  "Packet decode", Packet.code_tests ;
]

let () = Alcotest.run "DNS name and packet tests" tests
