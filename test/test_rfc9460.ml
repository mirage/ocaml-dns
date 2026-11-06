open Dns

let n = Domain_name.of_string_exn
let example = n "example.com"

let of_hex s =
  let s = String.concat "" (String.split_on_char ' ' s) in
  String.init (String.length s / 2) (fun i ->
      Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))

let to_hex s = Ohex.encode s

let svcb ~priority ~target params =
  match Svcb.v ~priority ~target:(n target) params with
  | Ok t -> t
  | Error (`Msg m) -> Alcotest.fail ("Svcb.v: " ^ m)

let ip4 = Ipaddr.V4.of_string_exn
let ip6 = Ipaddr.V6.of_string_exn

let svcb_t =
  let module M = struct
    type t = Svcb.t
    let pp = Svcb.pp
    let equal a b = Svcb.compare a b = 0
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let msg =
  let module M = struct
    type t = [ `Msg of string ]
    let pp ppf (`Msg s) = Fmt.string ppf s
    let equal _ _ = true
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

(* a response for example.com with a single SVCB or HTTPS answer *)
let packet_of_rdata ?(typ = 64) rdata =
  let len = Bytes.create 2 in
  Bytes.set_uint16_be len 0 (String.length rdata);
  of_hex "0001 8400 0001 0001 0000 0000" ^
  of_hex "07 6578616d706c65 03 636f6d 00" ^
  of_hex (Printf.sprintf "%04x 0001" typ) ^
  of_hex (Printf.sprintf "c00c %04x 0001 00000e10" typ) ^ Bytes.to_string len ^ rdata

let decode_rdata ?(typ = 64) rdata =
  match Packet.decode (packet_of_rdata ~typ rdata) with
  | Error e -> Error e
  | Ok p -> match p.Packet.data with
    | `Answer (a, _) ->
      let set = match typ with
        | 64 -> Option.map snd (Name_rr_map.find example Rr_map.Svcb a)
        | _ -> Option.map snd (Name_rr_map.find example Rr_map.Https a)
      in
      (match set with
       | Some s when Rr_map.Svcb_set.cardinal s = 1 -> Ok (Rr_map.Svcb_set.choose s)
       | _ -> Alcotest.fail "expected a single record")
    | _ -> Alcotest.fail "expected an answer"

let encode_rdata t =
  let set = Rr_map.Svcb_set.singleton t in
  let answer = Name_rr_map.singleton example Rr_map.Svcb (3600l, set) in
  let p =
    Packet.create (1, Packet.Flags.empty) (example, `K (Rr_map.K Rr_map.Svcb))
      (`Answer (answer, Domain_name.Map.empty))
  in
  let wire, _ = Packet.encode `Udp p in
  (* header 12, question 17, answer header 12 *)
  String.sub wire 41 (String.length wire - 41)

let parse_one zone =
  match Dns_zone.parse zone with
  | Error e -> Error e
  | Ok m ->
    let set = match Name_rr_map.find example Rr_map.Svcb m with
      | Some (_, s) -> s
      | None -> match Name_rr_map.find example Rr_map.Https m with
        | Some (_, s) -> s
        | None -> Alcotest.fail "no SVCB or HTTPS record"
    in
    Ok (Rr_map.Svcb_set.elements set)

(* RFC 9460 Appendix D.1 and D.2: presentation, wire format, value *)
let foo_com = "03666f6f 076578616d706c65 03636f6d 00"
let foo_org = "03666f6f 076578616d706c65 036f7267 00"

let vectors = [
  "D.1 AliasMode", "HTTPS 0 foo.example.com.",
  "0000" ^ foo_com,
  svcb ~priority:0 ~target:"foo.example.com" [] ;
  "D.2 TargetName is .", "SVCB 1 .",
  "0001 00",
  svcb ~priority:1 ~target:"." [] ;
  "D.2 port", "SVCB 16 foo.example.com. port=53",
  "0010" ^ foo_com ^ "0003 0002 0035",
  svcb ~priority:16 ~target:"foo.example.com" [ Port 53 ] ;
  "D.2 generic key", "SVCB 1 foo.example.com. key667=hello",
  "0001" ^ foo_com ^ "029b 0005 68656c6c6f",
  svcb ~priority:1 ~target:"foo.example.com" [ Key (667, "hello") ] ;
  "D.2 generic key with escape", {|SVCB 1 foo.example.com. key667="hello\210qoo"|},
  "0001" ^ foo_com ^ "029b 0009 68656c6c6fd2716f6f",
  svcb ~priority:1 ~target:"foo.example.com" [ Key (667, "hello\210qoo") ] ;
  "D.2 two ipv6 hints",
  {|SVCB 1 foo.example.com. (
                  ipv6hint="2001:db8::1,2001:db8::53:1"
                  )|},
  "0001" ^ foo_com ^ "0006 0020 20010db8000000000000000000000001 20010db8000000000000000000530001",
  svcb ~priority:1 ~target:"foo.example.com"
    [ Ipv6_hint [ ip6 "2001:db8::1" ; ip6 "2001:db8::53:1" ] ] ;
  "D.2 ipv6 hint with embedded ipv4",
  {|SVCB 1 example.com. ipv6hint="2001:db8:122:344::192.0.2.33"|},
  "0001 076578616d706c65 03636f6d 00 0006 0010 20010db8012203440000 0000c0000221",
  svcb ~priority:1 ~target:"example.com"
    [ Ipv6_hint [ ip6 "2001:db8:122:344::192.0.2.33" ] ] ;
  "D.2 key ordering",
  {|SVCB 16 foo.example.org. (
                  alpn=h2,h3-19 mandatory=ipv4hint,alpn
                  ipv4hint=192.0.2.1
                  )|},
  "0010" ^ foo_org ^ "0000 0004 0001 0004 0001 0009 02 6832 05 68332d3139 0004 0004 c0000201",
  svcb ~priority:16 ~target:"foo.example.org"
    [ Mandatory [ 4 ; 1 ] ; Alpn [ "h2" ; "h3-19" ] ; Ipv4_hint [ ip4 "192.0.2.1" ] ] ;
  "D.2 alpn escapes (quoted)", {|SVCB 16 foo.example.org. alpn="f\\\\oo\\,bar,h2"|},
  "0010" ^ foo_org ^ "0001 000c 08 665c6f6f2c626172 02 6832",
  svcb ~priority:16 ~target:"foo.example.org" [ Alpn [ "f\\oo,bar" ; "h2" ] ] ;
  "D.2 alpn escapes (unquoted)", {|SVCB 16 foo.example.org. alpn=f\\\092oo\092,bar,h2|},
  "0010" ^ foo_org ^ "0001 000c 08 665c6f6f2c626172 02 6832",
  svcb ~priority:16 ~target:"foo.example.org" [ Alpn [ "f\\oo,bar" ; "h2" ] ] ;
  (* beyond the RFC vectors *)
  "no-default-alpn", "HTTPS 1 . alpn=h2 no-default-alpn",
  "0001 00 0001 0003 026832 0002 0000",
  svcb ~priority:1 ~target:"." [ Alpn [ "h2" ] ; No_default_alpn ] ;
  "ech", "HTTPS 1 . alpn=h2 ech=AQID port=443",
  "0001 00 0001 0003 026832 0003 0002 01bb 0005 0003 010203",
  svcb ~priority:1 ~target:"." [ Alpn [ "h2" ] ; Port 443 ; Ech "\001\002\003" ] ;
  "alpn order kept", "HTTPS 1 foo.example.com. alpn=h3,h2,http/1.1",
  "0001" ^ foo_com ^ "0001 000f 026833 026832 08687474702f312e31",
  svcb ~priority:1 ~target:"foo.example.com" [ Alpn [ "h3" ; "h2" ; "http/1.1" ] ] ;
  "ipv4 hint order kept", "SVCB 1 foo.example.com. ipv4hint=192.0.2.3,192.0.2.1",
  "0001" ^ foo_com ^ "0004 0008 c0000203 c0000201",
  svcb ~priority:1 ~target:"foo.example.com" [ Ipv4_hint [ ip4 "192.0.2.3" ; ip4 "192.0.2.1" ] ] ;
  "generic form of a known key", {|SVCB 1 foo.example.com. key3="\001\187"|},
  "0001" ^ foo_com ^ "0003 0002 01bb",
  svcb ~priority:1 ~target:"foo.example.com" [ Port 443 ] ;
  "complex mandatory",
  "SVCB 1 foo.example.com. mandatory=port,alpn,ipv4hint port=443 alpn=h2,h3 ipv4hint=192.0.2.1",
  "0001" ^ foo_com ^ "0000 0006 0001 0003 0004 0001 0006 026832 026833 0003 0002 01bb 0004 0004 c0000201",
  svcb ~priority:1 ~target:"foo.example.com"
    [ Mandatory [ 1 ; 3 ; 4 ] ; Alpn [ "h2" ; "h3" ] ; Port 443 ; Ipv4_hint [ ip4 "192.0.2.1" ] ] ;
  "high priority and key", "SVCB 65535 foo.example.com. key65000=value123",
  "ffff" ^ foo_com ^ "fde8 0008 76616c7565313233",
  svcb ~priority:65535 ~target:"foo.example.com" [ Key (65000, "value123") ] ;
  "AliasMode root target", "HTTPS 0 .",
  "0000 00",
  svcb ~priority:0 ~target:"." [] ;
]

let typ_of zone = if String.sub zone 0 4 = "SVCB" then 64 else 65

let zone_parse (_, zone, _, expected) () =
  Alcotest.(check (result (list svcb_t) msg) "parse"
              (Ok [ expected ]) (parse_one ("example.com. 3600 " ^ zone ^ "\n")))

let zone_roundtrip (_, zone, _, _) () =
  match Dns_zone.parse ("example.com. 3600 " ^ zone ^ "\n") with
  | Error (`Msg m) -> Alcotest.fail m
  | Ok m ->
    let text =
      Domain_name.Map.fold (fun name rrs acc ->
          Rr_map.fold (fun b acc -> acc ^ Rr_map.text_b name b ^ "\n") rrs acc)
        m ""
    in
    match Dns_zone.parse text with
    | Error (`Msg e) -> Alcotest.failf "%s does not parse: %s" text e
    | Ok m' -> Alcotest.(check bool ("roundtrip " ^ text) true (Name_rr_map.equal m m'))

let wire_encode (_, _, hex, value) () =
  Alcotest.(check string "encode") (to_hex (of_hex hex)) (to_hex (encode_rdata value))

let wire_decode (_, zone, hex, value) () =
  let typ = typ_of zone in
  match decode_rdata ~typ (of_hex hex) with
  | Error e -> Alcotest.failf "decode error %a" Packet.pp_err e
  | Ok t ->
    Alcotest.check svcb_t "decoded" value t;
    Alcotest.(check string "re-encoded") (to_hex (of_hex hex)) (to_hex (encode_rdata t))

let vector_tests f = List.map (fun ((d, _, _, _) as v) -> d, `Quick, f v) vectors

(* RFC 9460 Appendix D.3 and other invalid zone input *)
let zone_failures = [
  "repeated key", "SVCB 1 foo.example.com. key123=abc key123=def" ;
  "mandatory without value", "SVCB 1 foo.example.com. mandatory" ;
  "alpn without value", "SVCB 1 foo.example.com. alpn" ;
  "port without value", "SVCB 1 foo.example.com. port" ;
  "ipv4hint without value", "SVCB 1 foo.example.com. ipv4hint" ;
  "ipv6hint without value", "SVCB 1 foo.example.com. ipv6hint" ;
  "empty alpn", "SVCB 1 foo.example.com. alpn=" ;
  "empty port", "SVCB 1 foo.example.com. port=" ;
  "no-default-alpn with value", "SVCB 1 foo.example.com. no-default-alpn=abc" ;
  "mandatory key missing", "SVCB 1 foo.example.com. mandatory=key123" ;
  "mandatory lists mandatory", "SVCB 1 foo.example.com. mandatory=mandatory" ;
  "mandatory repeats key", "SVCB 1 foo.example.com. mandatory=key123,key123 key123=abc" ;
  "mandatory twice", "SVCB 1 foo.example.com. mandatory=alpn mandatory=port alpn=h2 port=443" ;
  "AliasMode with params", "HTTPS 0 foo.example.com. port=443" ;
  "no-default-alpn without alpn", "HTTPS 1 foo.example.com. no-default-alpn" ;
  "port out of range", "SVCB 1 foo.example.com. port=65536" ;
  "port with escape", {|SVCB 1 foo.example.com. port=\053\051|} ;
  "bad ipv4hint", "SVCB 1 foo.example.com. ipv4hint=192.0.2.256" ;
  "bad ech", "SVCB 1 foo.example.com. ech=!!" ;
  "unknown key name", "SVCB 1 foo.example.com. foo=bar" ;
  "key with leading zero", "SVCB 1 foo.example.com. key0667=hello" ;
  "invalid key 65535", "SVCB 1 foo.example.com. key65535=x" ;
  "empty list item", "SVCB 1 foo.example.com. alpn=h2,,h3" ;
]

let zone_failure (_, zone) () =
  match parse_one ("example.com. 3600 " ^ zone ^ "\n") with
  | Ok _ -> Alcotest.fail "expected parse error"
  | Error _ -> ()

(* malformed wire format, must be rejected without exceptions *)
let wire_failures = [
  "truncated rdata", "0001" ;
  "key without length", "0001" ^ foo_com ^ "0003" ;
  "param exceeds rdata", "0001" ^ foo_com ^ "0003 0004 01bb" ;
  "keys not increasing", "0001" ^ foo_com ^ "0003 0002 01bb 0001 0003 026832" ;
  "duplicate key", "0001" ^ foo_com ^ "0003 0002 01bb 0003 0002 0050" ;
  "mandatory odd length", "0001" ^ foo_com ^ "0000 0003 000100" ;
  "mandatory empty", "0001" ^ foo_com ^ "0000 0000" ;
  "mandatory lists mandatory", "0001" ^ foo_com ^ "0000 0002 0000" ;
  "mandatory not increasing", "0001" ^ foo_com ^ "0000 0004 0003 0001 0001 0003 026832 0003 0002 01bb" ;
  "mandatory key missing", "0001" ^ foo_com ^ "0000 0002 0003" ;
  "alpn empty", "0001" ^ foo_com ^ "0001 0000" ;
  "alpn-id empty", "0001" ^ foo_com ^ "0001 0001 00" ;
  "alpn-id exceeds value", "0001" ^ foo_com ^ "0001 0002 0568 0003 0002 01bb" ;
  "no-default-alpn without length", "0001" ^ foo_com ^ "0001 0003 026832 0002" ;
  "no-default-alpn with value", "0001" ^ foo_com ^ "0001 0003 026832 0002 0001 00" ;
  "no-default-alpn without alpn", "0001" ^ foo_com ^ "0002 0000" ;
  "port length 1", "0001" ^ foo_com ^ "0003 0001 01" ;
  "port length 4", "0001" ^ foo_com ^ "0003 0004 01bb0000" ;
  "ipv4hint length 5", "0001" ^ foo_com ^ "0004 0005 c000020101" ;
  "ipv4hint empty", "0001" ^ foo_com ^ "0004 0000" ;
  "ipv6hint length 15", "0001" ^ foo_com ^ "0006 000f 20010db8000000000000000000000001" ;
  "key 65535", "0001" ^ foo_com ^ "ffff 0000" ;
]

let wire_failure (_, hex) () =
  match decode_rdata (of_hex hex) with
  | Ok t -> Alcotest.failf "expected an error, got %a" Svcb.pp t
  | Error _ -> ()
  | exception e -> Alcotest.failf "exception %s" (Printexc.to_string e)

(* records with the same priority and target but a different number of
   params made Packet.decode raise from compare *)
let compare_exception () =
  let pkt =
    of_hex "1234 0000 0001 0000 0000 0002" ^
    of_hex "07 6578616d706c65 03 636f6d 00 0001 0001" ^
    of_hex "c00c 0041 0001 0000012c 000a 0001 00 0001 0003 026832" ^
    of_hex "c00c 0041 0001 0000012c 0010 0001 00 0001 0003 026832 0003 0002 0001"
  in
  match Packet.decode pkt with
  | Ok _ -> ()
  | Error e -> Alcotest.failf "decode error %a" Packet.pp_err e
  | exception e -> Alcotest.failf "exception %s" (Printexc.to_string e)

let samples =
  let t = "svc.example.com" in
  [
    svcb ~priority:1 ~target:t [] ;
    svcb ~priority:1 ~target:t [ Port 1 ] ;
    svcb ~priority:1 ~target:t [ Port 2 ] ;
    svcb ~priority:1 ~target:t [ Alpn [ "h2" ] ; Port 1 ] ;
    svcb ~priority:1 ~target:t [ Alpn [ "h2" ; "h3" ] ; Port 1 ] ;
    svcb ~priority:1 ~target:t [ Alpn [ "h3" ; "h2" ] ; Port 1 ] ;
    svcb ~priority:1 ~target:t [ Alpn [ "h2" ] ; No_default_alpn ] ;
    svcb ~priority:1 ~target:t [ Mandatory [ 1 ] ; Alpn [ "h2" ] ] ;
    svcb ~priority:1 ~target:t [ Mandatory [ 1 ; 3 ] ; Alpn [ "h2" ] ; Port 1 ] ;
    svcb ~priority:1 ~target:t [ Ipv4_hint [ ip4 "192.0.2.1" ] ] ;
    svcb ~priority:1 ~target:t [ Ipv4_hint [ ip4 "192.0.2.1" ; ip4 "192.0.2.2" ] ] ;
    svcb ~priority:1 ~target:t [ Ech "a" ] ;
    svcb ~priority:1 ~target:t [ Ipv6_hint [ ip6 "2001:db8::1" ] ] ;
    svcb ~priority:1 ~target:t [ Key (7, "a") ] ;
    svcb ~priority:1 ~target:t [ Key (7, "b") ] ;
    svcb ~priority:1 ~target:t [ Key (8, "a") ] ;
    svcb ~priority:1 ~target:"other.example.com" [ Port 1 ] ;
    svcb ~priority:2 ~target:t [] ;
  ]

let compare_total_order () =
  let sign x = Int.compare x 0 in
  List.iteri (fun i a ->
      List.iteri (fun j b ->
          let c = Svcb.compare a b in
          Alcotest.(check int "antisymmetric" (sign c) (- (sign (Svcb.compare b a))));
          Alcotest.(check bool "equal iff same" (i = j) (c = 0));
          List.iter (fun x ->
              if c < 0 && Svcb.compare b x < 0 then
                Alcotest.(check bool "transitive" true (Svcb.compare a x < 0)))
            samples)
        samples)
    samples;
  let set = List.fold_left (fun s x -> Rr_map.Svcb_set.add x s) Rr_map.Svcb_set.empty (samples @ samples) in
  Alcotest.(check int "set cardinality" (List.length samples) (Rr_map.Svcb_set.cardinal set))

let v_sorts () =
  let a = svcb ~priority:1 ~target:"." [ Port 1 ; Mandatory [ 3 ; 1 ] ; Alpn [ "h2" ] ] in
  let b = svcb ~priority:1 ~target:"." [ Mandatory [ 1 ; 3 ] ; Alpn [ "h2" ] ; Port 1 ] in
  Alcotest.check svcb_t "sorted" a b;
  Alcotest.(check (list int) "keys" [ 0 ; 1 ; 3 ] (List.map Svcb.param_key a.svc_params))

let v_errors () =
  let bad name params =
    match Svcb.v ~priority:1 ~target:(n ".") params with
    | Ok t -> Alcotest.failf "%s: expected an error, got %a" name Svcb.pp t
    | Error _ -> ()
  in
  bad "duplicate key" [ Port 1 ; Port 2 ] ;
  bad "duplicate in mandatory" [ Mandatory [ 3 ; 3 ] ; Port 1 ] ;
  bad "empty alpn" [ Alpn [] ] ;
  bad "empty alpn-id" [ Alpn [ "" ] ] ;
  bad "long alpn-id" [ Alpn [ String.make 256 'a' ] ] ;
  bad "port range" [ Port 65536 ] ;
  bad "empty hint" [ Ipv4_hint [] ] ;
  bad "key 3 as Key" [ Key (3, "x") ] ;
  bad "key 65535" [ Key (65535, "") ] ;
  bad "value too long" [ Key (7, String.make 65536 'a') ] ;
  (match Svcb.v ~priority:65536 ~target:(n ".") [] with
   | Ok _ -> Alcotest.fail "priority out of range"
   | Error _ -> ())

let pp_output () =
  let t = svcb ~priority:1 ~target:"." [ Alpn [ "h2" ; "a,b" ] ; Port 443 ; Key (667, "x y\"") ] in
  Alcotest.(check string "pp" {|1 . alpn=h2,a\\,b port=443 key667=x\032y\"|}
              (Fmt.to_to_string Svcb.pp t))

(* the SVCB lexer rule must not break unquoted key=value TXT data *)
let txt_with_equals () =
  match Dns_zone.parse "example.com. 3600 TXT v=spf1\n" with
  | Error (`Msg m) -> Alcotest.fail m
  | Ok m ->
    match Name_rr_map.find example Rr_map.Txt m with
    | Some (_, s) -> Alcotest.(check (list string) "txt" [ "v=spf1" ] (Rr_map.Txt_set.elements s))
    | None -> Alcotest.fail "no TXT"

let tests = [
  "zone parse", vector_tests zone_parse ;
  "zone roundtrip", vector_tests zone_roundtrip ;
  "wire encode", vector_tests wire_encode ;
  "wire decode", vector_tests wire_decode ;
  "zone failures", List.map (fun ((d, _) as f) -> d, `Quick, zone_failure f) zone_failures ;
  "wire failures", List.map (fun ((d, _) as f) -> d, `Quick, wire_failure f) wire_failures ;
  "misc", [
    "decode with differing param counts", `Quick, compare_exception ;
    "compare is a total order", `Quick, compare_total_order ;
    "v sorts", `Quick, v_sorts ;
    "v errors", `Quick, v_errors ;
    "pp escapes", `Quick, pp_output ;
    "TXT with =", `Quick, txt_with_equals ;
  ] ;
]

let () = Alcotest.run "rfc9460" tests
