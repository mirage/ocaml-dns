open Dns

let n = Domain_name.of_string_exn
let example = n "example.com"
let ip4 = Ipaddr.V4.of_string_exn
let ip6 = Ipaddr.V6.of_string_exn

let of_hex s =
  let s = String.concat "" (String.split_on_char ' ' s) in
  String.init (String.length s / 2) (fun i ->
      Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))

let to_hex s = Ohex.encode s

let svcb ~priority ~target svc_params =
  Svcb.{ svc_priority = priority ;
         target_name = Domain_name.host_exn (n target) ;
         svc_params }

(* Https.t is a copy of Svcb.t; the tests compare everything as Svcb.t *)
let svcb_of_https (h : Https.t) =
  let param : Https.svc_param -> Svcb.svc_param = function
    | Mandatory ks -> Mandatory ks
    | Alpn ids -> Alpn ids
    | No_default_alpn -> No_default_alpn
    | Port p -> Port p
    | Ipv4_hint ips -> Ipv4_hint ips
    | Ipv6_hint ips -> Ipv6_hint ips
    | Key (k, v) -> Key (k, v)
  in
  Svcb.{ svc_priority = h.svc_priority ;
         target_name = h.target_name ;
         svc_params = List.map param h.svc_params }

let svcb_t =
  let module M = struct
    type t = Svcb.t
    let pp = Svcb.pp
    let equal = ( = )
  end in
  (module M : Alcotest.TESTABLE with type t = M.t)

let single = function
  | [ x ] -> x
  | l -> Alcotest.failf "expected one record, got %d" (List.length l)

(* records of the given type at example.com, as Svcb.t *)
let find typ m =
  match typ with
  | `Svcb ->
    Option.map (fun (_, s) -> Rr_map.Svcb_set.elements s)
      (Name_rr_map.find example Rr_map.Svcb m)
  | `Https ->
    Option.map (fun (_, s) -> List.map svcb_of_https (Rr_map.Https_set.elements s))
      (Name_rr_map.find example Rr_map.Https m)

(* a response for example.com with a single SVCB or HTTPS answer *)
let packet_of_rdata typ rdata =
  let typ = match typ with `Svcb -> 64 | `Https -> 65 in
  of_hex "0001 8400 0001 0001 0000 0000" ^
  of_hex "07 6578616d706c65 03 636f6d 00" ^
  of_hex (Printf.sprintf "%04x 0001" typ) ^
  of_hex (Printf.sprintf "c00c %04x 0001 00000e10 %04x" typ (String.length rdata)) ^
  rdata

let decode_rdata typ rdata =
  match Packet.decode (packet_of_rdata typ rdata) with
  | Error e -> Error e
  | Ok { Packet.data = `Answer (a, _) ; _ } ->
    (match find typ a with
     | Some l -> Ok (single l)
     | None -> Alcotest.fail "no record in the answer")
  | Ok _ -> Alcotest.fail "expected an answer"

(* the RDATA of t, encoded as an SVCB answer for example.com *)
let encode_rdata t =
  let answer =
    Name_rr_map.singleton example Rr_map.Svcb (3600l, Rr_map.Svcb_set.singleton t)
  in
  let p =
    Packet.create (1, Packet.Flags.empty) (example, `K (Rr_map.K Rr_map.Svcb))
      (`Answer (answer, Domain_name.Map.empty))
  in
  let wire, _ = Packet.encode `Udp p in
  (* header (12), question (17), answer up to and including RDLENGTH (12) *)
  String.sub wire 41 (String.length wire - 41)

let zone rr = "example.com. 3600 " ^ rr ^ "\n"

let typ_of rr = if String.starts_with ~prefix:"HTTPS" rr then `Https else `Svcb

let parse rr =
  match Dns_zone.parse (zone rr) with
  | Error e -> Error e
  | Ok m ->
    match find (typ_of rr) m with
    | Some l -> Ok l
    | None -> Alcotest.fail "no SVCB or HTTPS record"

(* name, presentation format, wire format (RDATA), value *)
let foo_com = "03666f6f 076578616d706c65 03636f6d 00"

let vectors = [
  (* RFC 9460, Appendix D.1 and D.2 *)
  "D.1 AliasMode", "HTTPS 0 foo.example.com.",
  "0000" ^ foo_com,
  svcb ~priority:0 ~target:"foo.example.com" [] ;
  "D.2 port", "SVCB 16 foo.example.com. port=53",
  "0010" ^ foo_com ^ "0003 0002 0035",
  svcb ~priority:16 ~target:"foo.example.com" [ Port 53 ] ;
  "D.2 generic key", "SVCB 1 foo.example.com. key667=hello",
  "0001" ^ foo_com ^ "029b 0005 68656c6c6f",
  svcb ~priority:1 ~target:"foo.example.com" [ Key (667, "hello") ] ;
  (* more *)
  "AliasMode", "HTTPS 0 target.example.org.",
  "0000 06746172676574 076578616d706c65 036f7267 00",
  svcb ~priority:0 ~target:"target.example.org" [] ;
  "ServiceMode without params", "SVCB 1 foo.example.com.",
  "0001" ^ foo_com,
  svcb ~priority:1 ~target:"foo.example.com" [] ;
  "target is owner", "SVCB 1 example.com. port=8080",
  "0001 076578616d706c65 03636f6d 00 0003 0002 1f90",
  svcb ~priority:1 ~target:"example.com" [ Port 8080 ] ;
  "HTTPS port", "HTTPS 1 . port=443",
  "0001 00 0003 0002 01bb",
  svcb ~priority:1 ~target:"." [ Port 443 ] ;
  "high priority and key", "SVCB 65535 foo.example.com. key65000=value123",
  "ffff" ^ foo_com ^ "fde8 0008 76616c7565313233",
  svcb ~priority:65535 ~target:"foo.example.com" [ Key (65000, "value123") ] ;
  "one alpn", "HTTPS 1 foo.example.com. alpn=h2",
  "0001" ^ foo_com ^ "0001 0003 026832",
  svcb ~priority:1 ~target:"foo.example.com" [ Alpn [ "h2" ] ] ;
  "one ipv4 hint", "SVCB 1 foo.example.com. ipv4hint=192.0.2.1",
  "0001" ^ foo_com ^ "0004 0004 c0000201",
  svcb ~priority:1 ~target:"foo.example.com" [ Ipv4_hint [ ip4 "192.0.2.1" ] ] ;
  "one ipv6 hint", "SVCB 1 foo.example.com. ipv6hint=2001:db8::1",
  "0001" ^ foo_com ^ "0006 0010 20010db8000000000000000000000001",
  svcb ~priority:1 ~target:"foo.example.com" [ Ipv6_hint [ ip6 "2001:db8::1" ] ] ;
]

(* zone file input only: name, presentation format, value *)
let parse_only = [
  "D.2 two ipv6 hints",
  {|SVCB 1 foo.example.com. (
                  ipv6hint="2001:db8::1,2001:db8::53:1"
                  )|},
  svcb ~priority:1 ~target:"foo.example.com"
    [ Ipv6_hint [ ip6 "2001:db8::1" ; ip6 "2001:db8::53:1" ] ] ;
  "D.2 key ordering",
  {|SVCB 16 foo.example.org. (
                  alpn=h2,h3-19 mandatory=ipv4hint,alpn
                  ipv4hint=192.0.2.1
                  )|},
  svcb ~priority:16 ~target:"foo.example.org"
    [ Mandatory [ 1 ; 4 ] ; Alpn [ "h2" ; "h3-19" ] ; Ipv4_hint [ ip4 "192.0.2.1" ] ] ;
  "alpn order kept", "HTTPS 1 foo.example.com. alpn=h3,h2,http/1.1",
  svcb ~priority:1 ~target:"foo.example.com" [ Alpn [ "h3" ; "h2" ; "http/1.1" ] ] ;
  "ipv4 hint order kept", "SVCB 1 foo.example.com. ipv4hint=192.0.2.3,192.0.2.1",
  svcb ~priority:1 ~target:"foo.example.com" [ Ipv4_hint [ ip4 "192.0.2.3" ; ip4 "192.0.2.1" ] ] ;
  "mandatory", "SVCB 1 foo.example.com. mandatory=alpn alpn=h2",
  svcb ~priority:1 ~target:"foo.example.com" [ Mandatory [ 1 ] ; Alpn [ "h2" ] ] ;
  "complex mandatory",
  "SVCB 1 foo.example.com. mandatory=port,alpn,ipv4hint port=443 alpn=h2,h3 ipv4hint=192.0.2.1",
  svcb ~priority:1 ~target:"foo.example.com"
    [ Mandatory [ 1 ; 3 ; 4 ] ; Alpn [ "h2" ; "h3" ] ; Port 443 ; Ipv4_hint [ ip4 "192.0.2.1" ] ] ;
  "HTTPS with several params",
  "HTTPS 1 foo.example.com. alpn=h2,h3 port=8443 ipv4hint=192.0.2.1 ipv6hint=2001:db8::1",
  svcb ~priority:1 ~target:"foo.example.com"
    [ Alpn [ "h2" ; "h3" ] ; Port 8443 ; Ipv4_hint [ ip4 "192.0.2.1" ] ; Ipv6_hint [ ip6 "2001:db8::1" ] ] ;
]

let zone_parse rr value () =
  match parse rr with
  | Error (`Msg m) -> Alcotest.fail m
  | Ok l -> Alcotest.check svcb_t "parsed" value (single l)

let wire_encode (_, _, hex, value) () =
  Alcotest.(check string "encoded") (to_hex (of_hex hex)) (to_hex (encode_rdata value))

let wire_decode (_, rr, hex, value) () =
  match decode_rdata (typ_of rr) (of_hex hex) with
  | Error e -> Alcotest.failf "decode error %a" Packet.pp_err e
  | Ok t ->
    Alcotest.check svcb_t "decoded" value t;
    Alcotest.(check string "re-encoded") (to_hex (of_hex hex)) (to_hex (encode_rdata t))

(* RFC 9460, Appendix D.3, and other invalid zone file input *)
let zone_failures = [
  "repeated key", "SVCB 1 foo.example.com. key123=abc key123=def" ;
  "mandatory key missing", "SVCB 1 foo.example.com. mandatory=port" ;
  "mandatory lists mandatory", "SVCB 1 foo.example.com. mandatory=mandatory,alpn alpn=h2" ;
  "mandatory repeats key", "SVCB 1 foo.example.com. mandatory=key123,key123 key123=abc" ;
  "mandatory repeats known key", "SVCB 1 foo.example.com. mandatory=port,alpn,port alpn=h2 port=443" ;
  "mandatory twice", "SVCB 1 foo.example.com. mandatory=alpn mandatory=port alpn=h2 port=443" ;
  "AliasMode with params", "HTTPS 0 foo.example.com. port=443" ;
]

let zone_failure (_, rr) () =
  match parse rr with
  | Ok l -> Alcotest.failf "expected an error, got %a" Fmt.(list Svcb.pp) l
  | Error _ -> ()

let tests = [
  "zone parse", List.map (fun (d, rr, _, v) -> d, `Quick, zone_parse rr v) vectors ;
  "zone parse only", List.map (fun (d, rr, v) -> d, `Quick, zone_parse rr v) parse_only ;
  "wire encode", List.map (fun ((d, _, _, _) as v) -> d, `Quick, wire_encode v) vectors ;
  "wire decode", List.map (fun ((d, _, _, _) as v) -> d, `Quick, wire_decode v) vectors ;
  "zone failures", List.map (fun ((d, _) as f) -> d, `Quick, zone_failure f) zone_failures ;
]

let () = Alcotest.run "rfc9460" tests
