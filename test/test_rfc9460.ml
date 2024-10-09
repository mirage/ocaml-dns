
open Dns

let n_of_s = Domain_name.of_string_exn


let name_map_ok =
    let module M = struct
      type t = Name_rr_map.t
      let pp = Name_rr_map.pp
      let equal = Name_rr_map.equal
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

let err =
    let module M = struct
        type t = [ `Msg of string ]
        let pp ppf (`Msg s) = Fmt.string ppf s
        let equal _ _ = true
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)
    
module Passing = struct

(* 
From appendix D - test vectors

D.1. AliasMode
--------------

; AliasMode
example.com. HTTPS 0 foo.example.com.

\# 19 (
00 00                                              ; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target
)

\x00\x00                      # priority
\x03foo\x07example\x03com\x00 # target
*)

let alias_mode = {|
; AliasMode
example.com. HTTPS 0 foo.example.com.
|}

let parse_alias_mode () =
  let rrs =
    (* let tld = n_of_s "com" in *)
      let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let https = Https.{
        svc_priority = 0 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [] ;
      } in
      let https' = Rr_map.Https_set.singleton https in
      Name_rr_map.add example Rr_map.Https (ttl,https') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "alias mode"
                (Ok rrs)  (Dns_zone.parse alias_mode))

(* 

D.2. ServiceMode
----------------

; TargetName Is "."
example.com. SVCB 1 .

\# 3 (
00 01 ; priority
00    ; target (root label)
)

\x00\x01 # priority
\x00     # target (root label)
*)

let service_mode = {|
; TargetName Is "."
example.com. SVCB 1 .
|}

(* 
let parse_service_mode () =
  let rrs =
    (* let tld = n_of_s "com" in *)
      let ttl = 3600l in
    let example = n_of_s "example.com" in
    let dot = n_of_s "." in
    let svcb = Svcb.{
        svc_priority = 0 ;
        (* target_name = Domain_name.host_exn dot ; *)
        target_name = Domain_name. dot ;
        svc_params = [] ;
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "service mode"
                (Ok rrs)  (Dns_zone.parse alias_mode))
 *)

(*
; Specifies a port
example.com. SVCB 16 foo.example.com. port=53

\# 25 (
00 10                                              ; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target
00 03                                              ; key 3
00 02                                              ; length 2
00 35                                              ; value
)

\x00\x10                      # priority
\x03foo\x07example\x03com\x00 # target
\x00\x03                      # key 3
\x00\x02                      # length 2
\x00\x35                      # value

*)

let port_specification = {|
; Specifies a port
example.com. SVCB 16 foo.example.com. port=53
|}

let parse_port_specification () =
  let rrs =
    (* let tld = n_of_s "com" in *)
      let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let svcb = Svcb.{
        svc_priority = 16 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Port 53
        ] ;
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "port specification"
                (Ok rrs)  (Dns_zone.parse port_specification))


(*
; A Generic Key and Unquoted Value
example.com. SVCB 1 foo.example.com. key667=hello

\# 28 (
00 01                                              ; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target
02 9b                                              ; key 667
00 05                                              ; length 5
68 65 6c 6c 6f                                     ; value
)

\x00\x01                      # priority
\x03foo\x07example\x03com\x00 # target
\x02\x9b                      # key 667
\x00\x05                      # length 5
hello                         # value
*)

let value_unquoted = {|
; A Generic Key and Unquoted Value
example.com. SVCB 1 foo.example.com. key667=hello
|}

let parse_value_unquoted () =
  let rrs =
    (* let tld = n_of_s "com" in *)
      let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let svcb = Svcb.{
        svc_priority = 1 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Key (667,"hello")
        ] ;
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "value unquoted"
                (Ok rrs)  (Dns_zone.parse value_unquoted))



(*
; A Generic Key and Quoted Value with a Decimal Escape
example.com. SVCB 1 foo.example.com. key667="hello\210qoo"

\# 32 (
00 01                                              ; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target
02 9b                                              ; key 667
00 09                                              ; length 9
68 65 6c 6c 6f d2 71 6f 6f                         ; value
)

\x00\x01                      # priority
\x03foo\x07example\x03com\x00 # target
\x02\x9b                      # key 667
\x00\x09                      # length 9
hello\xd2qoo                  # value
*)
(* 
let quoted = {|
; A Generic Key and Quoted Value with a Decimal Escape
example.com. SVCB 1 foo.example.com. key667="hello\210qoo"
|}

let parse_quoted () =
  let rrs =
    (* let tld = n_of_s "com" in *)
      let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let svcb = Svcb.{
        svc_priority = 1 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Key (667,"hello\\210qoo")
        ] ;
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "value quoted"
                (Ok rrs)  (Dns_zone.parse value_unquoted))
 *)

(*
; Two Quoted IPv6 Hints
example.com. SVCB 1 foo.example.com. (
                  ipv6hint="2001:db8::1,2001:db8::53:1"
                  )

\# 55 (
00 01                                              ; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 ; target
00 06                                              ; key 6
00 20                                              ; length 32
20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01    ; first address
20 01 0d b8 00 00 00 00 00 00 00 00 00 53 00 01    ; second address
)

\x00\x01                             # priority
\x03foo\x07example\x03com\x00        # target
\x00\x06                             # key 6
\x00\x20                             # length 32
\x20\x01\x0d\xb8\x00\x00\x00\x00
    \x00\x00\x00\x00\x00\x00\x00\x01 # first address
\x20\x01\x0d\xb8\x00\x00\x00\x00
    \x00\x00\x00\x00\x00\x53\x00\x01 # second address
*)

let quoted_hints = {|
; Two Quoted IPv6 Hints
example.com. SVCB 1 foo.example.com. (
                  ipv6hint="2001:db8::1,2001:db8::53:1"
                  )
|}

let parse_quoted_hints () =
  (* let ip1 = Result.get_ok (Ipaddr.V6.of_string "2001:db8::1") in
  let ip2 = Result.get_ok (Ipaddr.V6.of_string "2001:db8::53:1") in *)
  let ip1 = Ipaddr.V6.of_string_exn "2001:db8::1" in
  let ip2 = Ipaddr.V6.of_string_exn "2001:db8::53:1" in
  let rrs =
    (* let tld = n_of_s "com" in *)
      let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let svcb = Svcb.{
        svc_priority = 1 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Ipv6_hint [ip1;ip2]
        ] ;
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "quoted hints"
                (Ok rrs)  (Dns_zone.parse quoted_hints))



(*
; An IPv6 Hint Using the Embedded IPv4 Syntax
example.com. SVCB 1 example.com. (
                  ipv6hint="2001:db8:122:344::192.0.2.33"
                  )

\# 35 (
00 01                                           ; priority
07 65 78 61 6d 70 6c 65 03 63 6f 6d 00          ; target
00 06                                           ; key 6
00 10                                           ; length 16
20 01 0d b8 01 22 03 44 00 00 00 00 c0 00 02 21 ; address
)

\x00\x01                         # priority
\x07example\x03com\x00           # target
\x00\x06                         # key 6
\x00\x10                         # length 16
\x20\x01\x0d\xb8\x01\x22\x03\x44
\x00\x00\x00\x00\xc0\x00\x02\x21 # address
*)
(* 
let generic_key_and_quoted_hints = {|
; An IPv6 Hint Using the Embedded IPv4 Syntax
example.com. SVCB 1 example.com. (
                  ipv6hint="2001:db8:122:344::192.0.2.33"
                  )
|}

let parse_generic_key_and_quoted_hints () =
  let ip1 = Result.get_ok (Ipaddr.V6.of_string "2001:db8:122:344") in
  let ip2 = Result.get_ok (Ipaddr.V4.of_string "192.0.2.33") in
  let rrs =
    (* let tld = n_of_s "com" in *)
      let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let svcb = Svcb.{
        svc_priority = 1 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Ipv6_hint [ip1;ip2]
        ] ;
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "generic key and quoted hints"
                (Ok rrs)  (Dns_zone.parse generic_key_and_quoted_hints))
 *)


(*
; SvcParamKey Ordering Is Arbitrary in Presentation Format but Sorted in Wire Format
example.com. SVCB 16 foo.example.org. (
                  alpn=h2,h3-19 mandatory=ipv4hint,alpn
                  ipv4hint=192.0.2.1
                  )

\# 48 (
00 10                                              ; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target
00 00                                              ; key 0
00 04                                              ; param length 4
00 01                                              ; value: key 1
00 04                                              ; value: key 4
00 01                                              ; key 1
00 09                                              ; param length 9
02                                                 ; alpn length 2
68 32                                              ; alpn value
05                                                 ; alpn length 5
68 33 2d 31 39                                     ; alpn value
00 04                                              ; key 4
00 04                                              ; param length 4
c0 00 02 01                                        ; param value
)

\x00\x10                      # priority
\x03foo\x07example\x03org\x00 # target
\x00\x00                      # key 0
\x00\x04                      # param length 4
\x00\x01                      # value: key 1
\x00\x04                      # value: key 4
\x00\x01                      # key 1
\x00\x09                      # param length 9
\x02                          # alpn length 2
h2                            # alpn value
\x05                          # alpn length 5
h3-19                         # alpn value
\x00\x04                      # key 4
\x00\x04                      # param length 4
\xc0\x00\x02\x01              # param value
*)

(*
(
                  alpn=h2,h3-19 mandatory=ipv4hint,alpn
                  ipv4hint=192.0.2.1
                  )
*)

let svc_param_key_ordering = {|
; SvcParamKey Ordering Is Arbitrary in Presentation Format but Sorted in Wire Format
example.com. SVCB 16 foo.example.org. (
                  alpn=h2,h3-19 mandatory=ipv4hint,alpn
                  ipv4hint=192.0.2.1
                  )
|}

let parse_svc_param_key_ordering () =
  let ip = Ipaddr.V4.of_string_exn "192.0.2.1" in
  let rrs =
    (* let tld = n_of_s "com" in *)
    let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.org" in
    let svcb = Svcb.{
        svc_priority = 16 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Mandatory [1;4];
          Alpn ["h2"; "h3-19"];
          Ipv4_hint [ip]
        ] ;
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "svc param key ordering"
                (Ok rrs)  (Dns_zone.parse svc_param_key_ordering))

                (*
                
          Mandatory [1;4];
          Alpn ["h2"; "h3-19"];
          Ipv4_hint [ip]
          
          *)

(*
; An "alpn" Value with an Escaped Comma and an Escaped Backslash in Two Presentation Formats
example.com. SVCB 16 foo.example.org. alpn="f\\\\oo\\,bar,h2"
example.com. SVCB 16 foo.example.org. alpn=f\\\092oo\092,bar,h2

\# 35 (
00 10                                              ; priority
03 66 6f 6f 07 65 78 61 6d 70 6c 65 03 6f 72 67 00 ; target
00 01                                              ; key 1
00 0c                                              ; param length 12
08                                                 ; alpn length 8
66 5c 6f 6f 2c 62 61 72                            ; alpn value
02                                                 ; alpn length 2
68 32                                              ; alpn value
)

\x00\x10                      # priority
\x03foo\x07example\x03org\x00 # target
\x00\x01                      # key 1
\x00\x0c                      # param length 12
\x08                          # alpn length 8
f\oo,bar                      # alpn value
\x02                          # alpn length 2
h2                            # alpn value
*)

let escaped_comma_backslash = {|
; An "alpn" Value with an Escaped Comma and an Escaped Backslash in Two Presentation Formats
example.com. SVCB 16 foo.example.org. alpn="f\\\\oo\\,bar,h2"
example.com. SVCB 16 foo.example.org. alpn=f\\\092oo\092,bar,h2
|}


let parse_escaped_comma_backslash () =
  let rrs =
    let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.org" in
    let svcb1 = Svcb.{
        svc_priority = 16 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Alpn ["f\\\\oo\\"; "bar"; "h2"]
        ] ;
      } in
    let svcb1' = Rr_map.Svcb_set.singleton svcb1 in
    let svcb2 = Svcb.{
        svc_priority = 16 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Alpn ["f\\\092oo\092"; "bar"; "h2"]
        ] ;
      } in
    let svcb2' = Rr_map.Svcb_set.singleton svcb2 in
    Name_rr_map.(add example Rr_map.Svcb (ttl,svcb1') (singleton example Rr_map.Svcb (ttl,svcb2')));
  in
  Alcotest.(check (result name_map_ok err) "escaped comma backslash"
                (Ok rrs)  (Dns_zone.parse escaped_comma_backslash))

    let tests = [
        "parse alias mode", `Quick, parse_alias_mode;
        (* "parse service mode", `Quick, parse_service_mode; *) (* failing on target = '.' *)
        "parse port specification", `Quick, parse_port_specification;
        "parse value unquoted", `Quick, parse_value_unquoted;
        (* "parse quoted", `Quick, parse_quoted; *)
        "quoted hints", `Quick, parse_quoted_hints;
        (* "generic key and quoted hints", `Quick, parse_generic_key_and_quoted_hints; *) (* need to implement happy eyeballs v2 synthesis*)
        "svc param key ordering", `Quick, parse_svc_param_key_ordering;
        "escaped comma backslash", `Quick, parse_escaped_comma_backslash
    ]

end


module Failing = struct
(* 

Failure Cases
-------------

; Multiple Instances of the Same SvcParamKey
example.com. SVCB 1 foo.example.com. (
                  key123=abc key123=def
                  )
*)

let failure_svc_param_key = {|
; Multiple Instances of the Same SvcParamKey
example.com. SVCB 1 foo.example.com. (
                  key123=abc key123=def
                  )
|}

let parse_failure_svc_param_key () =
  let rrs =
    let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let svcb = Svcb.{
        svc_priority = 0 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Key (123,"abc");
          Key (123,"def")
        ]
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "failure svc param key"
                (Ok rrs)  (Dns_zone.parse failure_svc_param_key))


(*
; Missing SvcParamValues That Must Be Non-Empty
example.com. SVCB 1 foo.example.com. mandatory
example.com. SVCB 1 foo.example.com. alpn
example.com. SVCB 1 foo.example.com. port
example.com. SVCB 1 foo.example.com. ipv4hint
example.com. SVCB 1 foo.example.com. ipv6hint
*)
(* 
let failure_missing_svc_param_values = {|
; Missing SvcParamValues That Must Be Non-Empty
example.com. SVCB 1 foo.example.com. mandatory
example.com. SVCB 1 foo.example.com. alpn
example.com. SVCB 1 foo.example.com. port
example.com. SVCB 1 foo.example.com. ipv4hint
example.com. SVCB 1 foo.example.com. ipv6hint
|}

Unable to build the key
 *)

(*
; The "no-default-alpn" SvcParamKey Value Must Be Empty
example.com. SVCB 1 foo.example.com. no-default-alpn=abc
*)
(* 
let failure_no_default_alpn_not_empty = {|
; The "no-default-alpn" SvcParamKey Value Must Be Empty
example.com. SVCB 1 foo.example.com. no-default-alpn=abc
|}

Unable to build the key
 *)

(*
; A Mandatory SvcParam Is Missing
example.com. SVCB 1 foo.example.com. mandatory=key123
*)
(* 
let failure_mandatory_svc_param_missing = {|
; A Mandatory SvcParam Is Missing
example.com. SVCB 1 foo.example.com. mandatory=key123
|}

Unable to build the key
 *)
(*
; The "mandatory" SvcParamKey Must Not Be Included in the Mandatory List
example.com. SVCB 1 foo.example.com. mandatory=mandatory
*)
(* 
let failure_mandatory_in_mandatory_list = {|
; The "mandatory" SvcParamKey Must Not Be Included in the Mandatory List
example.com. SVCB 1 foo.example.com. mandatory=mandatory
                  )
|}

Unable to build the key
 *)
(*
; Multiple Instances of the Same SvcParamKey in the Mandatory List
example.com. SVCB 1 foo.example.com. (
                  mandatory=key123,key123 key123=abc
                  )
*)

let failure_key_repitition_in_mandatory_list = {|
; Multiple Instances of the Same SvcParamKey in the Mandatory List
example.com. SVCB 1 foo.example.com. (
                  mandatory=key123,key123 key123=abc
                  )
|}

let parse_key_repitition_in_mandatory_list () =
  let rrs =
    let ttl = 3600l in
    let example = n_of_s "example.com" in
    let foo_example = n_of_s "foo.example.com" in
    let svcb = Svcb.{
        svc_priority = 0 ;
        target_name = Domain_name.host_exn foo_example ;
        svc_params = [
          Mandatory [123;123];
          Key (123,"abc")
        ]
      } in
      let svcb' = Rr_map.Svcb_set.singleton svcb in
      Name_rr_map.add example Rr_map.Svcb (ttl,svcb') Name_rr_map.empty
  in
  Alcotest.(check (result name_map_ok err) "failure key repitition in mandatory list"
                (Ok rrs)  (Dns_zone.parse failure_key_repitition_in_mandatory_list))


    let tests = [
        "failure_svc_param_key", `Quick, parse_failure_svc_param_key;
        "key repitition in mandatory list", `Quick, parse_key_repitition_in_mandatory_list
    ]

end


let tests = [
  "rfc9460 passing", Passing.tests ;
  "rfc9460 failing", Failing.tests
]

let () =
  Printexc.record_backtrace true;
  Logs.set_reporter (Logs_fmt.reporter ());
  Logs.set_level ~all:true (Some Logs.Debug);
  Alcotest.run "rfc9460 tests" tests
