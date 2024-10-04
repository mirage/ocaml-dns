
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


(*
Failure Cases
-------------

; Multiple Instances of the Same SvcParamKey
example.com. SVCB 1 foo.example.com. (
                  key123=abc key123=def
                  )
*)


(*
; Missing SvcParamValues That Must Be Non-Empty
example.com. SVCB 1 foo.example.com. mandatory
example.com. SVCB 1 foo.example.com. alpn
example.com. SVCB 1 foo.example.com. port
example.com. SVCB 1 foo.example.com. ipv4hint
example.com. SVCB 1 foo.example.com. ipv6hint
*)


(*
; The "no-default-alpn" SvcParamKey Value Must Be Empty
example.com. SVCB 1 foo.example.com. no-default-alpn=abc
*)


(*
; A Mandatory SvcParam Is Missing
example.com. SVCB 1 foo.example.com. mandatory=key123
*)


(*
; The "mandatory" SvcParamKey Must Not Be Included in the Mandatory List
example.com. SVCB 1 foo.example.com. mandatory=mandatory
v
; Multiple Instances of the Same SvcParamKey in the Mandatory List
example.com. SVCB 1 foo.example.com. (
                  mandatory=key123,key123 key123=abc
                  )
*)



