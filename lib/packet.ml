(*
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

(* RFC1035, RFC1186 *)

open Printf
open Operators
open Uri_IP
open Wire
open Name

type dnssec_alg = 
  | RSAMD5 
  | DH
  | DSA
  | ECC
  | RSASHA1
  | RSASHA256
  | RSASHA512
  | UNKNOWN
let byte_to_dnssec_alg = function
  | 1  -> RSAMD5 
  | 2  -> DH
  | 3  -> DSA
  | 4  -> ECC
  | 5  -> RSASHA1
  | 8  -> RSASHA256
  | 10 -> RSASHA512
  | _  -> UNKNOWN
let dnssec_alg_to_byte = function
  | RSAMD5    -> 1 
  | DH        -> 2 
  | DSA       -> 3
  | ECC       -> 4
  | RSASHA1   -> 5
  | RSASHA256 -> 8
  | RSASHA512 -> 10
  | UNK       -> 6
let dnssec_alg_to_string = function
  | RSAMD5    -> "RSAMD5"  
  | DH        -> "DH"
  | DSA       -> "DSA"
  | ECC       -> "ECC"
  | RSASHA1   -> "RSASHA1"
  | RSASHA256 -> "RSASHA256"
  | RSASHA512 -> "RSASHA512"
  | UNK       -> "UNK"

type rr_type = [
| `A | `NS | `MD | `MF | `CNAME | `SOA | `MB | `MG | `MR | `NULL 
| `WKS | `PTR | `HINFO | `MINFO | `MX | `TXT | `RP | `AFSDB | `X25 
| `ISDN | `RT | `NSAP | `NSAP_PTR | `SIG | `KEY | `PX | `GPOS | `AAAA 
| `LOC | `NXT | `EID | `NIMLOC | `SRV | `ATMA | `NAPTR | `KM | `CERT 
| `A6 | `DNAME | `SINK | `OPT | `APL | `DS | `SSHFP | `IPSECKEY 
| `RRSIG | `NSEC | `DNSKEY | `SPF | `UINFO | `UID | `GID | `UNSPEC
| `Unknown of int * bytes
]

let rr_type_to_int : rr_type -> int = function
  | `A        -> 1
  | `NS       -> 2
  | `MD       -> 3
  | `MF       -> 4
  | `CNAME    -> 5
  | `SOA      -> 6
  | `MB       -> 7
  | `MG       -> 8
  | `MR       -> 9
  | `NULL     -> 10
  | `WKS      -> 11
  | `PTR      -> 12
  | `HINFO    -> 13
  | `MINFO    -> 14
  | `MX       -> 15
  | `TXT      -> 16
  | `RP       -> 17
  | `AFSDB    -> 18
  | `X25      -> 19
  | `ISDN     -> 20
  | `RT       -> 21
  | `NSAP     -> 22
  | `NSAP_PTR -> 23
  | `SIG      -> 24
  | `KEY      -> 25
  | `PX       -> 26
  | `GPOS     -> 27
  | `AAAA     -> 28
  | `LOC      -> 29
  | `NXT      -> 30
  | `EID      -> 31
  | `NIMLOC   -> 32
  | `SRV      -> 33
  | `ATMA     -> 34
  | `NAPTR    -> 35
  | `KM       -> 36
  | `CERT     -> 37
  | `A6       -> 38
  | `DNAME    -> 39
  | `SINK     -> 40
  | `OPT      -> 41
  | `APL      -> 42
  | `DS       -> 43
  | `SSHFP    -> 44
  | `IPSECKEY -> 45
  | `RRSIG    -> 46
  | `NSEC     -> 47
  | `DNSKEY   -> 48
    
  | `SPF      -> 99
  | `UINFO    -> 100
  | `UID      -> 101
  | `GID      -> 102
  | `UNSPEC   -> 103
   
  | `Unknown _ -> -1
and int_to_rr_type : int -> rr_type = function
  | 1  -> `A
  | 2  -> `NS
  | 3  -> `MD
  | 4  -> `MF
  | 5  -> `CNAME
  | 6  -> `SOA
  | 7  -> `MB
  | 8  -> `MG
  | 9  -> `MR
  | 10 -> `NULL
  | 11 -> `WKS
  | 12 -> `PTR
  | 13 -> `HINFO
  | 14 -> `MINFO
  | 15 -> `MX
  | 16 -> `TXT
  | 17 -> `RP
  | 18 -> `AFSDB 
  | 19 -> `X25 
  | 20 -> `ISDN 
  | 21 -> `RT
  | 22 -> `NSAP 
  | 23 -> `NSAP_PTR 
  | 24 -> `SIG 
  | 25 -> `KEY
  | 26 -> `PX 
  | 27 -> `GPOS 
  | 28 -> `AAAA 
  | 29 -> `LOC
  | 30 -> `NXT 
  | 31 -> `EID 
  | 32 -> `NIMLOC 
  | 33 -> `SRV 
  | 34 -> `ATMA 
  | 35 -> `NAPTR 
  | 36 -> `KM 
  | 37 -> `CERT 
  | 38 -> `A6 
  | 39 -> `DNAME 
  | 40 -> `SINK 
  | 41 -> `OPT 
  | 42 -> `APL 
  | 43 -> `DS 
  | 44 -> `SSHFP 
  | 45 -> `IPSECKEY 
  | 46 -> `RRSIG 
  | 47 -> `NSEC 
  | 48 -> `DNSKEY 
    
  | 99  -> `SPF 
  | 100 -> `UINFO 
  | 101 -> `UID 
  | 102 -> `GID 
  | 103 -> `UNSPEC

  | _ -> invalid_arg "int_to_rr_type"
and rr_type_to_string:rr_type -> string = function
  | `A        -> "A"
  | `NS       -> "NS"
  | `MD       -> "MD"
  | `MF       -> "MF"
  | `CNAME    -> "CNAME"
  | `SOA      -> "SOA"
  | `MB       -> "MB"
  | `MG       -> "MG"
  | `MR       -> "MR"
  | `NULL     -> "NULL"
  | `WKS      -> "WKS"
  | `PTR      -> "PTR"
  | `HINFO    -> "HINFO"
  | `MINFO    -> "MINFO"
  | `MX       -> "MX"
  | `TXT      -> "TXT"
  | `RP       -> "RP"
  | `AFSDB    -> "AFSDB"
  | `X25      -> "X25"
  | `ISDN     -> "ISDN"
  | `RT       -> "RT"
  | `NSAP     -> "NSAP"
  | `NSAP_PTR -> "NSAP"
  | `SIG      -> "SIG"
  | `KEY      -> "KEY"
  | `PX       -> "PX"
  | `GPOS     -> "GPOS"
  | `AAAA     -> "AAAA"
  | `LOC      -> "LOC"
  | `NXT      -> "NXT"
  | `EID      -> "EID"
  | `NIMLOC   -> "NIMLOC"
  | `SRV      -> "SRV"
  | `ATMA     -> "ATMA"
  | `NAPTR    -> "NAPTR"
  | `KM       -> "KM"
  | `CERT     -> "CERT"
  | `A6       -> "A6"
  | `DNAME    -> "DNAME"
  | `SINK     -> "SINK"
  | `OPT      -> "OPT"
  | `APL      -> "APL"
  | `DS       -> "DS"
  | `SSHFP    -> "SSHFP"
  | `IPSECKEY -> "IPSECKEY"
  | `RRSIG    -> "RRSIG"
  | `NSEC     -> "NSEC"
  | `DNSKEY   -> "DNSKEY"
  | `SPF      -> "SPF"
  | `UINFO    -> "UINFO"
  | `UID      -> "UID"
  | `GID      -> "GID"
  | `UNSPEC   -> "UNSPEC"
  | `Unknown (i, _) -> sprintf "Unknown (%d)" i

type rr_rdata = [
| `A of ipv4
| `AAAA of bytes
| `AFSDB of int16 * domain_name
| `CNAME of domain_name
| `DNSKEY of byte * dnssec_alg * string 
| `HINFO of string * string
| `ISDN of string * string option
| `MB of domain_name
| `MD of domain_name
| `MF of domain_name
| `MG of domain_name
| `MINFO of domain_name * domain_name
| `MR of domain_name
| `MX of int16 * domain_name
| `NS of domain_name
| `PTR of domain_name
| `RP of domain_name * domain_name
| `RT of int16 * domain_name
| `SOA of domain_name * domain_name * int32 * int32 * int32 * int32 * int32
| `SRV of int16 * int16 * int16 * domain_name
| `TXT of string list
| `UNKNOWN of int * bytes
| `UNSPEC of bytes
| `WKS of int32 * byte * string
| `X25 of string 
]

let rdata_to_string r = 
  match r with
      <<<<<<< HEAD
    | `A ip -> sprintf "A (%s)" (ipv4_to_string ip)
    | `AAAA bs -> sprintf "AAAA (%s)" (bytes_to_string bs)
    | `AFSDB (x, n)
      -> sprintf "AFSDB (%d, %s)" x (domain_name_to_string n)
    | `CNAME n -> sprintf "CNAME (%s)" (domain_name_to_string n)
    | `DNSKEY (flags, alg, key) ->
        sp "DNSKEY (%x %s %s)" flags (string_of_dnssec_alg alg)
          (Base64.str_encode key)
    | `HINFO (cpu, os) -> sprintf "HINFO (%s, %s)" cpu os
    | `ISDN (a, sa)
      -> sprintf "ISDN (%s, %s)" a (match sa with None -> "" | Some sa -> sa)
    | `MB n -> sprintf "MB (%s)" (domain_name_to_string n)
    | `MD n -> sprintf "MD (%s)" (domain_name_to_string n)
    | `MF n -> sprintf "MF (%s)" (domain_name_to_string n)
    | `MG n -> sprintf "MG (%s)" (domain_name_to_string n)
    | `MINFO (rm, em)
      -> (sprintf "MINFO (%s, %s)" 
            (domain_name_to_string rm) (domain_name_to_string em)
      )
    | `MR n -> sprintf "MR (%s)" (domain_name_to_string n)
    | `MX (pref, name)
      -> sprintf "MX (%d, %s)" pref (domain_name_to_string name)
    | `NS n -> sprintf "NS (%s)" (domain_name_to_string n)
    | `PTR n -> sprintf "PTR (%s)" (domain_name_to_string n)
    | `RP (mn, nn)
      -> (sprintf "RP (%s, %s)" 
            (domain_name_to_string mn) (domain_name_to_string nn)
      )
    | `RT (x, n) 
      -> sprintf "RT (%d, %s)" x (domain_name_to_string n)
    | `SOA (mn, rn, serial, refresh, retry, expire, minimum)
      -> (sprintf "SOA (%s,%s, %ld,%ld,%ld,%ld,%ld)"
            (domain_name_to_string mn) (domain_name_to_string rn) 
            serial refresh retry expire minimum)
    | `SRV (x, y, z, n) 
      -> (sprintf "SRV (%d,%d,%d, %s)" x y z (domain_name_to_string n)
      )
    | `TXT sl -> sprintf "TXT (%s)" (join "" sl)
    | `UNKNOWN (x, bs) -> sprintf "UNKNOWN (%d) '%s'" x (bytes_to_string bs)
    | `UNSPEC bs -> sprintf "UNSPEC (%s)" (bytes_to_string bs)
    | `WKS (x, y, s) -> sprintf "WKS (%ld,%d, %s)" x (byte_to_int y) s
    | `X25 s -> sprintf "X25 (%s)" s

let parse_rdata names base t bits = 
  (** Drop remainder bitstring to stop parsing and demuxing. *) 
  let stop (x, bits) = x in
  (** Extract (length, string) encoded strings, with remainder for
      chaining. *)
  let parse_charstr bits = 
    bitmatch bits with
      | { len: 8; str: (len*8): string; bits: -1: bitstring } -> str, bits
  in
  match t with
    | `A -> `A (bits |> bits_to_bytes |> bytes_to_ipv4)
    | `NS -> `NS (bits |> parse_name names base |> stop)
    | `CNAME -> `CNAME (bits |> parse_name names base |> stop)
    | `DNSKEY -> (
      bitmatch bits with 
        | {flags:16;3:8;alg:8; key:-1:string} -> 
            `DNSKEY (flags, (dnssec_alg_of_char alg), key)
    )
    | `SOA -> let mn, bits = parse_name names base bits in
              let rn, bits = parse_name names base bits in 
              (bitmatch bits with
                | { serial: 32; refresh: 32; retry: 32; expire: 32;
                    minimum: 32 }
                  -> `SOA (mn, rn, serial, refresh, retry, expire, minimum)
              )
                
    | `WKS -> (
      bitmatch bits with 
        | { addr: 32; proto: 8; bitmap: -1: string } 
          -> `WKS (addr, byte proto, bitmap)
    )
    | `PTR -> `PTR (bits |> parse_name names base |> stop)
    | `HINFO -> let cpu, bits = parse_charstr bits in
                let os = bits |> parse_charstr |> stop in
                `HINFO (cpu, os)
    | `MINFO -> let rm, bits = parse_name names base bits in
                let em = bits |> parse_name names base |> stop in
                `MINFO (rm, em)
    | `MX -> (
      bitmatch bits with
        | { preference: 16; bits: -1: bitstring } 
          -> `MX ((int16 preference, 
                   bits |> parse_name names base |> stop))
    )
    | `TXT -> let names, _ = 
                let rec aux ns bits = 
                  let n, bits = parse_name names base bits in
                  aux (n :: ns) bits
                in
                aux [] bits
              in
              `TXT names
    | t -> `UNKNOWN (rr_type_to_int t, bits_to_bytes bits)

type rr_class = [ `IN | `CS | `CH | `HS ]
let rr_class_to_int : rr_class -> int = function
  | `IN -> 1
  | `CS -> 2
  | `CH -> 3
  | `HS -> 4
and int_to_rr_class : int -> rr_class = function
  | 1   -> `IN
  | 2   -> `CS
  | 3   -> `CH
  | 4   -> `HS
  | x   -> `IN (* TODO edns0 hack (#2) invalid_arg "int_to_rr_class" *)
and rr_class_to_string : rr_class -> string = function
  | `IN -> "IN"
  | `CS -> "CS"
  | `CH -> "CH"
  | `HS -> "HS"

type rr = {
  rr_name  : domain_name;
  rr_class : rr_class;
  rr_ttl   : int32;
  rr_rdata : rr_rdata;
}

let rr_to_string rr = 
  sprintf "%s <%s|%ld> %s" 
    (domain_name_to_string rr.rr_name) (rr_class_to_string rr.rr_class) 
    rr.rr_ttl (rdata_to_string rr.rr_rdata)

let parse_rr names base bits =
  let name, bits = parse_name names base bits in
  bitmatch bits with
    | { t: 16; c: 16; ttl: 32; 
        rdlen: 16; rdata: (rdlen*8): bitstring;
        data: -1: bitstring } 
      -> let rdata = parse_rdata names base (int_to_rr_type t) rdata in
         { rr_name = name;
           rr_class = int_to_rr_class c;
           rr_ttl = ttl;
           rr_rdata = rdata;
         }, data
    | { _ } -> raise (Unparsable ("parse_rr", bits))

type q_type = [ rr_type | `AXFR | `MAILB | `MAILA | `ANY | `TA | `DLV ]
let q_type_to_int : q_type -> int = function
  | `AXFR         -> 252
  | `MAILB        -> 253
  | `MAILA        -> 254
  | `ANY          -> 255
  | `TA           -> 32768
  | `DLV          -> 32769
  | #rr_type as t -> rr_type_to_int t
and int_to_q_type : int -> q_type = function
  | 252           -> `AXFR
  | 253           -> `MAILB
  | 254           -> `MAILA
  | 255           -> `ANY
  | 32768         -> `TA
  | 32769         -> `DLV
  | n             -> (int_to_rr_type n :> q_type)
and q_type_to_string:q_type -> string = function
  | `AXFR         -> "AXFR"
  | `MAILB        -> "MAILB"
  | `MAILA        -> "MAILA"
  | `ANY          -> "ANY"
  | `TA           -> "TA"
  | `DLV          -> "DLV"
  | #rr_type as t -> rr_type_to_string t

type q_class = [ rr_class | `NONE | `ANY ]

let q_class_to_int : q_class -> int = function
  | `NONE          -> 254
  | `ANY           -> 255
  | #rr_class as c -> rr_class_to_int c
and int_to_q_class : int -> q_class = function
  | 254            -> `NONE
  | 255            -> `ANY
  | n              -> (int_to_rr_class n :> q_class)
and q_class_to_string : q_class -> string = function
  | `NONE          -> "NONE"
  | `ANY           -> "ANY"
  | #rr_class as c -> rr_class_to_string c

type question = {
  q_name  : domain_name;
  q_type  : q_type;
  q_class : q_class;
}

let question_to_string q = 
  sprintf "%s <%s|%s>" 
    (domain_name_to_string q.q_name) 
    (q_type_to_string q.q_type) (q_class_to_string q.q_class)

let parse_question names base bits = 
  let n, bits = parse_name names base bits in
  bitmatch bits with
    | { t: 16; c: 16; data: -1: bitstring }
      -> { q_name = n;
           q_type = int_to_q_type t;
           q_class = int_to_q_class c;
         }, data

type qr = [ `Query | `Answer ]
let bool_to_qr = function
  | false -> `Query
  | true  -> `Answer
let qr_to_bool = function
  | `Query  -> false
  | `Answer -> true

type opcode = [ qr | `Status | `Reserved | `Notify | `Update ]
let int_to_opcode = function
  | 0 -> `Query
  | 1 -> `Answer
  | 2 -> `Status
  | 3 -> `Reserved
  | 4 -> `Notify
  | 5 -> `Update
  | x -> failwith (sprintf "dnspacket: unknown opcode [%d]" x)
let opcode_to_int = function
  | `Query -> 0
  | `Answer -> 1
  | `Status -> 2
  | `Reserved -> 3
  | `Notify -> 4
  | `Update -> 5

type rcode = [
| `NoError  | `FormErr
| `ServFail | `NXDomain | `NotImp  | `Refused
| `YXDomain | `YXRRSet  | `NXRRSet | `NotAuth
| `NotZone  | `BadVers  | `BadKey  | `BadTime
| `BadMode  | `BadName  | `BadAlg 
]
let int_to_rcode = function
  | 0 -> `NoError
  | 1 -> `FormErr
  | 2 -> `ServFail
  | 3 -> `NXDomain
  | 4 -> `NotImp
  | 5 -> `Refused
  | 6 -> `YXDomain
  | 7 -> `YXRRSet
  | 8 -> `NXRRSet
  | 9 -> `NotAuth
  | 10 -> `NotZone
    
  | 16 -> `BadVers
  | 17 -> `BadKey
  | 18 -> `BadTime
  | 19 -> `BadMode
  | 20 -> `BadName
  | 21 -> `BadAlg
  | x -> failwith (sprintf "unknown rcode [%d]" x)
and rcode_to_int = function
  | `NoError -> 0
  | `FormErr -> 1
  | `ServFail -> 2
  | `NXDomain -> 3
  | `NotImp -> 4
  | `Refused -> 5
  | `YXDomain -> 6
  | `YXRRSet -> 7
  | `NXRRSet -> 8
  | `NotAuth -> 9
  | `NotZone -> 10
    
  | `BadVers -> 16
  | `BadKey -> 17
  | `BadTime -> 18
  | `BadMode -> 19
  | `BadName -> 20
  | `BadAlg -> 21
and rcode_to_string = function
  | `NoError -> "NoError"
  | `FormErr -> "FormErr"
  | `ServFail -> "ServFail"
  | `NXDomain -> "NXDomain"
  | `NotImp -> "NotImp"
  | `Refused -> "Refused"
  | `YXDomain -> "YXDomain"
  | `YXRRSet -> "YXRRSet"
  | `NXRRSet -> "NXRRSet"
  | `NotAuth -> "NotAuth"
  | `NotZone -> "NotZone"
    
  | `BadVers -> "BadVers"
  | `BadKey -> "BadKey"
  | `BadTime -> "BadTime"
  | `BadMode -> "BadMode"
  | `BadName -> "BadName"
  | `BadAlg -> "BadAlg"

type detail = {
  qr: qr;
  opcode: opcode;
  aa: bool; 
  tc: bool; 
  rd: bool; 
  ra: bool;
  rcode: rcode;
}
let detail_to_string d = 
  sprintf "%c:%02x %s:%s:%s:%s %d"
    (match d.qr with `Query -> 'Q' | `Answer -> 'R')
    (opcode_to_int d.opcode)
    (if d.aa then "a" else "na") (* authoritative vs not *)
    (if d.tc then "t" else "c") (* truncated vs complete *)
    (if d.rd then "r" else "nr") (* recursive vs not *)
    (if d.ra then "ra" else "rn") (* recursion available vs not *)
    (rcode_to_int d.rcode)

let parse_detail bits = 
  bitmatch bits with
    | { qr:1; opcode:4; aa:1; tc:1; rd:1; ra:1; z:3; rcode:4 } 
      -> { qr=bool_to_qr qr; opcode=int_to_opcode opcode; 
           aa; tc; rd; ra; 
           rcode=int_to_rcode rcode }

let build_detail d = 
  (BITSTRING {
    (qr_to_bool d.qr):1; (opcode_to_int d.opcode):4; 
    d.aa:1; d.tc:1; d.rd:1; d.ra:1; (* z *) 0:3;
    (rcode_to_int d.rcode):4
  })

type dns = {
  id          : int16;
  detail      : Bitstring.t;
  questions   : question list;
  answers     : rr list;
  authorities : rr list;
  additionals : rr list;
}

let dns_to_string d = 
  sprintf "%04x %s <qs:%s> <an:%s> <au:%s> <ad:%s>"
    d.id (d.detail |> parse_detail |> detail_to_string)
    (d.questions ||> question_to_string |> join ",")
    (d.answers ||> rr_to_string |> join ",")
    (d.authorities ||> rr_to_string |> join ",")
    (d.additionals ||> rr_to_string |> join ",")

let parse_dns names bits = 
  let parsen pf ns b n bits = 
    let rec aux rs n bits = 
      match n with
        | 0 -> rs, bits
        | _ -> let r, bits = pf ns b bits in 
               aux (r :: rs) (n-1) bits
    in
    aux [] n bits
  in
  let base = offset_of_bitstring bits in
  (bitmatch bits with
    | { id:16; detail:16:bitstring;
        qdcount:16; ancount:16; nscount:16; arcount:16;
        bits:-1:bitstring
      }
      -> (let questions, bits = parsen parse_question names base qdcount bits
          in
          let answers, bits = parsen parse_rr names base ancount bits in
          let authorities, bits = parsen parse_rr names base nscount bits in
          let additionals, _ = parsen parse_rr names base arcount bits in 
          let dns = { id=int16 id; 
                      detail; questions; answers; authorities; additionals }
          in
          dns
      )
  )

let marshal_dns dns = 
  eprintf "resp: %s\n%!" (dns_to_string dns);
  
  (** Alias {! Bitstring.bitstring_length}, but in bytes. *)
  let bsl b = (Bitstring.bitstring_length b)/8 in 

  (** Current position in buffer. *)
  let pos = ref 0 in
  
  (** Map name (list of labels) to an offset. *)
  let (names:(string list,int) Hashtbl.t) = Hashtbl.create 8 in

  (** Encode string as label by prepending length. *)
  let charstr s =
    sprintf "%c%s" (s |> String.length |> char_of_int) s 
  in

  (** Marshall names, with compression. *)
  let mn_compress (labels:domain_name) = 
    let pos = ref (!pos) in

    let pointer off = 
      let ptr = (0b11_l <<< 14) +++ (Int32.of_int off) in
      let hi = ((ptr &&& 0xff00_l) >>> 8) |> Int32.to_int |> char_of_int in
      let lo =  (ptr &&& 0x00ff_l)        |> Int32.to_int |> char_of_int in
      sprintf "%c%c" hi lo
    in
    
    let lookup h k =
      if Hashtbl.mem h k then Some (Hashtbl.find h k) else None
    in

    let lset = label_set labels in 

    let bits = ref [] in    
    let pointed = ref false in
    List.iter (fun ls ->
      if (not !pointed) then (
        eprintf "\tlabel:%s\n%!" (ls |> join "/");
        match lookup names ls with
          | None 
            -> (eprintf "\t\tnot found! pos:%d ls:%s\n%!" !pos (join "/" ls);
                Hashtbl.add names ls !pos;
                match ls with 
                  | [] 
                    -> (eprintf "\t\t\t[]\n%!";
                        bits := "\000" :: !bits; 
                        pos := !pos + 1
                    )
                  | label :: tail
                    -> (eprintf "\t\t\tlabel:%s tail:'%s'\n%!" label (join "/" tail);
                        let len = String.length label in
                        assert(len < 64);
                        bits := (charstr label) :: !bits;
                        pos := !pos + len +1
                    )
            )
          | Some off
            -> (eprintf "\t\tfound! pos:%d off:%d ls:%s\n%!" !pos off (join "/" ls);
                bits := (pointer off) :: !bits;
                pos := !pos + 2;
                pointed := true
            )
      )
    ) lset;
    if (not !pointed) then (
      bits := "\000" :: !bits;
      pos := !pos + 1
    );
    !bits |> List.rev |> String.concat "" |> (fun s -> 
      BITSTRING { s:((String.length s)*8):string })
  in

  let mn_nocompress (labels:domain_name) =
    let bits = ref [] in
    labels |> domain_name_to_string_list 
           |> List.iter (fun s -> bits := (charstr s) :: !bits);
    !bits |> List.rev |> String.concat ""
           |> (fun s -> 
             if String.length s > 0 then
               BITSTRING { s:((String.length s)*8):string; 0:8 }
             else
               BITSTRING { 0:8 }
           )
  in
  
  let mn ?(off = 0) ls = 
    eprintf "labels:%s\n%!"
      (ls |> domain_name_to_string_list |> join "/");

    eprintf "IN: pos:%d off:%d\n%!" !pos off;
    pos := !pos + off;
    let n = mn_compress ls in
    (pos := !pos - off; 
     eprintf "OUT:  pos:%d off:%d\n%!" !pos off;
     n)
  in

  let mr r = 
    let mrdata = function
      | `A ip -> (BITSTRING { ip:32 }, `A)
        
      | `AAAA _ -> failwith (sprintf "AAAA")
        
      | `AFSDB (t, n) 
        -> BITSTRING { t:16; (mn ~off:2 n):-1:bitstring }, `AFSDB
      | `CNAME n -> BITSTRING { (mn n):-1:bitstring }, `CNAME
      | `HINFO (cpu, os) -> BITSTRING { cpu:-1:string; os:-1:string }, `HINFO
      | `ISDN (a, sa) -> (
        (match sa with 
          | None -> BITSTRING { (charstr a):-1:string }
          | Some sa
            -> BITSTRING { (charstr a):-1:string; (charstr sa):-1:string }
        ), `ISDN
      )
      | `MB n -> BITSTRING { (mn n):-1:bitstring }, `MB
      | `MD n -> BITSTRING { (mn n):-1:bitstring }, `MD
      | `MF n -> BITSTRING { (mn n):-1:bitstring }, `MF
      | `MG n -> BITSTRING { (mn n):-1:bitstring }, `MG
      | `MINFO (rm,em)
        -> (let rm = mn rm in
            let em = mn ~off:(bsl rm) em in
            BITSTRING { rm:-1:bitstring; em:-1:bitstring }, `MINFO
        )
      | `MR n -> BITSTRING { (mn n):-1:bitstring }, `MR
      | `MX (pref, exchange)
        -> BITSTRING { pref:16; (mn ~off:2 exchange):-1:bitstring }, `MX
      | `NS n -> BITSTRING { (mn n):-1:bitstring }, `NS
      | `PTR n -> BITSTRING { (mn n):-1:bitstring }, `PTR
      | `RP (mbox, txt) 
        -> (let mbox = mn mbox in
            let txt = mn ~off:(bsl mbox) txt in
            BITSTRING { mbox:-1:bitstring; txt:-1:bitstring }, `RP
        )
      | `RT (p, ih) -> BITSTRING { p:16; (mn ~off:2 ih):-1:bitstring }, `RT
      | `SOA (mname, rname, serial, refresh, retry, expire, minimum) 
        -> (let mname = mn mname in 
            let rname = mn ~off:(bsl mname) rname in 
            BITSTRING { mname:-1:bitstring; 
                        rname:-1:bitstring; 
                        serial:32; 
                        refresh:32; retry:32; expire:32; minimum:32 }, `SOA
        )
      | `SRV (prio, weight, port, target)
        -> BITSTRING { prio:16; weight:16; port:16;
                       (mn ~off:6 target):-1:bitstring }, `SRV
      | `TXT sl -> BITSTRING { (sl ||> charstr |> join ""):-1:string }, `TXT
        
      | `UNKNOWN _ -> failwith (sprintf "UNKNOWN")
      | `UNSPEC _ -> failwith (sprintf "UNSPEC")
        
      | `WKS (a, p, bm) -> BITSTRING { a:32; (byte_to_int p):8; bm:-1:string }, `WKS
      | `X25 s -> BITSTRING { (charstr s):-1:string }, `X25
    in

    let name = mn r.rr_name in
    pos := !pos + (bsl name)+2+2+4+2;
    let rdata, rr_type = mrdata r.rr_rdata in
    let rdlength = bsl rdata in
    pos := !pos + rdlength;
    (BITSTRING {
      name:-1:bitstring;
      (rr_type_to_int rr_type):16;
      (rr_class_to_int r.rr_class):16;
      r.rr_ttl:32;
      rdlength:16;
      rdata:(rdlength*8):bitstring
    }) 
  in

  let mq q =
    let bits = mn q.q_name in
    pos := !pos + (bsl bits)+2+2;
    (BITSTRING {
      bits:-1:bitstring; 
      (q_type_to_int q.q_type):16;
      (q_class_to_int q.q_class):16
    })
  in

  let header = 
    pos := !pos + 2+2+2+2+2+2;
    (BITSTRING {
      dns.id:16; 
      dns.detail:16:bitstring; 
      (List.length dns.questions):16;
      (List.length dns.answers):16;
      (List.length dns.authorities):16;
      (List.length dns.additionals):16
    })
  in

  let qs = dns.questions ||> mq in
  let ans = dns.answers ||> mr in
  let auths = dns.authorities ||> mr in
  let adds = dns.additionals ||> mr in

  Bitstring.concat (header :: qs @ ans @ auths @ adds)
