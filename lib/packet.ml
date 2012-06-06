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
(* open Wire *)
open Name

type byte = int

(** Encode string as label by prepending length. *)
let charstr s = sprintf "%c%s" (s |> String.length |> char_of_int) s 

let mn_nocompress (labels:domain_name) =
  let bits = ref [] in
  labels |> List.iter (fun s -> bits := (charstr s) :: !bits);
  !bits |> List.rev |> String.concat ""
    |> (fun s -> if String.length s > 0 then
        BITSTRING { s:((String.length s)*8):string; 0:8 }
      else
        BITSTRING { 0:8 }
    )

cenum digest_alg {
  SHA1 = 1
} as uint8_t

cenum gateway_tc {
  NONE  = 0;
  IPv4 = 1;
  IPv6 = 2;
  NAME = 3
} as uint8_t

type gateway =
  | IPv4 of ipv4
  | IPv6 of ipv6
  | NAME of domain_name
let gateway_to_string = function
  | IPv4 i -> ipv4_to_string i
  | IPv6 i -> ipv6_to_string i
  | NAME n -> domain_name_to_string n
and gateway_to_bits buf = function
  | IPv4 i -> Cstruct.BE.set_uint32 buf 0 i
  | IPv6 (hi,lo) -> Cstruct.BE.set_uint64 buf 0 hi; Cstruct.BE.set_uint64 buf 8 lo
  | NAME n -> () (* BITSTRING { (mn_nocompress n):-1:bitstring }, -1*)

cenum pubkey_alg {
  RESERVED = 0;
  RSA = 1;
  DSS = 2
} as uint8_t

cenum ipseckey_alg {
  DSA = 1;
  RSA = 2
} as uint8_t

cenum hash_alg {
  SHA1 = 1
} as uint8_t

cenum fp_type {
  SHA1 = 1
} as uint8_t

cenum dnssec_alg {
  RSAMD5     = 1; 
  DH         = 2; 
  DSA        = 3;
  ECC        = 4;
  RSASHA1    = 5;
  RSANSEC3   = 7;
  RSASHA256  = 8;
  RSASHA512  = 10;
  INDIRECT   = 252;
  PRIVATEDNS = 253;
  PRIVATEOID = 254
} as uint8_t

cenum rr_type {
  A          = 1;
  NS         = 2;
  MD         = 3;
  MF         = 4;
  CNAME      = 5;
  SOA        = 6;
  MB         = 7;
  MG         = 8;
  MR         = 9;
  NULL       = 10;
  WKS        = 11;
  PTR        = 12;
  HINFO      = 13;
  MINFO      = 14;
  MX         = 15;
  TXT        = 16;
  RP         = 17;
  AFSDB      = 18;
  X25        = 19;
  ISDN       = 20;
  RT         = 21;
  NSAP       = 22;
  NSAP_PTR   = 23;
  SIG        = 24;
  KEY        = 25;
  PX         = 26;
  GPOS       = 27;
  AAAA       = 28;
  LOC        = 29;
  NXT        = 30;
  EID        = 31;
  NIMLOC     = 32;
  SRV        = 33;
  ATMA       = 34;
  NAPTR      = 35;
  KM         = 36;
  CERT       = 37;
  A6         = 38;
  DNAME      = 39;
  SINK       = 40;
  OPT        = 41;
  APL        = 42;
  DS         = 43;
  SSHFP      = 44;
  IPSECKEY   = 45;
  RRSIG      = 46;
  NSEC       = 47;
  DNSKEY     = 48;
  NSEC3      = 50;
  NSEC3PARAM = 51;
  SPF        = 99;
  UINFO      = 100;
  UID        = 101;
  GID        = 102;
  UNSPEC     = 103
} as uint8_t

(*
   The Type Bit Maps field identifies the RRset types that exist at the
   NSEC RR's owner name.

   The RR type space is split into 256 window blocks, each representing
   the low-order 8 bits of the 16-bit RR type space.  Each block that
   has at least one active RR type is encoded using a single octet
   window number (from 0 to 255), a single octet bitmap length (from 1
   to 32) indicating the number of octets used for the window block's
   bitmap, and up to 32 octets (256 bits) of bitmap.

   Blocks are present in the NSEC RR RDATA in increasing numerical
   order.

      Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+

      where "|" denotes concatenation.

   Each bitmap encodes the low-order 8 bits of RR types within the
   window block, in network bit order.  The first bit is bit 0.  For
   window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
   to RR type 2 (NS), and so forth.  For window block 1, bit 1
   corresponds to RR type 257, and bit 2 to RR type 258.  If a bit is
   set, it indicates that an RRset of that type is present for the NSEC
   RR's owner name.  If a bit is clear, it indicates that no RRset of
   that type is present for the NSEC RR's owner name.

   Bits representing pseudo-types MUST be clear, as they do not appear
   in zone data.  If encountered, they MUST be ignored upon being read.

   Blocks with no types present MUST NOT be included.  Trailing zero
   octets in the bitmap MUST be omitted.  The length of each block's
   bitmap is determined by the type code with the largest numerical
   value, within that block, among the set of RR types present at the
   NSEC RR's owner name.  Trailing zero octets not specified MUST be
   interpreted as zero octets.

   The bitmap for the NSEC RR at a delegation point requires special
   attention.  Bits corresponding to the delegation NS RRset and the RR
   types for which the parent zone has authoritative data MUST be set;
   bits corresponding to any non-NS RRset for which the parent is not
   authoritative MUST be clear.

   A zone MUST NOT include an NSEC RR for any domain name that only
   holds glue records.
*)
type type_bit_map = byte * byte * bytes
let type_bit_map_to_string (tbm:type_bit_map) : string = 
  "TYPE_BIT_MAP"
(*
let marshall_tbm (block, bitmapl, bitmap) = 
  let bl = byte_to_int bitmapl in
  BITSTRING { (byte_to_int block):8; 
              bl:8; (bytes_to_string bitmap):(bl*8):string
            }
*)

type type_bit_maps = type_bit_map list
let type_bit_maps_to_string (tbms:type_bit_maps) : string = 
  tbms ||> type_bit_map_to_string |> String.concat "; "
(*
let marshall_tbms tbms = 
  tbms ||> marshall_tbm |> Bitstring.concat 
*)

type rr_rdata = [
| `A of ipv4
| `AAAA of bytes
| `AFSDB of Cstruct.uint16 * domain_name
| `CNAME of domain_name
| `DNSKEY of Cstruct.uint16 * dnssec_alg * string
| `DS of Cstruct.uint16 * dnssec_alg * digest_alg * string
| `HINFO of string * string
| `IPSECKEY of byte * gateway_tc * ipseckey_alg * gateway * bytes
| `ISDN of string * string option
| `MB of domain_name
| `MD of domain_name
| `MF of domain_name
| `MG of domain_name
| `MINFO of domain_name * domain_name
| `MR of domain_name
| `MX of Cstruct.uint16 * domain_name
| `NS of domain_name
| `NSEC of domain_name (* uncompressed *) * type_bit_maps
| `NSEC3 of hash_alg * byte * Cstruct.uint16 * byte * bytes * byte * bytes * 
    type_bit_maps
| `NSEC3PARAM of hash_alg * byte * Cstruct.uint16 * byte * bytes
| `PTR of domain_name
| `RP of domain_name * domain_name
| `RRSIG of rr_type * dnssec_alg * byte * int32 * int32 * int32 * Cstruct.uint16 * 
    domain_name (* uncompressed *) * bytes
| `RT of Cstruct.uint16 * domain_name
| `SOA of domain_name * domain_name * int32 * int32 * int32 * int32 * int32
| `SRV of Cstruct.uint16 * Cstruct.uint16 * Cstruct.uint16 * domain_name
| `SSHFP of pubkey_alg * fp_type * bytes
| `TXT of string list
| `UNKNOWN of int * bytes
| `UNSPEC of bytes
| `WKS of int32 * byte * string
| `X25 of string 
]

let rdata_to_string = function
  | `A ip -> sprintf "A (%s)" (ipv4_to_string ip)
  | `AAAA bs -> sprintf "AAAA (%s)" (bytes_to_string bs)
  | `AFSDB (x, n)
    -> sprintf "AFSDB (%d, %s)" x (domain_name_to_string n)
  | `CNAME n -> sprintf "CNAME (%s)" (domain_name_to_string n)
  | `DNSKEY (flags, alg, key) 
    -> (sprintf "DNSKEY (%x, %s, %s)" 
          flags (dnssec_alg_to_string alg) 
          (Cryptokit.(transform_string (Base64.encode_compact ()) key))
    )
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
          serial refresh retry expire minimum
    )
  | `SRV (x, y, z, n) 
    -> sprintf "SRV (%d,%d,%d, %s)" x y z (domain_name_to_string n)
  | `TXT sl -> sprintf "TXT (%s)" (join "" sl)
  | `UNKNOWN (x, bs) -> sprintf "UNKNOWN (%d) '%s'" x (bytes_to_string bs)
  | `UNSPEC bs -> sprintf "UNSPEC (%s)" (bytes_to_string bs)
  | `WKS (x, y, s) -> sprintf "WKS (%ld,%d, %s)" x y s
  | `X25 s -> sprintf "X25 (%s)" s

  | `DS (keytag, alg, digest_t, digest) 
    -> (sprintf "DS (%d,%s,%s, '%s')" keytag
          (dnssec_alg_to_string alg) (digest_alg_to_string digest_t) digest
    )
  | `IPSECKEY (precedence, gw_type, alg, gw, pubkey)
    -> (sprintf "IPSECKEY (%d, %s,%s, %s, '%s')" precedence
          (gateway_tc_to_string gw_type) (ipseckey_alg_to_string alg)
          (gateway_to_string gw) (bytes_to_string pubkey)
    )
  | `NSEC (next_name, tbms) 
    -> (sprintf "NSEC (%s, %s)" 
          (domain_name_to_string next_name) (type_bit_maps_to_string tbms)
    )
  | `NSEC3 (halg, flgs, iterations, salt_l, salt, hash_l, next_name, tbms)
    -> (sprintf "NSEC3 (%s, %x, %d, %d,'%s', %d,'%s', %s)"
          (hash_alg_to_string halg) flgs iterations
          salt_l (bytes_to_string salt)
          hash_l (bytes_to_string next_name)
          (type_bit_maps_to_string tbms)
    )
  | `NSEC3PARAM (halg, flgs, iterations, salt_l, salt)
    -> (sprintf "NSEC3PARAM (%s,%x, %d, %d, '%s')"
          (hash_alg_to_string halg) flgs iterations salt_l 
          (bytes_to_string salt)
    )
  | `RRSIG (tc, alg, nlbls, ttl, expiration, inception, keytag, name, sign)
    -> (sprintf "RRSIG (%s,%s,%d, %ld, %ld,%ld, %d, %s, %s)"
          (rr_type_to_string tc) (dnssec_alg_to_string alg) 
          nlbls ttl expiration inception keytag
          (domain_name_to_string name) (bytes_to_string sign)
    )
  | `SSHFP (alg, fpt, fp)
    -> (sprintf "SSHFP (%s,%s, '%s')" (pubkey_alg_to_string alg) 
          (fp_type_to_string fpt) (bytes_to_string fp)
    )

let parse_rdata names base t buf = 
  (** Drop remainder bitstring to stop parsing and demuxing. *) 
  let stop (x, _) = x in
  (** Extract (length, string) encoded strings, with remainder for
      chaining. *)
  let parse_charstr buf = 
    let len = Cstruct.get_uint8 buf 0 in
    Cstruct.to_string (Cstruct.sub buf 1 len), slide buf (1+len)
  in
  match t with
    | Some A -> `A (Cstruct.BE.get_uint32 buf 0)
    | Some NS -> `NS (buf |> parse_name names base |> stop)
    | Some CNAME -> `CNAME (buf |> parse_name names base |> stop)
    | Some DNSKEY -> 
        Cstruct.(
          let flags = BE.get_uint16 buf 0 in
          let alg = 
            let a = get_uint8 buf 3 in
            match int_to_dnssec_alg a with
              | None -> failwith (sprintf "parse_rdata: DNSKEY alg %d" a)
              | Some a -> a
          in
          let key = slide buf 4 |> to_string in
          `DNSKEY (flags, alg, key)
        )
    | Some SOA -> 
        let mn, (o, buf) = parse_name names base buf in
        let rn, (_, buf) = parse_name names (base+o) buf in 
        Cstruct.BE.(`SOA (mn, rn, 
                          get_uint32 buf 0,  (* serial *)
                          get_uint32 buf 4,  (* refresh *)
                          get_uint32 buf 8,  (* retry *)
                          get_uint32 buf 12, (* expire *)
                          get_uint32 buf 16  (* minimum *)
        ))
    | Some WKS -> 
        Cstruct.(
          let addr = BE.get_uint32 buf 0 in
          let proto = get_uint8 buf 4 in
          let bitmap = slide buf 5 |> to_string in
          `WKS (addr, proto, bitmap)
        )
    | Some PTR -> `PTR (buf |> parse_name names base |> stop)
    | Some HINFO -> let cpu, buf = parse_charstr buf in
                    let os = buf |> parse_charstr |> stop in
                    `HINFO (cpu, os)
    | Some MINFO -> let rm, (o,buf) = buf |> parse_name names base in
                    let em = buf |> parse_name names (base+o) |> stop in
                    `MINFO (rm, em)
    | Some MX -> `MX (Cstruct.BE.get_uint16 buf 0,
                      slide buf 2 |> parse_name names base |> stop)
    | Some SRV -> 
        Cstruct.BE.(
          `SRV (get_uint16 buf 0, (* prio *)
                get_uint16 buf 2, (* weight *)
                get_uint16 buf 4, (* port *)
                parse_name names (base+6) buf |> stop
          )
        )
    | Some TXT -> 
        let strings = 
          let rec aux strings base buf =
            match Cstruct.len buf with
              | 0 -> strings ||> (fun a -> join "" a)
              | _ ->
                  let n, (o,buf) = parse_name ~check_len:false names base buf in
                  aux (n :: strings) (base+o) buf
          in
          aux [] base buf
        in
        `TXT strings
    | Some t -> failwith (sprintf "parse_rdata: %s" (rr_type_to_string t))
    | None -> failwith "parse_rdata: unknown rr_type"
        
cenum rr_class {
  IN = 1;
  CS = 2;
  CH = 3;
  HS = 4
} as uint8_t
      
cstruct rr {
  uint16_t typ;
  uint16_t cls;
  uint32_t ttl;
  uint16_t rdlen
} as big_endian

type rr = {
  name  : domain_name;
  cls   : rr_class;
  ttl   : int32;
  rdata : rr_rdata;
}

let rr_to_string rr = 
  sprintf "%s <%s|%ld> %s" 
    (domain_name_to_string rr.name) (rr_class_to_string rr.cls) 
    rr.ttl (rdata_to_string rr.rdata)

let parse_rr names base buf =
  let name, (o,buf) = parse_name names base buf in
  let typ = get_rr_typ buf |> int_to_rr_type in
  let cls = get_rr_cls buf |> int_to_rr_class in
  let ttl = get_rr_ttl buf in
  let rdlen = get_rr_rdlen buf in
  let rdata = parse_rdata names (base+o+sizeof_rr) typ buf in
  match cls with
    | None -> failwith "parse_rr: unknown class"
    | Some cls -> { name; cls; ttl; rdata }, ((o+sizeof_rr+rdlen), slide buf (sizeof_rr+rdlen))

cenum q_type {
  A          = 1;
  NS         = 2;
  MD         = 3;
  MF         = 4;
  CNAME      = 5;
  SOA        = 6;
  MB         = 7;
  MG         = 8;
  MR         = 9;
  NULL       = 10;
  WKS        = 11;
  PTR        = 12;
  HINFO      = 13;
  MINFO      = 14;
  MX         = 15;
  TXT        = 16;
  RP         = 17;
  AFSDB      = 18;
  X25        = 19;
  ISDN       = 20;
  RT         = 21;
  NSAP       = 22;
  NSAP_PTR   = 23;
  SIG        = 24;
  KEY        = 25;
  PX         = 26;
  GPOS       = 27;
  AAAA       = 28;
  LOC        = 29;
  NXT        = 30;
  EID        = 31;
  NIMLOC     = 32;
  SRV        = 33;
  ATMA       = 34;
  NAPTR      = 35;
  KM         = 36;
  CERT       = 37;
  A6         = 38;
  DNAME      = 39;
  SINK       = 40;
  OPT        = 41;
  APL        = 42;
  DS         = 43;
  SSHFP      = 44;
  IPSECKEY   = 45;
  RRSIG      = 46;
  NSEC       = 47;
  DNSKEY     = 48;
  NSEC3      = 50;
  NSEC3PARAM = 51;

  SPF        = 99;
  UINFO      = 100;
  UID        = 101;
  GID        = 102;
  UNSPEC     = 103;
  
  AXFR  = 252;
  MAILB = 253;
  MAILA = 254;
  ANY   = 255;
  
  TA    = 32768;
  DLV   = 32769
} as uint8_t

cenum q_class {
  IN   = 1;
  CS   = 2;
  CH   = 3;
  HS   = 4;
  NONE = 254;
  ANY  = 255
} as uint8_t

cstruct q {
  uint16_t typ;
  uint16_t cls
} as big_endian

type question = {
  q_name  : domain_name;
  q_type  : q_type;
  q_class : q_class;
}

let question_to_string q = 
  sprintf "%s <%s|%s>" 
    (domain_name_to_string q.q_name) 
    (q_type_to_string q.q_type) (q_class_to_string q.q_class)

let parse_question names base buf = 
  let q_name, (o,buf) = parse_name names base buf in
  let q_type = 
    let typ = get_q_typ buf in
    match int_to_q_type typ with
      | None -> failwith (sprintf "parse_question: typ %d" typ)
      | Some typ -> typ
  in
  let q_class = 
    let cls = get_q_cls buf in
    match int_to_q_class cls with
      | None -> failwith (sprintf "parse_question: cls %d" cls)
      | Some cls -> cls
  in
  { q_name; q_type; q_class }, (base+o+sizeof_q, slide buf sizeof_q)


type qr = [ `Query | `Answer ]
let bool_to_qr = function
  | false -> `Query
  | true  -> `Answer
let qr_to_bool = function
  | `Query  -> false
  | `Answer -> true

cenum opcode {
  Query = 0;
  Answer = 1;
  Status = 2;
  Reserved = 3;
  Notify = 4;
  Update = 5
} as uint8_t

cenum rcode {
  NoError = 0;
  FormErr = 1;
  ServFail = 2;
  NXDomain = 3;
  NotImp = 4;
  Refused = 5;
  YXDomain = 6;
  YXRRSet = 7;
  NXRRSet = 8;
  NotAuth = 9;
  NotZone = 10;
    
  BadVers = 16;
  BadKey = 17;
  BadTime = 18;
  BadMode = 19;
  BadName = 20;
  BadAlg = 21
} as uint8_t

(*
let header_to_string h = 
  sprintf "%04x %c:%02x %s:%s:%s:%s %d"
    h.id
    (match h.qr with `Query -> 'Q' | `Answer -> 'R')
    (opcode_to_int h.opcode)
    (if h.aa then "a" else "na") (* authoritative vs not *)
    (if h.tc then "t" else "c") (* truncated vs complete *)
    (if h.rd then "r" else "nr") (* recursive vs not *)
    (if h.ra then "ra" else "rn") (* recursion available vs not *)
    (rcode_to_int h.rcode)
let parse_header buf = 
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
*)

cstruct h {
  uint16_t id;
  uint16_t detail;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount
} as big_endian

type dns = {
  id          : Cstruct.uint16;
  detail      : Cstruct.uint16;
  questions   : question list; (* Cstruct.iter; *)
  answers     : rr list; (* Cstruct.iter; *)
  authorities : rr list; (* Cstruct.iter; *)
  additionals : rr list; (* Cstruct.iter; *)
}

let parse_dns names buf = 
  let parsen f ns b n buf = 
    let rec aux rs n off buf = 
      match n with
        | 0 -> rs, (off, buf)
        | _ -> let r, (o, buf) = f ns b buf in 
               aux (r :: rs) (n-1) (o+off) buf
    in
    aux [] n b buf
  in

  let id = get_h_id buf in
  let detail = get_h_detail buf in
  let qdcount = get_h_qdcount buf in
  let ancount = get_h_ancount buf in
  let nscount = get_h_nscount buf in
  let arcount = get_h_arcount buf in

  let base = sizeof_h in
  let questions, (base, buf) = parsen parse_question names base qdcount buf in
  let answers, (base, buf) = parsen parse_rr names base ancount buf in
  let authorities, (base, buf) = parsen parse_rr names base nscount buf in
  let additionals, _ = parsen parse_rr names base arcount buf in

  { id; detail; questions; answers; authorities; additionals }

(*
let dns_to_string d = 
  sprintf "%04x %s <qs:%s> <an:%s> <au:%s> <ad:%s>"
    (int16_to_int d.id) (detail_to_string d.detail)
    (d.questions ||> question_to_string |> join ",")
    (d.answers ||> rr_to_string |> join ",")
    (d.authorities ||> rr_to_string |> join ",")
    (d.additionals ||> rr_to_string |> join ",")
*)

(*
let marshal_dns dns = 
  (** Alias {! Bitstring.bitstring_length}, but in bytes. *)
  let bsl b = (Bitstring.bitstring_length b)/8 in 

  (** Current position in buffer. *)
  let pos = ref 0 in
  
  (** Map name (list of labels) to an offset. *)
  let (names:(string list,int) Hashtbl.t) = Hashtbl.create 8 in

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

    let lset = 
      let rec aux = function
        | [] -> [] (* don't double up the terminating null? *)
        | x :: [] -> [ x :: [] ]
        | hd :: tl -> (hd :: tl) :: (aux tl)
      in aux labels
    in

    let bits = ref [] in    
    let pointed = ref false in
    List.iter (fun ls ->
      if (not !pointed) then (
        match lookup names ls with
          | None 
            -> (Hashtbl.add names ls !pos;
                match ls with 
                  | [] 
                    -> (bits := "\000" :: !bits; 
                        pos := !pos + 1
                    )
                  | label :: tail
                    -> (let len = String.length label in
                        assert(len < 64);
                        bits := (charstr label) :: !bits;
                        pos := !pos + len +1
                    )
            )
          | Some off
            -> (bits := (pointer off) :: !bits;
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

  let mn ?(off = 0) ls = 
    pos := !pos + off;
    let n = mn_compress ls in
    (pos := !pos - off; 
     n)
  in

  let mr r = 
    let mrdata = function
      | `A ip -> (BITSTRING { ip:32 }, `A)
          
      | `AAAA _ -> failwith (sprintf "AAAA")
          
      | `AFSDB (t, n)
        -> (BITSTRING { (int16_to_int t):16; (mn ~off:2 n):-1:bitstring }, 
            `AFSDB
        )
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
        -> BITSTRING { (int16_to_int pref):16; (mn ~off:2 exchange):-1:bitstring }, `MX
      | `NS n -> BITSTRING { (mn n):-1:bitstring }, `NS
      | `PTR n -> BITSTRING { (mn n):-1:bitstring }, `PTR
      | `RP (mbox, txt) 
        -> (let mbox = mn mbox in
            let txt = mn ~off:(bsl mbox) txt in
            BITSTRING { mbox:-1:bitstring; txt:-1:bitstring }, `RP
        )
      | `RT (p, ih) -> BITSTRING { (int16_to_int p):16; (mn ~off:2 ih):-1:bitstring }, `RT
      | `SOA (mname, rname, serial, refresh, retry, expire, minimum) 
        -> (let mname = mn mname in 
            let rname = mn ~off:(bsl mname) rname in 
            BITSTRING { mname:-1:bitstring; 
                        rname:-1:bitstring; 
                        serial:32; 
                        refresh:32; retry:32; expire:32; minimum:32 }, `SOA
        )
      | `SRV (prio, weight, port, target)
        -> BITSTRING { (int16_to_int prio):16; (int16_to_int weight):16; 
                       (int16_to_int port):16; (mn ~off:6 target):-1:bitstring
                     }, `SRV
      | `TXT sl -> BITSTRING { (sl ||> charstr |> join ""):-1:string }, `TXT
        
      | `UNKNOWN _ -> failwith (sprintf "UNKNOWN")
      | `UNSPEC _ -> failwith (sprintf "UNSPEC")
          
      | `WKS (a, p, bm) 
        -> BITSTRING { a:32; (byte_to_int p):8; bm:-1:string }, `WKS
      | `X25 s -> BITSTRING { (charstr s):-1:string }, `X25
        
      | `DNSKEY (flags, alg, key)
        -> let bkey = 
             Cryptokit.(transform_string (Base64.encode_compact ()) key) 
           in
           (BITSTRING { (int16_to_int flags):16; 3:8; 
                        (dnssec_alg_to_int alg):8; key:-1:string }, `DNSKEY)
      | `DS (keytag, alg, digest_t, digest) 
        -> BITSTRING { (int16_to_int keytag):16; (dnssec_alg_to_int alg):8;
                       (digest_alg_to_int digest_t):8; digest:-1:string
                     }, `DS

      | `IPSECKEY (precedence, gw_type, alg, gw, pubkey)
        -> (let gw, gw_l = gateway_to_bits gw in            
            BITSTRING { (byte_to_int precedence):8; 
                        (gw_type_to_int gw_type):8;
                        (ipseckey_alg_to_int alg):8; gw:gw_l:bitstring;
                        (bytes_to_string pubkey):-1:string
                      }, `IPSECKEY
        )

      | `NSEC (next_name, tbms) 
        -> BITSTRING { (mn_nocompress next_name):-1:bitstring;
                       (marshall_tbms tbms):-1:bitstring
                     }, `NSEC

      | `NSEC3 (halg, flgs, iterations, salt_l, salt, hash_l, namehash, tbms)
        -> BITSTRING { (hash_alg_to_int halg):8; (byte_to_int flgs):8; 
                       (int16_to_int iterations):16; 
                       (byte_to_int salt_l):8; 
                       (bytes_to_string salt):-1:string; 
                       (byte_to_int hash_l):8; 
                       (bytes_to_string namehash):-1:string;
                       (marshall_tbms tbms):-1:bitstring
                     }, `NSEC3

      | `NSEC3PARAM (halg, flgs, iterations, salt_l, salt)
        -> BITSTRING { (hash_alg_to_int halg):8; (byte_to_int flgs):8; 
                       (int16_to_int iterations):16; 
                       (byte_to_int salt_l):8; 
                       (bytes_to_string salt):-1:string
                     }, `NSEC3PARAM

      | `RRSIG (tc, alg, nlbls, ttl, expiration, inception, keytag, name, sgn)
        -> BITSTRING { (rr_type_to_int tc):16; (dnssec_alg_to_int alg):8;
                       (byte_to_int nlbls):8; ttl:32; expiration:32; inception:32;
                       (int16_to_int keytag):16;
                       (mn_nocompress name):-1:bitstring;
                       (bytes_to_string sgn):-1:string
                     }, `RRSIG

      | `SSHFP (alg, fpt, fp)
        -> BITSTRING { (pubkey_alg_to_int alg):8;
                       (fp_type_to_int fpt):8;
                       (bytes_to_string fp):-1:string
                     }, `SSHFP
          
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
      (int16_to_int dns.id):16; 
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
*)
