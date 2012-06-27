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
open Name
open Cstruct

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
  RR_A          = 1;
  RR_NS         = 2;
  RR_MD         = 3;
  RR_MF         = 4;
  RR_CNAME      = 5;
  RR_SOA        = 6;
  RR_MB         = 7;
  RR_MG         = 8;
  RR_MR         = 9;
  RR_NULL       = 10;
  RR_WKS        = 11;
  RR_PTR        = 12;
  RR_HINFO      = 13;
  RR_MINFO      = 14;
  RR_MX         = 15;
  RR_TXT        = 16;
  RR_RP         = 17;
  RR_AFSDB      = 18;
  RR_X25        = 19;
  RR_ISDN       = 20;
  RR_RT         = 21;
  RR_NSAP       = 22;
  RR_NSAPPTR    = 23;
  RR_SIG        = 24;
  RR_KEY        = 25;
  RR_PX         = 26;
  RR_GPOS       = 27;
  RR_AAAA       = 28;
  RR_LOC        = 29;
  RR_NXT        = 30;
  RR_EID        = 31;
  RR_NIMLOC     = 32;
  RR_SRV        = 33;
  RR_ATMA       = 34;
  RR_NAPTR      = 35;
  RR_KM         = 36;
  RR_CERT       = 37;
  RR_A6         = 38;
  RR_DNAME      = 39;
  RR_SINK       = 40;
  RR_OPT        = 41;
  RR_APL        = 42;
  RR_DS         = 43;
  RR_SSHFP      = 44;
  RR_IPSECKEY   = 45;
  RR_RRSIG      = 46;
  RR_NSEC       = 47;
  RR_DNSKEY     = 48;
  RR_NSEC3      = 50;
  RR_NSEC3PARAM = 51;
  RR_SPF        = 99;
  RR_UINFO      = 100;
  RR_UID        = 101;
  RR_GID        = 102;
  RR_UNSPEC     = 103
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
type type_bit_map = byte * byte * Cstruct.buf
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

type rdata =
  | A of ipv4
  | AAAA of string
  | AFSDB of uint16 * domain_name
  | CNAME of domain_name
  | DNSKEY of uint16 * dnssec_alg * string
  | DS of uint16 * dnssec_alg * digest_alg * string
  | HINFO of string * string
  | IPSECKEY of byte * gateway_tc * ipseckey_alg * gateway * string
  | ISDN of string * string option
  | MB of domain_name
  | MD of domain_name
  | MF of domain_name
  | MG of domain_name
  | MINFO of domain_name * domain_name
  | MR of domain_name
  | MX of uint16 * domain_name
  | NS of domain_name
  | NSEC of domain_name (* uncompressed *) * type_bit_maps
  | NSEC3 of hash_alg * byte * uint16 * byte * string * byte * string * 
      type_bit_maps
  | NSEC3PARAM of hash_alg * byte * uint16 * byte * string
  | PTR of domain_name
  | RP of domain_name * domain_name
  | RRSIG of rr_type * dnssec_alg * byte * int32 * int32 * int32 * uint16 * 
      domain_name (* uncompressed *) * string
  | RT of uint16 * domain_name
  | SOA of domain_name * domain_name * int32 * int32 * int32 * int32 * int32
  | SRV of uint16 * uint16 * uint16 * domain_name
  | SSHFP of pubkey_alg * fp_type * string
  | TXT of string list
  | UNKNOWN of int * string
  (*  | UNSPEC of string -- wikipedia says deprecated in the 90s *)
  | WKS of int32 * byte * string
  | X25 of string 

let rdata_to_string = function
  | A ip -> sprintf "A (%s)" (ipv4_to_string ip)
  | AAAA bs -> sprintf "AAAA (%s)" bs
  | AFSDB (x, n)
    -> sprintf "AFSDB (%d, %s)" x (domain_name_to_string n)
  | CNAME n -> sprintf "CNAME (%s)" (domain_name_to_string n)
  | DNSKEY (flags, alg, key) 
    -> (sprintf "DNSKEY (%x, %s, %s)" 
          flags (dnssec_alg_to_string alg) 
          (Cryptokit.(transform_string (Base64.encode_compact ()) key))
    )
  | HINFO (cpu, os) -> sprintf "HINFO (%s, %s)" cpu os
  | ISDN (a, sa)
    -> sprintf "ISDN (%s, %s)" a (match sa with None -> "" | Some sa -> sa)
  | MB n -> sprintf "MB (%s)" (domain_name_to_string n)
  | MD n -> sprintf "MD (%s)" (domain_name_to_string n)
  | MF n -> sprintf "MF (%s)" (domain_name_to_string n)
  | MG n -> sprintf "MG (%s)" (domain_name_to_string n)
  | MINFO (rm, em)
    -> (sprintf "MINFO (%s, %s)" 
          (domain_name_to_string rm) (domain_name_to_string em)
    )
  | MR n -> sprintf "MR (%s)" (domain_name_to_string n)
  | MX (pref, name)
    -> sprintf "MX (%d, %s)" pref (domain_name_to_string name)
  | NS n -> sprintf "NS (%s)" (domain_name_to_string n)
  | PTR n -> sprintf "PTR (%s)" (domain_name_to_string n)
  | RP (mn, nn)
    -> (sprintf "RP (%s, %s)" 
          (domain_name_to_string mn) (domain_name_to_string nn)
    )
  | RT (x, n) 
    -> sprintf "RT (%d, %s)" x (domain_name_to_string n)
  | SOA (mn, rn, serial, refresh, retry, expire, minimum)
    -> (sprintf "SOA (%s,%s, %ld,%ld,%ld,%ld,%ld)"
          (domain_name_to_string mn) (domain_name_to_string rn) 
          serial refresh retry expire minimum
    )
  | SRV (x, y, z, n) 
    -> sprintf "SRV (%d,%d,%d, %s)" x y z (domain_name_to_string n)
  | TXT sl -> sprintf "TXT (%s)" (join "" sl)
  | UNKNOWN (x, bs) -> sprintf "UNKNOWN (%d) '%s'" x bs
  (* | UNSPEC bs -> sprintf "UNSPEC (%s)" bs*)
  | WKS (x, y, s) -> sprintf "WKS (%ld,%d, %s)" x (byte_to_int y) s
  | X25 s -> sprintf "X25 (%s)" s

  | DS (keytag, alg, digest_t, digest) 
    -> (sprintf "DS (%d,%s,%s, '%s')" keytag
          (dnssec_alg_to_string alg) (digest_alg_to_string digest_t) digest
    )
  | IPSECKEY (precedence, gw_type, alg, gw, pubkey)
    -> (sprintf "IPSECKEY (%d, %s,%s, %s, '%s')" (byte_to_int precedence)
          (gateway_tc_to_string gw_type) (ipseckey_alg_to_string alg)
          (gateway_to_string gw) pubkey
    )
  | NSEC (next_name, tbms) 
    -> (sprintf "NSEC (%s, %s)" 
          (domain_name_to_string next_name) (type_bit_maps_to_string tbms)
    )
  | NSEC3 (halg, flgs, iterations, salt_l, salt, hash_l, next_name, tbms)
    -> (sprintf "NSEC3 (%s, %x, %d, %d,'%s', %d,'%s', %s)"
          (hash_alg_to_string halg) (byte_to_int flgs) iterations 
          (byte_to_int salt_l) salt (byte_to_int  hash_l) next_name
          (type_bit_maps_to_string tbms)
    )
  | NSEC3PARAM (halg, flgs, iterations, salt_l, salt)
    -> (sprintf "NSEC3PARAM (%s,%x, %d, %d, '%s')"
          (hash_alg_to_string halg) (byte_to_int flgs) iterations 
          (byte_to_int salt_l) salt
    )
  | RRSIG (tc, alg, nlbls, ttl, expiration, inception, keytag, name, sign)
    -> (sprintf "RRSIG (%s,%s,%d, %ld, %ld,%ld, %d, %s, %s)"
          (rr_type_to_string tc) (dnssec_alg_to_string alg) 
          (byte_to_int nlbls) ttl expiration inception keytag
          (domain_name_to_string name) sign
    )
  | SSHFP (alg, fpt, fp)
    -> (sprintf "SSHFP (%s,%s, '%s')" (pubkey_alg_to_string alg) 
          (fp_type_to_string fpt) fp
    )

cenum rr_class {
  RR_IN = 1;
  RR_CS = 2;
  RR_CH = 3;
  RR_HS = 4
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
  rdata : rdata;
}

let rr_to_string rr = 
  sprintf "%s <%s|%ld> [%s]"
    (domain_name_to_string rr.name) (rr_class_to_string rr.cls) 
    rr.ttl (rdata_to_string rr.rdata)

cenum q_type {
  Q_A          = 1;
  Q_NS         = 2;
  Q_MD         = 3;
  Q_MF         = 4;
  Q_CNAME      = 5;
  Q_SOA        = 6;
  Q_MB         = 7;
  Q_MG         = 8;
  Q_MR         = 9;
  Q_NULL       = 10;
  Q_WKS        = 11;
  Q_PTR        = 12;
  Q_HINFO      = 13;
  Q_MINFO      = 14;
  Q_MX         = 15;
  Q_TXT        = 16;
  Q_RP         = 17;
  Q_AFSDB      = 18;
  Q_X25        = 19;
  Q_ISDN       = 20;
  Q_RT         = 21;
  Q_NSAP       = 22;
  Q_NSAPPTR    = 23;
  Q_SIG        = 24;
  Q_KEY        = 25;
  Q_PX         = 26;
  Q_GPOS       = 27;
  Q_AAAA       = 28;
  Q_LOC        = 29;
  Q_NXT        = 30;
  Q_EID        = 31;
  Q_NIMLOC     = 32;
  Q_SRV        = 33;
  Q_ATMA       = 34;
  Q_NAPTR      = 35;
  Q_KM         = 36;
  Q_CERT       = 37;
  Q_A6         = 38;
  Q_DNAME      = 39;
  Q_SINK       = 40;
  Q_OPT        = 41;
  Q_APL        = 42;
  Q_DS         = 43;
  Q_SSHFP      = 44;
  Q_IPSECKEY   = 45;
  Q_RRSIG      = 46;
  Q_NSEC       = 47;
  Q_DNSKEY     = 48;
  Q_NSEC3      = 50;
  Q_NSEC3PARAM = 51;

  Q_SPF        = 99;
  Q_UINFO      = 100;
  Q_UID        = 101;
  Q_GID        = 102;
  Q_UNSPEC     = 103;
  
  Q_AXFR    = 252;
  Q_MAILB   = 253;
  Q_MAILA   = 254;
  Q_ANY_TYP = 255;
  
  Q_TA    = 32768;
  Q_DLV   = 32769
} as uint8_t
                                            
cenum q_class {
  Q_IN   = 1;
  Q_CS   = 2;
  Q_CH   = 3;
  Q_HS   = 4;
  Q_NONE = 254;
  Q_ANY_CLS = 255
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
  sprintf "%s. <%s|%s>" 
    (domain_name_to_string q.q_name) 
    (q_type_to_string q.q_type) (q_class_to_string q.q_class)

let parse_question names base buf = 
  let q_name, (base,buf) = parse_name names base buf in  
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
  { q_name; q_type; q_class }, (base+sizeof_q, Cstruct.shift buf sizeof_q)

let marshal_question (names, base, buf) q =
  let names, base, buf = marshal_name names base buf q.q_name in
  set_q_typ buf (q_type_to_int q.q_type);
  set_q_cls buf (q_class_to_int q.q_class);
  names, base+sizeof_q, Cstruct.shift buf sizeof_q

let parse_rdata names base t buf = 
  (** Drop remainder bitstring to stop parsing and demuxing. *) 
  let stop (x, _) = x in
  (** Extract (length, string) encoded strings, with remainder for
      chaining. *)
  let parse_charstr buf = 
    let len = get_uint8 buf 0 in
    to_string (sub buf 1 len), Cstruct.shift buf (1+len)
  in
  match t with
    | RR_A -> A (BE.get_uint32 buf 0)
        
    | RR_AAAA -> AAAA (buf |> parse_charstr |>stop)
        
    | RR_AFSDB -> AFSDB (BE.get_uint16 buf 0,
                         buf |> parse_name names (base+2) |> stop)
        
    | RR_CNAME -> CNAME (buf |> parse_name names base |> stop)
        
    | RR_DNSKEY -> 
        let flags = BE.get_uint16 buf 0 in
        let alg = 
          let a = get_uint8 buf 3 in
          match int_to_dnssec_alg a with
            | None -> failwith (sprintf "parse_rdata: DNSKEY alg %d" a)
            | Some a -> a
        in
        let key = Cstruct.shift buf 4 |> to_string in
        DNSKEY (flags, alg, key)

    | RR_HINFO -> let cpu, buf = parse_charstr buf in
                  let os = buf |> parse_charstr |> stop in
                  HINFO (cpu, os)
                    
    | RR_ISDN -> let a, buf = parse_charstr buf in
                 let sa = match Cstruct.len buf with
                   | 0 -> None
                   | _ -> Some (buf |> parse_charstr |> stop)
                 in
                 ISDN (a, sa)        
        
    | RR_MB -> MB (buf |> parse_name names base |> stop)
        
    | RR_MG -> MG (buf |> parse_name names base |> stop)
        
    | RR_MINFO -> let rm, (o,buf) = buf |> parse_name names base in
                  let em = buf |> parse_name names (base+o) |> stop in
                  MINFO (rm, em)
                    
    | RR_MR -> MR (buf |> parse_name names base |> stop)
        
    | RR_MX -> MX (BE.get_uint16 buf 0,
                   Cstruct.shift buf 2 |> parse_name names base |> stop)
        
    | RR_NS -> NS (buf |> parse_name names base |> stop)
        
    | RR_PTR -> PTR (buf |> parse_name names base |> stop)
        
    | RR_RP -> let mbox, (o,buf) = buf |> parse_name names base in
               let txt = buf |> parse_name names (base+o) |> stop in
               RP (mbox, txt)
                 
    | RR_RT -> RT (BE.get_uint16 buf 0,
                   Cstruct.shift buf 2 |> parse_name names base |> stop)
    
    | RR_SOA -> 
        let mn, (base, buf) = parse_name names base buf in
        let rn, (_, buf) = parse_name names base buf in 
        BE.(SOA (mn, rn, 
                 BE.get_uint32 buf 0,  (* serial *)
                 BE.get_uint32 buf 4,  (* refresh *)
                 BE.get_uint32 buf 8,  (* retry *)
                 BE.get_uint32 buf 12, (* expire *)
                 BE.get_uint32 buf 16  (* minimum *)
        ))
          
    | RR_SRV -> 
        BE.(
          SRV (get_uint16 buf 0, (* prio *)
               get_uint16 buf 2, (* weight *)
               get_uint16 buf 4, (* port *)
               parse_name names (base+6) buf |> stop
          ))
          
    | RR_TXT -> 
        let strings = 
          let rec aux strings buf =
            match Cstruct.len buf with
              | 0 -> strings
              | len ->
                  let s, buf = parse_charstr buf in
                  aux (s :: strings) buf
          in
          aux [] buf
        in
        TXT strings
              
    | RR_WKS -> 
        let addr = BE.get_uint32 buf 0 in
        let proto = get_uint8 buf 4 in
        let bitmap = Cstruct.shift buf 5 |> to_string in
        WKS (addr, byte proto, bitmap)
    
    | RR_X25 ->
        let x25,_ = parse_charstr buf in
        X25 x25

let marshal_rdata names base buf rdata = 
  let base, rdbuf = base+sizeof_rr, Cstruct.shift buf sizeof_rr in
  let t, names, rdlen = match rdata with 
    | A ip -> 
        BE.set_uint32 rdbuf 0 ip;
        RR_A, names, 4

    | AAAA s -> 
        let s, slen = charstr s in
        Cstruct.set_buffer s 0 rdbuf 0 slen;
        RR_AAAA, names, slen

    | AFSDB (x,name) ->
        BE.set_uint16 rdbuf 0 x;
        let names, offset, _ = 
          marshal_name names (base+2) (Cstruct.shift rdbuf 2) name 
        in
        RR_AFSDB, names, offset-base
          
    | CNAME name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_CNAME, names, offset-base

    | DNSKEY (flags, alg, key) ->
        BE.set_uint16 rdbuf 0 flags;
        set_uint8 rdbuf 2 3;
        set_uint8 rdbuf 3 (dnssec_alg_to_int alg);
        let slen = String.length key in
        Cstruct.set_buffer key 0 rdbuf 4 slen;
        RR_DNSKEY, names, 4+slen

    | HINFO (cpu,os) ->
        let cpustr, cpulen = charstr cpu in
        Cstruct.set_buffer cpustr 0 rdbuf 0 cpulen;
        let osstr, oslen = charstr os in
        Cstruct.set_buffer osstr 0 rdbuf cpulen oslen;
        RR_HINFO, names, cpulen+oslen
          
    | ISDN (a,sa) ->
        let astr, alen = charstr a in
        Cstruct.set_buffer astr 0 rdbuf 0 alen;
        let sastr, salen = match sa with
          | None -> "", 0
          | Some sa -> charstr sa
        in
        Cstruct.set_buffer sastr 0 rdbuf alen salen;
        RR_ISDN, names, alen+salen
          
    | MB name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_MB, names, offset-base

    | MD name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_MD, names, offset-base

    | MF name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_MF, names, offset-base

    | MG name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_MG, names, offset-base

    | MINFO (rm,em) ->
        let names, offset, rdbuf = marshal_name names base rdbuf rm in
        let names, offset, _ = marshal_name names offset rdbuf em in
        RR_MINFO, names, offset-base

    | MR name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_MR, names, offset-base

    | MX (pref,xchg) ->
        BE.set_uint16 rdbuf 0 pref;
        let names, offset, _ = 
          marshal_name names (base+2) (Cstruct.shift rdbuf 2) xchg 
        in 
        RR_MX, names, offset-base

    | NS name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_NS, names, offset-base

    | RP (mbox,txt) ->
        let names, offset, rdbuf = marshal_name names base rdbuf mbox in
        let names, offset, _ = marshal_name names offset rdbuf txt in
        RR_RP, names, offset-base
    
    | RT (x, name) ->
        BE.set_uint16 rdbuf 0 x;
        let names, offset, _ = 
          marshal_name names (base+2) (Cstruct.shift rdbuf 2) name
        in
        RR_RT, names, offset-base

    | PTR name -> 
        let names, offset, _ = marshal_name names base rdbuf name in
        RR_PTR, names, offset-base

    | SOA (mn,rn, serial, refresh, retry, expire, minimum) ->
        let names, offset, rdbuf = marshal_name names base rdbuf mn in
        let names, offset, rdbuf = marshal_name names offset rdbuf rn in
        BE.set_uint32 rdbuf 0 serial;
        BE.set_uint32 rdbuf 4 refresh;
        BE.set_uint32 rdbuf 8 retry;
        BE.set_uint32 rdbuf 12 expire;
        BE.set_uint32 rdbuf 16 minimum;
        RR_SOA, names, 20+offset-base

    | SRV (prio, weight, port, name) ->
        BE.set_uint16 rdbuf 0 prio;
        BE.set_uint16 rdbuf 2 weight;
        BE.set_uint16 rdbuf 4 port;
        let names, offset, _ = 
          marshal_name names (base+6) (Cstruct.shift rdbuf 6) name
        in
        RR_SRV, names, offset-base

    | TXT strings -> 
        RR_TXT, names, List.fold_left (fun acc s ->
          let s, slen = charstr s in
          Cstruct.set_buffer s 0 rdbuf acc slen;
          acc+slen
        ) 0 strings

    | WKS (a,p, bm) ->
        BE.set_uint32 rdbuf 0 a;
        set_uint8 rdbuf 4 (byte_to_int p);
        let bmlen = String.length bm in
        Cstruct.set_buffer bm 0 rdbuf 5 bmlen;
        RR_WKS, names, 5+bmlen

    | X25 x25 ->
        let s,slen = charstr x25 in
        Cstruct.set_buffer s 0 rdbuf 0 slen;
        RR_X25, names, slen
          
  in
  set_rr_typ buf (rr_type_to_int t);
  set_rr_rdlen buf rdlen;
  names, base+rdlen, Cstruct.shift buf (sizeof_rr+rdlen)

let parse_rr names base buf =
  let name, (base,buf) = parse_name names base buf in
  let t = get_rr_typ buf in
  match int_to_rr_type t with
    | None -> failwith (sprintf "parse_rr: unknown type: %d" t)

    | Some typ ->
        let ttl = get_rr_ttl buf in
        let rdlen = get_rr_rdlen buf in
        let rdata = 
          let rdbuf = Cstruct.sub buf sizeof_rr rdlen in
          parse_rdata names (base+sizeof_rr) typ rdbuf
        in
        match get_rr_cls buf |> int_to_rr_class with
          | None -> failwith "parse_rr: unknown class"
          | Some cls -> 
              ({ name; cls; ttl; rdata }, 
               ((base+sizeof_rr+rdlen), Cstruct.shift buf (sizeof_rr+rdlen))
              )

let marshal_rr (names, base, buf) rr =
  let names, base, buf = marshal_name names base buf rr.name in
  set_rr_cls buf (rr_class_to_int rr.cls);
  set_rr_ttl buf rr.ttl;
  marshal_rdata names base buf rr.rdata

cenum qr {
  Query = 0;
  Response = 1
} as uint8_t
    
cenum opcode {
  Standard = 0;
  Inverse = 1;
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

cstruct h {
  uint16_t id;
  uint16_t detail;
  uint16_t qdcount;
  uint16_t ancount;
  uint16_t nscount;
  uint16_t arcount
} as big_endian

type detail = {
  qr: qr;
  opcode: opcode;
  aa: bool; 
  tc: bool; 
  rd: bool; 
  ra: bool;
  rcode: rcode;
}

let marshal_detail d = 
  let (<<<) x y = x lsl y in
  let (|||) x y = x lor y in
  (qr_to_int d.qr <<< 15)
  ||| (opcode_to_int d.opcode <<< 11)
    ||| (if d.aa then 1 <<< 10 else 0)
      ||| (if d.tc then 1 <<<  9 else 0)
        ||| (if d.rd then 1 <<<  8 else 0)
          ||| (if d.ra then 1 <<<  7 else 0)
            ||| (rcode_to_int d.rcode)

let detail_to_string d = 
  sprintf "%s:%d %s:%s:%s:%s %d"
    (qr_to_string d.qr)
    (opcode_to_int d.opcode)
    (if d.aa then "a" else "na") (* authoritative vs not *)
    (if d.tc then "t" else "c") (* truncated vs complete *)
    (if d.rd then "r" else "nr") (* recursive vs not *)
    (if d.ra then "ra" else "rn") (* recursion available vs not *)
    (rcode_to_int d.rcode)

let parse_detail d = 
  let qr = match (d lsr 15 land 1) |> int_to_qr with
    | Some qr -> qr
    | None -> failwith "bad qr"
  in
  let opcode = match (d lsr 11 land 0b0_1111) |> int_to_opcode with
    | Some opcode -> opcode
    | None -> failwith "bad opcode"
  in
  let aa = (d lsr 10 land 1) |> int_to_bool in
  let tc = (d lsr  9 land 1) |> int_to_bool in
  let rd = (d lsr  8 land 1) |> int_to_bool in
  let ra = (d lsr  7 land 1) |> int_to_bool in
  let rcode = match (d land 0b0_1111) |> int_to_rcode with
    | Some rcode -> rcode
    | None -> failwith "bad rcode"
  in
  { qr; opcode; aa; tc; rd; ra; rcode }

type t = {
  id          : int;
  detail      : detail;
  questions   : question list; (* Cstruct.iter; *)
  answers     : rr list; (* Cstruct.iter; *)
  authorities : rr list; (* Cstruct.iter; *)
  additionals : rr list; (* Cstruct.iter; *)
}

let to_string d = 
  sprintf "%04x %s <qs:%s> <an:%s> <au:%s> <ad:%s>"
    d.id (detail_to_string d.detail)
    (d.questions ||> question_to_string |> join ",")
    (d.answers ||> rr_to_string |> join ",")
    (d.authorities ||> rr_to_string |> join ",")
    (d.additionals ||> rr_to_string |> join ",")

let parse names buf = 
  let parsen f names base n buf = 
    let rec aux acc n base buf = 
      match n with
        | 0 -> acc, (base,buf)
        | _ -> let r, (base,buf) = f names base buf in 
               aux (r :: acc) (n-1) base buf
    in
    aux [] n base buf
  in

  let id = get_h_id buf in
  let detail = get_h_detail buf |> parse_detail in
  let qdcount = get_h_qdcount buf in
  let ancount = get_h_ancount buf in
  let nscount = get_h_nscount buf in
  let arcount = get_h_arcount buf in

  let base = sizeof_h in
  let buf = Cstruct.shift buf base in
  let questions, (base,buf) = parsen parse_question names base qdcount buf in
  let answers, (base,buf) = parsen parse_rr names base ancount buf in
  let authorities, (base,buf) = parsen parse_rr names base nscount buf in
  let additionals, _ = parsen parse_rr names base arcount buf in
  let dns = { id; detail; questions; answers; authorities; additionals } in
  (* eprintf "RX: %s\n%!" (to_string dns); *)
  dns

let marshal txbuf dns = 
  let marshaln f names base buf values = 
    List.fold_left f (names, base, buf) values
  in
                        
  set_h_id txbuf dns.id;
  set_h_detail txbuf (marshal_detail dns.detail);
  set_h_qdcount txbuf (List.length dns.questions);
  set_h_ancount txbuf (List.length dns.answers);
  set_h_nscount txbuf (List.length dns.authorities);
  set_h_arcount txbuf (List.length dns.additionals);

  (** Map name (list of labels) to an offset. *)
  let (names:(domain_name, int) Hashtbl.t) = Hashtbl.create 8 in
  let base,buf = sizeof_h, Cstruct.shift txbuf sizeof_h in
  let names,base,buf = marshaln marshal_question names base buf dns.questions in
  let names,base,buf = marshaln marshal_rr names base buf dns.answers in
  let names,base,buf = marshaln marshal_rr names base buf dns.authorities in
  let _,_,buf = marshaln marshal_rr names base buf dns.additionals in

  let txbuf = Cstruct.(sub txbuf 0 (len txbuf - len buf)) in
  (* Cstruct.hexdump txbuf;   *)
  (* eprintf "TX: %s\n%!" (txbuf |> parse (Hashtbl.create 8) |> to_string); *)
  txbuf
       
(*
mr:
      | `RT (p, ih) -> BITSTRING { (int16_to_int p):16; (mn ~off:2 ih):-1:bitstring }, `RT
      | `SRV (prio, weight, port, target)
        -> BITSTRING { (int16_to_int prio):16; (int16_to_int weight):16; 
                       (int16_to_int port):16; (mn ~off:6 target):-1:bitstring
                     }, `SRV
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
          
*)
