/*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
 * Copyright (c) 2017, 2018 Hannes Mehnert <hannes@mehnert.org>
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
 *
 *  dnsparser.mly -- ocamlyacc parser for DNS "Master zone file" format
 */

%{

open Dns_zone_state
open Dns

let parse_error s = raise (Zone_parse_problem s)

(* Parsers for numbers *)
let parse_uint8 s =
  try let d = int_of_string s in
  if d < 0 || d > 255 then raise Parsing.Parse_error;
  d
  with Failure _ -> raise Parsing.Parse_error

let parse_uint16 s =
  try
    let n = int_of_string s in
    if n > 65535 then raise Parsing.Parse_error;
    n
  with Failure _ -> raise Parsing.Parse_error

let parse_uint32 s =
  try
    let n = Int64.of_string s in
    if n >= 4294967296L then raise Parsing.Parse_error;
    Int64.to_int32 n
  with Failure _ -> raise Parsing.Parse_error

(* Parse an IPv6 address.  (RFC 3513 section 2.2) *)
let parse_ipv6 s =
  Ipaddr.V6.of_string_exn s

let add_to_map name ~ttl (Rr_map.B (k, v)) =
  let v = Rr_map.with_ttl k v ttl in
  Name_rr_map.add name k v

let parse_lat lat dir =
  List.map (Int32.to_string) lat @ [dir] 

%}

%token EOF
%token EOL
%token SORIGIN
%token STTL
%token AT
%token DOT
%token SPACE
%token GENERIC
%token <string> NUMBER
%token <string> CHARSTRING

%token <string> TYPE_A
%token <string> TYPE_NS
%token <string> TYPE_CNAME
%token <string> TYPE_SOA
%token <string> TYPE_PTR
%token <string> TYPE_MX
%token <string> TYPE_TXT
%token <string> TYPE_AAAA
%token <string> TYPE_SRV
%token <string> TYPE_CAA
%token <string> TYPE_DNSKEY
%token <string> TYPE_TLSA
%token <string> TYPE_SSHFP
%token <string> TYPE_DS
%token <string> TYPE_LOC
%token <string> TYPE_GENERIC

%token <string> CLASS_IN
%token <string> CLASS_CS
%token <string> CLASS_CH
%token <string> CLASS_HS

%token <string> METERS
%token <string> LAT_DIR
%token <string> LONG_DIR

%start zfile
%type <Dns.Name_rr_map.t> zfile

%%

zfile: lines EOF { state.zone }

lines:
   /* nothing */ { }
 | lines EOL { }
 | lines origin EOL { }
 | lines ttl EOL { }
 | lines rrline EOL { }

s: SPACE {} | s SPACE {}

origin: SORIGIN s domain { state.origin <- $3 }

ttl: STTL s int32 { state.ttl <- $3 }

rrline:
   owner s int32 s rrclass s rr { state.zone <- add_to_map $1 ~ttl:$3 $7 state.zone }
 | owner s rrclass s int32 s rr { state.zone <- add_to_map $1 ~ttl:$5 $7 state.zone  }
 | owner s rrclass s rr { state.zone <- add_to_map $1 ~ttl:state.ttl $5 state.zone }
 | owner s int32 s rr { state.zone <- add_to_map $1 ~ttl:$3 $5 state.zone }
 | owner s rr { state.zone <- add_to_map $1 ~ttl:state.ttl $3 state.zone }

rrclass:
   CLASS_IN {}
 | CLASS_CS { parse_error "class must be \"IN\"" }
 | CLASS_CH { parse_error "class must be \"IN\"" }
 | CLASS_HS { parse_error "class must be \"IN\"" }

rr:
generic_type s generic_rdata {
  match Rr_map.I.of_int $1 with
  | Ok i -> B (Unknown i, (0l, Rr_map.Txt_set.singleton $3))
  | Error _ -> parse_error "type code reserved, not generic"
}
     /* RFC 1035 */
 | TYPE_A s ipv4 { B (A, (0l, Ipaddr.V4.Set.singleton $3)) }
 | TYPE_NS s hostname { B (Ns, (0l, Domain_name.Host_set.singleton $3)) }
 | TYPE_CNAME s domain { B (Cname, (0l, $3)) }
 | TYPE_SOA s domain s domain s int32 s int32 s int32 s int32 s int32
     { B (Soa, { Soa.nameserver = $3 ; hostmaster = $5 ; serial = $7 ;
                 refresh = $9 ; retry = $11 ; expiry = $13 ; minimum = $15 }) }
 | TYPE_PTR s hostname { B (Ptr, (0l, $3)) }
 | TYPE_MX s int16 s hostname
     { let mx = { Mx.preference = $3 ; mail_exchange = $5 } in
       B (Mx, (0l, Rr_map.Mx_set.singleton mx)) }
 | TYPE_TXT s charstrings
     { let txt = String.concat "" $3 in
       if String.length txt > 65279 then
         (* there's only so much space for a RR - TXT needs for each 255 byte an extra length byte *)
         parse_error "A single TXT rdata may not exceed 65279 bytes";
       B (Txt, (0l, Rr_map.Txt_set.singleton txt)) }
     /* RFC 2782 */
 | TYPE_SRV s int16 s int16 s int16 s hostname
     { let srv = { Srv.priority = $3 ; weight = $5 ; port = $7 ; target = $9 } in
       B (Srv, (0l, Rr_map.Srv_set.singleton srv)) }
     /* RFC 3596 */
 | TYPE_TLSA s int8 s int8 s int8 s hex
     { try
         let cert_usage = Tlsa.int_to_cert_usage $3
         and selector = Tlsa.int_to_selector $5
         and matching_type = Tlsa.int_to_matching_type $7
         in
         if Cstruct.length $9 > max_rdata_length - 3 then
           parse_error "TLSA payload exceeds maximum rdata size";
         let tlsa = { Tlsa.cert_usage ; selector ; matching_type ; data = $9 } in
         B (Tlsa, (0l, Rr_map.Tlsa_set.singleton tlsa ))
       with
       | Invalid_argument err -> parse_error err
     }
 | TYPE_SSHFP s int8 s int8 s hex
     { try
         let algorithm = Sshfp.int_to_algorithm $3
         and typ = Sshfp.int_to_typ $5
         in
         if Cstruct.length $7 > max_rdata_length - 2 then
           parse_error "SSHFP payload exceeds maximum rdata size";
         let sshfp = { Sshfp.algorithm ; typ ; fingerprint = $7 } in
         B (Sshfp, (0l, Rr_map.Sshfp_set.singleton sshfp))
       with
       | Invalid_argument err -> parse_error err
     }
 | TYPE_DS s int16 s int8 s int8 s hex
     { try
         let key_tag = $3
         and algorithm = Dnskey.int_to_algorithm $5
         and digest_type = Ds.int_to_digest_type $7
         in
         if Cstruct.length $9 > max_rdata_length - 4 then
           parse_error "DS payload exceeds maximum rdata size";
         let ds = { Ds.key_tag ; algorithm ; digest_type ; digest = $9 } in
         B (Ds, (0l, Rr_map.Ds_set.singleton ds))
       with
       | Invalid_argument err -> parse_error err
     }
 | TYPE_AAAA s ipv6 { B (Aaaa, (0l, Ipaddr.V6.Set.singleton $3)) }
 | TYPE_DNSKEY s int16 s int8 s int8 s charstring
     { if not ($5 = 3) then
         parse_error ("DNSKEY protocol is not 3, but " ^ string_of_int $5) ;
       try
         let algorithm = Dnskey.int_to_algorithm $7 in
         if String.length $9 > max_rdata_length - 4 then
           parse_error "DNSKEY exceeds maximum rdata size";
         let flags = Dnskey.decode_flags $3 in
         let dnskey = { Dnskey.flags ; algorithm ; key = Cstruct.of_string $9 } in
         B (Dnskey, (0l, Rr_map.Dnskey_set.singleton dnskey))
       with
       | Invalid_argument err -> parse_error err
     }
 | TYPE_CAA s int8 s charstring s charstrings
     { let critical = if $3 = 0x80 then true else false in
       if String.length $5 <= 0 || String.length $5 >= 16 then
         parse_error "CAA tag length must be > 0 and < 16";
       let size =
         (* the values are ';' separated (thus + 1 here) *)
         List.fold_left (fun acc s -> acc + 1 + String.length s)
           (String.length $5) $7
       in
       (* actually flag + tag length = 2, but we already added one for the first
          value above *)
       if size > max_rdata_length - 1 then
         parse_error "CAA exceeds maximum rdata size";
       let caa = { Caa.critical ; tag = $5 ; value = $7 } in
       B (Caa, (0l, Rr_map.Caa_set.singleton caa)) }
     /* RFC 1876 */
     // TODO optional args
 | TYPE_LOC s latitude s longitude s altitude precision
    { let lat = $3 in
      let long = $5 in
      let alt = $7 in
      let size, h_prec, v_prec = $8 in
      let list =
        lat
        @ long
        @ (List.map (Float.to_string) ([alt; size; h_prec; v_prec]))
      in
      let txt = String.concat " " list in
      B (Loc, (0l, Rr_map.Loc_set.singleton txt)) }
 | CHARSTRING s { parse_error ("TYPE " ^ $1 ^ " not supported") }

single_hex: charstring
  { Cstruct.of_hex $1 }

hex:
   single_hex { $1 }
 | hex s single_hex { Cstruct.append $1 $3 }

generic_type: TYPE_GENERIC
     { try parse_uint16 (String.sub $1 4 (String.length $1 - 4))
       with Parsing.Parse_error -> parse_error ($1 ^ " is not a 16-bit number")
     }

generic_rdata: GENERIC s NUMBER s hex
     { try
         let len = int_of_string $3
         and data = Cstruct.to_string $5
         in
         if not (String.length data = len) then
           parse_error ("generic data length field is "
			   ^ $3 ^ " but actual length is "
			      ^ string_of_int (String.length data));
         if len > max_rdata_length then
           parse_error ("generic data length field exceeds maximum rdata size: " ^ $3);
	 data
       with Failure _ ->
	 parse_error ("\\# should be followed by a number")
     }

ipv4: NUMBER DOT NUMBER DOT NUMBER DOT NUMBER
     { try
	 let a = parse_uint8 $1 in
	 let b = parse_uint8 $3 in
	 let c = parse_uint8 $5 in
	 let d = parse_uint8 $7 in
         Ipaddr.V4.make a b c d
       with Failure _ | Parsing.Parse_error ->
	 parse_error ("invalid IPv4 address " ^ $1 ^ "." ^ $3 ^ "." ^ $5 ^ "." ^ $7)
     }

ipv6: charstring
     { try parse_ipv6 $1 with
       | Failure _ | Parsing.Parse_error ->
	  parse_error ("invalid IPv6 address " ^ $1)
     }

int8: NUMBER
     { try parse_uint8 $1
       with Parsing.Parse_error ->
	 parse_error ($1 ^ " is not a 8-bit number") }

int16: NUMBER
     { try parse_uint16 $1
       with Parsing.Parse_error ->
	 parse_error ($1 ^ " is not a 16-bit number") }

int32: NUMBER
     { try parse_uint32 $1
       with Failure _ ->
	 parse_error ($1 ^ " is not a 32-bit number") }

meters: METERS
     { try Float.of_string $1
       with Failure _ ->
	 parse_error ($1 ^ " is not a 32-bit number") }

latitude:
  | int32 s int32 s int32 s LAT_DIR { parse_lat [$1; $3; $5] $7 }
  | int32 s int32 s LAT_DIR { parse_lat [$1; $3; 0l] $5 }
  | int32 s LAT_DIR { parse_lat [$1; 0l; 0l] $3 }

longitude:
  | int32 s int32 s int32 s LONG_DIR { parse_lat [$1; $3; $5] $7 }
  | int32 s int32 s LONG_DIR { parse_lat [$1; $3; 0l] $5 }
  | int32 s LONG_DIR { parse_lat [$1; 0l; 0l] $3 }

// TODO why does this not work?
// "2 rules never reduced
// 2 shift/reduce conflicts."
// latitude: lat_long_deg_min_sec s LAT_DIR { parse_lat $1 $3 }

// lat_long_deg_min_sec:
//   int32 s int32 s int32 { [$1; $3; $5] }
//   | int32 s int32 { [$1; $3; 0l] }
//   | int32 { [$1; 0l; 0l] }

altitude: meters { $1 }

// TODO is there a better way to avoid duplicating default values?
precision:
  | { (1., 10000., 10.) }
  | s meters s meters s meters { ($2, $4, $6) }
  | s meters s meters { ($2, $4, 10.) }
  | s meters { ($2, 10000., 10.) }

/* The owner of an RR is more restricted than a general domain name: it
   can't be a pure number or a type or class.  If we see one of those we
   assume the owner field was omitted */
owner:
   /* nothing */ { state.owner }
 | domain { state.owner <- $1 ; state.owner }

domain:
   DOT { Domain_name.root }
 | AT { state.origin }
 | label_except_at { Domain_name.prepend_label_exn state.origin $1 }
 | label DOT { Domain_name.of_strings_exn [$1] }
 | label DOT domain_labels { Domain_name.of_strings_exn ($1 :: $3 @ (Domain_name.to_strings state.origin)) }
 | label DOT domain_labels DOT { Domain_name.of_strings_exn ($1 :: $3) }

domain_labels:
   label { [$1] }
 | domain_labels DOT label { $1 @ [$3] }

hostname: domain { Domain_name.host_exn $1 }

/* It's acceptable to re-use numbers and keywords as character-strings.
   This is pretty ugly: we need special cases to distinguish a domain
   that's made up of just an '@'. */

charstrings: charstring { [$1] } | charstrings s charstring { $1 @ [$3] }

charstring: CHARSTRING { $1 } | keyword_or_number { $1 } | AT { "@" }

label_except_specials: CHARSTRING
    { if String.length $1 > 63 then
        parse_error "label is longer than 63 bytes";
      $1 }

label_except_at: label_except_specials { $1 } | keyword_or_number { $1 }

label: label_except_at { $1 } | AT { "@" }

keyword_or_number:
   NUMBER { $1 }
 | TYPE_A { $1 }
 | TYPE_NS { $1 }
 | TYPE_CNAME { $1 }
 | TYPE_SOA { $1 }
 | TYPE_PTR { $1 }
 | TYPE_MX { $1 }
 | TYPE_TXT { $1 }
 | TYPE_AAAA { $1 }
 | TYPE_SRV { $1 }
 | TYPE_DNSKEY { $1 }
 | TYPE_TLSA { $1 }
 | TYPE_SSHFP { $1 }
 | TYPE_LOC { $1 }
 | CLASS_IN { $1 }
 | CLASS_CS { $1 }
 | CLASS_CH { $1 }
 | CLASS_HS { $1 }

%%
