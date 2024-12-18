(*
 * Copyright (c) 2006 Tim Deegan <tjd@phlegethon.org>
 * Copyright (c) 2010-12 Anil Madhavapeddy <anil@recoil.org>
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
 *  dnslexer.mll -- ocamllex lexer for DNS "Master zone file" format
 *
 *  DNS master zonefile format is defined in RFC 1035, section 5.
 *  Escapes and octets are clarified in RFC 4343
 *)

{

open Dns_zone_state
open Dns_zone_parser
open Lexing

(* Disambiguate keywords and generic character strings -- when updating this,
   please ensure to update the keyword_or_number rule in dns_zone_parser.mly
   and add it to the testuite in test/server.ml *)
let kw_or_cs s = match (String.uppercase_ascii s) with
    "A" -> TYPE_A s
  | "NS" -> TYPE_NS s
  | "CNAME" -> TYPE_CNAME s
  | "SOA" -> TYPE_SOA s
  | "PTR" -> TYPE_PTR s
  | "MX" -> TYPE_MX s
  | "TXT" -> TYPE_TXT s
  | "AAAA" -> TYPE_AAAA s
  | "SRV" -> TYPE_SRV s
  | "SVCB" -> TYPE_SVCB s
  | "HTTPS" -> TYPE_HTTPS s
  | "DNSKEY" -> TYPE_DNSKEY s
  | "CAA" -> TYPE_CAA s
  | "TLSA" -> TYPE_TLSA s
  | "SSHFP" -> TYPE_SSHFP s
  | "DS" -> TYPE_DS s
  | "LOC" -> TYPE_LOC s
  | "IN" -> CLASS_IN s
  | "CS" -> CLASS_CS s
  | "CH" -> CLASS_CH s
  | "HS" -> CLASS_HS s
  | "N" -> LAT_DIR s
  | "S" -> LAT_DIR s
  | "E" -> LONG_DIR s
  | "W" -> LONG_DIR s
  | _ -> CHARSTRING s

(* Scan an accepted token for linebreaks *)
let count_linebreaks s =
  String.iter (function '\n' -> state.lineno <- state.lineno + 1 | _ -> ()) s

}

let eol = [' ''\t']* (';' [^'\n']*)? '\n'
let octet = '\\' ['0'-'9'] ['0'-'9'] ['0'-'9']
let escape = '\\' _ (* Strictly \0 is not an escape, but be liberal *)
let qstring = '"' ((([^'\\''"']|octet|escape)*) as contents) '"'
let label = (([^'\\'' ''\t''\n''.''('')']|octet|escape)*) as contents
let number = (['0'-'9']+) as contents
let neg_number = ('-' ['0'-'9']+) as contents
let meters = ('-'? ['0'-'9']+ ('.' ['0'-'9']? ['0'-'9']?)? as contents) 'm'
let openpar = [' ''\t']* '(' ([' ''\t''\n'] | eol)*
let closepar = (eol | [' ''\t''\n'])* ')' [' ''\t']*
let typefoo = (['T''t']['Y''y']['P''p']['E''e'] number) as contents

(* Rfc9460 Appendix A *)
let svcb_non_special = '!' | ['#'-'\''] | ['*'-':'] | ['<'-'['] | [']'-'~']
let svcb_non_digit = ['!'-'/'] | [':'-'~']
let svcb_dec_octet = (('0' | '1') ['0'-'9'] ['0'-'9']) | ('2' ((['0'-'4'] ['0'-'9']) ('5' ['0'-'5'])))
let svcb_escaped = '\\' (svcb_non_digit | svcb_dec_octet)
let svcb_contigious = (svcb_non_special | svcb_escaped)+
let svcb_quoted = '"' (svcb_contigious | (['\\']? ' ')) '"' 
let svcb_char_string = svcb_contigious | svcb_quoted

(* Rfc9460 2.1 *)
let svcbkey = (['a'-'z']|['0'-'9']|'-')*
let svcbval = svcb_char_string
let svcbvalq = '"' svcbval '"'
let svcbparam = (svcbkey '=' (svcbval | svcbvalq)) as contents

rule token = parse
  eol           { state.lineno <- state.lineno + 1;
	          if state.paren > 0 then SPACE else EOL }
| openpar       { state.paren <- state.paren + 1;
	          count_linebreaks (lexeme lexbuf); SPACE }
| closepar      { if state.paren > 0 then state.paren <- state.paren - 1;
	          count_linebreaks (lexeme lexbuf); SPACE }
| closepar eol  { if state.paren > 0 then state.paren <- state.paren - 1;
	          count_linebreaks (lexeme lexbuf); EOL }
| "\\#"         { GENERIC }
| "$ORIGIN"     { SORIGIN }
| "$TTL"        { STTL }
| '.'           { DOT }
| '@'           { AT }
| number        { NUMBER contents }
| neg_number    { NEG_NUMBER contents }
| meters        { METERS contents }
| typefoo       { TYPE_GENERIC contents }
| qstring       { count_linebreaks contents; CHARSTRING contents }
| svcbparam     { count_linebreaks contents; SVCBPARAM contents }
| label         { count_linebreaks contents; kw_or_cs contents }
| [' ''\t']+    { SPACE }
| eof           { EOF }
