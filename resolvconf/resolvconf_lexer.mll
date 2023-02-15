{
open Resolvconf_state
open Resolvconf_parser
}

let ipv4 = (['0'-'9']+ '.' ['0'-'9']+ '.' ['0'-'9']+ '.' ['0'-'9']+) as contents
let ipv6 = (['0'-'9' 'a'-'f' 'A'-'F' ':']+) as contents

let zone_id = (['0'-'9' 'a'-'z' 'A'-'Z' '.' ]+) as contents

(* inspired by https://github.com/tailhook/resolv-conf/blob/master/src/grammar.rs *)

rule lex = parse
  | "nameserver" { SNAMESERVER }
  | "options" ([^'\n']*) '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | "search" ([^'\n']*) '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | "domain" ([^'\n']*) '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | "sortlist" ([^'\n']*) '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | "lookup" ([^'\n']*) '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | "family" ([^'\n']*) '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | [' ' '\t']+ { SPACE }
  | ipv4 { IPV4 contents }
  | ipv6 { IPV6 contents }
  | '.' { DOT }
  | ':' { COLON }
  | '%' { PERCENT }
  | [' ' '\t']* ('#' [^'\n']*)? '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | [' ' '\t']* (';' [^'\n']*)? '\n' { state.lineno <- state.lineno + 1 ; EOL }
  | zone_id { ZONE_ID contents }
  | eof { EOF }
