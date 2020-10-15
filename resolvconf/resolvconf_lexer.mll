{
open Resolvconf_parser
}

let ipv4 = (['0'-'9']+ '.' ['0'-'9']+ '.' ['0'-'9']+ '.' ['0'-'9']+) as contents
let ipv6 = (['0'-'9' 'a'-'f' 'A'-'F' ':']+) as contents

(* inspired by https://github.com/tailhook/resolv-conf/blob/master/src/grammar.rs *)

rule lex = parse
  | "nameserver" { SNAMESERVER }
  | "options" ([^'\n']*) '\n' { EOL }
  | "search" ([^'\n']*) '\n' { EOL }
  | "domain" ([^'\n']*) '\n' { EOL }
  | "sortlist" ([^'\n']*) '\n' { EOL }
  | "lookup" ([^'\n']*) '\n' { EOL }
  | "family" ([^'\n']*) '\n' { EOL }
  | [' ' '\t']+ { SPACE }
  | ipv4 { IPV4 contents }
  | ipv6 { IPV6 contents }
  | '.' { DOT }
  | ':' { COLON }
  | [' ' '\t']* ('#' [^'\n']*)? '\n' { EOL }
  | [' ' '\t']* (';' [^'\n']*)? '\n' { EOL }
  | eof { EOF }
