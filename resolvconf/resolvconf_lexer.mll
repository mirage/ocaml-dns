{
exception Illegal_character of char * Lexing.position

open Resolvconf_parser
}

let ipv4 = (['0'-'9']+ '.' ['0'-'9']+ '.' ['0'-'9']+ '.' ['0'-'9']+) as contents
let ipv6 = (['0'-'9' 'a'-'f' 'A'-'F' ':']+) as contents

(* inspired by https://github.com/tailhook/resolv-conf/blob/master/src/grammar.rs *)

rule lex = parse
  | "nameserver" { SNAMESERVER }
  | "options" ([^'\n']*) '\n' { Lexing.new_line lexbuf; EOL }
  | "search" ([^'\n']*) '\n' { Lexing.new_line lexbuf; EOL }
  | "domain" ([^'\n']*) '\n' { Lexing.new_line lexbuf; EOL }
  | "sortlist" ([^'\n']*) '\n' { Lexing.new_line lexbuf; EOL }
  | "lookup" ([^'\n']*) '\n' { Lexing.new_line lexbuf; EOL }
  | "family" ([^'\n']*) '\n' { Lexing.new_line lexbuf; EOL }
  | [' ' '\t']+ { SPACE }
  | ipv4 { IPV4 contents }
  | ipv6 { IPV6 contents }
  | '.' { DOT }
  | ':' { COLON }
  | [' ' '\t']* ('#' [^'\n']*)? '\n' { Lexing.new_line lexbuf; EOL }
  | [' ' '\t']* (';' [^'\n']*)? '\n' { Lexing.new_line lexbuf; EOL }
  | eof { EOF }
  | (_ as c ) { raise @@ Illegal_character (c, Lexing.lexeme_end_p lexbuf) }
