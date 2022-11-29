let parse buf =
  try
    let buf =
      if String.(get buf (pred (length buf))) = '\n' then buf else buf ^ "\n"
    in
    let lexbuf = Lexing.from_string buf in
    Ok (Resolvconf_parser.resolvconf Resolvconf_lexer.lex lexbuf)
  with
    | Parsing.Parse_error -> Error (`Msg "parse error")
    | Resolvconf_lexer.Illegal_character (c , pos) ->
      let err = 
        Printf.sprintf "lexing: Illegal character '%c' at line: %d, col: %d"
          c pos.pos_lnum
          (pos.pos_cnum - pos.pos_bol)
      in
      Error (`Msg err)
    | exn -> Error (`Msg (Printexc.to_string exn))
