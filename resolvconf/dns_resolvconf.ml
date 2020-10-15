let parse buf =
  try
    let buf =
      if String.(get buf (pred (length buf))) = '\n' then buf else buf ^ "\n"
    in
    let lexbuf = Lexing.from_string buf in
    Ok (Resolvconf_parser.resolvconf Resolvconf_lexer.lex lexbuf)
  with
    | Parsing.Parse_error -> Error (`Msg "parse error")
    | exn -> Error (`Msg (Printexc.to_string exn))
