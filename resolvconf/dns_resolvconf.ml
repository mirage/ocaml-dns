let parse buf =
  try
    Resolvconf_state.reset ();
    let buf =
      if String.(get buf (pred (length buf))) = '\n' then buf else buf ^ "\n"
    in
    let lexbuf = Lexing.from_string buf in
    Ok (Resolvconf_parser.resolvconf Resolvconf_lexer.lex lexbuf)
  with
  | Parsing.Parse_error ->
    Error (`Msg (Fmt.str "parse error at line %d" Resolvconf_state.(state.lineno)))
  | exn ->
    Error (`Msg (Fmt.str "error at line %d: %s" Resolvconf_state.(state.lineno)
                   (Printexc.to_string exn)))
