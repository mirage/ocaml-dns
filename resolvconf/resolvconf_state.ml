(* State variables for the parser & lexer *)
type parserstate = {
  mutable lineno : int ;
}

let state = {
  lineno = 1 ;
}

let reset () =
  state.lineno <- 1
