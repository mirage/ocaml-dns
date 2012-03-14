(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
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
 * dnsserver.ml -- an authoritative DNS server
 *
 *)

open Loader

let load_zone origin buf =
  try 
    let lexbuf = Lexing.from_string buf in
    state.paren <- 0;
    state.filename <- "<string>";
    state.lineno <- 1;
    state.origin <- List.map String.lowercase origin;
    state.ttl <- Int32.of_int 3600;
    state.owner <- state.origin;
    Zone_parser.zfile Zone_lexer.token lexbuf
  with
    | Parsing.Parse_error -> (
      Printf.eprintf "Parse error: line %d\n%!" state.lineno;
      ()
    )
