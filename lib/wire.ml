(*
 * Copyright (c) 2011 Richard Mortier <mort@cantab.net>
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
 *)

open Operators

exception Unparsable of string * Bitstring.t

let offset_of_bitstring bits = 
    let (_, offset, _) = bits in offset

type int16 = int
let int16 (i:int) : int16 = min i 0xffff
let int16_to_int (i:int16) : int = i
                                    
type byte = char
let byte (i:int) : byte = Char.chr i
let byte_to_int b = int_of_char b
let byte_to_int32 b = b |> byte_to_int |> Int32.of_int

type bytes = Uri_IP.bytes
let bytes (s:string) : bytes = Uri_IP.bytes s
let bits_to_bytes bits = Bitstring.string_of_bitstring bits|> bytes
let bytes_to_string (bs:bytes) : string = Uri_IP.bytes_to_string bs
(*
let bytes_to_string (bs:bytes) : string =
  let s = ref [] in 
  let l = Uri_IP.bytes_length bs in
  for i = 0 to (l-1) do 
    s := (Printf.sprintf "%02x" (byte_to_int bs.[i])) :: !s
  done;
  String.concat "." !s
*)
let bytes_to_ipv4 bs = Uri_IP.bytes_to_ipv4 bs
