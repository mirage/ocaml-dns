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

(** Wire type and bit manipulation. 

    @author Richard Mortier <mort\@cantab.net>
    @author Anil Madhavapeddy <anil\@recoil.org>
*)

(** Received some unparsable bits. *)
exception Unparsable of string * Bitstring.t

(** Extract [offset] from {! Bitstring.t }. *)
val offset_of_bitstring : Bitstring.t -> int

(** For readability. *)
type int16

(** Convert {! int } to {! byte }; useful in pipelines. *)
val int16 : int -> int16

(** *)
val int16_to_int : int16 -> int

(** Single octet, for bit manipulation. *)
type byte

(** Convert {! int } to {! byte }; useful in pipelines. *)
val byte : int -> byte

(** Convert {! byte } to {! int }. *)
val byte_to_int : byte -> int

(** Convert {! byte } to {! Int32 }. *)
val byte_to_int32 : byte -> int32

(** For readability. *)
type bytes

(** Convert {! string} to {! bytes}. *)
val bytes : string -> bytes 

(** Render {! Bitstring.t} to {! bytes}. *)
val bits_to_bytes : Bitstring.t -> bytes

(** Convert {! bytes} to {! string}. *)
val bytes_to_string : bytes -> string

(** Convert (4) {! bytes} to {! Uri_IP.ipv4}. *)
val bytes_to_ipv4 : bytes -> Uri_IP.ipv4
