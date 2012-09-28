(*
 * Copyright (c) 2004 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2004 David Scott <dave@recoil.org>
 * Copyright (c) 2005 Fraser Research Inc
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
 * $Id: utils.ml,v 1.1 2005/12/03 18:00:08 avsm Exp $
 *)

(** A bunch of utility functions which I always use and which aren't in the standard library.
  * Some of these are probably in one of the Extlib packages. Some of these are the same as
  * those in the Standard ML basis library. *)

(** Take a string and return a list containing it's constituent characters *)
let rec explode (s: string) : char list = 
    let len = String.length s in
    let rec listchars from = if from >= len then [] else s.[from]::(listchars (from+1)) in
    listchars 0

(** Take a list of characters and return a string with them all combined together *)
let rec implode (chars: char list) : string = 
  let s = String.create (List.length chars) in
  ignore(List.fold_left (fun i c -> s.[i] <- c; i + 1) 0 chars); s
  
 
(** Returns the first n elements of a list, raises a Failure if the list is too short *)
let rec take (n: int) (xs: 'a list) : 'a list = match n, xs with
  | 0, _       -> []
  | _, []      -> failwith "take: list too short"
  | n, (x::xs) -> x::(take (n-1) xs)
   
(** Returns a list minus the first n elements, raises a Failure if the list is too short *)
let rec drop (n: int) (xs: 'a list) : 'a list = match n, xs with
  | 0, xs      -> xs
  | _, []      -> failwith "drop: list too short"
  | n, (_::xs) -> drop (n-1) xs
  
(** Returns a list of integers in the range [f:t] inclusive, in ascending order *)
let rec range (f: int) (t: int) : int list = if (f > t) then [] else f::(range (f+1) t)

(** Pair each element of a list up with an integer index, starting from f *)
let make_index (f: int) (x: 'a list) : (int * 'a) list = List.combine (range f (f + List.length x - 1)) x

(** Turns a list of items into a list of lists, where each item satisfying a predicate starts a new item *)
let split_on_pred (items: 'a list) (pred: 'a -> bool) : 'a list list = 
    (* NB we build everything up backwards and then do a lot of reversing at the end. "items" are the
     * completed item lists while "current" is built up until pred evaluates to true. *)
    let completed, leftover = 
        List.fold_left (fun (items, current) item -> if pred item then (current::items, [item])
                                                     else (items, item::current)) ([], []) items in
    (* Extra empty lists are filtered (e.g. consider what happens if pred is true for two successive items) *)
    let all = List.filter (fun x -> x <> []) (leftover::completed) in
    List.rev (List.map List.rev all)

(** Splits a list into sub-lists of a certain length (note the last item might be shorter) *)
let split_on_size (items: 'a list) (size: int) : 'a list list = 
    List.map (List.map snd) (split_on_pred (make_index 0 items) (fun (i, _) -> i mod size = 0))
    
(** Turns a string into a list of strings, separated by those characters where pred evaluates to true *)
let split_string_on_char (str: string) (pred: char -> bool) : string list = 
    List.map implode (split_on_pred (explode str) pred)

(** Returns true if a character is thought to be printable (for pretty-printing binary) *)
let printable_ascii : char -> bool = function
    | 'a'..'z' | 'A'..'Z' | '0'..'9'
    | '/' | '\\' | '-' | ' ' | '?' | '+' | '\'' | '`' | '!' | '@' | '#' 
    | '$' | '%' | '^' | '&' | '*' | '(' | ')' | '_' | '='  -> true
    | _ -> false

(** Returns true if a character is thought to be whitespace *)
let whitespace : char -> bool = function
    | ' ' | '\t' | '\n' -> true
    | _ -> false

(** Remove all the items from _the beginning and end_ of a list which satisfy a predicate *)
let trim (items: 'a list) (pred: 'a -> bool) : 'a list =
    let rec trim_start = function
      | [] -> []
      | x::xs -> if pred x then trim_start xs else x::xs in
    trim_start (List.rev (trim_start (List.rev items)))
      
(** Remove all the characters from _the beginning and end_ of a string which satisfy a predicate *)
let trim_string (str: string) (pred: char -> bool) = implode (trim (explode str) pred)

(** Returns a string padded out to a certain length ("upto") with characters ("char") *)
let pad_string (str: string) (upto: int) (char: char) : string = 
    let len = String.length str in
    if len >= upto then str
    else let buffer = String.make upto char in
             String.blit str 0 buffer 0 len;
             buffer

(** Applies a function to an optional value, if it is defined *)    
let may (f: 'a -> 'b) : 'a option -> 'b option = function
  | None   -> None
  | Some x -> Some (f x)

(** Raised if an "None" value is passed to valof *)
exception No_value

(** Returns the value wrapped in an option *)
let valof : 'a option -> 'a = function
  | None -> raise No_value
  | Some x -> x

(** Returns an optional value if defined, otherwise a default *)
let default (d: 'a) : 'a option -> 'a = function
  | None -> d
  | Some x -> x

(** Extracts the values of all defined optional values from a list *)
let rec options : 'a option list -> 'a list = function
  | [] -> []
  | None::xs -> options xs
  | (Some x)::xs -> x::(options xs)

