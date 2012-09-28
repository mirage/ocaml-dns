(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2005 Fraser Research Inc. <djs@fraserresearch.org>
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
 *)

(* Code to parse the standard /etc/resolv.conf file for compatability with the
 * standard resolver. Note the file format is so simple we don't bother with
 * a full-blown yacc-style parser.
 *)
 
(* File format described in 
 * http://mirbsd.bsdadvocacy.org/cman/man5/resolv.conf.htm
 * It doesn't mention case - we assume case-insensitive
 * The standard resolver supports overrides through environment vars. Not implemented.
 *)
 
let default_configuration_file = "/etc/resolv.conf"

let raw_read_file filename = 
  let c = open_in filename in
  let lines = ref [] in
  try
    while true do
      let line = input_line c in
      lines := line :: !lines
    done;
    [] (* never reached *)
  with End_of_file ->
    close_in c;
    List.rev (!lines)

let whitespace = [ ' '; '\t' ] (* excluding \n already *)

let split (txt: string) (pred: char -> bool): string list =               
    let bits = Utils.split_string_on_char txt pred in
    let bits = List.map (fun x -> Utils.implode (Utils.trim (Utils.explode x) pred)) bits in
    List.filter (fun x -> x <> "") bits 

(* Ignore everything on a line after a '#' or ';' *)
let strip_comments x = match (split x (fun c -> c = '#' || c = ';')) with
  | [] -> ""
  | [x] -> x
  | (x::_) -> x
(* A blank line is either empty or one where every character is whitespace *)
let filter_blanks = List.filter (fun line -> not( List.fold_left (&&) true (List.map (fun x -> List.mem x whitespace) (Utils.explode line)) ))
 
(* Remove any whitespace prefix and suffix from a line *)
let trim s = 
  let trim_prefix s = 
    let chars = Utils.make_index 0 (Utils.explode s) in
    match (List.filter (fun (i,c) -> not(List.mem c whitespace)) chars) with
    | [] -> s
    | (i,_)::_ -> String.sub s i (String.length s - i) in
  let string_rev x = Utils.implode (List.rev (Utils.explode x)) in
  string_rev (trim_prefix (string_rev (trim_prefix s)))

(* Reads a file and strips out everything other than keywords and values ie no excess whitespace or blank lines *)
let read_file file =
  let all = raw_read_file file in
  let all = List.map (fun line -> trim (strip_comments line)) all in
  filter_blanks all 

module LookupValue = struct
  type t = Bind | File | Yp
  exception Unknown of string
  let of_string x = match (String.lowercase x) with
  | "bind" -> Bind
  | "file" -> File
  | "yp"   -> Yp
  | x -> raise (Unknown x)
  let to_string = function
  | Bind -> "bind"
  | File -> "file"
  | Yp   -> "yp"
end
module OptionsValue = struct
  type t = Debug | Edns0 | Inet6 | Insecure1 | Insecure2 | Ndots of int
  exception Unknown of string
  let of_string x = 
    let x = String.lowercase x in
    if String.length x >= 6 && (String.sub x 0 6 = "ndots:") then begin
      try
        Ndots (int_of_string (String.sub x 6 (String.length x - 6)))
      with Failure("int_of_string") -> raise (Unknown x)
    end else match x with
    | "debug"     -> Debug
    | "edns0"     -> Edns0
    | "inet6"     -> Inet6
    | "insecure1" -> Insecure1
    | "insecure2" -> Insecure2
    | x -> raise (Unknown x)
  let to_string = function
  | Debug -> "debug" | Edns0 -> "edns0" | Inet6 -> "inet6"
  | Insecure1 -> "insecure1" | Insecure2 -> "insecure2" | Ndots n -> "ndots:" ^ (string_of_int n)
end

module KeywordValue = struct
  type t = Nameserver of string (* ipv4 dotted quad or ipv6 hex and colon *)
         | Domain of string
         | Lookup of LookupValue.t list
         | Search of string list
         | Sortlist of string list 
         | Options of OptionsValue.t list
  exception Unknown of string
  let of_string x = 
    let tokens = List.filter (fun x -> x <> "") (split (String.lowercase x) (fun c -> List.mem c whitespace)) in match tokens with
    | [ "nameserver"; ns ] -> Nameserver ns
    | [ "domain"; domain ] -> Domain domain
    | "lookup"::lst        -> Lookup (List.map LookupValue.of_string lst)
    | "search"::lst        -> Search lst
    | "sortlist"::lst      -> Sortlist lst
    | "options"::lst       -> Options (List.map OptionsValue.of_string lst)
    | _ -> raise (Unknown x)
  let to_string = 
    let sc = String.concat " " in function
    | Nameserver ns -> sc [ "nameserver"; ns ]
    | Domain domain -> sc [ "domain"; domain ]
    | Lookup l      -> sc ( "lookup"::(List.map LookupValue.to_string l) )
    | Search lst    -> sc ( "search"::lst )
    | Sortlist lst  -> sc ( "sortlist"::lst )
    | Options lst   -> sc ( "options"::(List.map OptionsValue.to_string lst) )
end

(* The state of the resolver could be extended later *)
type t = KeywordValue.t list

let all_servers config = Utils.options (List.map (function (KeywordValue.Nameserver x) -> Some x | _ -> None) config)

(* Choose a DNS server to query. Might do some round-robin thingy later *)
let choose_server config =
  match (all_servers config) with
  | [] -> None
  | x::_ -> Some x

(* Return a list of domain suffixes to search *)
let search_domains config = 
  let relevant_entries = List.map (function
    | KeywordValue.Domain x -> Some [x]
    | (KeywordValue.Search xs) -> Some xs
    | _ -> None) config in
  (* entries are mutually-exclusive, last one overrides *)
  match (List.rev (Utils.options relevant_entries)) with
  | [] -> []
  | x::_ -> x

let parse_file ?(file="/etc/resolv.conf") () = 
  let all = read_file file in
  let warn x = prerr_endline (Printf.sprintf "resolvconf in file %s: %s" file x) in
  let all = List.map (fun line -> 
    try Some (KeywordValue.of_string line)
    with 
    | KeywordValue.Unknown x -> warn ("unknown keyword: " ^ x); None
    | OptionsValue.Unknown x -> warn ("unknown option: " ^ x); None
    | LookupValue.Unknown x  -> warn ("unknown lookup option: " ^ x); None
  ) all in
  Utils.options all
