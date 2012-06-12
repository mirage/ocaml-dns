(*
 * Copyright (c) 2012 Richard Mortier <mort@cantab.net>
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

(* open Wire *)
(* open Re_str *)

open Printf
open Operators
open Cstruct

type domain_name = string list
let domain_name_to_string dn = join "." dn
let string_to_domain_name (s:string) : domain_name = 
  Re_str.split (Re_str.regexp "\\.") s

let for_reverse ip = 
  (".arpa.in-addr." ^ ipv4_to_string ip) |> string_to_domain_name |> List.rev 

type label =              
  | L of string * int (* string *)
  | P of int * int (* pointer *)
  | Z of int (* zero; terminator *)

let parse_label check_len offset buf = match Cstruct.get_uint8 buf 0 with 
  | 0 -> Z offset, 1
  | len when (((len lsr 6) land 0b0_11) != 0) -> 
      let ptr = ((len land 0b0_00111111) lsl 8) + Cstruct.get_uint8 buf 1 in 
      P (ptr, offset), 2
  | len ->
      if check_len && not ((0 < len) && (len < 64)) then
        failwith (sprintf "parse_label: invalid length %d" len)
      else (
        let name = Cstruct.sub buf 1 len in
        L (Cstruct.to_string name, offset), 1+len
      )
                                          
let parse_name ?(check_len=true) names offset buf = (* what. a. mess. *)
  let rec aux offsets name base buf = 
    match parse_label check_len base buf with
      | (L (n, o) as label, offset) -> 
          Hashtbl.add names o label;
          offsets |> List.iter (fun off -> (Hashtbl.add names off label));
          aux (o :: offsets) (n :: name) (base+offset) (slide buf offset)

      | (P (p, _), offset) -> 
          let ns = (Hashtbl.find_all names p
                       |> List.filter (function L _ -> true | _ -> false)
                       |> List.rev)
          in
          offsets |> List.iter (fun o ->
            ns |> List.iter (fun n -> Hashtbl.add names o n)
          );
          ((ns |> List.rev ||> (function
            | L (nm,_) -> nm
            | _ -> failwith "parse_name")
           ) @ name), (offset, slide buf offset)

      | (Z o as zero, offset) -> 
          Hashtbl.add names o zero; 
          name, (offset, slide buf offset)
  in 
  let name, (offset, buf) = aux [] [] offset buf in
  List.rev name, (offset, buf)

(* Hash-consing: character strings *)
module CSH = Hashcons.Make (struct 
  type t = string
  let equal a b = (a = b)
  let hash s = Hashtbl.hash s
end)
let cstr_hash = ref (CSH.create 101)
let hashcons_charstring s = CSH.hashcons !cstr_hash s

(* 
   Hash-consing: domain names (string lists).  This requires a little
   more subtlety than the Hashcons module gives us directly: we want to 
   merge common suffixes, and we're downcasing everything. 
   N.B. RFC 4343 says we shouldn't do this downcasing.
*)
module DNH = Hashcons.Make (struct 
  type t = domain_name
  let equal a b = (a = b)
  let hash s = Hashtbl.hash s
end)
let dn_hash = ref (DNH.create 101)
let rec hashcons_domainname (x:domain_name) = match x with
  | [] -> DNH.hashcons !dn_hash []
  | h :: t -> 
      let th = hashcons_domainname t in 
      DNH.hashcons !dn_hash 
	    (((hashcons_charstring (String.lowercase h)).Hashcons.node) 
	     :: (th.Hashcons.node))

let clear_cons_tables () = 
  DNH.clear !dn_hash;
  CSH.clear !cstr_hash;
  dn_hash := DNH.create 1;
  cstr_hash := CSH.create 1

exception BadDomainName of string

type key = string

let canon2key domain_name = 
  let labelize s = 
    if String.contains s '\000' then 
      raise (BadDomainName "contains null character");
    if String.length s = 0 then 
      raise (BadDomainName "zero-length label");
    if String.length s > 63 then 
      raise (BadDomainName ("label too long: " ^ s));
    s 
  in List.fold_left (fun s l -> (labelize l) ^ "\000" ^ s) "" domain_name

