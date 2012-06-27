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

let parse_label base buf = 
  (* NB. we're shifting buf for each call; offset is for the names Hashtbl *)
  match Cstruct.get_uint8 buf 0 with 
    | 0 -> 
        Z base, 1
          
    | v when ((v land 0b0_11000000) != 0) -> 
        let ptr = ((v land 0b0_00111111) lsl 8) + Cstruct.get_uint8 buf 1 in 
        P (ptr, base), 2
          
    | v ->
        if ((0 < v) && (v < 64)) then (
          let name = Cstruct.(sub buf 1 v |> to_string) in
          L (name, base), 1+v
        )
        else 
          failwith (sprintf "parse_label: invalid length %d" v)
                                          
let parse_name names base buf = (* what. a. mess. *)
  let rec aux offsets name base buf = 
    match parse_label base buf with
      | (Z o as zero, offset) -> 
          Hashtbl.add names o zero; 
          name, base+offset, Cstruct.shift buf offset
      
      | (L (n, o) as label, offset) -> 
          Hashtbl.add names o label;
          offsets |> List.iter (fun off -> (Hashtbl.add names off label));
          aux (o :: offsets) (n :: name) (base+offset) (Cstruct.shift buf offset)

      | (P (p, _), offset) -> 
          let ns = (Hashtbl.find_all names p
                       |> List.filter (function L _ -> true | _ -> false))
          in
          (* update the list of offsets-so-far to include current label *)
          offsets |> List.iter (fun o ->
            ns |> List.iter (fun n -> Hashtbl.add names o n)
          );
          (* convert label list into string list *)
          (ns ||> (function
            | L (nm,_) -> nm
            | _ -> failwith "parse_name")
          ) @ name, base+offset, Cstruct.shift buf offset

  in 
  let name, base, buf = aux [] [] base buf in
  List.rev name, (base,buf)

let marshal_name names base buf name = 
  let not_compressed names base buf name = 
    let base, buf = 
      List.fold_left (fun (base,buf) label ->
        let label,llen = charstr label in
        Cstruct.set_buffer label 0 buf 0 llen;
        base+llen, Cstruct.shift buf llen
      ) (base, buf) name
    in names, base+1, Cstruct.shift buf 1
  in
  
  let compressed names base buf name = 
    let pointer o = ((0b11_l <<< 14) +++ (Int32.of_int o)) |> Int32.to_int in
    
    let lookup n = 
      Hashtbl.(if mem names n then Some (find names n) else None)
    in
    
    let rec aux offset labels = 
      match lookup labels with
        | None -> 
            (match labels with
              | [] -> 
                  set_uint8 buf offset 0; 
                  offset+1
                    
              | (hd :: tl) as ls -> 
                  Hashtbl.replace names ls (base+offset);
                  let label, llen = charstr hd in
                  Cstruct.set_buffer label 0 buf offset llen;
                  aux (offset+llen) tl
            )     
              
        | Some o -> 
            eprintf "P: ptr:%04x offset:%d\n%!" (pointer o) o;
            BE.set_uint16 buf offset (pointer o);
            offset+2
    in
    let offset = aux 0 name in
    names, (base+offset), Cstruct.shift buf offset
  in
  compressed names base buf name

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

