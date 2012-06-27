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

let parse_label check_len base buf = 
  (* NB. we're shifting buf for each call; offset is for the names Hashtbl *)
  (* eprintf "+ parse_label: base:%d len:%d\n%!" base (Cstruct.len buf); *)
  let v = Cstruct.get_uint8 buf 0 in
  (* eprintf "  v:%d\n%!" v; *)
  match v with 
    | 0 -> 
        (* eprintf "- parse_label: Z\n%!";  *)
        Z base, 1
    
    | v when ((v land 0b0_11000000) != 0) -> 
        let ptr = ((v land 0b0_00111111) lsl 8) + Cstruct.get_uint8 buf 1 in 
        (* eprintf "- parse_label: P ptr:%d\n%!" ptr; *)
        P (ptr, base), 2
    
    | v ->
        if check_len && not ((0 < v) && (v < 64)) then
          failwith (sprintf "parse_label: invalid length %d" v)
        else (
          let name = Cstruct.(sub buf 1 v |> to_string) in
          (* eprintf "- parse_label: L v:%d lbl:'%s'\n%!" v name; *)
          L (name, base), 1+v
        )
                                          
let parse_name ?(check_len=true) names base buf = (* what. a. mess. *)
  (* eprintf "+ parse_name: base:%d len:%d\n%!" base (Cstruct.len buf); *)
  
  let rec aux offsets name base buf = 
    (* eprintf "+ parse_name/aux: name:'%s' base:%d len:%d\n%!"  *)
    (*   (domain_name_to_string name) base (Cstruct.len buf); *)

    match parse_label check_len base buf with
      | (L (n, o) as label, offset) -> 
          Hashtbl.add names o label;
          offsets |> List.iter (fun off -> (Hashtbl.add names off label));
          aux (o :: offsets) (n :: name) (base+offset) (Cstruct.shift buf offset)

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
           ) @ name), (base+offset, Cstruct.shift buf offset)

      | (Z o as zero, offset) -> 
          Hashtbl.add names o zero; 
          (* eprintf "- parse_name/aux: o:%d offset:%d\n%!" o offset; *)
          name, (base+offset, Cstruct.shift buf offset)
  in 
  let name, (base,buf) = aux [] [] base buf in
  (* eprintf "- parse_name: base:%d len:%d\n%!" base (Cstruct.len buf); *)
  List.rev name, (base,buf)

let marshal_name names base buf name = 
  let not_compressed buf name = 
    let names, base, buf = 
      List.fold_left (fun (names,base,buf) label ->
        let open Cstruct in
            let llen = String.length label in
            set_uint8 buf 0 llen;
            set_buffer label 0 buf 1 llen;
            names, base+llen+1, shift buf (llen+1)
      ) (names, base, buf) name
    in names, base+1, Cstruct.shift buf 1
  in
  
  let compressed names base buf name = 
    let pointer offset = (0b11_l <<< 14) +++ (Int32.of_int off) in
    
    let lookup name = 
      Hashtbl.(if mem names name then Some (find names name) else None)
    in
    
    let labelset = 
      let rec aux = function
        | [] -> []
        | x :: [] -> [ x :: [] ]
        | hd :: tl -> (hd :: tl) :: (aux tl)
      in aux labels
    in
    
    names, base, buf
  in
  (* not_compressed buf name *)
  compressed names base buf name








(*
  (** Marshall names, with compression. *)
  let mn_compress (labels:domain_name) = 
    let pos = ref (!pos) in

    let pointer off = 
      let ptr = (0b11_l <<< 14) +++ (Int32.of_int off) in
      let hi = ((ptr &&& 0xff00_l) >>> 8) |> Int32.to_int |> char_of_int in
      let lo =  (ptr &&& 0x00ff_l)        |> Int32.to_int |> char_of_int in
      sprintf "%c%c" hi lo
    in
    
    let lookup h k =
      if Hashtbl.mem h k then Some (Hashtbl.find h k) else None
    in

    let lset = 
      let rec aux = function
        | [] -> [] (* don't double up the terminating null? *)
        | x :: [] -> [ x :: [] ]
        | hd :: tl -> (hd :: tl) :: (aux tl)
      in aux labels
    in

    let bits = ref [] in    
    let pointed = ref false in
    List.iter (fun ls ->
      if (not !pointed) then (
        match lookup names ls with
          | None 
            -> (Hashtbl.add names ls !pos;
                match ls with 
                  | [] 
                    -> (bits := "\000" :: !bits; 
                        pos := !pos + 1
                    )
                  | label :: tail
                    -> (let len = String.length label in
                        assert(len < 64);
                        bits := (charstr label) :: !bits;
                        pos := !pos + len +1
                    )
            )
          | Some off
            -> (bits := (pointer off) :: !bits;
                pos := !pos + 2;
                pointed := true
            )
      )
    ) lset;
    if (not !pointed) then (
      bits := "\000" :: !bits;
      pos := !pos + 1
    );
    !bits |> List.rev |> String.concat "" |> (fun s -> 
      BITSTRING { s:((String.length s)*8):string })
  in

  let mn ?(off = 0) ls = 
    pos := !pos + off;
    let n = mn_compress ls in
    (pos := !pos - off; 
     n)
  in

*)


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

