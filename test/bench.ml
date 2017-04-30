(* (c) 2017 Hannes Mehnert, all rights reserved *)

(* what are the interesting operations?
   - of_string / of_string_exn
   - parse / decode
   - marshal / encode
   - dnssec_compare / compare *)

(* this is the ocaml-dns code (name.ml) *)
module Old = struct
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

(** Element-wise pipe. *)
let (||>) l f = List.map f l

(** Encode string as label by prepending length. *)
let charstr s =
  let n = String.length s in
  String.make 1 (char_of_int n) ^ s, (n+1)

let (+++) x y = Int32.add x y
let (<|<) x y = Int32.shift_left x y

 open Printf
(*   open Operators *)

type t = string list

type key = string

module Ordered = struct
  type x = t
  type t = x
  let eq x y = x = y
  let rec compare l1 l2 = match (l1, l2) with
    | []    ,  []    -> 0
    | _::_  , []     -> 1
    | []    , _::_   -> -1
    | h1::t1, h2::t2 ->
      match String.compare h1 h2 with
      | 0 -> compare t1 t2
      | i -> i
end

module Map = Map.Make(Ordered)
module Set = Set.Make(Ordered)

let empty = []
let append = (@)
let cons x xs = (String.lowercase x) :: xs
let to_string_list dn = dn
let of_string_list = List.map String.lowercase

let to_string = String.concat "."

(* TODO: this looks wrong for the trailing dot case/we should ensure
   we handle the trailing dot case consistently *)
let of_string (s:string) : t =
  Re_str.split (Re_str.regexp "\\.") (String.lowercase s)
let string_to_domain_name = of_string

let of_ipaddr ip = of_string_list (Ipaddr.to_domain_name ip)

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
          failwith (sprintf "Name.parse_label: invalid length %d" v)

let parse names base buf = (* what. a. mess. *)
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
          (match Hashtbl.find_all names p with
           | [] -> failwith (sprintf "Name.parse_pointer: Cannot dereference pointer to (%n) at position (%n)" p base);
           | all ->
             let labels = (all |> List.filter (function L _ -> true | _ -> false)) in
             (* update the list of offsets-so-far to include current label *)
             (base :: offsets) |> List.iter (fun o ->
               (List.rev labels) |> List.iter (fun n -> Hashtbl.add names o n)
             );
             (* convert label list into string list *)
             (labels ||> (function
               | L (nm,_) -> nm
               | _ -> failwith "Name.parse")
             ) @ name, base+offset, Cstruct.shift buf offset
          )

  in
  let name, base, buf = aux [] [] base buf in
  List.rev name, (base,buf)

let marshal ?(compress=true) names base buf name =
  let not_compressed names base buf name =
    let base, buf =
      List.fold_left (fun (base,buf) label ->
        let label,llen = charstr label in
        Cstruct.blit_from_string label 0 buf 0 llen;
        base+llen, Cstruct.shift buf llen
      ) (base, buf) name
    in names, base+1, Cstruct.shift buf 1
  in

  let compressed names base buf name =
    let pointer o = ((0b11_l <|< 14) +++ (Int32.of_int o)) |> Int32.to_int in

    let lookup names n =
      try Some (Map.find n names)
      with Not_found -> None
    in

    let rec aux names offset labels =
      match lookup names labels with
        | None ->
            (match labels with
              | [] ->
                  Cstruct.set_uint8 buf offset 0;
                  names, offset+1

              | (hd :: tl) as ls ->
                  let names = Map.add ls (base+offset) names in
                  let label, llen = charstr hd in
                  Cstruct.blit_from_string label 0 buf offset llen;
                  aux names (offset+llen) tl
            )

        | Some o ->
            Cstruct.BE.set_uint16 buf offset (pointer o);
            names, offset+2
    in
    let names, offset = aux names 0 name in
    names, (base+offset), Cstruct.shift buf offset
  in
  if compress then compressed names base buf name
  else not_compressed names base buf name

(* Hash-consing: character strings *)
module CSH = Hashcons.Make (struct
  type t = string
  let equal a b = (a = b)
  let hash s = Hashtbl.hash s
end)
let cstr_hash = ref (CSH.create 101)
let hashcons_string s = CSH.hashcons !cstr_hash s

(*
   Hash-consing: domain names (string lists).  This requires a little
   more subtlety than the Hashcons module gives us directly: we want to
   merge common suffixes, and we're downcasing everything.
   N.B. RFC 4343 says we shouldn't do this downcasing.
*)
module DNH = Hashcons.Make (struct
  type x = t
  type t = x
  let equal a b = (a = b)
  let hash s = Hashtbl.hash s
end)
let dn_hash = ref (DNH.create 101)
let rec hashcons (x:t) = match x with
  | [] -> DNH.hashcons !dn_hash []
  | h :: t ->
      let th = hashcons t in
      DNH.hashcons !dn_hash
	    (((hashcons_string (String.lowercase h)).Hashcons.node)
	     :: (th.Hashcons.node))

let clear_cons_tables () =
  DNH.clear !dn_hash;
  CSH.clear !cstr_hash;
  dn_hash := DNH.create 1;
  cstr_hash := CSH.create 1

exception BadDomainName of string

let to_key domain_name =
  let check s =
    if String.contains s '\000' then
      raise (BadDomainName "contains null character");
    if String.length s = 0 then
      raise (BadDomainName "zero-length label");
    if String.length s > 63 then
      raise (BadDomainName ("label too long: " ^ s))
  in
  List.iter check domain_name;
  String.concat "\000" (List.rev_map String.lowercase domain_name)

let rec dnssec_compare a b =
  match (a, b) with
  | [], [] -> 0
  | [], _ -> -1
  | _, [] -> 1
  | a::a_tl, b::b_tl ->
      if (String.compare a b = 0) then
        compare a_tl b_tl
      else
        ( if (String.length a) = (String.length b) then
            String.compare a b
          else
            compare (String.length a) (String.length b)
        )
let dnssec_compare_str = dnssec_compare

end

module New = struct
  (* (c) 2017 Hannes Mehnert, all rights reserved *)

open Astring

type t = string list

let root = []

let check_host_label s =
  String.get s 0 <> '-' && (* leading may not be '-' *)
  String.for_all (function
      | 'a'..'z' | 'A'..'Z' | '0'..'9' | '-' -> true
      | _ -> false)
    s (* only LDH (letters, digits, hyphen)! *)

let is_hostname t =
  (* TLD should not be all-numeric! *)
  (match List.rev t with
   | x::_ -> String.exists Char.Ascii.is_letter x
   | _ -> true) &&
  List.for_all check_host_label t

let check_service_label s =
  match String.cut ~sep:"_" s with
  | None -> false
  | Some (empty, srv) ->
    if String.length empty > 0 then
      false
    else
      let slen = String.length srv in
      if slen > 0 && slen <= 15 then
        (* service must be LDH, at least one alpha char
           hyphen _not_ at begin nor end, no hyphen following a hyphen
           1-15 characters *)
        let v, a, _ = String.fold_left (fun (valid, alp, h) c ->
            let alpha = Char.Ascii.is_letter c in
            let h' = c = '-' in
            let v = alpha || Char.Ascii.is_digit c || h' in
            let hh = not (h && h') in
            (v && valid && hh, alp || alpha, h'))
            (true, false, false) srv
        in
        v && a && String.get srv 0 <> '-' && String.get srv (pred slen) <> '-'
      else
        false

let is_proto s =
  s = "_tcp" || s = "_udp" || s = "_sctp"

let is_service = function
  | srv::proto::name ->
    check_service_label srv && is_proto proto && is_hostname name
  | _ -> false

let check_label s =
  let l = String.length s in
  l < 64 && l > 0

let check hostname t =
  List.for_all check_label t &&
  List.fold_left (fun acc s -> acc + 1 + String.length s) 1 t <= 255 &&
  if hostname then is_hostname t else true

let of_strings ?(hostname = true) xs =
  if check hostname xs then Ok xs else Error "not a valid domain name"

let of_strings_exn ?(hostname = true) xs =
  if check hostname xs then xs else invalid_arg "invalid domain name"

let of_string ?hostname s =
  of_strings ?hostname (String.cuts ~sep:"." s)

let of_string_exn ?hostname s =
  of_strings_exn ?hostname (String.cuts ~sep:"." s)

let to_string = String.concat ~sep:"."

let to_strings dn = dn

let pp ppf xs = Fmt.string ppf (to_string xs)

module IntMap = Map.Make(struct
    type t = int
    let compare : int -> int -> int = compare
  end)

let compare_sub a b =
  String.compare (String.Ascii.lowercase a) (String.Ascii.lowercase b)

let rec compare a b =
  match a, b with
  | [], [] -> 0
  | [], _ -> -1
  | _, [] -> 1
  | ah::at, bh::bt ->
    match compare_sub ah bh with
    | 0 -> compare at bt
    | x -> x

let equal a b = compare a b = 0

let sub ~subdomain ~domain =
  let rec cmp super sub = match super, sub with
    | [], _ -> true
    | s::ss, u::us -> compare_sub s u = 0 && cmp ss us
    | _, [] -> false
  in
  cmp (List.rev domain) (List.rev subdomain)

module Ordered = struct
  type t = string list
  let compare = compare
end

module DomMap = Map.Make(Ordered)
module DomSet = Set.Make(Ordered)

type err =
  [ `Partial
  | `BadOffset of int
  | `BadTag of int
  | `BadContent of string
  | `TooLong ]

let pp_err ppf = function
  | `Partial -> Fmt.pf ppf "partial"
  | `BadOffset off -> Fmt.pf ppf "bad offset %d" off
  | `BadTag x -> Fmt.pf ppf "bad tag %d" x
  | `BadContent s -> Fmt.pf ppf "bad content %s" s
  | `TooLong -> Fmt.pf ppf "too long"

open Rresult.R.Infix

let ptr_tag = 0xC0 (* = 1100 0000 *)

let decode ?(hostname = true) names buf off =
  (* first collect all the labels (and their offsets) *)
  let rec aux offsets off =
    match Cstruct.get_uint8 buf off with
    | 0 -> Ok ((`Z, off), offsets, succ off)
    | i when i >= ptr_tag -> (* 192 is 1100_0000 which is the pointer tag *)
      let ptr = (i - ptr_tag) lsl 8 + Cstruct.get_uint8 buf (succ off) in
      Ok ((`P ptr, off), offsets, off + 2)
    | i when i >= 64 -> Error (`BadTag i) (* bit patterns starting with 10 or 01 *)
    | i -> (* this is clearly < 64! *)
      let name = Cstruct.to_string (Cstruct.sub buf (succ off) i) in
      aux ((name, off) :: offsets) (succ off + i)
  in
  (* Cstruct.xxx can raise, and we'll have a partial parse then *)
  (try aux [] off with _ -> Error `Partial) >>= fun (l, offs, foff) ->
  (* treat last element special -- either Z or P *)
  (match l with
   | `Z, off -> Ok (off, [], 1)
   | `P p, off -> match IntMap.find p names with
     | exception Not_found -> Error (`BadOffset p)
     | (exp, size) -> Ok (off, exp, size)) >>= fun (off, name, size) ->
  (* insert last label into names Map*)
  let names = IntMap.add off (name, size) names in
  (* fold over offs, insert into names Map, and reassemble the actual name *)
  let names, name, size =
    List.fold_left (fun (names, name, size) (l, off) ->
        let s = succ size + String.length l in
        IntMap.add off (l :: name, s) names, l :: name, s)
      (names, name, size) offs
  in
  match size <= 255, is_hostname name with
  | false, _ -> Error `TooLong
  | true, false when hostname ->
    Error (`BadContent (String.concat ~sep:"." name))
  | _ -> Ok (name, names, foff)

let encode ?(compress = true) names buf off name =
  let encode_lbl lbl off =
    let l = String.length lbl in
    Cstruct.set_uint8 buf off l ;
    Cstruct.blit_from_string lbl 0 buf (succ off) l ;
    off + succ l
  and z off =
    Cstruct.set_uint8 buf off 0 ;
    succ off
  in
  let names, off =
    if compress then
      let rec one names off = function
        | [] -> names, z off
        | n::ns ->
          match DomMap.find (n::ns) names with
          | exception Not_found ->
            let l = encode_lbl n off in
            one (DomMap.add (n::ns) off names) l ns
          | ptr ->
            let data = ptr_tag lsl 8 + ptr in
            Cstruct.BE.set_uint16 buf off data ;
            names, off + 2
      in
      one names off name
    else
      let rec one names off = function
        | [] -> names, z off
        | n::ns ->
          let l = encode_lbl n off in
          one (DomMap.add (n::ns) off names) l ns
      in
      one names off name
  in
  names, off
end

let long_name = "foo.bar.baz.foo.bar.baz.foo.bar.baz.foo.bar.baz"

let buf = Cstruct.create (2 + String.length long_name)

let curbody () =
  let n = Dns_name.of_string_exn ~hostname:false long_name in
  let _ = Dns_name.(encode DomMap.empty buf 0 n) in
  let _ = Dns_name.(decode ~hostname:false IntMap.empty buf 0) in
  let _ = Dns_name.compare n n in
  ()

let chkbody () =
  let n = Dns_name.of_string_exn long_name in
  let _ = Dns_name.(encode DomMap.empty buf 0 n) in
  let _ = Dns_name.(decode IntMap.empty buf 0) in
  let _ = Dns_name.compare n n in
  ()

let strbody () =
  let n = New.of_string_exn ~hostname:false long_name in
  let _ = New.(encode DomMap.empty buf 0 n) in
  let _ = New.(decode ~hostname:false IntMap.empty buf 0) in
  let _ = New.compare n n in
  ()

let oldbody () =
  let n = Old.of_string long_name in
  let _ = Old.marshal Old.Map.empty 0 buf n in
  let _ = Old.parse (Hashtbl.create 32) 0 buf in
  let _ = Old.dnssec_compare n n in
  ()

let run_bench body n =
  for _i = 1 to n do body () done

let () =
  run_bench oldbody 1000 ;
  for _i = 0 to 9 do
    let counter = Mtime_clock.counter () in
    run_bench oldbody 10000 ;
    let s = Mtime_clock.count counter in
    Printf.printf "old time %f\n%!" (Mtime.Span.to_ms s)
  done ;
  Gc.full_major () ;
  run_bench strbody 1000 ;
  for _i = 0 to 9 do
    let counter = Mtime_clock.counter () in
    run_bench strbody 10000 ;
    let s = Mtime_clock.count counter in
    Printf.printf "str time %f\n%!" (Mtime.Span.to_ms s)
  done ;
  Gc.full_major () ;
  run_bench curbody 1000 ;
  for _i = 0 to 9 do
    let counter = Mtime_clock.counter () in
    run_bench curbody 10000 ;
    let s = Mtime_clock.count counter in
    Printf.printf "cur time %f\n%!" (Mtime.Span.to_ms s)
  done ;
  Gc.full_major () ;
  run_bench chkbody 1000 ;
  for _i = 0 to 9 do
    let counter = Mtime_clock.counter () in
    run_bench chkbody 10000 ;
    let s = Mtime_clock.count counter in
    Printf.printf "chk time %f\n%!" (Mtime.Span.to_ms s)
  done ;
  Gc.full_major ()
