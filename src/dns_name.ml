(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Astring

type s = string array

let root = Array.make 0 ""

let [@inline always] check_host_label s =
  String.get s 0 <> '-' && (* leading may not be '-' *)
  String.for_all (function
      | 'a'..'z' | 'A'..'Z' | '0'..'9' | '-' -> true
      | _ -> false)
    s (* only LDH (letters, digits, hyphen)! *)

let is_hostname t =
  (* TLD should not be all-numeric! *)
  (if Array.length t > 0 then
     String.exists Char.Ascii.is_letter (Array.get t 0)
   else true) &&
  Array.for_all check_host_label t

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

let [@inline always] is_proto s =
  s = "_tcp" || s = "_udp" || s = "_sctp"

let [@inline always] check_label_length s =
  let l = String.length s in
  l < 64 && l > 0

let [@inline always] check_total_length t =
  Array.fold_left (fun acc s -> acc + 1 + String.length s) 1 t <= 255

let is_service t =
  let l = Array.length t in
  if l > 2 then
    let name = Array.sub t 0 (l - 2) in
    check_service_label (Array.get t (l - 1)) &&
    is_proto (Array.get t (l - 2)) &&
    Array.for_all check_label_length name &&
    check_total_length t &&
    is_hostname name
  else
    false

let [@inline always] check hostname t =
  Array.for_all check_label_length t &&
  check_total_length t &&
  if hostname then is_hostname t else true

let prepend ?(hostname = true) xs lbl =
  let n = Array.make 1 lbl in
  let n = Array.append xs n in
  if check hostname n then Ok n
  else Error (`Msg "invalid host name")

let prepend_exn ?hostname xs lbl =
  match prepend ?hostname xs lbl with
  | Ok t -> t
  | Error (`Msg e) -> invalid_arg e

let of_strings ?(hostname = true) xs =
  let t = Array.of_list (List.rev xs) in
  if check hostname t then Ok t
  else Error (`Msg "invalid host name")

let of_strings_exn ?hostname xs =
  match of_strings ?hostname xs with
  | Ok t -> t
  | Error (`Msg e) -> invalid_arg e

let of_string ?hostname s = of_strings ?hostname (String.cuts ~sep:"." s)

let of_string_exn ?hostname s = of_strings_exn ?hostname (String.cuts ~sep:"." s)

let of_array a = a

let to_array a = a

let to_strings dn = List.rev (Array.to_list dn)

let to_string dn = String.concat ~sep:"." (to_strings dn)

let canonical t =
  let str = to_string t in
  of_string_exn ~hostname:false (String.Ascii.lowercase str)

(*BISECT-IGNORE-BEGIN*)
let pp ppf xs = Fmt.string ppf (to_string xs)
(*BISECT-IGNORE-END*)

module IntMap = Map.Make(struct
    type t = int
    let compare : int -> int -> int = compare
  end)

let compare_sub a b =
  String.compare (String.Ascii.lowercase a) (String.Ascii.lowercase b)

let compare_domain a b =
  let la = Array.length a in
  match compare la (Array.length b) with
  | 0 ->
    let rec cmp idx =
      if idx = la then 0
      else
        match compare_sub (Array.get a idx) (Array.get b idx) with
        | 0 -> cmp (succ idx)
        | x -> x
    in
    cmp 0
  | x -> x

let compare = compare_domain

let equal a b = compare_domain a b = 0

let sub ~subdomain ~domain =
  let supl = Array.length domain in
  let rec cmp idx =
    if idx = supl then
      true
    else
      compare_sub (Array.get domain idx) (Array.get subdomain idx) = 0 &&
      cmp (succ idx)
  in
  if Array.length subdomain < supl then
    false
  else
    cmp 0

module Ordered = struct
  type t = s
  let compare = compare_domain
end

type t = s

module DomMap = Map.Make(Ordered)
module DomSet = Set.Make(Ordered)

type err =
  [ `Partial
  | `BadOffset of int
  | `BadTag of int
  | `BadContent of string
  | `TooLong ]

(*BISECT-IGNORE-BEGIN*)
let pp_err ppf = function
  | `Partial -> Fmt.string ppf "partial"
  | `BadOffset off -> Fmt.pf ppf "bad offset %d" off
  | `BadTag x -> Fmt.pf ppf "bad tag %d" x
  | `BadContent s -> Fmt.pf ppf "bad content %s" s
  | `TooLong -> Fmt.string ppf "name too long"
(*BISECT-IGNORE-END*)

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
   | `Z, off -> Ok (off, root, 1)
   | `P p, off -> match IntMap.find p names with
     | exception Not_found -> Error (`BadOffset p)
     | (exp, size) -> Ok (off, exp, size)) >>= fun (off, name, size) ->
  (* insert last label into names Map*)
  let names = IntMap.add off (name, size) names in
  (* fold over offs, insert into names Map, and reassemble the actual name *)
  let t = Array.(append name (make (List.length offs) "")) in
  let names, _, size =
    List.fold_left (fun (names, idx, size) (l, off) ->
        let s = succ size + String.length l in
        Array.set t idx l ;
        let sub = Array.sub t 0 (succ idx) in
        IntMap.add off (sub, s) names, succ idx, s)
      (names, Array.length name, size) offs
  in
  if size > 255 then
    Error `TooLong
  else if hostname && not (is_hostname t) then
    Error (`BadContent (to_string t))
  else
    Ok (t, names, foff)

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
      let rec one names off name =
        let l = Array.length name in
        if l = 0 then
          names, z off
        else
          match DomMap.find name names with
          | exception Not_found ->
            let last = Array.get name (pred l)
            and rem = Array.sub name 0 (pred l)
            in
            let l = encode_lbl last off in
            one (DomMap.add name off names) l rem
          | ptr ->
            let data = ptr_tag lsl 8 + ptr in
            Cstruct.BE.set_uint16 buf off data ;
            names, off + 2
      in
      one names off name
    else
      let rec one names off name =
        let l = Array.length name in
        if l = 0 then
          names, z off
        else
          let last = Array.get name (pred l)
          and rem = Array.sub name 0 (pred l)
          in
          let l = encode_lbl last off in
          one (DomMap.add name off names) l rem
      in
      one names off name
  in
  names, off
