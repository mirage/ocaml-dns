(* (c) 2017 Hannes Mehnert, all rights reserved *)

module IntMap = Map.Make(struct
    type t = int
    let compare : int -> int -> int = compare
  end)

open Domain_name

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
  let t = Array.(append (to_array name) (make (List.length offs) "")) in
  let names, _, size =
    List.fold_left (fun (names, idx, size) (l, off) ->
        let s = succ size + String.length l in
        Array.set t idx l ;
        let sub = of_array (Array.sub t 0 (succ idx)) in
        IntMap.add off (sub, s) names, succ idx, s)
      (names, Array.length (to_array name), size) offs
  in
  let t = of_array t in
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
        let arr = to_array name in
        let l = Array.length arr in
        if l = 0 then
          names, z off
        else
          match Map.find name names with
          | None ->
            let last = Array.get arr (pred l)
            and rem = Array.sub arr 0 (pred l)
            in
            let l = encode_lbl last off in
            one (Map.add name off names) l (of_array rem)
          | Some ptr ->
            let data = ptr_tag lsl 8 + ptr in
            Cstruct.BE.set_uint16 buf off data ;
            names, off + 2
      in
      one names off name
    else
      let rec one names off name =
        let arr = to_array name in
        let l = Array.length arr in
        if l = 0 then
          names, z off
        else
          let last = Array.get arr (pred l)
          and rem = Array.sub arr 0 (pred l)
          in
          let l = encode_lbl last off in
          one (Map.add name off names) l (of_array rem)
      in
      one names off name
  in
  names, off
