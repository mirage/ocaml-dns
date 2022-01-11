(* RFC 4648, Section 7 - Base 32 with extended hex alphabet *)

let make_alphabet alphabet =
  if String.length alphabet <> 32
  then invalid_arg "Length of alphabet must be 32" ;
  if String.contains alphabet '='
  then invalid_arg "Alphabet can not contain padding character" ;
  let emap =
    Array.init (String.length alphabet) (fun i -> Char.code alphabet.[i]) in
  let dmap = Array.make 256 (-1) in
  String.iteri (fun idx chr -> dmap.(Char.code chr) <- idx) alphabet ;
  (emap, dmap)

let alphabet = make_alphabet "0123456789ABCDEFGHIJKLMNOPQRSTUV"

let pad_char = '='
let pad_int = int_of_char pad_char

let encode ?(pad = true) str =
  let len = String.length str in
  (* since String.get_uint8 is OCaml >= 4.13 only *)
  let str = Bytes.unsafe_of_string str in
  let out_len = (len + 4) / 5 * 8 in
  let out = Bytes.make out_len pad_char in
  let o1 b1 = b1 lsr 3
  and o2 b1 b2 = (b1 land 0x07) lsl 2 + b2 lsr 6
  and o3 b2 = (b2 land 0x3E) lsr 1
  and o4 b2 b3 = ((b2 land 0x01) lsl 4) + b3 lsr 4
  and o5 b3 b4 = (b3 land 0x0F) lsl 1 + b4 lsr 7
  and o6 b4 = (b4 land 0x7c) lsr 2
  and o7 b4 b5 = (b4 land 0x03) lsl 3 + b5 lsr 5
  and o8 b5 = b5 land 0x1F
  in
  let emit b1 b2 b3 b4 b5 off =
    List.iteri (fun idx v -> Bytes.set_uint8 out (off + idx) ((fst alphabet).(v)))
      [ o1 b1; o2 b1 b2; o3 b2; o4 b2 b3; o5 b3 b4; o6 b4; o7 b4 b5; o8 b5 ]
  in
  let rec enc s_off d_off =
    if s_off = len then
      (* case 1 *) 0
    else if s_off = len - 1 then
      (* case 2 - 6 padding = *)
      let b1 = Bytes.get_uint8 str s_off in
      let p1 = o1 b1 and p2 = o2 b1 0 in
      Bytes.set_uint8 out d_off ((fst alphabet).(p1));
      Bytes.set_uint8 out (d_off + 1) ((fst alphabet).(p2));
      6
    else if s_off = len - 2 then
      (* case 3 - 4 padding = *)
      let b1 = Bytes.get_uint8 str s_off
      and b2 = Bytes.get_uint8 str (s_off + 1)
      in
      let p1 = o1 b1 and p2 = o2 b1 b2 and p3 = o3 b2 and p4 = o4 b2 0 in
      Bytes.set_uint8 out d_off ((fst alphabet).(p1));
      Bytes.set_uint8 out (d_off + 1) ((fst alphabet).(p2));
      Bytes.set_uint8 out (d_off + 2) ((fst alphabet).(p3));
      Bytes.set_uint8 out (d_off + 3) ((fst alphabet).(p4));
      4
    else if s_off = len - 3 then
      (* case 4 - 3 padding = *)
      let b1 = Bytes.get_uint8 str s_off
      and b2 = Bytes.get_uint8 str (s_off + 1)
      and b3 = Bytes.get_uint8 str (s_off + 2)
      in
      let p1 = o1 b1 and p2 = o2 b1 b2 and p3 = o3 b2 and p4 = o4 b2 b3 and p5 = o5 b3 0 in
      Bytes.set_uint8 out d_off ((fst alphabet).(p1));
      Bytes.set_uint8 out (d_off + 1) ((fst alphabet).(p2));
      Bytes.set_uint8 out (d_off + 2) ((fst alphabet).(p3));
      Bytes.set_uint8 out (d_off + 3) ((fst alphabet).(p4));
      Bytes.set_uint8 out (d_off + 4) ((fst alphabet).(p5));
      3
    else if s_off = len - 4 then
      (* case 5 - 1 padding = *)
      let b1 = Bytes.get_uint8 str s_off
      and b2 = Bytes.get_uint8 str (s_off + 1)
      and b3 = Bytes.get_uint8 str (s_off + 2)
      and b4 = Bytes.get_uint8 str (s_off + 3)
      in
      let p1 = o1 b1 and p2 = o2 b1 b2 and p3 = o3 b2 and p4 = o4 b2 b3 and p5 = o5 b3 b4 and p6 = o6 b4 and p7 = o7 b4 0 in
      Bytes.set_uint8 out d_off ((fst alphabet).(p1));
      Bytes.set_uint8 out (d_off + 1) ((fst alphabet).(p2));
      Bytes.set_uint8 out (d_off + 2) ((fst alphabet).(p3));
      Bytes.set_uint8 out (d_off + 3) ((fst alphabet).(p4));
      Bytes.set_uint8 out (d_off + 4) ((fst alphabet).(p5));
      Bytes.set_uint8 out (d_off + 5) ((fst alphabet).(p6));
      Bytes.set_uint8 out (d_off + 6) ((fst alphabet).(p7));
      1
    else
      let b1 = Bytes.get_uint8 str s_off in
      let b2 = Bytes.get_uint8 str (s_off + 1) in
      let b3 = Bytes.get_uint8 str (s_off + 2) in
      let b4 = Bytes.get_uint8 str (s_off + 3) in
      let b5 = Bytes.get_uint8 str (s_off + 4) in
      emit b1 b2 b3 b4 b5 d_off;
      enc (s_off + 5) (d_off + 8)
  in
  let padding_bytes = enc 0 0 in
  let out_s = Bytes.unsafe_to_string out in
  if pad then out_s else String.sub out_s 0 (out_len - padding_bytes)

(* RFC 4648 section 10
   BASE32-HEX("") = ""
   BASE32-HEX("f") = "CO======"
   BASE32-HEX("fo") = "CPNG===="
   BASE32-HEX("foo") = "CPNMU==="
   BASE32-HEX("foob") = "CPNMUOG="
   BASE32-HEX("fooba") = "CPNMUOJ1"
   BASE32-HEX("foobar") = "CPNMUOJ1E8======"
*)

let decode ?(unpadded = false) str =
  let ( let* ) = Result.bind in
  let* str =
    let lmod8 = String.length str mod 8 in
    if lmod8 > 0 then
      if unpadded then
        Ok (str ^ String.make (8 - lmod8) pad_char)
      else
        Error (`Msg "invalid input length (not divisible by 8)")
    else
      Ok str
  in
  let len = String.length str in
  let str = Bytes.unsafe_of_string str in
  let out_len = len / 8 * 5 in (* max length *)
  let out = Bytes.create out_len in
  let o1 b1 b2 = b1 lsl 3 + b2 lsr 2
  and o2 b2 b3 b4 = (b2 land 0x03) lsl 6 + b3 lsl 1 + b4 lsr 4
  and o3 b4 b5 = (b4 land 0x0F) lsl 4 + b5 lsr 1
  and o4 b5 b6 b7 = (b5 land 0x01) lsl 7 + b6 lsl 2 + b7 lsr 3
  and o5 b7 b8 = (b7 land 0x07) lsl 5 + b8
  in
  let c ~off idx =
    let r = (snd alphabet).(idx) in
    if r = -1 then
      Error (`Msg ("bad encoding at " ^ string_of_int off))
    else
      Ok r
  in
  let emit s_off v1 v2 v3 v4 v5 v6 v7 v8 off =
    let* b1 = c ~off:s_off v1 in
    let* b2 = c ~off:(s_off + 1) v2 in
    let* b3 = c ~off:(s_off + 2) v3 in
    let* b4 = c ~off:(s_off + 3) v4 in
    let* b5 = c ~off:(s_off + 4) v5 in
    let* b6 = c ~off:(s_off + 5) v6 in
    let* b7 = c ~off:(s_off + 6) v7 in
    let* b8 = c ~off:(s_off + 7) v8 in
    Bytes.set_uint8 out off (o1 b1 b2);
    Bytes.set_uint8 out (off + 1) (o2 b2 b3 b4);
    Bytes.set_uint8 out (off + 2) (o3 b4 b5);
    Bytes.set_uint8 out (off + 3) (o4 b5 b6 b7);
    Bytes.set_uint8 out (off + 4) (o5 b7 b8);
    Ok ()
  in
  let rec dec s_off d_off =
    if s_off = len then
      Ok (0, 0)
    else
      let v1 = Bytes.get_uint8 str s_off
      and v2 = Bytes.get_uint8 str (s_off + 1)
      and v3 = Bytes.get_uint8 str (s_off + 2)
      and v4 = Bytes.get_uint8 str (s_off + 3)
      and v5 = Bytes.get_uint8 str (s_off + 4)
      and v6 = Bytes.get_uint8 str (s_off + 5)
      and v7 = Bytes.get_uint8 str (s_off + 6)
      and v8 = Bytes.get_uint8 str (s_off + 7)
      in
      if v3 = pad_int then
        let* b1 = c ~off:s_off v1 in
        let* b2 = c ~off:(s_off + 1) v2 in
        let p1 = o1 b1 b2 in
        Bytes.set_uint8 out d_off p1;
        Ok (6, 4)
      else if v5 = pad_int then
        let* b1 = c ~off:s_off v1 in
        let* b2 = c ~off:(s_off + 1) v2 in
        let* b3 = c ~off:(s_off + 2) v3 in
        let* b4 = c ~off:(s_off + 3) v4 in
        let p1 = o1 b1 b2
        and p2 = o2 b2 b3 b4
        in
        Bytes.set_uint8 out d_off p1;
        Bytes.set_uint8 out (d_off + 1) p2;
        Ok (4, 3)
      else if v6 = pad_int then
        let* b1 = c ~off:s_off v1 in
        let* b2 = c ~off:(s_off + 1) v2 in
        let* b3 = c ~off:(s_off + 2) v3 in
        let* b4 = c ~off:(s_off + 3) v4 in
        let* b5 = c ~off:(s_off + 4) v5 in
        let p1 = o1 b1 b2
        and p2 = o2 b2 b3 b4
        and p3 = o3 b4 b5
        in
        Bytes.set_uint8 out d_off p1;
        Bytes.set_uint8 out (d_off + 1) p2;
        Bytes.set_uint8 out (d_off + 2) p3;
        Ok (3, 2)
      else if v8 = pad_int then
        let* b1 = c ~off:s_off v1 in
        let* b2 = c ~off:(s_off + 1) v2 in
        let* b3 = c ~off:(s_off + 2) v3 in
        let* b4 = c ~off:(s_off + 3) v4 in
        let* b5 = c ~off:(s_off + 4) v5 in
        let* b6 = c ~off:(s_off + 5) v6 in
        let* b7 = c ~off:(s_off + 6) v7 in
        let p1 = o1 b1 b2
        and p2 = o2 b2 b3 b4
        and p3 = o3 b4 b5
        and p4 = o4 b5 b6 b7
        in
        Bytes.set_uint8 out d_off p1;
        Bytes.set_uint8 out (d_off + 1) p2;
        Bytes.set_uint8 out (d_off + 2) p3;
        Bytes.set_uint8 out (d_off + 3) p4;
        Ok (1, 1)
      else
        let* () = emit s_off v1 v2 v3 v4 v5 v6 v7 v8 d_off in
        dec (s_off + 8) (d_off + 5)
  in
  let* (pad_bytes, to_remove) = dec 0 0 in
  let rec check_pad = function
    | 0 -> Ok ()
    | n ->
      if Bytes.get_uint8 str (len - n) = pad_int then
        check_pad (n - 1)
      else
        Error (`Msg ("expected pad character at " ^ (string_of_int (len - n))))
  in
  let* () = check_pad pad_bytes in
  let out_str = Bytes.unsafe_to_string out in
  if to_remove > 0 then
    Ok (String.sub out_str 0 (out_len - to_remove))
  else
    Ok out_str
