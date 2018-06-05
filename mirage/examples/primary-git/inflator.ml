let size_buffer   = 0x800
let input_buffer  = Bytes.create size_buffer
let output_buffer = Bytes.create size_buffer
let window = Decompress.Window.create ~proof:Decompress.B.proof_bytes

let deflate ?(level = 4) buff =
  let pos = ref 0 in
  let res = Buffer.create (Cstruct.len buff) in

  Decompress.Deflate.bytes
    input_buffer output_buffer
    (fun input_buffer -> function
     | Some max ->
       let n = min max (min size_buffer (Cstruct.len buff - !pos)) in
       Cstruct.blit_to_bytes buff !pos input_buffer 0 n;
       pos := !pos + n;
       n
     | None ->
       let n = min size_buffer (Cstruct.len buff - !pos) in
       Cstruct.blit_to_bytes buff !pos input_buffer 0 n;
       pos := !pos + n;
       n)
    (fun output_buffer len ->
     Buffer.add_subbytes res output_buffer 0 len;
     size_buffer)
    (Decompress.Deflate.default ~proof:Decompress.B.proof_bytes level)
  |> function
     | Ok _t -> Cstruct.of_string @@ Buffer.contents res
     | Error _exn -> failwith "Deflate.deflate"

let inflate ?output_size orig =
  let res = Buffer.create (match output_size with Some len -> len | None -> size_buffer) in

  let open Decompress.Inflate in

  let rec loop ~refill:rest t =
    match eval (Decompress.B.from_bytes input_buffer) (Decompress.B.from_bytes output_buffer) t with
    | `Await t ->
      Mstruct.shift orig (used_in t - rest);

      let len = min size_buffer (Mstruct.length orig) in

      (match Mstruct.pick_string orig len with
       | Some str ->
         Bytes.blit_string str 0 input_buffer 0 len;
         loop ~refill:0 (refill 0 len t)
       | None -> failwith "Inflate.inflate")
    | `Flush t ->
      Mstruct.shift orig (used_in t - rest);

      Buffer.add_subbytes res output_buffer 0 (used_out t);
      loop ~refill:(used_in t) (flush 0 size_buffer t)
    | `Error (_t, _exn) -> None
    | `End t ->
      Mstruct.shift orig (used_in t - rest);

      if used_out t <> 0
      then begin
        Buffer.add_subbytes res output_buffer 0 (used_out t);
        Some (Mstruct.of_string (Buffer.contents res))
      end else Some (Mstruct.of_string (Buffer.contents res))
  in

  loop ~refill:0 (default (Decompress.Window.reset window))
