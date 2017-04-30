(* (c) 2017 Hannes Mehnert, all rights reserved *)

let max_size = 10000
let inp = Bytes.create max_size

let get_input () =
  set_binary_mode_in stdin true;
  let rec read off =
    let count = input stdin inp off (max_size - off)  in
    if count = 0 then () else read (off + count)
  in
  read 0

let main () =
  get_input () ;
  (*  match Dns_name.(decode IntMap.empty (Cstruct.of_bytes inp) 0) with
      | Ok (n, _m, _b) -> Format.printf "%a" Dns_name.pp n
      | Error e -> Format.printf "%a" Dns_name.pp_err e *)
  match Dns_packet.decode (Cstruct.of_bytes inp) with
  | Ok n -> Format.printf "%a" Dns_packet.pp n
  | Error e -> Format.printf "%a" Dns_packet.pp_err e

let () = AflPersistent.run main
