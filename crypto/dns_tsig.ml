(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult.R.Infix

let algorithm_to_nc = function
  | Dns_packet.SHA1 -> `SHA1
  | Dns_packet.SHA224 -> `SHA224
  | Dns_packet.SHA256 -> `SHA256
  | Dns_packet.SHA384 -> `SHA384
  | Dns_packet.SHA512 -> `SHA512

let compute_tsig name tsig ~key buf =
  let h = algorithm_to_nc tsig.Dns_packet.algorithm
  and data = Dns_packet.encode_raw_tsig name tsig
  in
  Nocrypto.Hash.mac h ~key (Cstruct.append buf data)

let guard p err = if p then Ok () else Error err

(* TODO: should name compression be done?  atm it's convenient not to do it *)
let add_tsig ?max_size name tsig buf =
  Cstruct.BE.set_uint16 buf 10 (succ (Cstruct.BE.get_uint16 buf 10)) ;
  let tsig = Dns_packet.encode_full_tsig name tsig in
  match max_size with
  | Some x when x - Cstruct.len buf < Cstruct.len tsig -> None
  | _ -> Some (Cstruct.(append buf tsig))

let mac_to_prep = function
  | None -> Cstruct.create 0
  | Some mac ->
    let l = Cstruct.create 2 in
    Cstruct.BE.set_uint16 l 0 (Cstruct.len mac) ;
    Cstruct.append l mac

let sign ?mac ?max_size name tsig ~key buf =
  match Nocrypto.Base64.decode key.Dns_packet.key with
  | None -> None
  | Some key ->
    let prep = mac_to_prep mac in
    let mac = compute_tsig name tsig ~key (Cstruct.append prep buf) in
    let tsig = Dns_packet.with_mac tsig mac in
    (* RFC2845 Sec 3.1: if TSIG leads to truncation, alter message:
       - header stays (truncated = true)!
       - only question is preserved
       - _one_ additional, the TSIG itself *)
    match add_tsig ?max_size name tsig buf with
    | Some out -> Some (out, mac)
    | None ->
      match Dns_packet.decode_question Dns_name.IntMap.empty buf 12 with
      | Error e ->
        Logs.err
          (fun m -> m "dns_tsig sign: truncated, couldn't reparse question %a:@.%a"
              Dns_packet.pp_err e Cstruct.hexdump_pp buf) ;
        None (* assert false? *)
      | Ok (q, _, off) ->
        let new_buf = Cstruct.sub buf 0 off in
        Cstruct.set_uint8 new_buf 2 (0x02 lor (Cstruct.get_uint8 new_buf 2)) ;
        Cstruct.BE.set_uint16 new_buf 4 1 ;
        Cstruct.BE.set_uint16 new_buf 6 0 ;
        Cstruct.BE.set_uint16 new_buf 8 0 ;
        Cstruct.BE.set_uint16 new_buf 10 1 ;
        let mac = compute_tsig name tsig ~key (Cstruct.append prep new_buf) in
        let tsig = Dns_packet.with_mac tsig mac in
        match add_tsig name tsig new_buf with
        | None ->
          Logs.err (fun m -> m "dns_tsig sign: query %a with tsig %a too big %a:@.%a"
                       Dns_packet.pp_question q Dns_packet.pp_tsig tsig Fmt.(option ~none:(unit "none") int) max_size Cstruct.hexdump_pp new_buf) ;
          None
        | Some out -> Some (out, mac)

let verify_raw ?mac now name ~key tsig tbs =
  Rresult.R.of_option ~none:(fun () -> Error (`BadKey (name, tsig)))
    (Nocrypto.Base64.decode key.Dns_packet.key) >>= fun priv ->
  let ac = Cstruct.BE.get_uint16 tbs 10 in
  Cstruct.BE.set_uint16 tbs 10 (pred ac) ;
  let prep = mac_to_prep mac in
  let computed = compute_tsig name tsig ~key:priv (Cstruct.append prep tbs) in
  let mac = tsig.Dns_packet.mac in
  guard (Cstruct.len mac = Cstruct.len computed) (`BadTruncation (name, tsig)) >>= fun () ->
  guard (Cstruct.equal computed mac) (`InvalidMac (name, tsig)) >>= fun () ->
  guard (Dns_packet.valid_time now tsig) (`BadTimestamp (name, tsig, key)) >>= fun () ->
  Rresult.R.of_option ~none:(fun () -> Error (`BadTimestamp (name, tsig, key)))
    (Dns_packet.with_signed tsig now) >>= fun tsig ->
  Ok (tsig, mac)

let verify ?mac now v header name ~key tsig tbs =
  match
    Rresult.R.of_option ~none:(fun () -> Error (`BadKey (name, tsig))) key >>= fun key ->
    verify_raw ?mac now name ~key tsig tbs >>= fun (tsig, mac) ->
    Ok (tsig, mac, key)
  with
  | Ok x -> Ok x
  | Error e ->
    let header = { header with Dns_packet.query = not header.Dns_packet.query } in
    let or_empty = function None -> Cstruct.create 0 | Some x -> x in
    match Dns_packet.error header v Dns_enum.NotAuth, e with
    | None, _ -> Error (Cstruct.create 0)
    | Some (err, max_size), `BadKey (name, tsig) ->
      let tsig = Dns_packet.with_error (Dns_packet.with_mac tsig (Cstruct.create 0)) Dns_enum.BadKey in
      Error (or_empty (add_tsig ~max_size name tsig err))
    | Some (err, max_size), `InvalidMac (name, tsig) ->
      let tsig = Dns_packet.with_error (Dns_packet.with_mac tsig (Cstruct.create 0)) Dns_enum.BadVersOrSig in
      Error (or_empty (add_tsig ~max_size name tsig err))
    | Some (err, max_size), `BadTruncation (name, tsig) ->
      let tsig = Dns_packet.with_error (Dns_packet.with_mac tsig (Cstruct.create 0)) Dns_enum.BadTrunc in
      Error (or_empty (add_tsig ~max_size name tsig err))
    | Some (err, max_size), `BadTimestamp (name, tsig, key) ->
      let tsig = Dns_packet.with_error tsig Dns_enum.BadTime in
      match Dns_packet.with_other tsig (Some now) with
      | None -> Error err
      | Some tsig ->
        match sign ~max_size ~mac:tsig.Dns_packet.mac name tsig ~key err with
        | None -> Error err
        | Some (buf, _) -> Error buf

let encode_and_sign ?(proto = `Udp) header v now key keyname =
  let b, _ = Dns_packet.encode proto header v in
  match Dns_packet.dnskey_to_tsig_algo key with
  | None -> Error "cannot discover tsig algorithm of key"
  | Some algorithm -> match Dns_packet.tsig ~algorithm ~signed:now () with
    | None -> Error "couldn't create tsig"
    | Some tsig -> match sign keyname ~key tsig b with
      | None -> Error "key is not good"
      | Some r -> Ok r

let decode_and_verify now key keyname ?mac buf =
  match Dns_packet.decode buf with
  | Error _ -> Error "decode"
  | Ok (_, None) -> Error "not signed"
  | Ok ((header, v, opt, t), Some tsig_off) ->
    match t with
    | None -> Error "no tsig"
    | Some (name, tsig) when Domain_name.equal keyname name ->
      begin match verify_raw ?mac now keyname ~key tsig (Cstruct.sub buf 0 tsig_off) with
        | Ok (_, mac) -> Ok ((header, v, opt, t), mac)
        | Error _ -> Error "invalid signature"
      end
    | Some _ -> Error "invalid key name"
