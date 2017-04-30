(* (c) 2017 Hannes Mehnert, all rights reserved *)

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
  let mac = Nocrypto.Hash.mac h ~key (Cstruct.append buf data) in
  Logs.debug (fun m -> m "computed mac @.%a using key @.%a of buf @.%a"
                 Cstruct.hexdump_pp mac Cstruct.hexdump_pp key
                 Cstruct.hexdump_pp buf) ;
  mac

let guard p err = if p then Ok () else Error err

let add_tsig name tsig buf =
  let ad = Cstruct.BE.get_uint16 buf 10 in
  Cstruct.BE.set_uint16 buf 10 (succ ad) ;
  let tsig = Dns_packet.encode_full_tsig name tsig in
  Cstruct.(append buf tsig)

let mac_to_prep = function
  | None -> Cstruct.create 0
  | Some mac ->
    let l = Cstruct.create 2 in
    Cstruct.BE.set_uint16 l 0 (Cstruct.len mac) ;
    Cstruct.append l mac

let sign ?mac name tsig ~key buf =
  match Nocrypto.Base64.decode key.Dns_packet.key with
  | None -> None
  | Some key ->
    let prep = mac_to_prep mac in
    let mac = compute_tsig name tsig ~key (Cstruct.append prep buf) in
    let tsig = Dns_packet.with_mac tsig mac in
    Some (add_tsig name tsig buf, mac)

let verify ?mac now v header name ~key tsig tbs =
  match
    Rresult.R.of_option ~none:(fun () -> Error (`BadKey (name, tsig))) key >>= fun key ->
    Rresult.R.of_option ~none:(fun () -> Error (`BadKey (name, tsig)))
      (Nocrypto.Base64.decode key.Dns_packet.key) >>= fun priv ->
    let ac = Cstruct.BE.get_uint16 tbs 10 in
    Cstruct.BE.set_uint16 tbs 10 (pred ac) ;
    Logs.app (fun m -> m "key %a (priv %a) tbs %a" Dns_packet.pp_dnskey key
                 Cstruct.hexdump_pp priv Cstruct.hexdump_pp tbs) ;
    let prep = mac_to_prep mac in
    let computed = compute_tsig name tsig ~key:priv (Cstruct.append prep tbs) in
    (* TODO: could be truncated to NN bytes ?!?! *)
    let mac = tsig.Dns_packet.mac in
    Logs.debug (fun m -> m "comparing mac@.%avs computed@.%a"
                   Cstruct.hexdump_pp mac Cstruct.hexdump_pp computed) ;
    guard (Cstruct.equal computed mac) (`InvalidMac (name, tsig)) >>= fun () ->
    Logs.debug (fun m -> m "mac is good") ;
    guard (Dns_packet.valid_time now tsig) (`BadTimestamp (name, tsig, key)) >>= fun () ->
    Logs.debug (fun m -> m "time is valid") ;
    Rresult.R.of_option ~none:(fun () -> Error (`BadTimestamp (name, tsig, key)))
      (Dns_packet.with_signed tsig now) >>= fun tsig ->
    Ok (tsig, mac, key)
  with
  | Ok x -> Ok x
  | Error e ->
    match Dns_packet.error header v Dns_enum.NotAuth, e with
    | None, _ -> Error (Cstruct.create 0)
    | Some err, `BadKey (name, tsig) ->
      let tsig = Dns_packet.with_error (Dns_packet.with_mac tsig (Cstruct.create 0)) Dns_enum.BadKey in
      Error (add_tsig name tsig err)
    | Some err, `InvalidMac (name, tsig) ->
      let tsig = Dns_packet.with_error (Dns_packet.with_mac tsig (Cstruct.create 0)) Dns_enum.BadVersOrSig in
      Error (add_tsig name tsig err)
    | Some err, `BadTimestamp (name, tsig, key) ->
      let tsig = Dns_packet.with_error tsig Dns_enum.BadTime in
      match Dns_packet.with_other tsig (Some now) with
      | None -> Error err
      | Some tsig ->
        match sign ~mac:tsig.Dns_packet.mac name tsig ~key err with
        | None -> Error err
        | Some (buf, _) -> Error buf
