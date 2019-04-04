(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult.R.Infix

open Udns

let src = Logs.Src.create "udns_tsig" ~doc:"DNS tsig"
module Log = (val Logs.src_log src : Logs.LOG)

let algorithm_to_nc = function
  | Tsig.SHA1 -> `SHA1
  | Tsig.SHA224 -> `SHA224
  | Tsig.SHA256 -> `SHA256
  | Tsig.SHA384 -> `SHA384
  | Tsig.SHA512 -> `SHA512

let compute_tsig name tsig ~key buf =
  let h = algorithm_to_nc tsig.Tsig.algorithm
  and data = Tsig.encode_raw name tsig
  in
  Nocrypto.Hash.mac h ~key (Cstruct.append buf data)

let guard p err = if p then Ok () else Error err

(* TODO: should name compression be done?  atm it's convenient not to do it *)
let add_tsig ?max_size name tsig buf =
  Cstruct.BE.set_uint16 buf 10 (succ (Cstruct.BE.get_uint16 buf 10)) ;
  let tsig = Tsig.encode_full name tsig in
  match max_size with
  | Some x when x - Cstruct.len buf < Cstruct.len tsig -> None
  | _ -> Some (Cstruct.(append buf tsig))

let mac_to_prep = function
  | None -> Cstruct.create 0
  | Some mac ->
    let l = Cstruct.create 2 in
    Cstruct.BE.set_uint16 l 0 (Cstruct.len mac) ;
    Cstruct.append l mac

let sign ?mac ?max_size name tsig ~key hdr question buf =
  match Nocrypto.Base64.decode key.Dnskey.key with
  | None -> None
  | Some key ->
    let prep = mac_to_prep mac in
    let mac = compute_tsig name tsig ~key (Cstruct.append prep buf) in
    let tsig = Tsig.with_mac tsig mac in
    (* RFC2845 Sec 3.1: if TSIG leads to truncation, alter message:
       - header stays (truncated = true)!
       - only question is preserved
       - _one_ additional, the TSIG itself *)
    match add_tsig ?max_size name tsig buf with
    | Some out -> Some (out, mac)
    | None ->
      Log.err (fun m -> m "dns_tsig sign: truncated, sending tsig error") ;
      let header = {
        hdr with Packet.Header.flags = Packet.Header.FS.add `Truncation hdr.Packet.Header.flags
      } in
      let new_buf, off = Packet.encode `Udp header question (`Query Packet.Query.empty) in
      let tbs = Cstruct.sub new_buf 0 off in
      let mac = compute_tsig name tsig ~key (Cstruct.append prep tbs) in
      let tsig = Tsig.with_mac tsig mac in
      match add_tsig name tsig new_buf with
      | None ->
        Log.err (fun m -> m "dns_tsig sign failed the second time: query %a %a with tsig %a too big %a:@.%a"
                    Packet.Header.pp header
                    Packet.Question.pp question
                    Tsig.pp tsig
                    Fmt.(option ~none:(unit "none") int) max_size
                    Cstruct.hexdump_pp new_buf) ;
        None
      | Some out -> Some (out, mac)

let verify_raw ?mac now name ~key tsig tbs =
  Rresult.R.of_option ~none:(fun () -> Error (`BadKey (name, tsig)))
    (Nocrypto.Base64.decode key.Dnskey.key) >>= fun priv ->
  let ac = Cstruct.BE.get_uint16 tbs 10 in
  Cstruct.BE.set_uint16 tbs 10 (pred ac) ;
  let prep = mac_to_prep mac in
  let computed = compute_tsig name tsig ~key:priv (Cstruct.append prep tbs) in
  let mac = tsig.Tsig.mac in
  guard (Cstruct.len mac = Cstruct.len computed) (`BadTruncation (name, tsig)) >>= fun () ->
  guard (Cstruct.equal computed mac) (`InvalidMac (name, tsig)) >>= fun () ->
  guard (Tsig.valid_time now tsig) (`BadTimestamp (name, tsig, key)) >>= fun () ->
  Rresult.R.of_option ~none:(fun () -> Error (`BadTimestamp (name, tsig, key)))
    (Tsig.with_signed tsig now) >>= fun tsig ->
  Ok (tsig, mac)

let verify ?mac now header question name ~key tsig tbs =
  match
    Rresult.R.of_option ~none:(fun () -> Error (`BadKey (name, tsig))) key >>= fun key ->
    verify_raw ?mac now name ~key tsig tbs >>= fun (tsig, mac) ->
    Ok (tsig, mac, key)
  with
  | Ok x -> Ok x
  | Error e ->
    let header = { header with Packet.Header.query = not header.Packet.Header.query } in
    let or_err f err = match f err with None -> Some err | Some x -> Some x in
    match Packet.error header question Udns_enum.NotAuth, e with
    | None, _ -> Error None
    | Some (err, max_size), `BadKey (name, tsig) ->
      let tsig = Tsig.with_error (Tsig.with_mac tsig Cstruct.empty) Udns_enum.BadKey in
      Error (or_err (add_tsig ~max_size name tsig) err)
    | Some (err, max_size), `InvalidMac (name, tsig) ->
      let tsig = Tsig.with_error (Tsig.with_mac tsig Cstruct.empty) Udns_enum.BadVersOrSig in
      Error (or_err (add_tsig ~max_size name tsig) err)
    | Some (err, max_size), `BadTruncation (name, tsig) ->
      let tsig = Tsig.with_error (Tsig.with_mac tsig (Cstruct.create 0)) Udns_enum.BadTrunc in
      Error (or_err (add_tsig ~max_size name tsig) err)
    | Some (err, max_size), `BadTimestamp (name, tsig, key) ->
      let tsig = Tsig.with_error tsig Udns_enum.BadTime in
      match Tsig.with_other tsig (Some now) with
      | None -> Error (Some err)
      | Some tsig ->
        match sign ~max_size ~mac:tsig.Tsig.mac name tsig ~key header question err with
        | None -> Error (Some err)
        | Some (buf, _) -> Error (Some buf)

let encode_and_sign ?(proto = `Udp) ?additional header question p now key keyname =
  let b, _ = Packet.encode ?additional proto header question p in
  match Tsig.dnskey_to_tsig_algo key with
  | None -> Error "cannot discover tsig algorithm of key"
  | Some algorithm -> match Tsig.tsig ~algorithm ~signed:now () with
    | None -> Error "couldn't create tsig"
    | Some tsig -> match sign keyname ~key tsig header question b with
      | None -> Error "key is not good"
      | Some r -> Ok r

let decode_and_verify now key keyname ?mac buf =
  match Packet.decode buf with
  | Error _ -> Error "decode"
  | Ok (_, _, _, _, _, None) -> Error "not signed"
  | Ok ((_, _, _, _, _, Some (name, tsig, tsig_off)) as res) when Domain_name.equal keyname name ->
      begin match verify_raw ?mac now keyname ~key tsig (Cstruct.sub buf 0 tsig_off) with
        | Ok (_, mac) -> Ok (res, tsig, mac)
        | Error _ -> Error "invalid signature"
      end
  | Ok (_, _, _, _, _, Some _) ->
    Error "invalid key name"
