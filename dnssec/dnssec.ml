open Dns

let ( let* ) = Result.bind

let guard a e = if a then Ok () else Error e

(* used by DS, RFC 4034 section 5.1.4 *)
let digest algorithm owner dnskey =
  let* h =
    match algorithm with
    | Ds.SHA1 -> Ok `SHA1
    | Ds.SHA256 -> Ok `SHA256
    | Ds.SHA384 -> Ok `SHA384
    | dt ->
      Error (`Msg (Fmt.str "Unsupported hash algorithm %a"
                     Ds.pp_digest_type dt))
  in
  Ok (Mirage_crypto.Hash.digest h (Dnskey.digest_prep owner dnskey))

let dnskey_to_pk { Dnskey.algorithm ; key ; _ } =
  let map_ec_err r =
    Result.map_error (fun e -> `Msg (Fmt.to_to_string Mirage_crypto_ec.pp_error e)) r
  in
  match algorithm with
  | Dnskey.RSA_SHA1 | Dnskey.RSA_SHA256 | Dnskey.RSA_SHA512 ->
    (* described in RFC 3110 *)
    let* () = if Cstruct.length key > 0 then Ok () else Error (`Msg "key data too short") in
    let e_len = Cstruct.get_uint8 key 0 in
    let* () = if Cstruct.length key > (e_len + 1) then Ok () else Error (`Msg "key data too short") in
    let e, n = Cstruct.split (Cstruct.shift key 1) e_len in
    let e = Mirage_crypto_pk.Z_extra.of_cstruct_be e
    and n = Mirage_crypto_pk.Z_extra.of_cstruct_be n
    in
    let* pub = Mirage_crypto_pk.Rsa.pub ~e ~n in
    Ok (`RSA pub)
  | Dnskey.P256_SHA256 ->
    let four = Cstruct.create 1 in Cstruct.set_uint8 four 0 4 ;
    let* pub = map_ec_err (Mirage_crypto_ec.P256.Dsa.pub_of_cstruct (Cstruct.append four key)) in
    Ok (`P256 pub)
  | Dnskey.P384_SHA384 ->
    let four = Cstruct.create 1 in Cstruct.set_uint8 four 0 4 ;
    let* pub = map_ec_err (Mirage_crypto_ec.P384.Dsa.pub_of_cstruct (Cstruct.append four key)) in
    Ok (`P384 pub)
  | Dnskey.ED25519 ->
    let* pub = map_ec_err (Mirage_crypto_ec.Ed25519.pub_of_cstruct key) in
    Ok (`ED25519 pub)
  | MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | Unknown _ ->
    Error (`Msg (Fmt.str "unsupported key algorithm %a" Dnskey.pp_algorithm algorithm))

let verify now key name rrsig rrmap =
  (* from RFC 4034 section 3.1.8.1 *)
  let* algorithm =
    match rrsig.Rrsig.algorithm with
    | Dnskey.RSA_SHA1 -> Ok `SHA1
    | Dnskey.RSA_SHA256 -> Ok `SHA256
    | Dnskey.RSA_SHA512 -> Ok `SHA512
    | Dnskey.P256_SHA256 -> Ok `SHA256
    | Dnskey.P384_SHA384 -> Ok `SHA384
    | Dnskey.ED25519 -> Ok `SHA512
    | a -> Error (`Msg (Fmt.str "unsupported signature algorithm %a"
                          Dnskey.pp_algorithm a))
  in
  let* () =
    guard (Ptime.is_later ~than:now rrsig.Rrsig.signature_expiration)
      (`Msg "signature timestamp expired")
  in
  let* () =
    guard (Ptime.is_later ~than:rrsig.Rrsig.signature_inception now)
      (`Msg "signature not yet incepted")
  in
  let* data = Rr_map.prep_for_sig name rrsig rrmap in
  let scheme = match key with
    `RSA _ -> `RSA_PKCS1 | `ED25519 _ -> `ED25519 | `P256 _ | `P384 _ -> `ECDSA
  in
  X509.Public_key.verify algorithm ~scheme
    ~signature:rrsig.Rrsig.signature (key :> X509.Public_key.t) (`Message data)
