open Dns

let ( let* ) = Result.bind

let guard a e = if a then Ok () else Error e

type pub = [
  | `P256 of Mirage_crypto_ec.P256.Dsa.pub
  | `P384 of Mirage_crypto_ec.P384.Dsa.pub
  | `ED25519 of Mirage_crypto_ec.Ed25519.pub
  | `RSA of Mirage_crypto_pk.Rsa.pub
]

let pp_pub ppf = function
  | `P256 _ -> Fmt.string ppf "P256"
  | `P384 _ -> Fmt.string ppf "P384"
  | `ED25519 _ -> Fmt.string ppf "ED25519"
  | `RSA k -> Fmt.pf ppf "RSA %d bits" (Mirage_crypto_pk.Rsa.pub_bits k)

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

let verify : type a . Ptime.t -> pub -> [`raw] Domain_name.t -> Rrsig.t ->
  a Rr_map.key -> a -> (unit, [> `Msg of string ]) result = fun now key name rrsig t v ->
  (* from RFC 4034 section 3.1.8.1 *)
  Logs.info (fun m -> m "verifying for %a (with %a / %a)" Domain_name.pp name
    pp_pub key
    Dnskey.pp_algorithm rrsig.Rrsig.algorithm);
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
  let* data = Rr_map.prep_for_sig name rrsig t v in
  let hashed () = Mirage_crypto.Hash.digest algorithm data in
  let ok_if_true p = if p then Ok () else Error (`Msg "signature verification failed") in
  match key with
  | `P256 key ->
    ok_if_true (Mirage_crypto_ec.P256.Dsa.verify ~key (Cstruct.split rrsig.Rrsig.signature 32) (hashed ()))
  | `P384 key ->
    ok_if_true (Mirage_crypto_ec.P384.Dsa.verify ~key (Cstruct.split rrsig.Rrsig.signature 48) (hashed ()))
  | `ED25519 key ->
    ok_if_true (Mirage_crypto_ec.Ed25519.verify ~key rrsig.Rrsig.signature ~msg:data)
  | `RSA key ->
    let hashp = ( = ) algorithm in
    (match Mirage_crypto_pk.Rsa.PKCS1.sig_decode ~key rrsig.Rrsig.signature with
    | None -> Logs.warn (fun m -> m "none in sig_decode")
    | Some cs -> Logs.debug (fun m -> m "decoded sig %a" Cstruct.hexdump_pp cs));
    Logs.debug (fun m -> m "digest %a" Cstruct.hexdump_pp (Mirage_crypto.Hash.digest algorithm data));

    ok_if_true (Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature:rrsig.Rrsig.signature (`Message data))
