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
  Logs.debug (fun m -> m "verifying for %a (with %a / %a)" Domain_name.pp name
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

let validate_ds zone dnskeys ds =
  let* used_dnskey =
    let key_signing_keys =
      Rr_map.Dnskey_set.filter (fun dnsk ->
          Dnskey.F.mem `Secure_entry_point dnsk.Dnskey.flags &&
          Dnskey.key_tag dnsk = ds.Ds.key_tag)
        dnskeys
    in
    if Rr_map.Dnskey_set.cardinal key_signing_keys = 1 then
      Ok (Rr_map.Dnskey_set.choose key_signing_keys)
    else
      Error (`Msg "none or multiple key singing keys")
  in
  let* dgst = digest ds.Ds.digest_type zone used_dnskey in
  if Cstruct.equal ds.Ds.digest dgst then begin
    Logs.info (fun m -> m "DS for %a is good" Domain_name.pp zone);
    Ok used_dnskey
  end else
    Error (`Msg "key signing key couldn't be validated")

let validate_rrsig_keys now dnskeys rrsigs requested_domain t v =
  let keys_rrsigs =
    Rr_map.Dnskey_set.fold (fun key acc ->
        let key_tag = Dnskey.key_tag key in
        match
          Rr_map.Rrsig_set.fold (fun rrsig -> function
              | None when rrsig.Rrsig.key_tag = key_tag -> Some rrsig
              | Some a when rrsig.Rrsig.key_tag = key_tag ->
                Logs.warn (fun m -> m "multiple rrsig for key %d" key_tag);
                Some a
              | _ as s -> s)
            rrsigs None
        with
        | Some rrsig -> (key, rrsig) :: acc
        | None -> acc)
      dnskeys []
  in
  let* () = if keys_rrsigs = [] then Error (`Msg "no matching key and rrsig found") else Ok () in
  Logs.debug (fun m -> m "found %d key-rrsig pairs" (List.length keys_rrsigs));
  List.fold_left (fun r (key, rrsig) ->
      let* () = r in
      let* pkey = dnskey_to_pk key in
      Logs.debug (fun m -> m "checking sig with key_tag %d and key %a" rrsig.Rrsig.key_tag Dnskey.pp key);
      verify now pkey requested_domain rrsig t v)
    (Ok ()) keys_rrsigs

let validate_soa now name dnskeys auth =
  let _, rrsigs =
    Option.value ~default:(0l, Rr_map.Rrsig_set.empty)
      (Name_rr_map.find name Rr_map.Rrsig auth)
  in
  let* (soa, rrsigs_soa) =
    let soa_int = Rr_map.to_int Soa in
    match
      Name_rr_map.find name Rr_map.Soa auth,
      Rr_map.Rrsig_set.filter
        (fun rrsig -> rrsig.Rrsig.type_covered = soa_int)
        rrsigs
    with
    | Some soa, rrsigs when Rr_map.Rrsig_set.cardinal rrsigs > 0 -> Ok (soa, rrsigs)
    | None, _ ->
      Error (`Msg (Fmt.str "couldn't find SOA for %a" Domain_name.pp name))
    | _, _ ->
      Error (`Msg (Fmt.str "couldn't find RRSIG for SOA %a" Domain_name.pp name))
  in
  validate_rrsig_keys now dnskeys rrsigs_soa name Soa soa

let validate_nsec now name dnskeys auth =
  let _, rrsigs =
    Option.value ~default:(0l, Rr_map.Rrsig_set.empty)
      (Name_rr_map.find name Rr_map.Rrsig auth)
  in
  let* (nsec, rrsigs_nsec) =
    let nsec_int = Rr_map.to_int Nsec in
    match
      Name_rr_map.find name Rr_map.Nsec auth,
      Rr_map.Rrsig_set.filter
        (fun rrsig -> rrsig.Rrsig.type_covered = nsec_int)
        rrsigs
    with
    | Some nsec, rrsigs when Rr_map.Rrsig_set.cardinal rrsigs > 0 -> Ok (nsec, rrsigs)
    | None, _ ->
      Error (`Msg (Fmt.str "couldn't find NSEC for %a" Domain_name.pp name))
    | _, _ ->
      Error (`Msg (Fmt.str "couldn't find RRSIG for NSEC %a" Domain_name.pp name))
  in
  let* () = validate_rrsig_keys now dnskeys rrsigs_nsec name Nsec nsec in
  Ok nsec

let validate_nsec_no_domain now name dnskeys auth =
  (* no domain:
     - a SOA from parent (zone), plus RRSIG
     - a NSEC for zone, plus rrsig
     - a NSEC <prev domain> .. <next-domain>, plus rrsig
     -> ensure requested_domain is between these domains *)
  let parent =
    Domain_name.(Result.value ~default:root (drop_label name))
  in
  let* () = validate_soa now parent dnskeys auth in
  let* _nsec = validate_nsec now parent dnskeys auth in
  let* (prev, nsec) =
    let leftover = Domain_name.Map.remove parent auth in
    if Domain_name.Map.cardinal leftover = 1 then
      let name, _ = Domain_name.Map.choose leftover in
      let* nsec = validate_nsec now name dnskeys leftover in
      Ok (name, nsec)
    else
      Error (`Msg "too many records in authority")
  in
  let* () =
    let cmp a b =
      let cs = Cstruct.of_string Domain_name.(to_string (canonical a))
      and cs' = Cstruct.of_string Domain_name.(to_string (canonical b))
      in
      Rr_map.canonical_order cs cs'
    in
    if
      cmp prev name < 0 && cmp name (snd nsec).Nsec.next_domain > 0
    then begin
      Logs.debug (fun m -> m "name is between nsec and next_domain");
      Ok ()
    end else
      Error (`Msg "bad nsec")
  in
  Ok ()

let validate_nsec_no_data now name dnskeys k auth =
  (* no data:
     - SOA + RRSIG
     - NSEC (mentioning next domain, and _not_ this type) + RRSIG *)
  let* () = validate_soa now name dnskeys auth in
  let* nsec = validate_nsec now name dnskeys auth in
  let* () =
    let cmp a b =
      let cs = Cstruct.of_string Domain_name.(to_string (canonical a))
      and cs' = Cstruct.of_string Domain_name.(to_string (canonical b))
      in
      Rr_map.canonical_order cs cs'
    in
    if cmp name (snd nsec).Nsec.next_domain > 0 then begin
      Logs.debug (fun m -> m "next_domain is after name");
      Ok ()
    end else
      Error (`Msg "bad nsec")
  in
  if Bit_map.mem (Rr_map.to_int k) (snd nsec).Nsec.types then
    Error (`Msg "nsec claims this type to be present")
  else
    Ok ()
