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
  a Rr_map.key -> a -> ([`raw] Domain_name.t, [> `Msg of string ]) result =
  fun now key name rrsig t v ->
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
  let* (used_name, data) = Rr_map.prep_for_sig name rrsig t v in
  let hashed () = Mirage_crypto.Hash.digest algorithm data in
  let ok_if_true p =
    if p then Ok used_name else Error (`Msg "signature verification failed")
  in
  match key with
  | `P256 key ->
    let signature = Cstruct.split rrsig.Rrsig.signature 32 in
    ok_if_true (Mirage_crypto_ec.P256.Dsa.verify ~key signature (hashed ()))
  | `P384 key ->
    let signature = Cstruct.split rrsig.Rrsig.signature 48 in
    ok_if_true (Mirage_crypto_ec.P384.Dsa.verify ~key signature (hashed ()))
  | `ED25519 key ->
    let msg = data in
    ok_if_true (Mirage_crypto_ec.Ed25519.verify ~key rrsig.Rrsig.signature ~msg)
  | `RSA key ->
    let hashp = ( = ) algorithm
    and msg = `Message data
    and signature = rrsig.Rrsig.signature
    in
    ok_if_true (Mirage_crypto_pk.Rsa.PKCS1.verify ~hashp ~key ~signature msg)

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
        Logs.debug (fun m -> m "key tag (of dnskey) is %d" key_tag);
        match
          Rr_map.Rrsig_set.fold (fun rrsig ->
              Logs.debug (fun m -> m "key tag (of rrsig) is %d" rrsig.Rrsig.key_tag);
              function
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
      let* _name = r in
      let* pkey = dnskey_to_pk key in
      Logs.debug (fun m -> m "checking sig with key_tag %d and key %a"
                     rrsig.Rrsig.key_tag Dnskey.pp key);
      verify now pkey requested_domain rrsig t v)
    (Ok Domain_name.root) keys_rrsigs

let find_matching_rrsig typ rr_map =
  let _, rrsigs =
    Option.value ~default:(0l, Rr_map.Rrsig_set.empty)
      (Rr_map.find Rrsig rr_map)
  in
  let int = Rr_map.to_int typ in
  let rrsigs =
    Rr_map.Rrsig_set.filter
      (fun rrsig -> rrsig.Rrsig.type_covered = int)
      rrsigs
  in
  if Rr_map.Rrsig_set.is_empty rrsigs then
    Error (`Msg (Fmt.str "couldn't find RRSIG for %a" Rr_map.ppk (K typ)))
  else
    Ok rrsigs

let validate_soa now dnskeys auth =
  match
    Domain_name.Map.fold (fun k rr_map acc ->
        match Rr_map.(find Soa rr_map) with
        | Some soa -> Some (Domain_name.raw k, soa, rr_map)
        | None -> acc)
      auth None
  with
  | None -> Error (`Msg "no SOA in authority")
  | Some (name, soa, rr_map) ->
    let* rrsigs_soa = find_matching_rrsig Soa rr_map in
    let* used_name = validate_rrsig_keys now dnskeys rrsigs_soa name Soa soa in
    let* () =
      if Domain_name.equal name used_name then Ok () else
        Error (`Msg (Fmt.str "SOA owner %a differs from used name %a"
                       Domain_name.pp name Domain_name.pp used_name))
    in
    Ok name

let is_name_in_chain ~name ~owner nsec =
  (* for the last NSEC entry, next_domain is zone itself (thus = soa_name) *)
  let next_owner = (snd nsec).Nsec.next_domain
  and apex = Result.value ~default:name  (Domain_name.drop_label name)
  in
  Domain_name.(compare owner name < 0 &&
                  (compare name next_owner < 0 ||
                   compare apex next_owner = 0))

let name_in_chain ~name ~owner nsec =
  if is_name_in_chain ~name ~owner nsec then
    Ok ()
  else
    Error (`Msg (Fmt.str "name not in chain: owner %a, name %a, next owner %a"
                   Domain_name.pp owner
                   Domain_name.pp name
                   Domain_name.pp (snd nsec).Nsec.next_domain))

let wildcard_non_existence now name dnskeys auth =
  let* (wc_owner, rr_map) =
    (* for non-existing wildcard NSEC: its owner must be between
       <name> and <soa_name> *)
    (* TODO deal with nsec without rrsig etc. *)
    let rec find_it name =
      let wc_name = Domain_name.prepend_label_exn name "*" in
      let matches =
        Domain_name.Map.filter (fun owner rr_map ->
            match Rr_map.find Nsec rr_map with
            | Some nsec -> is_name_in_chain ~name:wc_name ~owner nsec
            | None -> false)
          auth
      in
      if Domain_name.Map.cardinal matches = 1 then
        Ok (Domain_name.Map.choose matches)
      else
        let* name = Domain_name.drop_label name in
        find_it name
    in
    find_it name
  in
  let wc_nsec = Rr_map.get Nsec rr_map in
  let* wc_rrsigs = find_matching_rrsig Nsec rr_map in
  let* wc_used_name =
    validate_rrsig_keys now dnskeys wc_rrsigs wc_owner Nsec wc_nsec
  in
  let* () =
    if Domain_name.equal wc_used_name wc_owner then Ok () else
      Error (`Msg (Fmt.str "wildcard owner %a and wildcard used name %a differ"
                     Domain_name.pp wc_owner Domain_name.pp wc_used_name))
  in
  let wc = Domain_name.prepend_label_exn wc_owner "*" in
  let* () = name_in_chain ~name:wc ~owner:wc_owner wc_nsec in
  Ok wc_nsec

let validate_nsec now owner dnskeys nsec rr_map =
  let* rrsigs = find_matching_rrsig Nsec rr_map in
  validate_rrsig_keys now dnskeys rrsigs owner Nsec nsec

let nsec_chain now name dnskeys auth =
  let* (owner, rr_map) =
    let matches =
      Domain_name.Map.filter (fun owner rr_map ->
          match Rr_map.find Nsec rr_map with
          | Some nsec -> is_name_in_chain ~name ~owner nsec
          | None -> false)
        auth
    in
    if Domain_name.Map.cardinal matches = 1 then
      Ok (Domain_name.Map.choose matches)
    else
      Error (`Msg (Fmt.str "couldn't find nsec chain record covering %a in %a"
                     Domain_name.pp name Name_rr_map.pp auth))
  in
  let nsec = Rr_map.get Nsec rr_map in
  let* used_name = validate_nsec now owner dnskeys nsec rr_map in
  let* () =
    if Domain_name.equal used_name owner then
      Ok ()
    else
      name_in_chain ~name ~owner nsec
  in
  Ok (owner, nsec)

let validate_nsec_no_domain now name dnskeys auth =
  (* no domain:
     - a SOA from a parent (zone), plus RRSIG
     - an NSEC for non-existing wildcard, plus rrsig
     - a NSEC <prev domain> .. <next-domain>, plus rrsig
     -> ensure requested_domain is between these domains *)
  let* soa_name = validate_soa now dnskeys auth in
  let* () =
    if Domain_name.is_subdomain ~subdomain:name ~domain:soa_name then
      Ok ()
    else
      Error (`Msg (Fmt.str "question %a is not subdomain of SOA %a"
                     Domain_name.pp name Domain_name.pp soa_name))
  in
  let* _ = wildcard_non_existence now name dnskeys auth in
  let* _ = nsec_chain now name dnskeys auth in
  Ok ()

let validate_no_data now name dnskeys k auth =
  (* no data:
     - SOA + RRSIG
     - (NSEC for name (and not for type = k) OR wildcard NSEC) + RRSIG
  *)
  let* soa_name = validate_soa now dnskeys auth in
  let* () =
    if Domain_name.is_subdomain ~subdomain:name ~domain:soa_name then
      Ok ()
    else
      Error (`Msg (Fmt.str "name %a is not a subdomain of soa %a"
                     Domain_name.pp name Domain_name.pp soa_name))
  in
  let* nsec =
    match Name_rr_map.find name Nsec auth with
    | None -> wildcard_non_existence now name dnskeys auth
    | Some nsec ->
      let rr_map = Option.get (Domain_name.Map.find name auth) in
      let* nsec_owner = validate_nsec now name dnskeys nsec rr_map in
      let* () =
        if Domain_name.equal nsec_owner name then
          Ok ()
        else
          Error (`Msg (Fmt.str "nsec owner %a is not name %a"
                         Domain_name.pp nsec_owner
                         Domain_name.pp name))
      in
      Ok nsec
  in
  if Bit_map.mem (Rr_map.to_int k) (snd nsec).Nsec.types then
    Error (`Msg (Fmt.str "nsec claims type %a to be present" Rr_map.ppk (K k)))
  else
    Ok ()

let rec validate_answer :
  type a. ?fuel:int -> ?follow_cname:bool -> Ptime.t -> [`raw] Domain_name.t ->
  Rr_map.Dnskey_set.t ->
  a Rr_map.rr -> Name_rr_map.t -> Name_rr_map.t ->
  (a, [> `Msg of string ]) result =
  fun ?(fuel = 20) ?(follow_cname = true) now name dnskeys k answer auth ->
  if fuel = 0 then
    Error (`Msg "too many redirections")
  else
    match Domain_name.Map.find name answer with
    | None ->
      Error (`Msg (Fmt.str "couldn't find rrs for %a (%a) in %a"
                     Domain_name.pp name Rr_map.ppk (K k)
                     Name_rr_map.pp answer))
    | Some rr_map ->
      match Rr_map.find k rr_map with
      | Some rrs ->
        let* rrsigs = find_matching_rrsig k rr_map in
        let* _used_name = validate_rrsig_keys now dnskeys rrsigs name k rrs in
        Ok rrs
      | None ->
        if follow_cname then
          match Rr_map.find Cname rr_map with
          | None ->
            Error (`Msg (Fmt.str "couldn't find rrs for %a" Rr_map.ppk (K k)))
          | Some rr ->
            let* rrsigs = find_matching_rrsig Cname rr_map in
            let* _used_name = validate_rrsig_keys now dnskeys rrsigs name Cname rr in
            Logs.info (fun m -> m "verified CNAME to %a" Domain_name.pp (snd rr));
            let fuel = fuel - 1 in
            validate_answer ~fuel ~follow_cname now (snd rr) dnskeys k answer auth
        else (* TODO verify cname RR *)
          Error (`Msg "no rr and follow_cname is false")
