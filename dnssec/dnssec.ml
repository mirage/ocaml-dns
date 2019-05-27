open Dns

let src = Logs.Src.create "dnssec" ~doc:"DNS Security"
module Log = (val Logs.src_log src : Logs.LOG)

let ( let* ) = Result.bind

module KM = Map.Make(struct type t = Rr_map.k let compare = Rr_map.comparek end)

let pp_km_name_rr_map ppf rrs =
  List.iter (fun (name, (rr_map, _)) ->
      Fmt.(list ~sep:(any "@.") string) ppf
        (List.map (Rr_map.text_b name) (Rr_map.bindings rr_map)))
    (Domain_name.Map.bindings rrs)

let guard a e = if a then Ok () else Error e

let open_err : ('a, [ `Msg of string ]) result ->
  ('a, [> `Msg of string ]) result = function
  | Ok _ as a -> a
  | Error (`Msg _) as b -> b

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
  | Dnskey.RSA_SHA1 | Dnskey.RSASHA1_NSEC3_SHA1 | Dnskey.RSA_SHA256 | Dnskey.RSA_SHA512 ->
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
  a Rr_map.key -> a ->
  ([`raw] Domain_name.t * [`raw] Domain_name.t, [ `Msg of string ]) result =
  fun now key name rrsig t v ->
  (* from RFC 4034 section 3.1.8.1 *)
  Log.debug (fun m -> m "verifying for %a (with %a / %a)" Domain_name.pp name
    pp_pub key
    Dnskey.pp_algorithm rrsig.Rrsig.algorithm);
  let* algorithm =
    match rrsig.Rrsig.algorithm with
    | Dnskey.RSA_SHA1 -> Ok `SHA1
    | Dnskey.RSASHA1_NSEC3_SHA1 -> Ok `SHA1
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
    if p then
      Ok (used_name, rrsig.Rrsig.signer_name)
    else
      Error (`Msg "signature verification failed")
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
    Log.info (fun m -> m "DS for %a is good" Domain_name.pp zone);
    Ok used_dnskey
  end else
    Error (`Msg "key signing key couldn't be validated")

let validate_rrsig_keys now dnskeys rrsigs requested_domain t v =
  Log.debug (fun m -> m "validating for %a typ %a"
                 Domain_name.pp requested_domain
                 Rr_map.ppk (K t));
  let keys_rrsigs =
    Rr_map.Dnskey_set.fold (fun key acc ->
        let key_tag = Dnskey.key_tag key in
        let matching =
          Rr_map.Rrsig_set.filter (fun rr -> rr.Rrsig.key_tag = key_tag) rrsigs
        in
        Rr_map.Rrsig_set.fold (fun rr acc -> (key, rr) :: acc) matching acc)
      dnskeys []
  in
  Log.debug (fun m -> m "found %d key-rrsig pairs" (List.length keys_rrsigs));
  let verify_signature (key, rrsig) =
    let* pkey = dnskey_to_pk key in
    open_err (verify now pkey requested_domain rrsig t v)
  in
  match List.partition Result.is_ok (List.map verify_signature keys_rrsigs) with
  | r :: _, _ -> r
  | [], e :: _ -> e
  | [], [] -> Error (`Msg "no key-rrsig pair found")

let find_soa auth =
  match
    Domain_name.Map.fold (fun k (rr_map, kms) acc ->
        match Rr_map.(find Soa rr_map) with
        | Some soa -> Some (Domain_name.raw k, soa, KM.find (K Soa) kms)
        | None -> acc)
      auth None
  with
  | None -> Error (`Msg "no SOA in authority")
  | Some (name, soa, used_name) ->
    if Domain_name.equal name used_name then
      Ok (name, soa)
    else
      Error (`Msg (Fmt.str "SOA owner %a differs from used name %a"
                     Domain_name.pp name Domain_name.pp used_name))

let is_name_in_chain ~soa_name ~name ~owner nsec =
  (* for the last NSEC entry, next_domain is zone itself (thus = soa_name) *)
  let next_owner = (snd nsec).Nsec.next_domain in
  Domain_name.(compare owner name < 0 &&
                  (compare name next_owner < 0 ||
                   compare soa_name next_owner = 0))

let name_in_chain ~soa_name ~name ~owner nsec =
  if is_name_in_chain ~soa_name ~name ~owner nsec then
    Ok ()
  else
    Error (`Msg (Fmt.str "name not in chain: owner %a, name %a, next owner %a (soa %a)"
                   Domain_name.pp owner
                   Domain_name.pp name
                   Domain_name.pp (snd nsec).Nsec.next_domain
                   Domain_name.pp soa_name))

let nsec_chain ~soa_name name auth =
  let matches =
    Domain_name.Map.filter (fun owner rr_map ->
        match Rr_map.find Nsec (fst rr_map) with
        | Some nsec ->
          Log.debug (fun m -> m "is domain name %a in chain %a (to %a)?"
                         Domain_name.pp name Domain_name.pp owner
                         Domain_name.pp (snd nsec).Nsec.next_domain);
          is_name_in_chain ~soa_name ~name ~owner nsec
        | None -> false)
      auth
  in
  if Domain_name.Map.cardinal matches = 1 then
    let owner, rrs = Domain_name.Map.choose matches in
    let nsec = Rr_map.get Nsec (fst rrs) in
    let used_name = KM.find (K Nsec) (snd rrs) in
    if Domain_name.equal used_name owner then
      Ok (owner, nsec)
    else
      Error (`Msg (Fmt.str "used_name %a is not owner %a in NSEC %a"
                     Domain_name.pp used_name Domain_name.pp owner
                     Nsec.pp (snd nsec)))
  else
    Error (`Msg (Fmt.str "couldn't find nsec chain record covering %a in %a"
                   Domain_name.pp name pp_km_name_rr_map auth))

let is_ent name ~owner nsec =
  Domain_name.is_subdomain ~domain:name ~subdomain:(snd nsec).Nsec.next_domain &&
    Domain_name.compare owner name < 0

let wildcard_non_existence ~soa_name name auth =
  Log.debug (fun m -> m "wildcard non-existence %a (soa %a)"
               Domain_name.pp name Domain_name.pp soa_name);
  (* for non-existing wildcard NSEC: its owner must be between
     <name> and <soa_name> *)
  let rec proof_wildcard_absence name =
    Log.debug (fun m -> m "proof_wildcards with %a" Domain_name.pp name);
    if Domain_name.equal soa_name name then
      Ok ()
    else
      match nsec_chain ~soa_name name auth with
      | Ok (owner, nsec) when is_ent name ~owner nsec -> Ok ()
      | _ ->
        let wc_name = Domain_name.(prepend_label_exn (drop_label_exn name) "*") in
        Log.debug (fun m -> m "proof_wildcard_absence %a, wc_name %a"
                     Domain_name.pp name
                     Domain_name.pp wc_name);
        if Domain_name.Map.exists (fun _owner (rr_map, kms) ->
              match Rr_map.find Nsec rr_map with
              | Some nsec ->
                let owner = KM.find (K Nsec) kms in
                is_name_in_chain ~soa_name ~name:wc_name ~owner nsec
              | None -> false)
            auth
        then
          proof_wildcard_absence (Domain_name.drop_label_exn wc_name)
        else
          Error (`Msg (Fmt.str "no denial of existence for %a found"
                         Domain_name.pp wc_name))
  in
  proof_wildcard_absence name

let nsec3_hash salt iterations name =
  let cs_name = Rr_map.canonical_encoded_name name in
  let rec more = function
    | 0 -> Mirage_crypto.Hash.SHA1.digest (Cstruct.append cs_name salt)
    | k -> Mirage_crypto.Hash.SHA1.digest (Cstruct.append (more (k - 1)) salt)
  in
  more iterations

let nsec3_hashed_name salt iterations ~soa_name name =
  let h = nsec3_hash salt iterations name in
  Domain_name.prepend_label_exn soa_name (Base32.encode (Cstruct.to_string h))

let nsec3_rrs auth =
  let nsec3_map =
    (* filter out any non-nsec3 rrs and those where label_count doesn't match *)
    Domain_name.Map.filter (fun name (rr_map, kms) ->
        Rr_map.exists (function
          | B (Nsec3, (_, nsec3)) ->
            begin match nsec3.Nsec3.flags with
              | Some `Opt_out | None -> true
              | Some `Unknown _ -> false
            end
          | _ -> false) rr_map &&
        Domain_name.equal name (KM.find (K Nsec3) kms))
      auth
  in
  if Domain_name.Map.is_empty nsec3_map then
    Error (`Msg "no NSEC3 resource record found")
  else begin
    Log.debug (fun m -> m "nsec3 non-existence %d" (Domain_name.Map.cardinal nsec3_map));
    let Nsec3.{ iterations ; salt ; _ } =
      let _, (rrs, _) = Domain_name.Map.choose nsec3_map in
      snd (Rr_map.get Nsec3 rrs)
    in
    if iterations > 150 then
      Error (`Msg "NSEC3 iterations greater than 150, ignoring")
    else
      Ok (nsec3_map, salt, iterations)
  end

let nsec3_closest_encloser nsec3_map salt iterations ~soa_name name =
  let rec find_it chop name =
    let hashed_name = nsec3_hashed_name ~soa_name salt iterations name in
    match Domain_name.Map.find hashed_name nsec3_map with
    | Some (rrs, _) -> Ok (chop, name, Rr_map.get Nsec3 rrs)
    | None ->
      let* parent = Domain_name.drop_label name in
      let chopped = Domain_name.get_label_exn name 0 in
      find_it chopped parent
  in
  let* (last_chop, closest_encloser, closest_encloser_nsec) = find_it "" name in
  Log.debug (fun m -> m "last chop %s closest encloser %a (hashed %a)"
                last_chop Domain_name.pp closest_encloser
                Domain_name.pp (nsec3_hashed_name ~soa_name salt iterations closest_encloser));
  (* 8.3: DNAME bit must not be set, and NS may only be set if SOA bit is set *)
  (* TODO DNAME *)
  let* () =
    let types = (snd closest_encloser_nsec).Nsec3.types in
    if Bit_map.mem (Rr_map.to_int Ns) types then
      if not (Bit_map.mem (Rr_map.to_int Soa) types) then
        Error (`Msg (Fmt.str "nsec3 with NS but not SOA %a %a"
                       Domain_name.pp closest_encloser
                       Nsec3.pp (snd closest_encloser_nsec)))
      else
        (* RFC 5155 8.9: presence of NS implies absence of DNAME *)
        Ok ()
    else if Bit_map.mem (*DNAME*)39 types then
      Error (`Msg (Fmt.str "nsec3 with DNAME %a %a"
                     Domain_name.pp closest_encloser
                     Nsec3.pp (snd closest_encloser_nsec)))
    else
      Ok ()
  in
  (* verify existence of nsec3 where owner < next_closer < next_owner_hashed *)
  let next_closer = Domain_name.prepend_label_exn closest_encloser last_chop in
  let next_closer_hashed = nsec3_hashed_name ~soa_name salt iterations next_closer in
  Ok (closest_encloser, next_closer, next_closer_hashed)

let nsec3_between nsec3_map ~soa_name hashed_name =
  Log.debug (fun m -> m "nsec3 between %a" Domain_name.pp hashed_name);
  let m =
    Domain_name.Map.filter (fun name (rrs, _) ->
        if Domain_name.compare name hashed_name < 0 then begin
          Log.debug (fun m -> m "(%a) yes %a" Domain_name.pp hashed_name
                        Domain_name.pp name);
          let _, nsec3 = Rr_map.get Nsec3 rrs in
          let hashed_next_owner =
            Domain_name.prepend_label_exn soa_name
              (Base32.encode (Cstruct.to_string nsec3.Nsec3.next_owner_hashed))
          in
          Log.debug (fun m -> m "(%a) comparing with %a: %d"
                        Domain_name.pp hashed_name
                        Domain_name.pp hashed_next_owner
                        (Domain_name.compare hashed_name hashed_next_owner));
          Domain_name.compare hashed_name hashed_next_owner < 0
        end else
          false)
      nsec3_map
  in
  if Domain_name.Map.cardinal m = 1 then
    Ok (Domain_name.Map.choose m)
  else begin
    Log.debug (fun m -> m "nsec3 between %a no" Domain_name.pp hashed_name);
    Error (`Msg (Fmt.str "no NSEC3 with owner < %a < next_owner_hashed"
                   Domain_name.pp hashed_name))
  end

let nsec3_non_existence name ~soa_name auth =
  Log.debug (fun m -> m "nsec3 non-existence %a (zone %a)"
                Domain_name.pp name Domain_name.pp soa_name);
  let* (nsec3_map, salt, iterations) = nsec3_rrs auth in
  let* (closest_encloser, _next_closer, hashed_next_closer) =
    nsec3_closest_encloser nsec3_map salt iterations ~soa_name name
  in
  let* (_, (rrs, _)) = nsec3_between nsec3_map ~soa_name hashed_next_closer in
  let nsec_next_closer = Rr_map.get Nsec3 rrs in
  let opt_out =
    match (snd nsec_next_closer).Nsec3.flags with
    | Some `Opt_out -> true
    | Some `Unknown _ | None -> false
  in
  Log.debug (fun m -> m "next_closer %a proved, opt out %B"
                Domain_name.pp hashed_next_closer opt_out);
  (* TODO 8.5 and 8.6!? *)
  if opt_out then
    Ok nsec_next_closer
  else
    (* verify existence of nsec3 where owner < wc < next_owner_hashed *)
    let wc = Domain_name.prepend_label_exn closest_encloser "*" in
    let hashed_wc = nsec3_hashed_name ~soa_name salt iterations wc in
    let* _ = nsec3_between nsec3_map ~soa_name hashed_wc in
    Ok nsec_next_closer

let nsec3_chain ~soa_name ~wc_name ~name auth =
  Log.debug (fun m -> m "nsec3 chain soa %a wc %a name %a"
                Domain_name.pp soa_name Domain_name.pp wc_name
                Domain_name.pp name);
  let closest_encloser = Domain_name.drop_label_exn wc_name in
  let next_closer =
    let lbl_idx = Domain_name.count_labels closest_encloser in
    let lbl = Domain_name.get_label_exn ~rev:true name lbl_idx in
    Domain_name.prepend_label_exn closest_encloser lbl
  in
  Log.debug (fun m -> m "next_closer %a" Domain_name.pp next_closer);
  let* (nsec3_map, salt, iterations) = nsec3_rrs auth in
  let hashed_next_closer =
    nsec3_hashed_name ~soa_name salt iterations next_closer
  in
  nsec3_between nsec3_map ~soa_name hashed_next_closer

let nsec_non_existence name ~soa_name auth =
  let* _ = nsec_chain ~soa_name name auth in
  wildcard_non_existence ~soa_name name auth

let no_domain name auth =
  (* no domain:
     - a SOA from a parent (zone), plus RRSIG
     - an NSEC for non-existing wildcard, plus rrsig
     - a NSEC <prev domain> .. <next-domain>, plus rrsig
     -> ensure requested_domain is between these domains *)
  let* (soa_name, soa) = find_soa auth in
  let* () =
    if Domain_name.is_subdomain ~subdomain:name ~domain:soa_name then
      Ok ()
    else
      Error (`Msg (Fmt.str "question %a is not subdomain of SOA %a"
                     Domain_name.pp name Domain_name.pp soa_name))
  in
  match
    nsec_non_existence name ~soa_name auth,
    nsec3_non_existence name ~soa_name auth
  with
  | Ok (), _ | _, Ok _ -> Ok (soa_name, soa)
  | Error _ as e, _ -> e

let nsec_no_data ~soa_name name k auth =
  match Domain_name.Map.find name auth with
  | Some (rr_map, kms) when Rr_map.mem Nsec rr_map ->
    let nsec = Rr_map.get Nsec rr_map
    and nsec_owner = KM.find (K Nsec) kms
    in
    let* () =
      if Domain_name.equal nsec_owner name then
        Ok ()
      else
        Error (`Msg (Fmt.str "nsec owner %a is not name %a"
                       Domain_name.pp nsec_owner
                       Domain_name.pp name))
    in
    if Bit_map.mem (Rr_map.to_int k) (snd nsec).Nsec.types then
      Error (`Msg (Fmt.str "nsec claims type %a to be present" Rr_map.ppk (K k)))
    else if Bit_map.mem (Rr_map.to_int Cname) (snd nsec).Nsec.types then
      Error (`Msg (Fmt.str "nsec claims CNAME to be present"))
    else
      Ok ()
  | _ ->
    (* nsec in chain ++ wildcard nsec *)
    let* _ = nsec_chain ~soa_name name auth in
    let rec find_wc name =
      if Domain_name.is_subdomain ~domain:soa_name ~subdomain:name then
        let wc_name = Domain_name.prepend_label_exn name "*" in
        Log.debug (fun m -> m "looking for %a" Domain_name.pp wc_name);
        match Domain_name.Map.find wc_name auth with
        | Some (rr_map, kms) when Rr_map.mem Nsec rr_map ->
          let nsec = Rr_map.get Nsec rr_map
          and nsec_owner = KM.find (K Nsec) kms
          in
          Ok (wc_name, nsec, nsec_owner)
        | _ ->
          let* name = Domain_name.drop_label name in
          find_wc name
      else
        Error (`Msg "no wildcard nsec found")
    in
    match find_wc name with
    | Ok (wc_name, wc_nsec, wc_nsec_owner) ->
      let* () =
        if Domain_name.equal wc_nsec_owner wc_name then
          Ok ()
        else
          Error (`Msg (Fmt.str "bad wildcard nsec, wc_name %a nsec_owner %a"
                         Domain_name.pp wc_name Domain_name.pp wc_nsec_owner))
      in
      if Bit_map.mem (Rr_map.to_int k) (snd wc_nsec).Nsec.types then
        Error (`Msg (Fmt.str "nsec claims type %a to be present" Rr_map.ppk (K k)))
      else
        Ok ()
    | Error _ ->
      wildcard_non_existence ~soa_name name auth

let nsec3_no_data ~soa_name name k auth =
  Log.debug (fun m -> m "nsec3 no data %a (zone %a)"
                Domain_name.pp name Domain_name.pp soa_name);
  let* (nsec3_map, salt, iterations) = nsec3_rrs auth in
  let hashed_name = nsec3_hashed_name ~soa_name salt iterations name in
  match Domain_name.Map.find hashed_name nsec3_map with
  | Some (rr_map, _) ->
    let _, nsec3 = Rr_map.get Nsec3 rr_map in
    if Bit_map.mem (Rr_map.to_int k) nsec3.Nsec3.types then
      Error (`Msg (Fmt.str "nsec3 claims type %a to be present" Rr_map.ppk (K k)))
    else if Bit_map.mem (Rr_map.to_int Cname) nsec3.Nsec3.types then
      Error (`Msg (Fmt.str "nsec3 claims type Cname to be present"))
    else
      Ok ()
  | None ->
    let* (_closest_encloser, _next_closer, hashed_next_closer) =
      nsec3_closest_encloser nsec3_map salt iterations ~soa_name name
    in
    let* (_, (rrs, _)) = nsec3_between nsec3_map ~soa_name hashed_next_closer in
    let nsec_next_closer = Rr_map.get Nsec3 rrs in
    let opt_out =
      match (snd nsec_next_closer).Nsec3.flags with
      | Some `Opt_out -> true
      | Some `Unknown _ | None -> false
    in
    Log.debug (fun m -> m "next_closer %a proved, opt out %B"
                  Domain_name.pp hashed_next_closer opt_out);
    if opt_out then
      Ok ()
    else
      Error (`Msg "no NSEC3, and next_closer has no opt-out")

let no_data name k auth =
  (* no data:
     - SOA + RRSIG
     - (NSEC for name (and not for type = k) OR wildcard NSEC) + RRSIG
  *)
  let* (soa_name, soa) = find_soa auth in
  let* () =
    if Domain_name.is_subdomain ~subdomain:name ~domain:soa_name then
      Ok ()
    else
      Error (`Msg (Fmt.str "name %a is not a subdomain of soa %a"
                     Domain_name.pp name Domain_name.pp soa_name))
  in
  match
    nsec_no_data ~soa_name name k auth,
    nsec3_no_data ~soa_name name k auth
  with
  | Ok (), _ | _, Ok () -> Ok (soa_name, soa)
  | Error _ as e, _ -> e

let has_delegation name_rr_map name =
  let rrs =
    Domain_name.Map.filter (fun owner_name rrs ->
        Domain_name.is_subdomain ~domain:owner_name ~subdomain:name &&
        Rr_map.mem Ns rrs) name_rr_map
  in
  Log.debug (fun m -> m "has_delegation with %d in %a"
                 (Domain_name.Map.cardinal rrs)
                 Name_rr_map.pp name_rr_map);
  if Domain_name.Map.cardinal rrs = 1 then
    Some (Domain_name.Map.choose rrs)
  else
    None

let validate_answer :
  type a. ?signer_name:[`raw] Domain_name.t ->
  [`raw] Domain_name.t -> a Rr_map.rr ->
  (Rr_map.t * [`raw] Domain_name.t KM.t) Domain_name.Map.t ->
  (Rr_map.t * [`raw] Domain_name.t KM.t) Domain_name.Map.t ->
  Name_rr_map.t ->
  (a,
   [> `Cname of [`raw] Domain_name.t
   | `Unsigned_delegation of [`raw] Domain_name.t * Domain_name.Host_set.t
   | `Signed_delegation of [`raw] Domain_name.t * Domain_name.Host_set.t * Rr_map.Ds_set.t
   | `No_data of [`raw] Domain_name.t * Soa.t
   | `Msg of string ]) result =
  fun ?signer_name name k answer auth raw_auth ->
  Log.debug (fun m -> m "validating %a (%a)"
                 Domain_name.pp name Rr_map.ppk (K k));
  match Domain_name.Map.find name answer with
  | None ->
    (* left are two options: no data OR delegation *)
    Option.fold
      ~none:(
        let* (soa_name, soa) = no_data name k auth in
        Log.debug (fun m -> m "validated no data");
        Error (`No_data (soa_name, soa)))
      ~some:(fun (zname, rrs) ->
          let _, ns = Rr_map.get Ns rrs in
          match Domain_name.Map.find zname auth with
          | Some (rrs, kms) when Rr_map.mem Ds rrs ->
            let ds = snd (Rr_map.get Ds rrs) in
            let used_name = KM.find (K Ds) kms in
            if not (Domain_name.equal used_name zname) then
              Error (`Msg (Fmt.str "owner %a of DS %a does not match used name %a"
                             Domain_name.pp zname
                             Fmt.(list ~sep:(any ", ") Ds.pp)
                             (Rr_map.Ds_set.elements ds)
                             Domain_name.pp used_name))
            else
              Error (`Signed_delegation (zname, ns, ds))
          | Some (rrs, kms) when Rr_map.mem Nsec rrs ->
            let nsec = snd (Rr_map.get Nsec rrs) in
            let used_name = KM.find (K Nsec) kms in
            if not (Domain_name.equal used_name zname) then
              Error (`Msg (Fmt.str "owner %a of Nsec %a does not match used name %a"
                             Domain_name.pp zname
                             Nsec.pp nsec
                             Domain_name.pp used_name))
            else if
              (not (Bit_map.mem (Rr_map.to_int Ds) nsec.Nsec.types)) &&
              Bit_map.mem (Rr_map.to_int Ns) nsec.Nsec.types
            then
              Error (`Unsigned_delegation (zname, ns))
            else
              Error (`Msg (Fmt.str "NSEC present for %a (%a), but either has DS or no NS bits"
                             Domain_name.pp zname Nsec.pp nsec))
          | _ ->
            let soa_name = Option.value ~default:Domain_name.root signer_name in
            let* nsec3 = nsec3_non_existence zname ~soa_name auth in
            if (snd nsec3).Nsec3.flags = Some `Opt_out then
              Error (`Unsigned_delegation (zname, ns))
            else
              Error (`Msg (Fmt.str "NSEC3 for closest encloser %a present %a, but not opt-out"
                             Domain_name.pp zname
                             Nsec3.pp (snd nsec3))))
      (has_delegation raw_auth name)
  | Some (rr_map, kms) ->
    let maybe_validate_wildcard_answer k =
      let used_name = KM.find (K k) kms in
      if Domain_name.equal used_name name then
        Ok ()
      else begin
        (* RFC 4035 5.3.4 - verify in authority the wildcard-expanded
           positive reply (no direct match) *)
        (* RFC 5155 8.8 - there's a candidate closest encloser for qname
           (the used_name without "*") - need to verify existence of a nsec3
           covering next_closer name to qname *)
        (match signer_name with
         | None -> Log.warn (fun m -> m "no signer name provided")
         | Some _ -> ());
        let soa_name = Option.value ~default:Domain_name.root signer_name in
        match
          nsec_chain ~soa_name name auth,
          nsec3_chain ~soa_name ~wc_name:used_name ~name auth
        with
        | Ok _, _ | _, Ok _ -> Ok ()
        | Error _ as e, _ -> e
      end
    in
    match Rr_map.find k rr_map with
    | Some rrs ->
      let* () = maybe_validate_wildcard_answer k in
      Ok rrs
    | None ->
      match Rr_map.find Cname rr_map with
      | None ->
        let* (soa_name, soa) = no_data name k auth in
        Log.debug (fun m -> m "validated no data");
        Error (`No_data (soa_name, soa))
      | Some rr ->
        let* () = maybe_validate_wildcard_answer Cname in
        Log.info (fun m -> m "verified CNAME to %a" Domain_name.pp (snd rr));
        Error (`Cname (snd rr))

type err = [
  | `Cname of [ `raw ] Domain_name.t
  | `Unsigned_delegation of [`raw] Domain_name.t * Domain_name.Host_set.t
  | `Signed_delegation of [`raw] Domain_name.t * Domain_name.Host_set.t * Rr_map.Ds_set.t
  | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t
  | `Msg of string
]

let pp_err ppf = function
  | `Cname alias -> Fmt.pf ppf "cname %a" Domain_name.pp alias
  | `Unsigned_delegation (owner, ns) ->
    Fmt.pf ppf "unsigned delegation of %a to %a"
      Domain_name.pp owner
      Fmt.(list ~sep:(any ", ") Domain_name.pp)
      (Domain_name.Host_set.elements ns)
  | `Signed_delegation (owner, ns, ds) ->
    Fmt.pf ppf "signed delegation of %a to %a (DS %a)"
      Domain_name.pp owner
      Fmt.(list ~sep:(any ", ") Domain_name.pp)
      (Domain_name.Host_set.elements ns)
      Fmt.(list ~sep:(any ", ") Ds.pp)
      (Rr_map.Ds_set.elements ds)
  | `No_data (name, soa) ->
    Fmt.pf ppf "no data %a %a" Domain_name.pp name Soa.pp soa
  | `No_domain (name, soa) ->
    Fmt.pf ppf "no domain %a %a" Domain_name.pp name Soa.pp soa
  | `Msg m -> Fmt.pf ppf "error %s" m

let verify_reply : type a. ?fuel:int -> ?follow_cname:bool ->
  Ptime.t -> Rr_map.Dnskey_set.t -> [`raw] Domain_name.t -> a Rr_map.rr ->
  Packet.reply ->
  (a,
   [> `Cname of [ `raw ] Domain_name.t
   | `Unsigned_delegation of [`raw] Domain_name.t * Domain_name.Host_set.t
   | `Signed_delegation of [`raw] Domain_name.t * Domain_name.Host_set.t * Rr_map.Ds_set.t
   | `No_data of [ `raw ] Domain_name.t * Dns.Soa.t
   | `No_domain of [ `raw ] Domain_name.t * Dns.Soa.t
   | `Msg of string ]) result =
  fun ?(fuel = 20) ?(follow_cname = true) now dnskeys name k reply ->
  Log.debug (fun m -> m "verifying %a (%a)"
                 Domain_name.pp name Rr_map.ppk (K k));
  let fold_option a b =
    match a, b with
    | None, None -> None
    | Some a, None -> Some a
    | None, Some b -> Some b
    | Some a, Some b ->
      if not (Domain_name.equal a b) then
        Log.warn (fun m -> m "different signer names %a and %a"
                     Domain_name.pp a Domain_name.pp b);
      Some a
  in
  (* to avoid missing a signature check, and also checking the signature
     multiple times, first verify all signatures in the map *)
  let check_signatures map =
    (* the result is again a map, but with an additional nesting to track the
       used name (wildcard signatures) *)
    Domain_name.Map.fold (fun name rr_map (signer_name, acc) ->
        let _, rrsigs =
          Option.value ~default:(0l, Rr_map.Rrsig_set.empty)
            (Rr_map.find Rrsig rr_map)
        in
        let signer_name, rrs = Rr_map.fold (fun b ((signer_name, (rrs, names)) as acc) ->
            match b with
            | B (Rr_map.Rrsig, _) -> acc
            | B (k, v) ->
              let int = Rr_map.to_int k in
              let rrsigs =
                Rr_map.Rrsig_set.filter
                  (fun rrsig -> rrsig.Rrsig.type_covered = int)
                  rrsigs
              in
              if Rr_map.Rrsig_set.is_empty rrsigs then
                Log.warn (fun m -> m "couldn't find RRSIG for %a %a"
                             Domain_name.pp name Rr_map.pp_b b);
              match validate_rrsig_keys now dnskeys rrsigs name k v with
              | Ok (used_name, signer_name') ->
                let signer = fold_option signer_name (Some signer_name') in
                signer, (Rr_map.add k v rrs, KM.add (Rr_map.K k) used_name names)
              | Error `Msg msg ->
                Log.warn (fun m -> m "RRSIG verification for %a %a failed: %s"
                             Domain_name.pp name Rr_map.pp_b b msg);
                acc) rr_map (signer_name, (Rr_map.empty, KM.empty))
        in
        signer_name,
        if Rr_map.is_empty (fst rrs) then
          acc
        else
          Domain_name.Map.add name rrs acc)
      map (None, Domain_name.Map.empty)
  in
  match reply with
  | `Answer (answer, authority) ->
    let signer_name, signed_answer = check_signatures answer
    and signer_name2, signed_authority = check_signatures authority
    in
    let signer_name = fold_option signer_name signer_name2 in
    begin
      let rec more ~fuel name =
        if fuel = 0 then
          Error (`Msg "too many CNAME redirections")
        else
          match validate_answer ?signer_name name k signed_answer signed_authority authority with
          | Error `Cname other when follow_cname ->
            more ~fuel:(fuel - 1) other
          | r -> r
      in
      more ~fuel name
    end
  | `Rcode_error (NXDomain, Query, Some (answer, authority)) ->
    let signer_name, _answer = check_signatures answer
    and signer_name2, authority = check_signatures authority
    in
    let _signer_name = fold_option signer_name signer_name2 in
    let* (soa_name, soa) = no_domain name authority in
    Error (`No_domain (soa_name, soa))
  | r ->
    Error (`Msg (Fmt.str "unexpected reply: %a" Packet.pp_reply r))
