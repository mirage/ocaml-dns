open Udns

let dns_header rng =
  let id = Randomconv.int16 rng in
  { Packet.Header.id ; query = true ; operation = Udns_enum.Query ;
    rcode = Udns_enum.NoError ; flags = Packet.Header.FS.empty }

let nsupdate rng now ~host ~keyname ~zone dnskey csr =
  let tlsa =
    { Tlsa.cert_usage = Domain_issued_certificate ;
      selector = Private ;
      matching_type = No_hash ;
      data = X509.Encoding.cs_of_signing_request csr ;
    }
  in
  let zone = (zone, Udns_enum.SOA)
  and update =
    let up =
      Domain_name.Map.singleton host
        [
          Packet.Update.Remove Udns_enum.TLSA ;
          Packet.Update.Add Rr_map.(B (Tlsa, (600l, Tlsa_set.singleton tlsa)))
        ]
    in
    (Domain_name.Map.empty, up)
  and header =
    let hdr = dns_header rng in
    { hdr with Packet.Header.operation = Udns_enum.Update }
  in
  let now = now () in
  match Udns_tsig.encode_and_sign ~proto:`Tcp header zone (`Update update) now dnskey keyname with
  | Ok (data, mac) ->
    Ok (data, (fun data ->
        match Udns_tsig.decode_and_verify now dnskey keyname ~mac data with
        | Error e -> Error e
        | Ok (res, _, _) when Packet.is_reply header zone res -> Ok ()
        | Ok (res, _, _) ->
          Error (Fmt.strf "nsupdate invalid reply %a" Packet.pp_res res)))
  | Error e -> Error e

let query rng public_key fqdn =
  let good_tlsa tlsa =
    tlsa.Tlsa.cert_usage = Domain_issued_certificate
    && tlsa.selector = Full_certificate
    && tlsa.matching_type = No_hash
  in
  let parse tlsa =
    match X509.Encoding.parse tlsa.Tlsa.data with
    | Some cert ->
      let keys_equal a b = Cstruct.equal (X509.key_id a) (X509.key_id b) in
      if keys_equal (X509.public_key cert) public_key then
        Some cert
      else
        None
    | _ -> None
  in
  let header = dns_header rng
  and question = (fqdn, Udns_enum.TLSA)
  in
  let out, _ = Packet.encode `Tcp header question (`Query Packet.Query.empty)
  and react data =
    match Packet.decode data with
    | Ok ((_, _, `Query (answer, _), _, _, _) as res)
      when Packet.is_reply header question res ->
      (* collect TLSA pems *)
      begin match Name_rr_map.find fqdn Tlsa answer with
        | None -> Error "no TLSA records found"
        | Some (_, tlsas) ->
          Rr_map.Tlsa_set.(fold (fun tlsa r ->
              match parse tlsa, r with Some c, _ -> Ok c | None, x -> x)
              (filter good_tlsa tlsas)
              (Error "no matching record found"))
      end
    | Ok res ->
      Error (Fmt.strf "expected a response, but got %a" Packet.pp_res res)
    | Error e ->
      Error (Fmt.strf "error %a while decoding answer" Packet.pp_err e)
  in
  (out, react)
