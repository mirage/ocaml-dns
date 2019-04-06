open Udns

let dns_header rng =
  let id = Randomconv.int16 rng in
  { Packet.Header.id ; query = true ; operation = Udns_enum.Query ;
    rcode = Udns_enum.NoError ; flags = Packet.Header.FS.empty }

let letsencrypt_name name =
  match Domain_name.prepend ~hostname:false name "_tcp" with
  | Ok name' -> Domain_name.prepend ~hostname:false name' "_letsencrypt"
  | Error e -> Error e

type u_err = [ `Tsig of Udns_tsig.e | `Bad_reply of Packet.res ]

let pp_u_err ppf = function
  | `Tsig e -> Fmt.pf ppf "tsig error %a" Udns_tsig.pp_e e
  | `Bad_reply res -> Fmt.pf ppf "bad reply %a" Packet.pp_res res

let nsupdate rng now ~host ~keyname ~zone dnskey csr =
  match letsencrypt_name host with
  | Error e -> Error e
  | Ok host ->
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
    | Error e -> Error (`Msg (Fmt.to_to_string Udns_tsig.pp_s e))
    | Ok (data, mac) ->
      Ok (data, (fun data ->
          match Udns_tsig.decode_and_verify now dnskey keyname ~mac data with
          | Error e -> Error (`Tsig e)
          | Ok (res, _, _) when Packet.is_reply header zone res -> Ok ()
          | Ok (res, _, _) -> Error (`Bad_reply res)))

type q_err = [
  | `Decode of Udns.Packet.err
  | `Bad_reply of Udns.Packet.res
  | `No_tlsa
  | `Rcode of Udns_enum.rcode
]

let pp_q_err ppf = function
  | `Decode err -> Fmt.pf ppf "decoding failed %a" Packet.pp_err err
  | `Bad_reply res -> Fmt.pf ppf "bad reply %a" Packet.pp_res res
  | `No_tlsa -> Fmt.pf ppf "No TLSA record found"
  | `Rcode r -> Fmt.pf ppf "Received rcode %a" Udns_enum.pp_rcode r

let query rng public_key host =
  match letsencrypt_name host with
  | Error e -> Error e
  | Ok host ->
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
    and question = (host, Udns_enum.TLSA)
    in
    let out, _ = Packet.encode `Tcp header question (`Query Packet.Query.empty)
    and react data =
      match Packet.decode data with
      | Ok ((header, _, `Query (answer, _), _, _, _) as res)
        when Packet.is_reply ~not_error:false header question res ->
        begin match header.Packet.Header.rcode with
          | Udns_enum.NXDomain -> Error `No_tlsa
          | Udns_enum.NoError ->
            (* collect TLSA pems *)
            begin match Name_rr_map.find host Tlsa answer with
              | None -> Error `No_tlsa
              | Some (_, tlsas) ->
                Rr_map.Tlsa_set.(fold (fun tlsa r ->
                    match parse tlsa, r with Some c, _ -> Ok c | None, x -> x)
                    (filter good_tlsa tlsas)
                    (Error `No_tlsa))
            end
          | e -> Error (`Rcode e)
        end
      | Ok res -> Error (`Bad_reply res)
      | Error e -> Error (`Decode e)
    in
    Ok (out, react)
