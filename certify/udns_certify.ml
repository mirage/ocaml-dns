open Udns

let dns_header rng =
  let id = Randomconv.int16 rng in
  (id, Packet.Flags.empty)

let letsencrypt_name name =
  match Domain_name.prepend ~hostname:false name "_tcp" with
  | Ok name' -> Domain_name.prepend ~hostname:false name' "_letsencrypt"
  | Error e -> Error e

type u_err = [ `Tsig of Udns_tsig.e | `Bad_reply of Packet.mismatch * Packet.t | `Unexpected_reply of Packet.reply ]

let pp_u_err ppf = function
  | `Tsig e -> Fmt.pf ppf "tsig error %a" Udns_tsig.pp_e e
  | `Bad_reply (e, res) -> Fmt.pf ppf "bad reply %a: %a" Packet.pp_mismatch e Packet.pp res
  | `Unexpected_reply r -> Fmt.pf ppf "unexpected reply %a" Packet.pp_reply r

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
    let zone = Packet.Question.create zone Soa
    and update =
      let up =
        Domain_name.Map.singleton host
          [
            Packet.Update.Remove (K Tlsa) ;
            Packet.Update.Add (B (Tlsa, (3600l, Rr_map.Tlsa_set.singleton tlsa)))
          ]
      in
      (Domain_name.Map.empty, up)
    and header = dns_header rng
    in
    let packet = Packet.create header zone (`Update update) in
    let now = now () in
    match Udns_tsig.encode_and_sign ~proto:`Tcp packet now dnskey keyname with
    | Error e -> Error (`Msg (Fmt.to_to_string Udns_tsig.pp_s e))
    | Ok (data, mac) ->
      Ok (data, (fun data ->
          match Udns_tsig.decode_and_verify now dnskey keyname ~mac data with
          | Error e -> Error (`Tsig e)
          | Ok (res, _, _) ->
            match Packet.reply_matches_request ~request:packet res with
            | Ok `Update_ack -> Ok ()
            | Ok r -> Error (`Unexpected_reply r)
            | Error e -> Error (`Bad_reply (e, res))))

type q_err = [
  | `Decode of Packet.err
  | `Bad_reply of Packet.mismatch * Packet.t
  | `Unexpected_reply of Packet.reply
  | `No_tlsa
]

let pp_q_err ppf = function
  | `Decode err -> Fmt.pf ppf "decoding failed %a" Packet.pp_err err
  | `Bad_reply (e, res) -> Fmt.pf ppf "bad reply %a: %a" Packet.pp_mismatch e Packet.pp res
  | `Unexpected_reply r -> Fmt.pf ppf "unexpected reply %a" Packet.pp_reply r
  | `No_tlsa -> Fmt.pf ppf "No TLSA record found"

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
    and question = Packet.Question.create host Tlsa
    in
    let request = Packet.create header question `Query in
    let out, _ = Packet.encode `Tcp request
    and react data =
      match Packet.decode data with
      | Error e -> Error (`Decode e)
      | Ok reply ->
        match Packet.reply_matches_request ~request reply with
        | Ok (`Answer (answer, _)) ->
          begin match Name_rr_map.find host Tlsa answer with
            | None -> Error `No_tlsa
            | Some (_, tlsas) ->
              Rr_map.Tlsa_set.(fold (fun tlsa r ->
                  match parse tlsa, r with Some c, _ -> Ok c | None, x -> x)
                  (filter good_tlsa tlsas)
                  (Error `No_tlsa))
          end
        | Ok (`Rcode_error (Rcode.NXDomain, Opcode.Query, _)) -> Error `No_tlsa
        | Ok reply -> Error (`Unexpected_reply reply)
        | Error e -> Error (`Bad_reply (e, reply))
    in
    Ok (out, react)
