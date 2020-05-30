open Dns

let src = Logs.Src.create "dns_certify" ~doc:"DNS certify"
module Log = (val Logs.src_log src : Logs.LOG)

let tlsa_is usage sel typ t =
  t.Tlsa.cert_usage = usage &&
  t.Tlsa.selector = sel &&
  t.Tlsa.matching_type = typ

let is_csr t =
  tlsa_is Tlsa.Domain_issued_certificate Tlsa.Private Tlsa.No_hash t

let csr req =
  let data = X509.Signing_request.encode_der req in
  {
    Tlsa.matching_type = Tlsa.No_hash ;
    cert_usage = Tlsa.Domain_issued_certificate ;
    selector = Tlsa.Private ;
    data
  }

let is_certificate t =
  tlsa_is Tlsa.Domain_issued_certificate Tlsa.Full_certificate Tlsa.No_hash t

let certificate cert =
  let data = X509.Certificate.encode_der cert in
  {
    Tlsa.matching_type = Tlsa.No_hash ;
    cert_usage = Tlsa.Domain_issued_certificate ;
    selector = Tlsa.Full_certificate ;
    data
  }

let is_ca_certificate t =
  tlsa_is Tlsa.CA_constraint Tlsa.Full_certificate Tlsa.No_hash t

let ca_certificate data = {
  Tlsa.matching_type = Tlsa.No_hash ;
  cert_usage = Tlsa.CA_constraint ;
  selector = Tlsa.Full_certificate ;
  data
}

let signing_request hostname ?(more_hostnames = []) key =
  let host = Domain_name.to_string hostname in
  let extensions =
    match more_hostnames with
    | [] -> X509.Signing_request.Ext.empty
    | _ ->
      let ext =
        let additional = List.map Domain_name.to_string more_hostnames in
        let gn = X509.General_name.(singleton DNS (host :: additional)) in
        X509.Extension.(singleton Subject_alt_name (false, gn))
      in
      X509.Signing_request.Ext.(singleton Extensions ext)
  in
  X509.(Signing_request.create
          [Distinguished_name.(Relative_distinguished_name.singleton (CN host))]
          ~extensions key)

let dns_header rng =
  let id = Randomconv.int16 rng in
  (id, Packet.Flags.empty)

let le_label = "_letsencrypt"
and p_label = "_tcp"

let is_name name =
  if Domain_name.count_labels name < 2 then
    false
  else
    Domain_name.(equal_label le_label (get_label_exn name 0) &&
                 equal_label p_label (get_label_exn name 1))

let letsencrypt_name name =
  match Domain_name.(prepend_label (raw name) p_label) with
  | Ok name' -> Domain_name.prepend_label name' le_label
  | Error e -> Error e

type u_err = [ `Tsig of Dns_tsig.e | `Bad_reply of Packet.mismatch * Packet.t | `Unexpected_reply of Packet.reply ]

let pp_u_err ppf = function
  | `Tsig e -> Fmt.pf ppf "tsig error %a" Dns_tsig.pp_e e
  | `Bad_reply (e, res) -> Fmt.pf ppf "bad reply %a: %a" Packet.pp_mismatch e Packet.pp res
  | `Unexpected_reply r -> Fmt.pf ppf "unexpected reply %a" Packet.pp_reply r

let nsupdate rng now ~host ~keyname ~zone dnskey request =
  match letsencrypt_name host with
  | Error e -> Error e
  | Ok host ->
    let tlsa = csr request in
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
    match Dns_tsig.encode_and_sign ~proto:`Tcp packet now dnskey keyname with
    | Error e -> Error (`Msg (Fmt.to_to_string Dns_tsig.pp_s e))
    | Ok (data, mac) ->
      Ok (data, (fun data ->
          match Dns_tsig.decode_and_verify now dnskey keyname ~mac data with
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

(* may be better suited in X509? *)
let cert_matches_csr ?until now csr cert =
  let until = match until with None -> now | Some x -> x in
  let csr_key = X509.Signing_request.((info csr).public_key)
  and csr_hostnames = X509.Signing_request.hostnames csr
  and cert_key = X509.Certificate.public_key cert
  and cert_hostnames = X509.Certificate.hostnames cert
  and (st, en) = X509.Certificate.validity cert
  in
  let valid = Ptime.is_later ~than:st now && Ptime.is_later ~than:until en in
  if not (Cstruct.equal (X509.Public_key.id cert_key) (X509.Public_key.id csr_key)) then begin
    Log.info (fun m -> m "public key of CSR and certificate %a do not match"
                 X509.Certificate.pp cert);
    false
  end else if not (X509.Host.Set.equal cert_hostnames csr_hostnames) then begin
    Log.info (fun m -> m "hostnames of CSR %a and certificate %a do not match"
                 X509.Host.Set.pp csr_hostnames X509.Host.Set.pp cert_hostnames);
    false
  end else if not valid then begin
    let pp_pt = Ptime.pp_rfc3339 () in
    Log.info (fun m -> m "Certificate is not valid now %a (until %a), it is \
                          valid from %a until %a)"
                 pp_pt now pp_pt until pp_pt st pp_pt en);
    false
  end else
    true

let tlsas_to_certchain host now csr tlsas =
  let certificates, ca_certificates =
    Rr_map.Tlsa_set.fold (fun tlsa (certs, cacerts as acc) ->
        if is_certificate tlsa || is_ca_certificate tlsa then
          match X509.Certificate.decode_der tlsa.Tlsa.data with
          | Error (`Msg msg) ->
            Log.warn (fun m -> m "couldn't decode tlsa record %a: %s (%a)"
                         Domain_name.pp host msg
                         Cstruct.hexdump_pp tlsa.Tlsa.data);
            acc
          | Ok cert ->
            match is_certificate tlsa, is_ca_certificate tlsa with
            | true, _ -> (cert :: certs, cacerts)
            | _, true -> (certs, cert :: cacerts)
            | _ -> acc
        else acc)
      tlsas ([], [])
  in
  match List.find_opt (cert_matches_csr now csr) certificates with
  | None -> Error `No_tlsa
  | Some server_cert ->
    match List.rev (X509.Validation.build_paths server_cert ca_certificates) with
    | (_server :: chain) :: _ -> Ok (server_cert, chain)
    | _ -> Ok (server_cert, []) (* build_paths always returns the server_cert *)

let query rng now host csr =
  match letsencrypt_name host with
  | Error e -> Error e
  | Ok host ->
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
            | Some (_, tlsas) -> tlsas_to_certchain host now csr tlsas
          end
        | Ok (`Rcode_error (Rcode.NXDomain, Opcode.Query, _)) -> Error `No_tlsa
        | Ok reply -> Error (`Unexpected_reply reply)
        | Error e -> Error (`Bad_reply (e, reply))
    in
    Ok (out, react)
