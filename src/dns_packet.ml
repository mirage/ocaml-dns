(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult.R.Infix

type proto = [ `Tcp | `Udp ]

(*BISECT-IGNORE-BEGIN*)
let pp_err ppf = function
  | #Dns_name.err as e -> Dns_name.pp_err ppf e
  | `BadTTL x -> Fmt.pf ppf "bad ttl %lu" x
  | `BadRRTyp x -> Fmt.pf ppf "bad rr typ %u" x
  | `DisallowedRRTyp x -> Fmt.pf ppf "disallowed rr typ %a" Dns_enum.pp_rr_typ x
  | `BadClass x -> Fmt.pf ppf "bad rr class %u" x
  | `DisallowedClass x -> Fmt.pf ppf "disallowed rr class %a" Dns_enum.pp_clas x
  | `UnsupportedClass x -> Fmt.pf ppf "unsupported rr class %a" Dns_enum.pp_clas x
  | `BadOpcode x -> Fmt.pf ppf "bad opcode %u" x
  | `UnsupportedOpcode x -> Fmt.pf ppf "unsupported opcode %a" Dns_enum.pp_opcode x
  | `BadRcode x -> Fmt.pf ppf "bad rcode %u" x
  | `BadCaaTag -> Fmt.string ppf "bad CAA tag"
  | `LeftOver -> Fmt.string ppf "leftover"
  | `NonZeroTTL ttl -> Fmt.pf ppf "TTL is %lu, must be 0" ttl
  | `NonZeroRdlen rdl -> Fmt.pf ppf "rdlen is %u, must be 0" rdl
  | `InvalidZoneCount x -> Fmt.pf ppf "invalid zone count %u, must be 0" x
  | `InvalidZoneRR typ -> Fmt.pf ppf "invalid zone typ %a, must be SOA" Dns_enum.pp_rr_typ typ
  | `InvalidTimestamp ts -> Fmt.pf ppf "invalid timestamp %Lu in TSIG" ts
  | `InvalidAlgorithm n -> Fmt.pf ppf "invalid algorithm %a" Domain_name.pp n
  | `BadProto num -> Fmt.pf ppf "bad protocol %u" num
  | `BadAlgorithm num -> Fmt.pf ppf "bad algorithm %u" num
  | `BadOpt -> Fmt.pf ppf "bad option"
  | `BadKeepalive -> Fmt.pf ppf "bad keepalive"
  | `BadTlsaCertUsage usage -> Fmt.pf ppf "bad TLSA cert usage %u" usage
  | `BadTlsaSelector selector -> Fmt.pf ppf "bad TLSA selector %u" selector
  | `BadTlsaMatchingType matching_type -> Fmt.pf ppf "bad TLSA matching type %u" matching_type
  | `BadSshfpAlgorithm i -> Fmt.pf ppf "bad SSHFP algorithm %u" i
  | `BadSshfpType i -> Fmt.pf ppf "bad SSHFP type %u" i
  | `Bad_edns_version i -> Fmt.pf ppf "bad edns version %u" i
  | `Multiple_tsig -> Fmt.string ppf "multiple TSIG"
  | `Multiple_edns -> Fmt.string ppf "multiple EDNS"
  | `Tsig_not_last -> Fmt.string ppf "TSIG not last"
(*BISECT-IGNORE-END*)

let guard p err = if p then Ok () else Error err


(* HEADER *)
let hdr_len = 12

type header = {
  id : int ;
  query : bool ;
  operation : Dns_enum.opcode ;
  authoritative : bool ;
  truncation : bool ;
  recursion_desired : bool ;
  recursion_available : bool ;
  authentic_data : bool ;
  checking_disabled : bool ;
  rcode : Dns_enum.rcode ;
}

let decode_flags hdr high low =
  let authoritative = if high land 0x04 > 0 then true else false
  and truncation = if high land 0x02 > 0 then true else false
  and recursion_desired = if high land 0x01 > 0 then true else false
  and recursion_available = if low land 0x80 > 0 then true else false
  and authentic_data = if low land 0x20 > 0 then true else false
  and checking_disabled = if low land 0x10 > 0 then true else false
  in
  { hdr with authoritative ; truncation ; recursion_desired ;
             recursion_available ; authentic_data ; checking_disabled }

let encode_flags hdr h l =
  let h =
    let h = if hdr.authoritative then h lor 0x04 else h in
    let h = if hdr.truncation then h lor 0x02 else h in
    if hdr.recursion_desired then h lor 0x01 else h
  and l =
    let l = if hdr.recursion_available then l lor 0x80 else l in
    let l = if hdr.authentic_data then l lor 0x20 else l in
    if hdr.checking_disabled then l lor 0x10 else l
  in
  (h, l)

(* header is:
bit 0  QR - 0 for query, 1 for response
bit 1 - 4 operation
bit 5  AA Authoritative Answer [RFC1035]                             \
bit 6  TC Truncated Response   [RFC1035]                             |
bit 7  RD Recursion Desired    [RFC1035]                             |
bit 8  RA Recursion Available  [RFC1035]                             |-> flags
bit 9     Reserved                                                   |
bit 10 AD Authentic Data       [RFC4035][RFC6840][RFC Errata 4924]   |
bit 11 CD Checking Disabled    [RFC4035][RFC6840][RFC Errata 4927]   /
bit 12-15 rcode *)

let decode_header buf =
  (* we only access the first 4 bytes, but anything <12 is a bad DNS frame *)
  guard (Cstruct.len buf >= hdr_len) `Partial >>= fun () ->
  let high = Cstruct.get_uint8 buf 2
  and low = Cstruct.get_uint8 buf 3
  in
  let op = (high land 0x78) lsr 3
  and rc = low land 0x0F
  in
  match Dns_enum.int_to_opcode op, Dns_enum.int_to_rcode rc with
  | None, _ -> Error (`BadOpcode op)
  | _, None -> Error (`BadRcode rc)
  | Some operation, Some rcode ->
    let id = Cstruct.BE.get_uint16 buf 0
    and query = high lsr 7 = 0
    in
    let hdr = { id ; query ; operation ; rcode ; authoritative = false ;
                truncation = false ; recursion_desired = false ;
                recursion_available = false ; authentic_data = false ;
                checking_disabled = false }
    in
    let hdr = decode_flags hdr high low in
    Ok hdr

let encode_header buf hdr =
  let h = if hdr.query then 0 else 0x80
  and l = 0
  in
  let h, l = encode_flags hdr h l in
  let h = ((Dns_enum.opcode_to_int hdr.operation) lsl 3) lor h
  and l = ((Dns_enum.rcode_to_int hdr.rcode) land 0xF) lor l
  in
  Cstruct.BE.set_uint16 buf 0 hdr.id ;
  Cstruct.set_uint8 buf 2 h ;
  Cstruct.set_uint8 buf 3 l

(*BISECT-IGNORE-BEGIN*)
let pp_header ppf hdr =
  let flags =
    (if hdr.authoritative then ["authoritative"] else []) @
    (if hdr.truncation then ["truncated"] else []) @
    (if hdr.recursion_desired then ["recursion desired"] else []) @
    (if hdr.recursion_available then ["recursion available"] else []) @
    (if hdr.authentic_data then ["authentic data"] else []) @
    (if hdr.checking_disabled then ["checking disabled"] else [])
  in
  Fmt.pf ppf "%04X %s operation %a rcode %a flags: %a"
    hdr.id (if hdr.query then "query" else "response")
    Dns_enum.pp_opcode hdr.operation
    Dns_enum.pp_rcode hdr.rcode
    (Fmt.list ~sep:(Fmt.unit ",@ ") Fmt.string) flags
(*BISECT-IGNORE-END*)


(* RESOURCE RECORD *)
let decode_ntc names buf off =
  Dns_name.decode ~hostname:false names buf off >>= fun (name, names, off) ->
  guard (Cstruct.len buf >= 4 + off) `Partial >>= fun () ->
  let typ = Cstruct.BE.get_uint16 buf off
  and cls = Cstruct.BE.get_uint16 buf (off + 2)
  (* CLS is interpreted differently by OPT, thus no int_to_clas called here *)
  in
  match Dns_enum.int_to_rr_typ typ with
  | None -> Error (`BadRRTyp typ)
  | Some Dns_enum.TLSA when Domain_name.is_service name ->
    Ok ((name, Dns_enum.TLSA, cls), names, off + 4)
  | Some Dns_enum.SRV when Domain_name.is_service name ->
    Ok ((name, Dns_enum.SRV, cls), names, off + 4)
  | Some Dns_enum.SRV ->
    Error (`BadContent (Domain_name.to_string name))
  | Some (Dns_enum.DNSKEY | Dns_enum.TSIG | Dns_enum.TXT as t) ->
    Ok ((name, t, cls),names, off + 4)
  | Some t when Domain_name.is_hostname name ->
    Ok ((name, t, cls), names, off + 4)
  | Some _ -> Error (`BadContent (Domain_name.to_string name))

let encode_ntc offs buf off (n, t, c) =
  let offs, off = Dns_name.encode offs buf off n in
  Cstruct.BE.set_uint16 buf off (Dns_enum.rr_typ_to_int t) ;
  Cstruct.BE.set_uint16 buf (off + 2) c ;
  (offs, off + 4)

type question = {
  q_name : Domain_name.t ;
  q_type : Dns_enum.rr_typ ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_question ppf q =
  Fmt.pf ppf "%a %a?" Domain_name.pp q.q_name Dns_enum.pp_rr_typ q.q_type
(*BISECT-IGNORE-END*)

let decode_question names buf off =
  decode_ntc names buf off >>= fun ((q_name, q_type, c), names, off) ->
  match Dns_enum.int_to_clas c with
  | None -> Error (`BadClass c)
  | Some Dns_enum.IN -> Ok ({ q_name ; q_type }, names, off)
  | Some x -> Error (`UnsupportedClass x)

let encode_question offs buf off q =
  encode_ntc offs buf off (q.q_name, q.q_type, Dns_enum.clas_to_int Dns_enum.IN)

let enc_character_str buf off s =
  let l = String.length s in
  Cstruct.set_uint8 buf off l ;
  Cstruct.blit_from_string s 0 buf (succ off) l ;
  off + l + 1

let dec_character_str buf off =
  let l = Cstruct.get_uint8 buf off in
  let data = Cstruct.to_string (Cstruct.sub buf (succ off) l) in
  (data, off + l + 1)

type soa = {
  nameserver : Domain_name.t ;
  hostmaster : Domain_name.t ;
  serial : int32 ;
  refresh : int32 ;
  retry : int32 ;
  expiry : int32 ;
  minimum : int32 ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_soa ppf soa =
  Fmt.pf ppf "SOA %a %a %lu %lu %lu %lu %lu"
    Domain_name.pp soa.nameserver Domain_name.pp soa.hostmaster
    soa.serial soa.refresh soa.retry soa.expiry soa.minimum
(*BISECT-IGNORE-END*)

let andThen v f = match v with 0 -> f | x -> x

let compare_soa soa soa' =
  andThen (compare soa.serial soa.serial)
    (andThen (Domain_name.compare soa.nameserver soa'.nameserver)
       (andThen (Domain_name.compare soa.hostmaster soa'.hostmaster)
          (andThen (compare soa.refresh soa'.refresh)
             (andThen (compare soa.retry soa'.retry)
                (andThen (compare soa.expiry soa'.expiry)
                   (compare soa.minimum soa'.minimum))))))

(* TODO: not clear whether this is a good idea, or just reuse nocrypto's polyvars *)
type tsig_algo =
  | SHA1
  | SHA224
  | SHA256
  | SHA384
  | SHA512

type tsig = {
  algorithm : tsig_algo ;
  signed : Ptime.t ;
  fudge : Ptime.Span.t ;
  mac : Cstruct.t ;
  original_id : int ; (* again 16 bit *)
  error : Dns_enum.rcode ;
  other : Ptime.t option
}

let algo_to_name, algo_of_name =
  let of_s = Domain_name.of_string_exn in
  let map =
    [ (* of_s "HMAC-MD5.SIG-ALG.REG.INT", MD5 ; *)
      of_s "hmac-sha1", SHA1 ;
      of_s "hmac-sha224", SHA224 ;
      of_s "hmac-sha256", SHA256 ;
      of_s "hmac-sha384", SHA384 ;
      of_s "hmac-sha512", SHA512 ]
  in
  (fun a -> fst (List.find (fun (_, t) -> t = a) map)),
  (fun b ->
     try Some (snd (List.find (fun (n, _) -> Domain_name.equal b n) map))
     with Not_found -> None)

(*BISECT-IGNORE-BEGIN*)
let pp_tsig_algo ppf a = Domain_name.pp ppf (algo_to_name a)
(*BISECT-IGNORE-END*)

(* this is here because I don't like float, and rather convert Ptime.t to int64 *)
let s_in_d = 86_400L
let ps_in_s = 1_000_000_000_000L

let ptime_span_to_int64 ts =
  let d_min, d_max = Int64.(div min_int s_in_d, div max_int s_in_d) in
  let d, ps = Ptime.Span.to_d_ps ts in
  let d = Int64.of_int d in
  if d < d_min || d > d_max then
    None
  else
    let s = Int64.mul d s_in_d in
    let s' = Int64.(add s (div ps ps_in_s)) in
    if s' < s then
      None
    else
      Some s'

let ptime_of_int64 s =
  let d, ps = Int64.(div s s_in_d, mul (rem s s_in_d) ps_in_s) in
  if d < Int64.of_int min_int || d > Int64.of_int max_int then
    None
  else
    Some (Ptime.v (Int64.to_int d, ps))

let valid_time now tsig =
  let ts = tsig.signed
  and fudge = tsig.fudge
  in
  match Ptime.add_span now fudge, Ptime.sub_span now fudge with
  | None, _ -> false
  | _, None -> false
  | Some late, Some early ->
    Ptime.is_earlier ts ~than:late && Ptime.is_later ts ~than:early

let tsig ~algorithm ~signed ?(fudge = Ptime.Span.of_int_s 300)
    ?(mac = Cstruct.create 0) ?(original_id = 0) ?(error = Dns_enum.NoError)
    ?other () =
  match ptime_span_to_int64 (Ptime.to_span signed), ptime_span_to_int64 fudge with
  | None, _ | _, None -> None
  | Some ts, Some fu ->
    if
      Int64.logand 0xffff_0000_0000_0000L ts = 0L &&
      Int64.logand 0xffff_ffff_ffff_0000L fu = 0L
    then
      Some { algorithm ; signed ; fudge ; mac ; original_id ; error ; other }
    else
      None

let with_mac tsig mac = { tsig with mac }

let with_error tsig error = { tsig with error }

let with_signed tsig signed =
  match ptime_span_to_int64 (Ptime.to_span signed) with
  | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
    Some { tsig with signed }
  | _ -> None

let with_other tsig other =
  match other with
  | None -> Some { tsig with other }
  | Some ts ->
    match ptime_span_to_int64 (Ptime.to_span ts) with
    | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
      Some { tsig with other }
    | _ -> None

(*BISECT-IGNORE-BEGIN*)
let pp_tsig ppf t =
  Fmt.pf ppf
    "TSIG %a signed %a fudge %a mac %a original id %04X err %a other %a"
    pp_tsig_algo t.algorithm
    (Ptime.pp_rfc3339 ()) t.signed Ptime.Span.pp t.fudge
    Cstruct.hexdump_pp t.mac t.original_id Dns_enum.pp_rcode t.error
    Fmt.(option ~none:(unit "none") (Ptime.pp_rfc3339 ())) t.other
(*BISECT-IGNORE-END*)

let decode_48bit_time buf off =
  let a = Cstruct.BE.get_uint16 buf off
  and b = Cstruct.BE.get_uint16 buf (off + 2)
  and c = Cstruct.BE.get_uint16 buf (off + 4)
  in
  Int64.(add
           (add (shift_left (of_int a) 32) (shift_left (of_int b) 16))
           (of_int c))

let decode_tsig names buf off =
  let l = Cstruct.len buf in
  Dns_name.decode ~hostname:false names buf off >>= fun (algorithm, names, off) ->
  guard (l > off + 10) `Partial >>= fun () ->
  let signed = decode_48bit_time buf off
  and fudge = Cstruct.BE.get_uint16 buf (off + 6)
  and mac_len = Cstruct.BE.get_uint16 buf (off + 8)
  in
  guard (l >= off + 10 + mac_len + 6) `Partial >>= fun () ->
  let mac = Cstruct.sub buf (off + 10) mac_len
  and original_id = Cstruct.BE.get_uint16 buf (off + 10 + mac_len)
  and error = Cstruct.BE.get_uint16 buf (off + 12 + mac_len)
  and other_len = Cstruct.BE.get_uint16 buf (off + 14 + mac_len)
  in
  guard (l = off + 10 + mac_len + 6 + other_len && (other_len = 0 || other_len = 6))
    `Partial >>= fun () ->
  match algo_of_name algorithm, ptime_of_int64 signed, Dns_enum.int_to_rcode error with
  | None, _, _ -> Error (`InvalidAlgorithm algorithm)
  | _, None, _ -> Error (`InvalidTimestamp signed)
  | _, _, None -> Error (`BadRcode error)
  | Some algorithm, Some signed, Some error ->
    (if other_len = 0 then
       Ok None
     else
       let other = decode_48bit_time buf (off + 16 + mac_len) in
       match ptime_of_int64 other with
       | None -> Error (`InvalidTimestamp other)
       | Some x -> Ok (Some x)) >>= fun other ->
    let fudge = Ptime.Span.of_int_s fudge in
    Ok ({ algorithm ; signed ; fudge ; mac ; original_id ; error ; other },
        names,
        off + 16 + mac_len + other_len)

let encode_48bit_time buf ?(off = 0) ts =
  match ptime_span_to_int64 (Ptime.to_span ts) with
  | None ->
    Logs.warn (fun m -> m "couldn't convert (to_span %a) to int64" Ptime.pp ts)
  | Some secs ->
    if Int64.logand secs 0xffff_0000_0000_0000L > 0L then
      Logs.warn (fun m -> m "secs %Lu > 48 bit" secs)
    else
      let a, b, c =
        let f s = Int64.(to_int (logand 0xffffL (shift_right secs s))) in
        f 32, f 16, f 0
      in
      Cstruct.BE.set_uint16 buf off a ;
      Cstruct.BE.set_uint16 buf (off + 2) b ;
      Cstruct.BE.set_uint16 buf (off + 4) c

let encode_16bit_time buf ?(off = 0) ts =
  match ptime_span_to_int64 ts with
  | None ->
    Logs.warn (fun m -> m "couldn't convert span %a to int64" Ptime.Span.pp ts)
  | Some secs ->
    if Int64.logand secs 0xffff_ffff_ffff_0000L > 0L then
      Logs.warn (fun m -> m "secs %Lu > 16 bit" secs)
    else
      let a = Int64.(to_int (logand 0xffffL secs)) in
      Cstruct.BE.set_uint16 buf off a

let encode_tsig t offs buf off =
  let algo = algo_to_name t.algorithm in
  let offs, off = Dns_name.encode ~compress:false offs buf off algo in
  encode_48bit_time buf ~off t.signed ;
  encode_16bit_time buf ~off:(off + 6) t.fudge ;
  let mac_len = Cstruct.len t.mac in
  Cstruct.BE.set_uint16 buf (off + 8) mac_len ;
  Cstruct.blit t.mac 0 buf (off + 10) mac_len ;
  Cstruct.BE.set_uint16 buf (off + 10 + mac_len) t.original_id ;
  Cstruct.BE.set_uint16 buf (off + 12 + mac_len) (Dns_enum.rcode_to_int t.error) ;
  let other_len = match t.other with None -> 0 | Some _ -> 6 in
  Cstruct.BE.set_uint16 buf (off + 14 + mac_len) other_len ;
  (match t.other with
   | None -> ()
   | Some t -> encode_48bit_time buf ~off:(off + 16 + mac_len) t) ;
  offs, off + 16 + mac_len + other_len

let canonical_name name =
  let buf = Cstruct.create 255
  and emp = Domain_name.Map.empty
  and nam = Domain_name.canonical name
  in
  let _, off = Dns_name.encode ~compress:false emp buf 0 nam in
  Cstruct.sub buf 0 off

let encode_raw_tsig_base name t =
  let name = canonical_name name
  and aname = canonical_name (algo_to_name t.algorithm)
  in
  let clttl = Cstruct.create 6 in
  Cstruct.BE.set_uint16 clttl 0 Dns_enum.(clas_to_int ANY_CLASS) ;
  Cstruct.BE.set_uint32 clttl 2 0l ;
  let time = Cstruct.create 8 in
  encode_48bit_time time t.signed ;
  encode_16bit_time time ~off:6 t.fudge ;
  let other =
    let buf = match t.other with
      | None ->
        let buf = Cstruct.create 4 in
        Cstruct.BE.set_uint16 buf 2 0 ;
        buf
      | Some t ->
        let buf = Cstruct.create 10 in
        Cstruct.BE.set_uint16 buf 2 6 ;
        encode_48bit_time buf ~off:4 t ;
        buf
    in
    Cstruct.BE.set_uint16 buf 0 (Dns_enum.rcode_to_int t.error) ;
    buf
  in
  name, clttl, [ aname ; time ], other

let encode_raw_tsig name t =
  let name, clttl, mid, fin = encode_raw_tsig_base name t in
  Cstruct.concat (name :: clttl :: mid @ [ fin ])

let encode_full_tsig name t =
  let name, clttl, mid, fin = encode_raw_tsig_base name t in
  let typ =
    let typ = Cstruct.create 2 in
    Cstruct.BE.set_uint16 typ 0 Dns_enum.(rr_typ_to_int TSIG) ;
    typ
  and mac =
    let len = Cstruct.len t.mac in
    let l = Cstruct.create 2 in
    Cstruct.BE.set_uint16 l 0 len ;
    let orig = Cstruct.create 2 in
    Cstruct.BE.set_uint16 orig 0 t.original_id ;
    [ l ; t.mac ; orig ]
  in
  let rdata = Cstruct.concat (mid @ mac @ [ fin ]) in
  let len =
    let buf = Cstruct.create 2 in
    Cstruct.BE.set_uint16 buf 0 (Cstruct.len rdata) ;
    buf
  in
  Cstruct.concat [ name ; typ ; clttl ; len ; rdata ]

type dnskey = {
  flags : int ; (* uint16 *)
  key_algorithm :  Dns_enum.dnskey ; (* u_int8_t *)
  key : Cstruct.t ;
}

let compare_dnskey a b =
  andThen (compare a.key_algorithm b.key_algorithm)
    (Cstruct.compare a.key b.key)

let dnskey_to_tsig_algo key =
  match key.key_algorithm with
  | Dns_enum.MD5 -> None
  | Dns_enum.SHA1 -> Some SHA1
  | Dns_enum.SHA224 -> Some SHA224
  | Dns_enum.SHA256 -> Some SHA256
  | Dns_enum.SHA384 -> Some SHA384
  | Dns_enum.SHA512 -> Some SHA512

(*BISECT-IGNORE-BEGIN*)
let pp_dnskey ppf t =
  Fmt.pf ppf
    "DNSKEY flags %u algo %a key %a"
    t.flags Dns_enum.pp_dnskey t.key_algorithm
    Cstruct.hexdump_pp t.key
(*BISECT-IGNORE-END*)

let dnskey_of_string key =
  let parse flags algo key =
    let key = Cstruct.of_string key in
    match Dns_enum.string_to_dnskey algo with
    | None -> None
    | Some key_algorithm -> Some { flags ; key_algorithm ; key }
  in
  match Astring.String.cuts ~sep:":" key with
  | [ flags ; algo ; key ] ->
    begin match try Some (int_of_string flags) with Failure _ -> None with
      | Some flags -> parse flags algo key
      | None -> None
    end
  | [ algo ; key ] -> parse 0 algo key
  | _ -> None

let decode_dnskey names buf off =
  let flags = Cstruct.BE.get_uint16 buf off
  and proto = Cstruct.get_uint8 buf (off + 2)
  and algo = Cstruct.get_uint8 buf (off + 3)
  in
  guard (proto = 3) (`BadProto proto) >>= fun () ->
  match Dns_enum.int_to_dnskey algo with
  | None -> Error (`BadAlgorithm algo)
  | Some key_algorithm ->
    let len = Dns_enum.dnskey_len key_algorithm in
    let key = Cstruct.sub buf (off + 4) len in
    Ok ({ flags ; key_algorithm ; key }, names, off + len + 4)

let encode_dnskey t offs buf off =
  Cstruct.BE.set_uint16 buf off t.flags ;
  Cstruct.set_uint8 buf (off + 2) 3 ;
  Cstruct.set_uint8 buf (off + 3) (Dns_enum.dnskey_to_int t.key_algorithm) ;
  let kl = Cstruct.len t.key in
  Cstruct.blit t.key 0 buf (off + 4) kl ;
  offs, off + 4 + kl

type srv = {
  priority : int ;
  weight : int ;
  port : int ;
  target : Domain_name.t
}

let compare_srv a b =
  andThen (compare a.priority b.priority)
    (andThen (compare a.weight b.weight)
       (andThen (compare a.port b.port)
          (Domain_name.compare a.target b.target)))

(*BISECT-IGNORE-BEGIN*)
let pp_srv ppf t =
  Fmt.pf ppf
    "SRV priority %d weight %d port %d target %a"
    t.priority t.weight t.port Domain_name.pp t.target
(*BISECT-IGNORE-END*)

let decode_srv names buf off =
  let priority = Cstruct.BE.get_uint16 buf off
  and weight = Cstruct.BE.get_uint16 buf (off + 2)
  and port = Cstruct.BE.get_uint16 buf (off + 4)
  in
  Dns_name.decode names buf (off + 6) >>= fun (target, names, off) ->
  Ok ({ priority ; weight ; port ; target }, names, off)

let encode_srv t offs buf off =
  Cstruct.BE.set_uint16 buf off t.priority ;
  Cstruct.BE.set_uint16 buf (off + 2) t.weight ;
  Cstruct.BE.set_uint16 buf (off + 4) t.port ;
  Dns_name.encode offs buf (off + 6) t.target

type caa = {
  critical : bool ;
  tag : string ;
  value : string list ;
}

let compare_caa a b =
  andThen (compare a.critical b.critical)
    (andThen (String.compare a.tag b.tag)
       (List.fold_left2 (fun r a b -> match r with
            | 0 -> String.compare a b
            | x -> x)
           0 a.value b.value))

(*BISECT-IGNORE-BEGIN*)
let pp_caa ppf t =
  Fmt.pf ppf
    "CAA critical %b tag %s value %a"
    t.critical t.tag Fmt.(list ~sep:(unit "; ") string) t.value
(*BISECT-IGNORE-END*)

let decode_caa buf off len =
  let critical = Cstruct.get_uint8 buf off = 0x80
  and tl = Cstruct.get_uint8 buf (succ off)
  in
  guard (tl > 0 && tl < 16) `BadCaaTag >>= fun () ->
  let tag = Cstruct.sub buf (off + 2) tl in
  let tag = Cstruct.to_string tag in
  let vs = 2 + tl in
  let value = Cstruct.sub buf (off + vs) (len - vs) in
  let value = Astring.String.cuts ~sep:";" (Cstruct.to_string value) in
  Ok { critical ; tag ; value }

let encode_caa t buf off =
  Cstruct.set_uint8 buf off (if t.critical then 0x80 else 0x0) ;
  let tl = String.length t.tag in
  Cstruct.set_uint8 buf (succ off) tl ;
  Cstruct.blit_from_string t.tag 0 buf (off + 2) tl ;
  let value = Astring.String.concat ~sep:";" t.value in
  let vl = String.length value in
  Cstruct.blit_from_string value 0 buf (off + 2 + tl) vl ;
  off + tl + 2 + vl

type extension =
  | Nsid of Cstruct.t
  | Cookie of Cstruct.t
  | Tcp_keepalive of int option
  | Padding of int
  | Extension of int * Cstruct.t

type opt = {
  extended_rcode : int ;
  version : int ;
  dnssec_ok : bool ;
  payload_size : int ;
  extensions : extension list ;
}

let opt ?(extended_rcode = 0) ?(version = 0) ?(dnssec_ok = false) ?(payload_size = 512) ?(extensions = []) () =
  { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions }

(* once we handle cookies, dnssec, or other extensions, need to adjust *)
let reply_opt = function
  | None -> None, None
  | Some edns ->
    let payload_size = edns.payload_size in
    Some payload_size, Some (opt ~payload_size ())

let compare_extension a b = match a, b with
  | Nsid a, Nsid b -> Cstruct.compare a b
  | Nsid _, _ -> 1 | _, Nsid _ -> -1
  | Cookie a, Cookie b -> Cstruct.compare a b
  | Cookie _, _ -> 1 | _, Cookie _ -> -1
  | Tcp_keepalive a, Tcp_keepalive b -> compare a b
  | Tcp_keepalive _, _ -> 1 | _, Tcp_keepalive _ -> -1
  | Padding a, Padding b -> compare a b
  | Padding _, _ -> 1 | _, Padding _ -> -1
  | Extension (t, v), Extension (t', v') -> andThen (compare t t') (Cstruct.compare v v')

let compare_opt a b =
  andThen (compare a.extended_rcode b.extended_rcode)
    (andThen (compare a.version b.version)
       (andThen (compare a.dnssec_ok b.dnssec_ok)
          (andThen (compare a.payload_size b.payload_size)
             (List.fold_left2
                (fun r a b -> if r = 0 then compare_extension a b else r)
                (compare (List.length a.extensions) (List.length b.extensions))
                a.extensions b.extensions))))

(*BISECT-IGNORE-BEGIN*)
let pp_extension ppf = function
  | Nsid cs -> Fmt.pf ppf "nsid %a" Cstruct.hexdump_pp cs
  | Cookie cs -> Fmt.pf ppf "cookie %a" Cstruct.hexdump_pp cs
  | Tcp_keepalive i -> Fmt.pf ppf "keepalive %a" Fmt.(option ~none:(unit "none") int) i
  | Padding i -> Fmt.pf ppf "padding %d" i
  | Extension (t, v) -> Fmt.pf ppf "unknown option %d: %a" t Cstruct.hexdump_pp v

let pp_opt ppf opt =
  Fmt.(pf ppf "opt (ext %u version %u dnssec_ok %b payload_size %u extensions %a"
         opt.extended_rcode opt.version opt.dnssec_ok opt.payload_size
         (list ~sep:(unit ", ") pp_extension) opt.extensions)
(*BISECT-IGNORE-END*)

let decode_extension buf off len =
  let code = Cstruct.BE.get_uint16 buf off
  and tl = Cstruct.BE.get_uint16 buf (off + 2)
  in
  guard (tl <= len - 4) `BadOpt >>= fun () ->
  let v = Cstruct.sub buf (off + 4) tl in
  let len = tl + 4 in
  match Dns_enum.int_to_edns_opt code with
  | Some Dns_enum.NSID -> Ok (Nsid v, len)
  | Some Dns_enum.Cookie -> Ok (Cookie v, len)
  | Some Dns_enum.TCP_keepalive ->
    (begin match tl with
       | 0 -> Ok None
       | 2 -> Ok (Some (Cstruct.BE.get_uint16 v 0))
       | _ -> Error `BadKeepalive
     end >>= fun i ->
     Ok (Tcp_keepalive i, len))
  | Some Dns_enum.Padding -> Ok (Padding tl, len)
  | _ -> Ok (Extension (code, v), len)

let decode_extensions buf off len =
  let rec one acc pos =
    if len = pos - off then
      Ok (List.rev acc)
    else
      decode_extension buf pos (len - (pos - off)) >>= fun (opt, len) ->
      one (opt :: acc) (pos + len)
  in
  one [] off

let encode_extension t buf off =
  let o_i = Dns_enum.edns_opt_to_int in
  let code, v = match t with
    | Nsid cs -> o_i Dns_enum.NSID, cs
    | Cookie cs -> o_i Dns_enum.Cookie, cs
    | Tcp_keepalive i -> o_i Dns_enum.TCP_keepalive, (match i with None -> Cstruct.create 0 | Some i -> let buf = Cstruct.create 2 in Cstruct.BE.set_uint16 buf 0 i ; buf)
    | Padding i -> o_i Dns_enum.Padding, Cstruct.create i
    | Extension (t, v) -> t, v
  in
  let l = Cstruct.len v in
  Cstruct.BE.set_uint16 buf off code ;
  Cstruct.BE.set_uint16 buf (off + 2) l ;
  Cstruct.blit v 0 buf (off + 4) l ;
  off + 4 + l

let encode_extensions t buf off =
  List.fold_left (fun off opt -> encode_extension opt buf off) off t

type tlsa = {
  tlsa_cert_usage : Dns_enum.tlsa_cert_usage ;
  tlsa_selector : Dns_enum.tlsa_selector ;
  tlsa_matching_type : Dns_enum.tlsa_matching_type ;
  tlsa_data : Cstruct.t ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_tlsa ppf tlsa =
  Fmt.pf ppf "TLSA %a %a %a %a"
    Dns_enum.pp_tlsa_cert_usage tlsa.tlsa_cert_usage
    Dns_enum.pp_tlsa_selector tlsa.tlsa_selector
    Dns_enum.pp_tlsa_matching_type tlsa.tlsa_matching_type
    Cstruct.hexdump_pp tlsa.tlsa_data
(*BISECT-IGNORE-END*)

let compare_tlsa t1 t2 =
  andThen (compare t1.tlsa_cert_usage t2.tlsa_cert_usage)
    (andThen (compare t1.tlsa_selector t2.tlsa_selector)
       (andThen (compare t1.tlsa_matching_type t2.tlsa_matching_type)
          (Cstruct.compare t1.tlsa_data t2.tlsa_data)))

let decode_tlsa buf off len =
  let usage, selector, matching_type =
    Cstruct.get_uint8 buf off,
    Cstruct.get_uint8 buf (off + 1),
    Cstruct.get_uint8 buf (off + 2)
  in
  let tlsa_data = Cstruct.sub buf (off + 3) (len - 3) in
  match
    Dns_enum.int_to_tlsa_cert_usage usage,
    Dns_enum.int_to_tlsa_selector selector,
    Dns_enum.int_to_tlsa_matching_type matching_type
  with
  | Some tlsa_cert_usage, Some tlsa_selector, Some tlsa_matching_type ->
    Ok { tlsa_cert_usage ; tlsa_selector ; tlsa_matching_type ; tlsa_data }
  | None, _, _ -> Error (`BadTlsaCertUsage usage)
  | _, None, _ -> Error (`BadTlsaSelector selector)
  | _, _, None -> Error (`BadTlsaMatchingType matching_type)

let encode_tlsa tlsa buf off =
  Cstruct.set_uint8 buf off (Dns_enum.tlsa_cert_usage_to_int tlsa.tlsa_cert_usage) ;
  Cstruct.set_uint8 buf (off + 1) (Dns_enum.tlsa_selector_to_int tlsa.tlsa_selector) ;
  Cstruct.set_uint8 buf (off + 2) (Dns_enum.tlsa_matching_type_to_int tlsa.tlsa_matching_type) ;
  let l = Cstruct.len tlsa.tlsa_data in
  Cstruct.blit tlsa.tlsa_data 0 buf (off + 3) l ;
  off + 3 + l

type sshfp = {
  sshfp_algorithm : Dns_enum.sshfp_algorithm ;
  sshfp_type : Dns_enum.sshfp_type ;
  sshfp_fingerprint : Cstruct.t ;
}

let compare_sshfp s1 s2 =
  andThen (compare s1.sshfp_algorithm s2.sshfp_algorithm)
    (andThen (compare s1.sshfp_type s2.sshfp_type)
       (Cstruct.compare s1.sshfp_fingerprint s2.sshfp_fingerprint))

(*BISECT-IGNORE-BEGIN*)
let pp_sshfp ppf sshfp =
  Fmt.pf ppf "SSHFP %a %a %a"
    Dns_enum.pp_sshfp_algorithm sshfp.sshfp_algorithm
    Dns_enum.pp_sshfp_type sshfp.sshfp_type
    Cstruct.hexdump_pp sshfp.sshfp_fingerprint
(*BISECT-IGNORE-END*)

let decode_sshfp buf off len =
  let algo, typ = Cstruct.get_uint8 buf off, Cstruct.get_uint8 buf (succ off) in
  let sshfp_fingerprint = Cstruct.sub buf (off + 2) (len - 2) in
  match Dns_enum.int_to_sshfp_algorithm algo, Dns_enum.int_to_sshfp_type typ with
  | Some sshfp_algorithm, Some sshfp_type ->
    Ok { sshfp_algorithm ; sshfp_type ; sshfp_fingerprint }
  | None, _ -> Error (`BadSshfpAlgorithm algo)
  | _, None -> Error (`BadSshfpType typ)

let encode_sshfp sshfp buf off =
  Cstruct.set_uint8 buf off (Dns_enum.sshfp_algorithm_to_int sshfp.sshfp_algorithm) ;
  Cstruct.set_uint8 buf (succ off) (Dns_enum.sshfp_type_to_int sshfp.sshfp_type) ;
  let l = Cstruct.len sshfp.sshfp_fingerprint in
  Cstruct.blit sshfp.sshfp_fingerprint 0 buf (off + 2) l ;
  off + l + 2

type rdata =
  | CNAME of Domain_name.t
  | MX of int * Domain_name.t
  | NS of Domain_name.t
  | PTR of Domain_name.t
  | SOA of soa
  | TXT of string list
  | A of Ipaddr.V4.t
  | AAAA of Ipaddr.V6.t
  | SRV of srv
  | TSIG of tsig
  | DNSKEY of dnskey
  | CAA of caa
  | OPTS of opt
  | TLSA of tlsa
  | SSHFP of sshfp
  | Raw of Dns_enum.rr_typ * Cstruct.t

let compare_rdata a b = match a, b with
  | CNAME a, CNAME a' -> Domain_name.compare a a'
  | CNAME _, _ -> 1 | _, CNAME _ -> -1
  | MX (p, a), MX (p', a') -> andThen (compare p p') (Domain_name.compare a a')
  | MX _, _ -> 1 | _, MX _ -> -1
  | NS a, NS a' -> Domain_name.compare a a'
  | NS _, _ -> 1 | _, NS _ -> -1
  | PTR a, PTR a' -> Domain_name.compare a a'
  | PTR _, _ -> 1 | _, PTR _ -> -1
  | SOA s, SOA s' -> compare_soa s s'
  | SOA _, _ -> 1 | _, SOA _ -> -1
  | TXT a, TXT a' ->
    andThen (compare (List.length a) (List.length a'))
      (List.fold_left2 (fun r a b -> match r with
           | 0 -> String.compare a b
           | x -> x)
          0 a a')
  | TXT _, _ -> 1 | _, TXT _ -> -1
  | A a, A a' -> Ipaddr.V4.compare a a'
  | A _, _ -> 1 | _, A _ -> -1
  | AAAA a, AAAA a' -> Ipaddr.V6.compare a a'
  | AAAA _, _ -> 1 | _, AAAA _ -> -1
  | SRV srv, SRV srv' -> compare_srv srv srv'
  | SRV _, _ -> 1 | _, SRV _ -> -1
  | DNSKEY a, DNSKEY b -> compare_dnskey a b
  | DNSKEY _, _ -> 1 | _, DNSKEY _ -> -1
  | CAA a, CAA b -> compare_caa a b
  | CAA _, _ -> 1 | _, CAA _ -> -1
  | OPTS a, OPTS b -> compare_opt a b
  | OPTS _, _ -> 1 | _, OPTS _ -> -1
  | TLSA a, TLSA b -> compare_tlsa a b
  | TLSA _, _ -> 1 | _, TLSA _ -> -1
  | SSHFP a, SSHFP b -> compare_sshfp a b
  | SSHFP _, _ -> 1 | _, SSHFP _ -> -1
  | Raw (t, v), Raw (t', v') ->
    andThen (compare t t') (Cstruct.compare v v')
  | _ -> 1 (* TSIG is missing here expicitly, it's never supposed to be in any set! *)

(*BISECT-IGNORE-BEGIN*)
let pp_rdata ppf = function
  | CNAME n -> Fmt.pf ppf "CNAME %a" Domain_name.pp n
  | MX (prio, n) -> Fmt.pf ppf "MX %d %a" prio Domain_name.pp n
  | NS n -> Fmt.pf ppf "NS %a" Domain_name.pp n
  | PTR n -> Fmt.pf ppf "PTR %a" Domain_name.pp n
  | SOA s -> pp_soa ppf s
  | TXT ds -> Fmt.pf ppf "TXT %a" (Fmt.list ~sep:(Fmt.unit ";@ ") Fmt.string) ds
  | A ip -> Fmt.pf ppf "A %a" Ipaddr.V4.pp_hum ip
  | AAAA ip -> Fmt.pf ppf "AAAA %a" Ipaddr.V6.pp_hum ip
  | SRV srv -> pp_srv ppf srv
  | TSIG ts -> pp_tsig ppf ts
  | DNSKEY tk -> pp_dnskey ppf tk
  | CAA caa -> pp_caa ppf caa
  | OPTS opts -> pp_opt ppf opts
  | TLSA tlsa -> pp_tlsa ppf tlsa
  | SSHFP sshfp -> pp_sshfp ppf sshfp
  | Raw (t, d) ->
    Fmt.pf ppf "%a: %a" Dns_enum.pp_rr_typ t Cstruct.hexdump_pp d
(*BISECT-IGNORE-END*)

let rdata_to_rr_typ = function
  | CNAME _ -> Dns_enum.CNAME
  | MX _ -> Dns_enum.MX
  | NS _ -> Dns_enum.NS
  | PTR _ -> Dns_enum.PTR
  | SOA _ -> Dns_enum.SOA
  | TXT _ -> Dns_enum.TXT
  | A _ -> Dns_enum.A
  | AAAA _ -> Dns_enum.AAAA
  | SRV _ -> Dns_enum.SRV
  | TSIG _ -> Dns_enum.TSIG
  | DNSKEY _ -> Dns_enum.DNSKEY
  | CAA _ -> Dns_enum.CAA
  | OPTS _ -> Dns_enum.OPT
  | TLSA _ -> Dns_enum.TLSA
  | SSHFP _ -> Dns_enum.SSHFP
  | Raw (t, _) -> t

let rdata_name = function
  | MX (_, n) -> Domain_name.Set.singleton n
  | NS n -> Domain_name.Set.singleton n
  | SRV srv -> Domain_name.Set.singleton srv.target
  | _ -> Domain_name.Set.empty

let decode_rdata names buf off len = function
  | Dns_enum.CNAME ->
    Dns_name.decode names buf off >>= fun (name, names, off) ->
    Ok (CNAME name, names, off)
  | Dns_enum.MX ->
    let prio = Cstruct.BE.get_uint16 buf off in
    Dns_name.decode ~hostname:false names buf (off + 2) >>= fun (name, names, off) ->
    Ok (MX (prio, name), names, off)
  | Dns_enum.NS ->
    Dns_name.decode names buf off >>= fun (name, names, off) ->
    Ok (NS name, names, off)
  | Dns_enum.PTR ->
    Dns_name.decode names buf off >>= fun (name, names, off) ->
    Ok (PTR name, names, off)
  | Dns_enum.SOA ->
    let hostname = false in
    Dns_name.decode ~hostname names buf off >>= fun (nameserver, names, off) ->
    Dns_name.decode ~hostname names buf off >>= fun (hostmaster, names, off) ->
    let serial = Cstruct.BE.get_uint32 buf off in
    let refresh = Cstruct.BE.get_uint32 buf (off + 4) in
    let retry = Cstruct.BE.get_uint32 buf (off + 8) in
    let expiry = Cstruct.BE.get_uint32 buf (off + 12) in
    let minimum = Cstruct.BE.get_uint32 buf (off + 16) in
    let soa =
      { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }
    in
    Ok (SOA soa, names, off + 20)
  | Dns_enum.TXT ->
    let sub = Cstruct.sub buf off len in
    let rec more acc off =
      if len = off then List.rev acc
      else
        let d, off = dec_character_str sub off in
        more (d::acc) off
    in
    Ok (TXT (more [] 0), names, off + len)
  | Dns_enum.A ->
    let ip = Cstruct.BE.get_uint32 buf off in
    Ok (A (Ipaddr.V4.of_int32 ip), names, off + 4)
  | Dns_enum.AAAA ->
    let iph = Cstruct.BE.get_uint64 buf off
    and ipl = Cstruct.BE.get_uint64 buf (off + 8)
    in
    Ok (AAAA (Ipaddr.V6.of_int64 (iph, ipl)), names, off + 16)
  | Dns_enum.SRV ->
    decode_srv names buf off >>= fun (srv, names, off) ->
    Ok (SRV srv, names, off)
  | Dns_enum.TSIG ->
    decode_tsig names buf off >>= fun (tsig, names, off) ->
    Ok (TSIG tsig, names, off)
  | Dns_enum.DNSKEY ->
    decode_dnskey names buf off >>= fun (tkey, names, off) ->
    Ok (DNSKEY tkey, names, off)
  | Dns_enum.CAA ->
    decode_caa buf off len >>= fun caa ->
    Ok (CAA caa, names, off + len)
  | Dns_enum.TLSA ->
    decode_tlsa buf off len >>= fun tlsa ->
    Ok (TLSA tlsa, names, off + len)
  | Dns_enum.SSHFP ->
    decode_sshfp buf off len >>= fun sshfp ->
    Ok (SSHFP sshfp, names, off + len)
  | x -> Ok (Raw (x, Cstruct.sub buf off len), names, off + len)

let encode_rdata offs buf off = function
  | CNAME nam -> Dns_name.encode offs buf off nam
  | MX (prio, nam) ->
    Cstruct.BE.set_uint16 buf off prio ;
    Dns_name.encode offs buf (off + 2) nam
  | NS nam -> Dns_name.encode offs buf off nam
  | PTR nam -> Dns_name.encode offs buf off nam
  | SOA soa ->
    let offs, off = Dns_name.encode offs buf off soa.nameserver in
    let offs, off = Dns_name.encode offs buf off soa.hostmaster in
    Cstruct.BE.set_uint32 buf off soa.serial ;
    Cstruct.BE.set_uint32 buf (off + 4) soa.refresh ;
    Cstruct.BE.set_uint32 buf (off + 8) soa.retry ;
    Cstruct.BE.set_uint32 buf (off + 12) soa.expiry ;
    Cstruct.BE.set_uint32 buf (off + 16) soa.minimum ;
    offs, off + 20
  | TXT ds ->
    let off = List.fold_left (enc_character_str buf) off ds in
    offs, off
  | A ip ->
    let ip = Ipaddr.V4.to_int32 ip in
    Cstruct.BE.set_uint32 buf off ip ;
    offs, off + 4
  | AAAA ip ->
    let iph, ipl = Ipaddr.V6.to_int64 ip in
    Cstruct.BE.set_uint64 buf off iph ;
    Cstruct.BE.set_uint64 buf (off + 8) ipl ;
    offs, off + 16
  | SRV srv -> encode_srv srv offs buf off
  | TSIG t -> encode_tsig t offs buf off
  | DNSKEY t -> encode_dnskey t offs buf off
  | CAA caa -> offs, encode_caa caa buf off
  | OPTS opts -> offs, encode_extensions opts.extensions buf off
  | TLSA tlsa -> offs, encode_tlsa tlsa buf off
  | SSHFP sshfp -> offs, encode_sshfp sshfp buf off
  | Raw (_, rr) ->
    let len = Cstruct.len rr in
    Cstruct.blit rr 0 buf off len ;
    offs, off + len

type rr = {
  name : Domain_name.t ;
  ttl : int32 ;
  rdata : rdata
}

(*BISECT-IGNORE-BEGIN*)
let pp_rr ppf rr =
  Fmt.pf ppf "%a TTL %lu %a" Domain_name.pp rr.name rr.ttl pp_rdata rr.rdata

let pp_rrs = Fmt.(list ~sep:(unit ";@.") pp_rr)
(*BISECT-IGNORE-END*)

let rr_equal a b =
  Domain_name.compare a.name b.name = 0 &&
  a.ttl = b.ttl &&
  compare_rdata a.rdata b.rdata = 0

let rr_name rr = rdata_name rr.rdata

let rr_names =
  List.fold_left
    (fun acc rr -> Domain_name.Set.union (rr_name rr) acc)
    Domain_name.Set.empty

let safe_decode_rdata names buf off len typ =
  (* decode_rdata is mostly safe, apart from some Cstruct._.get_ *)
  (try decode_rdata names buf off len typ with _ -> Error `Partial)
  >>= fun (rdata, names, off') ->
  guard (off' = off + len) `LeftOver >>= fun () ->
  Ok (rdata, names, off')

(* TTL in range 0 .. 2 ^ 31 - 1 -- otherwise invalid (see RFC2181 sec 8) *)
let check_ttl ttl = Int32.logand ttl 0x80000000l = 0l

let decode_rr names buf off =
  decode_ntc names buf off >>= fun ((name, typ, c), names, off) ->
  guard (Cstruct.len buf >= 6 + off) `Partial >>= fun () ->
  (* since QTYPE (and QCLASS) are supersets of RR_TYPE and RR_CLASS, we
     complaing about these not belonging to RR_TYPE/RR_CLASS here *)
  (* we are only concerned about class = IN, according to RFC6895 Sec 3.3.2:
     The IN, or Internet, CLASS is thus the only DNS CLASS in global use on
     the Internet at this time! *)
  let ttl = Cstruct.BE.get_uint32 buf off in
  (match typ with
   | Dns_enum.AXFR | Dns_enum.MAILB | Dns_enum.MAILA | Dns_enum.ANY ->
     Error (`DisallowedRRTyp typ)
   | Dns_enum.OPT -> Ok ()
   | Dns_enum.TSIG -> (* TTL = 0! and class = ANY *)
     begin match Dns_enum.int_to_clas c with
       | Some Dns_enum.ANY_CLASS when ttl = 0l -> Ok ()
       | _ -> Error (`BadClass c)
     end
   | _ -> match Dns_enum.int_to_clas c with
     | Some Dns_enum.IN -> Ok ()
     | None -> Error (`BadClass c)
     | Some Dns_enum.ANY_CLASS -> Error (`DisallowedClass Dns_enum.ANY_CLASS)
     | Some x -> Error (`UnsupportedClass x)) >>= fun () ->
  let len = Cstruct.BE.get_uint16 buf (off + 4) in
  guard (Cstruct.len buf >= len + 6) `Partial >>= fun () ->
  match typ with
  | Dns_enum.OPT ->
    (* crazyness: payload_size is encoded in class *)
    let payload_size = c
    (* it continues: the ttl is split into: 4bit extended rcode, 4bit version, 1bit dnssec_ok, 7bit 0 *)
    and extended_rcode = Cstruct.get_uint8 buf off
    and version = Cstruct.get_uint8 buf (off + 1)
    and flags = Cstruct.BE.get_uint16 buf (off + 2)
    in
    let off = off + 6 in
    let dnssec_ok = flags land 0x8000 = 0x8000 in
    guard (version = 0) (`Bad_edns_version version) >>= fun () ->
    (try decode_extensions buf off len with _ -> Error `Partial) >>= fun extensions ->
    let opt = { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions } in
    Ok ({ name ; ttl ; rdata = OPTS opt }, names, (off + len))
  | _ ->
    let off = off + 6 in
    guard (check_ttl ttl) (`BadTTL ttl) >>= fun () ->
    safe_decode_rdata names buf off len typ >>= fun (rdata, names, off') ->
    Ok ({ name ; ttl ; rdata }, names, off')

let encode_rr offs buf off rr =
  let clas, ttl = match rr.rdata with
    | OPTS opt ->
      let ttl =
        Int32.(add (shift_left (of_int opt.extended_rcode) 24)
                 (add (shift_left (of_int opt.version) 16)
                    (if opt.dnssec_ok then 0x8000l else 0x0000l)))
      in
      opt.payload_size, ttl
    | TSIG _ -> Dns_enum.(clas_to_int ANY_CLASS), 0l
    | _ -> Dns_enum.(clas_to_int IN), rr.ttl
  in
  let typ = rdata_to_rr_typ rr.rdata in
  let offs, off = encode_ntc offs buf off (rr.name, typ, clas) in
  Cstruct.BE.set_uint32 buf off ttl ;
  let offs, off' = encode_rdata offs buf (off + 6) rr.rdata in
  Cstruct.BE.set_uint16 buf (off + 4) (off' - (off + 6)) ;
  offs, off'

(* QUERY *)
let rec decode_n_partial f names buf off acc = function
  | 0 -> Ok (`Full (names, off, List.rev acc))
  | n ->
    match f names buf off with
    | Ok (ele, names, off') ->
      decode_n_partial f names buf off' (ele :: acc) (pred n)
    | Error `Partial -> Ok (`Partial (List.rev acc))
    | Error e -> Error e

let rdata_edns_tsig_ok rr edns tsig =
  match rr.rdata, edns, tsig with
  | TSIG ts, opt, None -> Ok (opt, Some (rr.name, ts))
  | TSIG _, _, Some _ -> Error `Multiple_tsig
  | OPTS opt, None, None -> Ok (Some opt, None)
  | OPTS _, Some _, _ -> Error `Multiple_edns
  | _, _, Some _ -> Error `Tsig_not_last
  | _, opt, ts -> Ok (opt, ts)

let rec decode_n_additional_partial names buf off r (acc, opt, tsig) = function
  | 0 -> Ok (`Full (off, List.rev acc, opt, tsig, r))
  | n ->
    match decode_rr names buf off with
    | Ok (ele, names, off') ->
      rdata_edns_tsig_ok ele opt tsig >>= fun (opt', tsig') ->
      decode_n_additional_partial names buf off' (Some off) (ele :: acc, opt', tsig') (pred n)
    | Error `Partial -> Ok (`Partial (List.rev acc, opt, tsig))
    | Error e -> Error e

type query = {
  question : question list ;
  answer : rr list ;
  authority : rr list ;
  additional : rr list
}

let decode_query buf t =
  guard (Cstruct.len buf >= 12) `Partial >>= fun () ->
  let qcount = Cstruct.BE.get_uint16 buf 4
  and ancount = Cstruct.BE.get_uint16 buf 6
  and aucount = Cstruct.BE.get_uint16 buf 8
  and adcount = Cstruct.BE.get_uint16 buf 10
  in
  let query question answer authority additional =
    `Query { question ; answer ; authority ; additional }
  in
  let empty = Dns_name.IntMap.empty in
  decode_n_partial decode_question empty buf hdr_len [] qcount >>= function
  | `Partial qs -> guard t `Partial >>= fun () -> Ok (query qs [] [] [], None, None, None)
  | `Full (names, off, qs) ->
    decode_n_partial decode_rr names buf off [] ancount >>= function
    | `Partial an -> guard t `Partial >>= fun () -> Ok (query qs an [] [], None, None, None)
    | `Full (names, off, an) ->
      decode_n_partial decode_rr names buf off [] aucount >>= function
      | `Partial au -> guard t `Partial >>= fun () -> Ok (query qs an au [], None, None, None)
      | `Full (names, off, au) ->
        decode_n_additional_partial names buf off None ([], None, None) adcount >>= function
        | `Partial (ad, opt, tsig) ->
          guard t `Partial >>= fun () ->
          Ok (query qs an au ad, opt, tsig, None)
        | `Full (off, ad, opt, tsig, lastoff) ->
          (if Cstruct.len buf > off then
             let n = Cstruct.len buf - off in
             Logs.warn (fun m -> m "received %d extra bytes %a"
                           n Cstruct.hexdump_pp (Cstruct.sub buf off n))) ;
          Ok (query qs an au ad, opt, tsig, lastoff)

let encode_query buf data =
  Cstruct.BE.set_uint16 buf 4 (List.length data.question) ;
  Cstruct.BE.set_uint16 buf 6 (List.length data.answer) ;
  Cstruct.BE.set_uint16 buf 8 (List.length data.authority) ;
  let offs, off =
    List.fold_left (fun (offs, off) q -> encode_question offs buf off q)
      (Domain_name.Map.empty, hdr_len) data.question
  in
  List.fold_left (fun (offs, off) rr -> encode_rr offs buf off rr)
    (offs, off) (data.answer @ data.authority)

(*BISECT-IGNORE-BEGIN*)
let pp_query ppf t =
  Fmt.pf ppf "%a@ %a@ %a@ %a"
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_question) t.question
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.answer
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.authority
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.additional
(*BISECT-IGNORE-END*)


(* UPDATE *)
type rr_prereq =
  | Exists of Domain_name.t * Dns_enum.rr_typ
  | Exists_data of Domain_name.t * rdata
  | Not_exists of Domain_name.t * Dns_enum.rr_typ
  | Name_inuse of Domain_name.t
  | Not_name_inuse of Domain_name.t

(*BISECT-IGNORE-BEGIN*)
let pp_rr_prereq ppf = function
  | Exists (name, typ) ->
    Fmt.pf ppf "exists? %a %a" Domain_name.pp name Dns_enum.pp_rr_typ typ
  | Exists_data (name, rd) ->
    Fmt.pf ppf "exists data? %a %a"
      Domain_name.pp name pp_rdata rd
  | Not_exists (name, typ) ->
    Fmt.pf ppf "doesn't exists? %a %a" Domain_name.pp name Dns_enum.pp_rr_typ typ
  | Name_inuse name -> Fmt.pf ppf "name inuse? %a" Domain_name.pp name
  | Not_name_inuse name -> Fmt.pf ppf "name not inuse? %a" Domain_name.pp name
(*BISECT-IGNORE-END*)

let decode_rr_prereq names buf off =
  decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
  let off' = off + 6 in
  guard (Cstruct.len buf >= off') `Partial >>= fun () ->
  let ttl = Cstruct.BE.get_uint32 buf off in
  guard (ttl = 0l) (`NonZeroTTL ttl) >>= fun () ->
  let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
  let r0 = guard (rlen = 0) (`NonZeroRdlen rlen) in
  let open Dns_enum in
  match int_to_clas cls, typ with
  | Some ANY_CLASS, ANY -> r0 >>= fun () -> Ok (Name_inuse name, names, off')
  | Some NONE, ANY -> r0 >>= fun () -> Ok (Not_name_inuse name, names, off')
  | Some ANY_CLASS, _ -> r0 >>= fun () -> Ok (Exists (name, typ), names, off')
  | Some NONE, _ -> r0 >>= fun () -> Ok (Not_exists (name, typ), names, off')
  | Some IN, _ ->
    safe_decode_rdata names buf off' rlen typ >>= fun (rdata, names, off'') ->
    Ok (Exists_data (name, rdata), names, off'')
  | _ -> Error (`BadClass cls)

let encode_rr_prereq offs buf off = function
  | Exists (name, typ) ->
    let offs, off =
      encode_ntc offs buf off (name, typ, Dns_enum.(clas_to_int ANY_CLASS))
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Exists_data (name, rdata) ->
    let typ = rdata_to_rr_typ rdata in
    let offs, off =
      encode_ntc offs buf off (name, typ, Dns_enum.(clas_to_int IN))
    in
    let offs, off' = encode_rdata offs buf (off + 6) rdata in
    let rdlenpos = off + 4 in
    Cstruct.BE.set_uint16 buf rdlenpos (off' - rdlenpos) ;
    (offs, off')
  | Not_exists (name, typ) ->
    let offs, off =
      encode_ntc offs buf off (name, typ, Dns_enum.(clas_to_int NONE))
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Name_inuse name ->
    let offs, off =
      encode_ntc offs buf off Dns_enum.(name, ANY, clas_to_int ANY_CLASS)
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Not_name_inuse name ->
    let offs, off =
      encode_ntc offs buf off Dns_enum.(name, ANY, clas_to_int NONE)
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)

type rr_update =
  | Remove of Domain_name.t * Dns_enum.rr_typ
  | Remove_all of Domain_name.t
  | Remove_single of Domain_name.t * rdata
  | Add of rr

let rr_update_name = function
  | Remove (name, _) -> name
  | Remove_all name -> name
  | Remove_single (name, _) -> name
  | Add rr -> rr.name

(*BISECT-IGNORE-BEGIN*)
let pp_rr_update ppf = function
  | Remove (name, typ) ->
    Fmt.pf ppf "remove! %a %a" Domain_name.pp name Dns_enum.pp_rr_typ typ
  | Remove_all name -> Fmt.pf ppf "remove all! %a" Domain_name.pp name
  | Remove_single (name, rd) ->
    Fmt.pf ppf "remove single! %a %a" Domain_name.pp name pp_rdata rd
  | Add rr ->
    Fmt.pf ppf "add! %a" pp_rr rr
(*BISECT-IGNORE-END*)

let decode_rr_update names buf off =
  decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
  let off' = off + 6 in
  guard (Cstruct.len buf >= off') `Partial >>= fun () ->
  let ttl = Cstruct.BE.get_uint32 buf off in
  let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
  let r0 = guard (rlen = 0) (`NonZeroRdlen rlen) in
  let ttl0 = guard (ttl = 0l) (`NonZeroTTL ttl) in
  match Dns_enum.int_to_clas cls, typ with
  | Some Dns_enum.ANY_CLASS, Dns_enum.ANY ->
    ttl0 >>= fun () ->
    r0 >>= fun () ->
    Ok (Remove_all name, names, off')
  | Some Dns_enum.ANY_CLASS, _ ->
    ttl0 >>= fun () ->
    r0 >>= fun () ->
    Ok (Remove (name, typ), names, off')
  | Some Dns_enum.NONE, _ ->
    ttl0 >>= fun () ->
    safe_decode_rdata names buf off' rlen typ >>= fun (rdata, names, off) ->
    Ok (Remove_single (name, rdata), names, off)
  | Some Dns_enum.IN, _ ->
    guard (check_ttl ttl) (`BadTTL ttl) >>= fun () ->
    safe_decode_rdata names buf off' rlen typ >>= fun (rdata, names, off) ->
    let rr = { name ; ttl ; rdata } in
    Ok (Add rr, names, off)
  | _ -> Error (`BadClass cls)

let encode_rr_update offs buf off = function
  | Remove (name, typ) ->
    let offs, off =
      encode_ntc offs buf off (name, typ, Dns_enum.(clas_to_int ANY_CLASS))
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Remove_all name ->
    let offs, off =
      encode_ntc offs buf off Dns_enum.(name, ANY, clas_to_int ANY_CLASS)
    in
    (* ttl + rdlen, both 0 *)
    (offs, off + 6)
  | Remove_single (name, rdata) ->
    let typ = rdata_to_rr_typ rdata in
    let offs, off =
      encode_ntc offs buf off (name, typ, Dns_enum.(clas_to_int NONE))
    in
    let offs, off' = encode_rdata offs buf (off + 6) rdata in
    let rdlenpos = off + 4 in
    Cstruct.BE.set_uint16 buf rdlenpos (off' - rdlenpos) ;
    (offs, off')
  | Add rr -> encode_rr offs buf off rr

type update = {
  zone : question ;
  prereq : rr_prereq list ;
  update : rr_update list ;
  addition : rr list ;
}

(*BISECT-IGNORE-BEGIN*)
let pp_update ppf t =
  Fmt.pf ppf "%a@ %a@ %a@ %a"
    pp_question t.zone
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr_prereq) t.prereq
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr_update) t.update
    (Fmt.list ~sep:(Fmt.unit ";@ ") pp_rr) t.addition
(*BISECT-IGNORE-END*)

let rec decode_n f names buf off acc = function
  | 0 -> Ok (names, off, List.rev acc)
  | n ->
    match f names buf off with
    | Ok (ele, names, off') ->
      decode_n f names buf off' (ele :: acc) (pred n)
    | Error e -> Error e

let rec decode_n_additional names buf off r (acc, opt, tsig) = function
  | 0 -> Ok (off, List.rev acc, opt, tsig, r)
  | n ->
    match decode_rr names buf off with
    | Ok (ele, names, off') ->
      rdata_edns_tsig_ok ele opt tsig >>= fun (opt', tsig') ->
      decode_n_additional names buf off' (Some off) (ele :: acc, opt', tsig') (pred n)
    | Error e -> Error e

let decode_update buf =
  guard (Cstruct.len buf >= hdr_len) `Partial >>= fun () ->
  let zcount = Cstruct.BE.get_uint16 buf 4
  and prcount = Cstruct.BE.get_uint16 buf 6
  and upcount = Cstruct.BE.get_uint16 buf 8
  and adcount = Cstruct.BE.get_uint16 buf 10
  in
  guard (zcount = 1) (`InvalidZoneCount zcount) >>= fun () ->
  decode_question Dns_name.IntMap.empty buf hdr_len >>= fun (q, ns, off) ->
  guard (q.q_type = Dns_enum.SOA) (`InvalidZoneRR q.q_type) >>= fun () ->
  decode_n decode_rr_prereq ns buf off [] prcount >>= fun (ns, off, pre) ->
  decode_n decode_rr_update ns buf off [] upcount >>= fun (ns, off, up) ->
  decode_n_additional ns buf off None ([], None, None) adcount >>= fun (off, addition, opt, tsig, loff) ->
  guard (Cstruct.len buf = off) `LeftOver >>= fun () ->
  Ok (`Update { zone = q ; prereq = pre ; update = up ; addition }, opt, tsig, loff)

let encode_update buf data =
  Cstruct.BE.set_uint16 buf 4 1 ;
  Cstruct.BE.set_uint16 buf 6 (List.length data.prereq) ;
  Cstruct.BE.set_uint16 buf 8 (List.length data.update) ;
  let offs, off =
    encode_question Domain_name.Map.empty buf hdr_len data.zone
  in
  let offs, off =
    List.fold_left (fun (offs, off) rr -> encode_rr_prereq offs buf off rr)
      (offs, off) data.prereq
  in
  List.fold_left (fun (offs, off) rr -> encode_rr_update offs buf off rr)
    (offs, off) data.update

type v = [ `Query of query | `Update of update | `Notify of query ]
type t = header * v * opt option * (Domain_name.t * tsig) option

(*BISECT-IGNORE-BEGIN*)
let pp_v ppf = function
  | `Query q -> pp_query ppf q
  | `Update u -> pp_update ppf u
  | `Notify n -> pp_query ppf n

let pp ppf (hdr, v, _, _) =
  pp_header ppf hdr ;
  Fmt.sp ppf () ;
  pp_v ppf v
(*BISECT-IGNORE-END*)

type tsig_verify = ?mac:Cstruct.t -> Ptime.t -> v -> header ->
  Domain_name.t -> key:dnskey option -> tsig -> Cstruct.t ->
  (tsig * Cstruct.t * dnskey, Cstruct.t option) result

type tsig_sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> tsig ->
  key:dnskey -> Cstruct.t -> (Cstruct.t * Cstruct.t) option

let decode_notify buf t =
  decode_query buf t >>| fun (`Query q, opt, tsig, off) ->
  (`Notify q, opt, tsig, off)

(* TODO: verify the following invariants:
   - notify allows only a single SOA in answer, rest better be empty
   - TSIG and EDNS are only allowed in additional section!
 *)
let decode buf =
  decode_header buf >>= fun hdr ->
  let t = hdr.truncation in
  let header = function
    | Some e when e.extended_rcode > 0 ->
      begin
        let rcode =
          Dns_enum.rcode_to_int hdr.rcode + e.extended_rcode lsl 4
        in
        match Dns_enum.int_to_rcode rcode with
        | None -> Error (`BadRcode rcode)
        | Some rcode -> Ok ({ hdr with rcode })
      end
    | _ -> Ok hdr
  in
  begin match hdr.operation with
  | Dns_enum.Query -> decode_query buf t
  | Dns_enum.Update -> decode_update buf
  | Dns_enum.Notify -> decode_notify buf t
  | x -> Error (`UnsupportedOpcode x)
  end >>= fun (data, opt, tsig, off) ->
  header opt >>| fun hdr ->
  ((hdr, data, opt, tsig), off)

let max_udp = 1484 (* in MirageOS. using IPv4 this is max UDP payload via ethernet *)
let max_reply_udp = 450 (* we don't want anyone to amplify! *)
let max_tcp = 1 lsl 16 - 1 (* DNS-over-TCP is 2 bytes len ++ payload *)

let size_edns max_size edns protocol query =
  let max = match max_size, query with
    | Some x, true -> x
    | Some x, false -> min x max_reply_udp
    | None, true -> max_udp
    | None, false -> max_reply_udp
  in
  (* it's udp payload size only, ignore any value for tcp *)
  let maximum = match protocol with
    | `Udp -> max
    | `Tcp -> max_tcp
  in
  let edns = match edns with
    | None -> None
    | Some opts -> Some ({ opts with payload_size = max })
  in
  maximum, edns

let encode_v buf v =
  match v with
  | `Query q | `Notify q -> encode_query buf q
  | `Update u -> encode_update buf u

let opt_rr opt = { name = Domain_name.root ; ttl = 0l ; rdata = OPTS opt }

let encode_opt opt =
  (* this is unwise! *)
  let rr = opt_rr opt in
  let buf = Cstruct.create 128 in
  let _, off = encode_rr Domain_name.Map.empty buf 0 rr in
  Cstruct.sub buf 0 off

let encode_ad hdr ?edns offs buf off ads =
  let ads, edns = match edns with
    | None -> ads, None
    | Some opt ->
      let ext_rcode = (Dns_enum.rcode_to_int hdr.rcode) lsr 4 in
      (* don't overwrite if rcode was already set -- really needed? *)
      if opt.extended_rcode = 0 && ext_rcode > 0 then
        let edns = opt_rr { opt with extended_rcode = ext_rcode } in
        [ edns ], Some edns
      else
        let edns = opt_rr opt in
        ads @ [ edns ], Some edns
  in
  try
    Cstruct.BE.set_uint16 buf 10 (List.length ads) ;
    snd (List.fold_left (fun (offs, off) rr -> encode_rr offs buf off rr)
           (offs, off) ads)
  with _ ->
  (* This is RFC 2181 Sec 9, not set truncated, just drop additional *)
  match edns with
  | None -> off
  | Some e ->
    try
      (* we attempt encoding edns only *)
      Cstruct.BE.set_uint16 buf 10 1 ;
      snd (encode_rr offs buf off e)
    with _ -> off

let encode ?max_size ?edns protocol hdr v =
  let max, edns = size_edns max_size edns protocol hdr.query in
  (* TODO: enforce invariants: additionals no TSIG and no EDNS! *)
  let try_encoding buf =
    let off, trunc =
      try
        encode_header buf hdr ;
        let offs, off = encode_v buf v in
        let ad = match v with
          | `Query q | `Notify q -> q.additional
          | `Update u -> u.addition
        in
        encode_ad hdr ?edns offs buf off ad, false
      with Invalid_argument _ -> (* set truncated *)
        (* if we failed to store data into buf, set truncation bit! *)
        Cstruct.set_uint8 buf 2 (0x02 lor (Cstruct.get_uint8 buf 2)) ;
        Cstruct.len buf, true
    in
    Cstruct.sub buf 0 off, trunc
  in
  let rec doit s =
    let cs = Cstruct.create s in
    match try_encoding cs with
    | (cs, false) -> (cs, max)
    | (cs, true) ->
      let next = min max (s * 2) in
      if next = s then
        (cs, max)
      else
        doit next
  in
  doit (min max 4000) (* (mainly for TCP) we use a page as initial allocation *)

let error header v rcode =
  if not header.query then
    let header = { header with rcode }
    and question = match v with
      | `Update u -> [ u.zone ]
      | `Query q | `Notify q -> q.question
    in
    let errbuf = Cstruct.create max_reply_udp in
    let query = { question ; answer = [] ; authority = [] ; additional = [] } in
    encode_header errbuf header ;
    let encode query =
      let _, off = encode_query errbuf query in
      let extended_rcode = (Dns_enum.rcode_to_int rcode) lsr 4 in
      if extended_rcode > 0 then
        encode_ad header ~edns:(opt ()) Domain_name.Map.empty errbuf off []
      else
        off
    in
    let off = try encode query with
      | Invalid_argument _ ->
        (* the question section could be larger than 450 byte, a single question
           can't (domain-name: 256 byte, type: 2 byte, class: 2 byte) *)
        let question = match question with [] -> [] | q::_ -> [ q ] in
        let query = { question ; answer = [] ; authority = [] ; additional = [] } in
        encode query
    in
    Some (Cstruct.sub errbuf 0 off, max_reply_udp)
  else
    None
