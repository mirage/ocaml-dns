(*
 * Copyright (c) 2012 Charalampos Rotsos <cr409@cl.cam.ac.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

(* RFC 2535 *)
open Lwt
open Packet
open Printf

module C = Cryptokit

external ssl_hash_msg : int -> string -> string = 
  "ocaml_ssl_hash_msg"

type key = 
| Rsa of Rsa.rsa_key

let get_dnskey_tag rdata =
  match rdata with
  | Packet.DNSKEY(_, Packet.RSAMD5, key) -> 
      failwith "Need to implement dnskey_tag for RSAMD5"
  | Packet.DNSKEY(_, Packet.RSASHA1, key)
  | Packet.DNSKEY(_, Packet.RSASHA256, key)
  | Packet.DNSKEY(_,Packet.RSASHA512, key) ->
      let names = Hashtbl.create 0 in 
      let buf = Lwt_bytes.create 1024 in 
      let (_, _, len) = Packet.marshal_rdata names 0 buf rdata in
      let buf = Cstruct.sub buf 0 len in 
      let res = ref 0l in
      let ix = ref 0 in 
      let _ = String.iter (
        fun ch ->
          let _ = 
            if ( (!ix land 1)  = 1) then 
              res := Int32.add !res (Int32.of_int (int_of_char ch))
            else
              res := Int32.add !res 
              (Int32.shift_left (Int32.of_int (int_of_char ch)) 8) 
          in 
            ix := !ix + 1
     ) (Cstruct.to_string buf) in
      Int32.to_int 
      (Int32.logand (Int32.add !res 
         (Int32.logand (Int32.shift_right (!res)  16) 0xffffl))  0xffffl)
   | Packet.DNSKEY(_, alg, _) -> 
      failwith (sprintf "unsupported %s algorith" 
            (dnssec_alg_to_string alg))
  | _ -> failwith("get_dnssec_key_tag: ")

(*
 * DNSSEC state definition and management 
 * *)
type dnssec_state = {
  resolver: Dns_resolver.t; 
  mutable anchors : (Packet.rr * key) list;
  (* store here the dnskeys that I have verified 
   * Keep also time, so I can timeout stuff *)
  mutable cache : (Packet.rr * float * key) list;
}

let init_dnssec ?(resolver=None) () =
  lwt resolver = 
    match resolver with 
    | None -> Dns_resolver.create () 
    | Some a -> return a
  in 
    return ({resolver; anchors=[]; cache=[];})

let add_anchor st anchor =
  if (not (List.exists (fun (a, _) -> a = anchor) st.anchors)) then
    match anchor.rdata with 
    | DNSKEY (_, RSAMD5, key)
    | DNSKEY (_, RSASHA1, key)
    | DNSKEY (_, RSASHA256, key)
    | DNSKEY (_, RSASHA512, key) -> 
      let key =  Rsa (Rsa.dnskey_to_rsa_key key) in 
        st.anchors <- st.anchors @ [(anchor, key)]
    | DNSKEY (_, alg, _) -> 
      failwith (sprintf "add_anchor: unsupported %s" 
      (dnssec_alg_to_string alg)) 

(* type dnssec_result = 
  | Signed of 'a
  | Failed of 'a
  | Unsigned of 'a *)

let cache_timeout st =
  st.cache <- List.filter (
    fun (rr, ts, _) -> 
      ((Int32.to_float rr.ttl) +. ts >= Unix.gettimeofday ())
 ) st.cache 

let lookup_dnskey_cache st tag owner =
  try 
    let _ = cache_timeout st in 
    let (_, _, key) = List.find 
      (fun (rr, ts, key) -> 
        match rr.rdata with 
        | DNSKEY (_, alg, dnskey) ->
            let dnskey_tag = get_dnskey_tag rr.rdata in
            (dnskey_tag = tag) && (owner = rr.name) 
        | _ -> false
    ) st.cache in
      Some (key)
  with Not_found -> None

let lookup_dnskey_anchors st tag owner = 
  try 
    let (_, key) = List.find 
      (fun (rr, key) -> 
        match rr.rdata with 
        | DNSKEY (_, alg, dnskey) ->
            let dnskey_tag = get_dnskey_tag rr.rdata in
            (dnskey_tag = tag) && (owner = rr.name) 
        | _ -> false
    ) st.anchors in
      Some (key)
  with Not_found -> None

let add_dnskey_to_cache st rr = 
  match rr.rdata with 
  | DNSKEY (_, RSAMD5, key)
  | DNSKEY (_, RSASHA1, key)
  | DNSKEY (_, RSASHA256, key)
  | DNSKEY (_, RSASHA512, key) -> 
      let key = Rsa.dnskey_to_rsa_key key in 
        st.cache <- st.cache @ [(rr, Unix.gettimeofday (), Rsa key)]
  | DNSKEY (_, alg, _) -> 
      failwith (sprintf "add_dnskey_to_cache: unsupported %s" 
      (dnssec_alg_to_string alg)) 
  | a -> failwith (sprintf "add_dnskey_to_cache: invalid record %s"
      (rr_to_string rr))

(*
 * DNSSEC resource records creation methods 
 * *)
let extract_type_from_rrset rrset = 
  List.fold_right (
    fun rr ret ->
      match ret with
      | (0l, [], RR_A) -> (rr.ttl, rr.name, (Packet.rdata_to_rr_type rr.rdata))
      | (ttl, name, typ) when (ttl = rr.ttl || name = rr.name || typ =
        (Packet.rdata_to_rr_type rr.rdata)) -> ret
      | _ -> failwith "SInged rr's must have the same ttl, name and type"
  ) rrset (0l, [], RR_A)

let get_dnskey_rr ?(ksk=true) ?(zsk=false) alg key =
  let flags =  (if (ksk) then 0x100 else 0x0) lor
     (if (zsk) then 0x1 else 0x0) in
  let key_bytes = 
    match (key) with
      | Rsa key -> Rsa.rsa_key_to_dnskey key 
      | _ -> failwith "Unsupported key type"
  in 
    DNSKEY(flags, alg, key_bytes)

let get_ds_rr owner digest rdata =
  match (rdata) with
  | Packet.DNSKEY(_, alg, key) -> 
     let names = Hashtbl.create 0 in 
      let buf = Lwt_bytes.create 1024 in
      let (_, name_len, _) = Name.marshal_name names 0 buf owner in  
      let (_, _, len) = Packet.marshal_rdata names 0 
                          (Cstruct.shift buf name_len) rdata in
      let buf = Cstruct.sub buf 0 (name_len + len) in
      let value = ssl_hash_msg  (digest_alg_to_int digest) 
          (Cstruct.to_string buf) in 
(*        match digest with
        | SHA1 -> 
            Cryptokit.hash_string (Cryptokit.Hash.sha1 ())
            (Cstruct.to_string buf) 
        | SHA256 -> 
            Cryptokit.hash_string (Cryptokit.Hash.sha256 ())
            (Cstruct.to_string buf)
        | _ -> failwith (sprintf "unsupported digest algorith")
      in *)
      let tag = get_dnskey_tag rdata in 
        Packet.DS(tag, alg, digest, value)
  | _ -> failwith("get_dnssec_key_tag: Invalid rdata ")

let marshal_rrsig_data ttl name rrsig rrset = 
  let buf = Lwt_bytes.create 4096 in 
  (* Firstly marshal the rrsig field *)
  let name_len = char_of_int (List.length name) in 
  let names = Hashtbl.create 0 in 
  let (_, names, rdbuf) = Packet.marshal_rdata names 
                            0 buf rrsig in 
  (* TODO If more than one records, I need to order them *)
  let rec marshall_rrset off buf = function
    | [] -> off
    | rr :: rrset -> 
      let names = Hashtbl.create 0 in 
      let buf = Cstruct.shift buf off in 
      let _, rdlen, _ = 
        marshal_rr (names, 0, buf) 
          Packet.({name=rr.name; ttl=ttl; cls=rr.cls;
                   rdata=rr.rdata;}) in
          off + (marshall_rrset rdlen buf rrset)
  in 
  let rdlen = marshall_rrset rdbuf buf rrset in
    Cstruct.to_string (Cstruct.sub buf 0 rdlen)
  
let sign_records 
  ?(inception=(Int32.of_float (Unix.gettimeofday ()))) (* inception now *)
  ?(expiration=604800l) (* 1 week duration *) 
  alg key tag owner rrset =
  let ttl, name, typ = extract_type_from_rrset rrset in
  let lbl = char_of_int (List.length name ) in 
  let unsign_sig_rr = RRSIG(typ, alg, lbl, ttl, expiration, inception,
    tag, owner, "") in
  let data = marshal_rrsig_data ttl name unsign_sig_rr rrset in 
  let sign = 
      match key with
      | Rsa key -> Rsa.sign_msg alg key data
      | _ -> failwith "invalid key type"
    in
     Packet.({
       name=name; cls=Packet.RR_IN; ttl=ttl;
       rdata=(RRSIG(typ, alg, lbl, ttl, expiration, inception,
              tag, owner, sign)); })
(*
 * Methods to resolve and verify dnssec records 
 * *)
let resolve_record st typ owner = 
  try_lwt
   lwt pkt = Dns_resolver.resolve ~dnssec:true 
              st.resolver Packet.Q_IN typ owner in 
   let (ds_rr, ds_rrsig) = 
     List.fold_right 
        (fun rr (ds_rr, ds_rrsig) ->
          match (rr.rdata) with
          | RRSIG (signed_typ, _, _, _, _, _, _, _, _)  
              when ((q_type_to_int typ) = (rr_type_to_int signed_typ)) -> 
              (ds_rr, Some(rr.rdata))
          | a when 
          (rr_type_to_int (rdata_to_rr_type a)) = (q_type_to_int typ) ->
            (ds_rr @ [rr], ds_rrsig) 
          | _ -> (ds_rr, ds_rrsig) 
        ) pkt.Packet.answers ([], None) in 
    match (ds_rr, ds_rrsig) with
      | [], _ -> failwith (sprintf "no ds record found for %s"
                    (Name.domain_name_to_string owner))
      | _, None -> failwith (sprintf "no rrsig record for DS records for %s"
                    (Name.domain_name_to_string owner))
      | a, Some b -> return (a, b)
  with ex -> 
    failwith (sprintf "get_ds_record failed:%s" (Printexc.to_string ex))

let verify_rr_inner ttl inception expiration alg key tag 
      owner rrset sign =
  printf "checking key using key \n%!";
  let _, name, typ = extract_type_from_rrset rrset in 
  (* Firstly marshal the rrsig field *)
  let lbl = char_of_int (List.length name ) in 
  let unsign_sig_rr = 
    RRSIG(typ, alg, lbl, ttl, expiration, inception, 
          tag, owner, "") in
  let data = marshal_rrsig_data ttl name unsign_sig_rr rrset in 
    match key with
      | Rsa key -> Rsa.verify_msg alg key data sign
      | _ -> failwith "invalid key type"

let rec verify_rr st rr rrsig =
  try_lwt
    match rrsig with 
    | Packet.RRSIG (typ, alg, lbl, ttl, exp_ts, inc_ts, tag, 
                    owner, sign) ->
        begin
      let anchor_key = lookup_dnskey_anchors st tag owner in 
      let cache_key = lookup_dnskey_cache st tag owner in
        match (anchor_key, cache_key) with
          | (Some key, _) -> 
              let _ = printf "signing dnskey for %s found in anchor\n%!"
                (Packet.rdata_to_string rrsig) in 
              return (verify_rr_inner ttl inc_ts exp_ts alg
                        key tag owner rr sign)
          | (_, Some key) -> 
              let _ = printf "signing dnskey for %s is cache \n%!"
                (Packet.rdata_to_string rrsig) in
              return (verify_rr_inner ttl inc_ts exp_ts alg 
                        key tag owner rr sign)
          | (_, _) ->
            match typ with 
            | RR_DNSKEY when ((List.hd rr).name = owner) -> begin 
              let dnskey_tag = 
                List.map (fun a -> 
                  get_dnskey_tag a.rdata) rr in
                if (List.mem tag dnskey_tag) then begin
                  let _ = 
                    printf "self-signed key, looking ds record for %s\n%!"
                    (Name.domain_name_to_string owner) in 
                  lwt (ds_rr, ds_rrsig) = resolve_record st Q_DS owner in
                   (* verify ds record signature, and the ds - dnskey 
                     * digest, add the key in cache and redo the check *)
                  lwt ds_verified = verify_rr st ds_rr ds_rrsig in
                  let rec contains_ds rr = function
                    | (DS(_, _, digest, msg)) :: tl -> 
                      (List.fold_right (fun rr res ->
                        let (DS (_, _, _, ds_digest) ) = 
                          get_ds_rr rr.name digest rr.rdata in
                        res || msg = ds_digest) rr false )
                        || (contains_ds rr tl) 
                    | [] -> false
                    | _ :: _ -> false
                  in
                    if (ds_verified && 
                      contains_ds rr (List.map (fun a->a.rdata) ds_rr) )
                    then
                      let _ = List.iter (add_dnskey_to_cache st) rr in
                        verify_rr st rr rrsig 
                    else 
                      return false
                end
                else 
                  return false
            end 
          | _ ->
              printf "non-dnskey. look for signing dnskey for %s\n%!"
                      (Name.domain_name_to_string owner); 
              lwt dnskey_rr, dnskey_rrsig  = 
                resolve_record st Q_DNSKEY owner in 
              lwt res = verify_rr st dnskey_rr dnskey_rrsig in
                if (res) then 
                  let _ = List.iter (add_dnskey_to_cache st) dnskey_rr in 
                    verify_rr st rr rrsig
                else
                  return false
      end 
    | _ -> failwith "verify_key: Invalid rr"
  with ex -> 
    let _ = eprintf "verify_rr failed: %s\n%!" (Printexc.to_string ex)in 
      return false 
  
(*
 * Key reading methods
 *
 * *)

let decode_value value = 
    C.transform_string (C.Base64.decode ()) 
        (Re_str.global_replace (Re_str.regexp "=") "" value)

let load_key file =
  let size = ref 0 in
  let n = ref "" in
  let e = ref "" in
  let d = ref "" in 
  let p = ref "" in
  let q = ref "" in 
  let dp = ref "" in 
  let dq = ref "" in 
  let qinv = ref "" in
  let dnssec_alg = ref RSAMD5 in 
  let fd = open_in file in 
  let rec parse_file in_stream =
    try
      let line = Re_str.split (Re_str.regexp "[\ \r]*:[\ \t]*") (input_line in_stream) in 
        match line with
          (* TODO: Need to check if this is an RSA key *)
          | "Modulus" :: value ->
              n := decode_value (List.hd value); 
              size := (String.length !n) * 8;
              parse_file in_stream 
          | "PublicExponent" :: value ->
              e := decode_value (List.hd value); parse_file in_stream             
          | "PrivateExponent" :: value ->
              d := decode_value (List.hd value); parse_file in_stream             
          | "Prime1" :: value ->
              p := decode_value (List.hd value); parse_file in_stream             
          | "Prime2" :: value ->
              q := decode_value (List.hd value); parse_file in_stream             
          | "Exponent1" :: value ->
              dp := decode_value (List.hd value); parse_file in_stream             
          | "Exponent2" :: value ->
              dq:= decode_value (List.hd value); parse_file in_stream             
          | "Coefficient" :: value ->
              qinv := decode_value (List.hd value); parse_file in_stream            
          | "Algorithm" :: value -> begin 
              let _ = 
                dnssec_alg := 
                match (int_to_dnssec_alg (int_of_string
                (List.hd (Re_str.split (Re_str.regexp "[\ \t]+") (List.hd
                value))))) with
                | None -> failwith "Unsupported dnssec algorithm" 
                | Some(a) when ((a=RSAMD5) || (a=RSASHA1) || (a=RSASHA256) || 
                                (a = RSASHA512)) -> a
                | Some a -> failwith (sprintf "Unsupported dnssec algorithm %s"
                                      (dnssec_alg_to_string a))
              in 
             parse_file in_stream 
          end
          | typ :: value -> parse_file in_stream
          | [] -> parse_file in_stream
    with  End_of_file -> ()
  in 
  let _ = parse_file fd in 
  let key = 
(*    C.RSA.new_key 1024 *)
    Rsa.({size=(!size);n=(!n);e=(!e);d=(!d);p=(!p);q=(!q);dp=(!dp);
    dq=(!dq);qinv=(!qinv);}) 
  in
    (!dnssec_alg, (Rsa (Rsa.new_rsa_key_from_param key)))
(* 
 * Helper function to extract the ttl, type and name of a number
 * of records from an rr list. 
 * *)


