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
open Dns.Packet
open Dns.Name
open Printf

module C = Cryptokit

external ssl_hash_msg : int -> string -> string = 
  "ocaml_ssl_hash_msg"

type key = 
| Rsa of Dnssec_rsa.rsa_key

type dnssec_result = 
  | Signed of rr list 
  | Failed of rr list
  | Unsigned of rr list

let dnssec_result_to_string = function
  | Signed r -> 
      sprintf "Signed result: %s\n"
      (List.fold_right 
      (fun r ret -> sprintf "%s\n%s" ret (rr_to_string r)) 
      r "" )
  | Failed r -> 
      sprintf "Failed result: %s\n"
      (List.fold_right 
      (fun r ret -> sprintf "%s\n%s" ret (rr_to_string r)) 
      r "" )
  | Unsigned r -> 
      sprintf "Unsigned result: %s\n"
      (List.fold_right 
      (fun r ret -> sprintf "%s\n%s" ret (rr_to_string r)) 
      r "" )

let get_dnskey_tag rdata =
  match rdata with
  | DNSKEY(_, RSAMD5, key) -> 
      failwith "Need to implement dnskey_tag for RSAMD5"
  | DNSKEY(_, RSASHA1, key)
  | DNSKEY(_, RSASHA256, key)
  | DNSKEY(_,RSASHA512, key) ->
      let names = Hashtbl.create 0 in 
      let buf = Lwt_bytes.create 1024 in 
      let (_, _, len) = marshal_rdata names 0 buf rdata in
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
   | DNSKEY(_, alg, _) -> 
      failwith (sprintf "unsupported %s algorith" 
            (dnssec_alg_to_string alg))
  | _ -> failwith("get_dnssec_key_tag: ")

(*
 * DNSSEC state definition and management 
 * *)
type dnssec_state = {
  resolver: Dns_resolver.t; 
  mutable anchors : (rr * key) list;
  (* store here the dnskeys that I have verified 
   * Keep also time, so I can timeout stuff *)
  mutable cache : (rr * float * key) list;
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
      let key =  Rsa (Dnssec_rsa.dnskey_to_rsa_key key) in 
        st.anchors <- st.anchors @ [(anchor, key)]
    | DNSKEY (_, alg, _) -> 
      failwith (sprintf "add_anchor: unsupported %s" 
      (dnssec_alg_to_string alg))
    | _ -> failwith "add_anchor: Invalid rdata type"

let cache_timeout st =
  st.cache <- List.filter (
    fun (rr, ts, key) -> 
      if ((Int32.to_float rr.ttl) +. ts < Unix.gettimeofday ()) then
        let _ = match key with 
                | Rsa k -> Dnssec_rsa.free_rsa_key k 
        in 
          false
      else true
 ) st.cache 

let lookup_dnskey_cache st tag owner =
  try 
    let _ = cache_timeout st in 
    let (_, _, key) = List.find 
      (fun (rr, ts, key) -> 
        match rr.rdata with 
        | DNSKEY (_, alg, dnskey) ->
            let dnskey_tag = get_dnskey_tag rr.rdata in
            (dnskey_tag = tag) && 
            ((Dns.Name.domain_name_to_string owner) = 
               (Dns.Name.domain_name_to_string rr.name)) 
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
            (dnskey_tag = tag) && 
            ((Dns.Name.domain_name_to_string owner) = 
               (Dns.Name.domain_name_to_string rr.name)) 
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
      let key = Dnssec_rsa.dnskey_to_rsa_key key in 
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
      | (0l, [], RR_A) -> (rr.ttl, rr.name, (rdata_to_rr_type rr.rdata))
      | (ttl, name, typ) when (ttl = rr.ttl || name = rr.name || typ =
        (rdata_to_rr_type rr.rdata)) -> ret
      | _ -> failwith "SInged rr's must have the same ttl, name and type"
  ) rrset (0l, [], RR_A)

let get_dnskey_rr ?(ksk=true) ?(zsk=false) alg key =
  let flags =  (if (ksk) then 0x100 else 0x0) lor
     (if (zsk) then 0x1 else 0x0) in
  let key_bytes = 
    match (key) with
      | Rsa key -> Dnssec_rsa.rsa_key_to_dnskey key 
      | _ -> failwith "Unsupported key type"
  in 
    DNSKEY(flags, alg, key_bytes)

let get_ds_rr owner digest rdata =
  match (rdata) with
  | DNSKEY(_, alg, key) -> 
     let names = Hashtbl.create 0 in 
      let buf = Lwt_bytes.create 1024 in
      let (_, name_len, _) = marshal_name names 0 buf owner in  
      let (_, _, len) = marshal_rdata names 0 
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
        DS(tag, alg, digest, value)
  | _ -> failwith("get_dnssec_key_tag: Invalid rdata ")

let resolve_record st typ owner = 
  try_lwt
   lwt pkt = Dns_resolver.resolve ~dnssec:true 
              st.resolver Q_IN typ owner in 
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
        ) pkt.answers ([], None) in 
    match (ds_rr, ds_rrsig) with
      | [], _ -> failwith (sprintf "no ds record found for %s"
                    (domain_name_to_string owner))
      | _, None -> failwith (sprintf "no rrsig record of %s records for %s"
                    (Dns.Packet.q_type_to_string typ) (domain_name_to_string owner))
      | a, Some b -> return (a, b)
  with ex -> 
    failwith (sprintf "get_ds_record failed:%s" (Printexc.to_string ex))

let marshal_rrsig_data ttl rrsig rrset =
  let buf = Lwt_bytes.create 4096 in
  (* Firstly marshal the rrsig field *)
  let names = Hashtbl.create 0 in
  let (_, names, rdbuf) = marshal_rdata names
                            0 buf rrsig in
  let rrset =
    List.sort (
      fun a b ->
        compare_rdata a.rdata b.rdata
    ) rrset in
  let rec marshall_rrset off buf = function
    | [] -> off
    | rr :: rrset -> 
        let names = Hashtbl.create 0 in 
        let buf = Cstruct.shift buf off in 
        let _, rdlen, _ = 
          marshal_rr ~compress:false (names, 0, buf) 
          ({name=rr.name; ttl=ttl; cls=rr.cls;
                   rdata=rr.rdata;}) in
        off + (marshall_rrset rdlen buf rrset)
  in 

  let rdlen = marshall_rrset rdbuf buf rrset in
    Cstruct.to_string (Cstruct.sub buf 0 rdlen)
  
let sign_records 
  ?(inception=(Int32.of_float (Unix.gettimeofday ()))) (* inception now *)
  ?(expiration=(Int32.of_float ((Unix.gettimeofday ()) +. 604800.0))) (* 1 week duration *)
  alg key tag owner rrset =
  let ttl, name, typ = extract_type_from_rrset rrset in
  let lbl = char_of_int (List.length name ) in 
  let unsign_sig_rr = RRSIG(typ, alg, lbl, ttl, expiration, inception,
    tag, owner, "") in
  let data = marshal_rrsig_data ttl unsign_sig_rr rrset in 
  let sign = 
      match key with
      | Rsa key -> Dnssec_rsa.sign_msg alg key data
      | _ -> failwith "invalid key type"
    in
      ({
       name=[]; cls=RR_IN; ttl=0l;
       rdata=(RRSIG(typ, alg, lbl, ttl, expiration, inception,
              tag, owner, sign)); })

let verify_rrsig ttl inception expiration alg key tag 
      owner rrset sign =
 let _, name, typ = extract_type_from_rrset rrset in 
  (* Firstly marshal the rrsig field *)
  printf "checking key %s using key  for %s - %d\n%!" 
          (domain_name_to_string name) 
          (domain_name_to_string owner) tag;
   let lbl = char_of_int (List.length name ) in 
  let unsign_sig_rr = 
    RRSIG(typ, alg, lbl, ttl, expiration, inception, 
          tag, owner, "") in
  let data = marshal_rrsig_data ttl unsign_sig_rr rrset in 
    match key with
      | Rsa key -> Dnssec_rsa.verify_msg alg key data sign
      | _ -> failwith "invalid key type"

(*
 * Methods to resolve and verify dnssec records 
 * *)
let rec verify_rr st rr rrsig =
  try_lwt
    match rrsig with 
    | RRSIG (typ, alg, lbl, ttl, exp_ts, inc_ts, tag, 
                    owner, sign) ->
        begin
      let anchor_key = lookup_dnskey_anchors st tag owner in 
      let cache_key = lookup_dnskey_cache st tag owner in
        match (anchor_key, cache_key) with
          | (Some key, _) -> 
              let _ = printf "signing dnskey for %s found in anchor\n%!"
                (rdata_to_string rrsig) in 
              return (verify_rrsig ttl inc_ts exp_ts alg
                        key tag owner rr sign)
          | (_, Some key) -> 
              let _ = printf "signing dnskey for %s in cache \n%!"
                (rdata_to_string rrsig) in
              return (verify_rrsig ttl inc_ts exp_ts alg 
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
                    (domain_name_to_string owner) in 
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
              printf "look for signing dnskey for %s\n%!"
                      (domain_name_to_string owner); 
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

let get_dnssec_key_of_owner st tag owner = 
  let anchor_key = lookup_dnskey_anchors st tag owner in 
  let cache_key = lookup_dnskey_cache st tag owner in
  match (anchor_key, cache_key) with
    | (Some key, _) 
    | (_, Some key) -> 
        return key
    | (None, None) -> 
      lwt keys, rrsig = resolve_record st Q_DNSKEY owner in
      lwt ret = verify_rr st keys rrsig in 
        match ret with 
        | false -> failwith "cannot find signing key"
        | true ->
            let rr = 
              List.find 
                (fun rr -> 
                  match rr.rdata with 
                  | DNSKEY (_, RSAMD5, dnskey) 
                  | DNSKEY (_, RSASHA1, dnskey) 
                  | DNSKEY (_, RSASHA256, dnskey) 
                  | DNSKEY (_, RSASHA512, dnskey) ->
                    let dnskey_tag = get_dnskey_tag rr.rdata in
                      (dnskey_tag = tag) && (owner = rr.name) 
                  | _ -> false
                ) keys in
            let DNSKEY(_, _, key) = rr.rdata in 
             return (Rsa (Dnssec_rsa.dnskey_to_rsa_key key))

let sign_packet 
  ?(inception=(Int32.of_float (Unix.gettimeofday ()))) (* inception now *)
  ?(expiration=(Int32.of_float ((Unix.gettimeofday ()) +. 300.0))) (* 1 week duration *)
  alg key tag owner pkt =
  let data = Lwt_bytes.create 4096 in 
  let rdata = SIG(alg, expiration, inception, tag, owner, "") in
  let names = Hashtbl.create 0 in 
  let (_, _, rdlen) = 
    marshal_rdata names ~compress:false 0 data rdata in
  let buf = Cstruct.shift data rdlen in 
  let datalen = Cstruct.len (marshal buf pkt) in
  let buf = Cstruct.to_string (Cstruct.sub data 0 (rdlen + datalen)) in
  let sign = 
    match key with
      | Rsa key -> Dnssec_rsa.sign_msg alg key buf
      | _ -> failwith "invalid key type"
  in
  let sig0 = ({
    name=[]; cls=RR_ANY; ttl=0l;
    rdata=(SIG(alg, expiration, inception, tag, owner, sign)); }) in
    {id=pkt.id; detail=pkt.detail;questions=pkt.questions; 
     answers=pkt.answers; authorities=pkt.authorities; 
     additionals=(pkt.additionals@[sig0]);} 


let verify_packet st pkt =
  try_lwt 
    let rec fetch_sig0 sig0 = function
      | [] -> ([], sig0)
      | hd::tl 
          when (Dns.Packet.rdata_to_rr_type hd.rdata = RR_SIG) ->
          let SIG(alg, exp_ts, inc_ts, tag, name, sign) = hd.rdata in 
          let additionals, _ = fetch_sig0 sig0 tl in 
           ((additionals), Some(alg, exp_ts, inc_ts, tag, name, sign))
      | hd :: tl -> 
          let additionals, sig0 = fetch_sig0 sig0 tl in 
            ((additionals @ [hd]), sig0)
    in
    let additionals, sig0 = fetch_sig0 None pkt.additionals in 
    let alg, expiration, inception, tag, owner, sign = 
      match sig0 with 
      | None -> failwith "sig0 records not found"
      | Some(alg, exp_ts, inc_ts, tag, owner, sign) -> 
          alg, exp_ts, inc_ts, tag, owner, sign 
    in
    let pkt = 
      {id=pkt.id; detail=pkt.detail;questions=pkt.questions; 
        answers=pkt.answers; authorities=pkt.authorities; 
        additionals;} in 
   let data = Lwt_bytes.create 4096 in 
   let rdata = SIG(alg, expiration, inception, tag, owner, "") in
   let names = Hashtbl.create 0 in 
   let (_, _, rdlen) = 
     marshal_rdata names ~compress:false 0 data rdata in
   let buf = Cstruct.shift data rdlen in 
   let datalen = Cstruct.len (marshal buf pkt) in
   let buf = Cstruct.to_string (Cstruct.sub data 0 (rdlen + datalen)) in
   lwt key = get_dnssec_key_of_owner st tag owner in
     match key with
      | Rsa key -> return (Dnssec_rsa.verify_msg alg key buf sign)
      | _ -> return false
  with exn -> 
    let _ = eprintf "[sec] verify_packet failed:%s\n%!" 
              (Printexc.to_string exn) in
      return false


let resolve st q typ name =
  lwt p = Dns_resolver.resolve st.resolver ~dnssec:true q typ name in
  let Some(rr_type) = int_to_rr_type (q_type_to_int typ) in 
  let (rr, rrsig) = 
    List.fold_right (
      fun r (rr, rrsig) ->
        match r.rdata with 
        | a when (rdata_to_rr_type a = rr_type ) -> 
            (rr @ [r], rrsig) 
        | RRSIG (typ, _, _, _, _, _, _, _, _) when (typ = rr_type) -> 
            (rr, Some(r.rdata) )
        | _ -> (rr, rrsig)
    ) p.answers ([], None) in
    match rrsig with
    | None -> return (Unsigned rr)
    | Some rrsig -> begin
        lwt res = verify_rr st rr rrsig in
          if (res) then 
            return (Signed rr)
          else 
            return (Failed rr)
    end 
(*
 * Key reading methods
 *
 * *)
let load_rsa_key file =
  let alg, key = (Dnssec_rsa.load_key file) in 
    alg, Rsa key
