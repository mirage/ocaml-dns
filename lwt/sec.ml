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

open Packet
open Printf

module C = Cryptokit

type key = 
| Rsa of Rsa.rsa_key

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
              printf "key size is %d\n%!" !size;
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
          | typ :: value ->
              Printf.printf "read field:%s\n%!" typ; parse_file in_stream
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

let extract_type_from_rrset rrset = 
  List.fold_right (
    fun rr ret ->
      match ret with
      | None -> Some(rr.ttl, rr.name, (Packet.rdata_to_rr_type rr.rdata))
      | Some(ttl, name, typ) when (ttl = rr.ttl || name = rr.name || typ =
        (Packet.rdata_to_rr_type rr.rdata)) -> ret
      | _ -> failwith "SInged rr's must have the same ttl, name and type"
  ) rrset None

let sign_records 
  ?(inception=(Int32.of_float (Unix.gettimeofday ()))) (* inception now *)
  ?(expiration=604800l) (* 1 week duration *) 
  alg key tag owner rrset =
    let ttl, name, typ = 
      match (extract_type_from_rrset rrset) with
      | None -> failwith "Invalid set of rr's requested from sign"
      | Some(ttl, name, typ) -> ttl, name,typ
    in
    (* Firstly marshal the rrsig field *)
    let buf = Lwt_bytes.create 4096 in 
    let name_len = char_of_int (List.length name) in 
    let unsign_sig_rr = RRSIG(typ, alg, name_len, ttl, expiration, inception,
    tag, owner, "") in
    let names = Hashtbl.create 0 in 
    let (_, names, rdbuf) = Packet.marshal_rdata names 0 buf unsign_sig_rr in 
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
    let data = Cstruct.to_string (Cstruct.sub buf 0 rdlen) in
   let sign = 
      match key with
      | Rsa key -> Rsa.sign_msg alg key data
      | _ -> failwith "invalid key type"
    in
     Packet.({
       name=name; cls=Packet.RR_IN; ttl=ttl;
       rdata=(RRSIG(typ, alg, name_len, ttl, expiration, inception,
              tag, owner, sign)); })
