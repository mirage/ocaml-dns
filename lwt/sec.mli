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
type key = 
  | Rsa of Rsa.rsa_key

type dnssec_state

val init_dnssec : ?resolver:Dns_resolver.t option -> unit -> 
  dnssec_state Lwt.t
val add_anchor : dnssec_state -> Packet.rr -> unit

(* type dnssec_result = 
  | Signed of 'a
  | Failed of 'a
  | Unsigned of 'a *)

(* Methods to resolve dnssec verified records from dns *)
val verify_rr : dnssec_state -> Packet.rr list -> Packet.rdata ->
  bool Lwt.t

(* Methods to sign a zone file *)
val load_key : string -> (Packet.dnssec_alg * key)
val sign_records : ?inception:int32 -> ?expiration:int32 -> 
  Packet.dnssec_alg -> key -> int -> Name.domain_name -> 
  Packet.rr list -> Packet.rr
val get_dnskey_tag : Packet.rdata -> int
val get_ds_rr : Name.domain_name -> Packet.digest_alg -> 
  Packet.rdata -> Packet.rdata

val get_dnskey_rr : ?ksk:bool -> ?zsk:bool -> Packet.dnssec_alg -> 
  key -> Packet.rdata 
