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

open Dns.Packet 
open Dns.Name 

type key = 
  | Rsa of Dnssec_rsa.rsa_key

type dnssec_state

val init_dnssec : ?resolver:Dns_resolver.t option -> unit -> 
  dnssec_state Lwt.t
val add_anchor : dnssec_state -> rr -> unit

type dnssec_result = 
  | Signed of rr list
  | Failed of rr list
  | Unsigned of rr list
val dnssec_result_to_string : dnssec_result -> string

(* Methods to resolve dnssec verified records from dns *)
val verify_rr : dnssec_state -> rr list -> rdata ->
  bool Lwt.t

(* Methods to sign a zone file *)
val load_rsa_key : string -> (dnssec_alg * key)
val sign_records : ?inception:int32 -> ?expiration:int32 -> 
  dnssec_alg -> key -> int -> domain_name -> rr list -> rr
val get_dnskey_tag : rdata -> int
val get_ds_rr : domain_name -> digest_alg -> rdata -> rdata

val get_dnskey_rr : ?ksk:bool -> ?zsk:bool -> dnssec_alg -> 
  key -> rdata

val resolve : dnssec_state -> q_class -> q_type -> domain_name ->
  dnssec_result Lwt.t 
