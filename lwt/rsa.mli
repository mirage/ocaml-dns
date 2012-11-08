(*
 * Copyright (c) 2011 Charalampos Rotsos <cr409@cl.cam.ac.uk>
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

type param =
  { size: int;    (** Size of the modulus [n], in bits *)
      n: string;    (** Modulus [n = p.q] *)
      e: string;    (** Public exponent [e] *)
      d: string;    (** Private exponent [d] *)
      p: string;    (** Prime factor [p] of [n] *)
      q: string;    (** The other prime factor [q] of [n] *)
      dp: string;   (** [dp] is [d mod (p-1)] *)
      dq: string;   (** [dq] is [d mod (q-1)] *)
      qinv: string  (** [qinv] is a multiplicative inverse of [q] modulo [p] *)
  }

type rsa_key

val load_key: string -> (Packet.dnssec_alg * rsa_key)
val new_rsa_key_from_param : param -> rsa_key
val free_rsa_key : rsa_key -> unit 

val sign_msg : Packet.dnssec_alg -> rsa_key -> string -> string
val verify_msg : Packet.dnssec_alg -> rsa_key -> string -> 
  string -> bool
val rsa_key_to_dnskey : rsa_key -> string
val dnskey_to_rsa_key : string -> rsa_key

(* Just for debugging purposes *)
val rsa_write_privkey : string -> rsa_key -> unit
