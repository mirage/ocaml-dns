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

module C = Cryptokit

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

external new_rsa_key : unit -> rsa_key = "ocaml_ssl_ext_new_rsa_key"
external free_rsa_key : rsa_key -> unit = "ocaml_ssl_ext_free_rsa_key"

external rsa_get_size : rsa_key -> int = "ocaml_ssl_ext_rsa_get_size"
external rsa_get_n : rsa_key -> string = "ocaml_ssl_ext_rsa_get_n"
external rsa_set_n : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_n"
external rsa_get_e : rsa_key -> string = "ocaml_ssl_ext_rsa_get_e"
external rsa_set_e : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_e"
external rsa_get_d : rsa_key -> string = "ocaml_ssl_ext_rsa_get_d"
external rsa_set_d : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_d"
external rsa_get_p : rsa_key -> string = "ocaml_ssl_ext_rsa_get_p"
external rsa_set_p : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_p"
external rsa_get_q : rsa_key -> string = "ocaml_ssl_ext_rsa_get_q"
external rsa_set_q : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_q"
external rsa_get_dp : rsa_key -> string = "ocaml_ssl_ext_rsa_get_dp"
external rsa_set_dp : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_dp"
external rsa_get_dq : rsa_key -> string = "ocaml_ssl_ext_rsa_get_dq"
external rsa_set_dq : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_dq"
external rsa_get_qinv : rsa_key -> string = "ocaml_ssl_ext_rsa_get_qinv"
external rsa_set_qinv : rsa_key -> string -> unit = "ocaml_ssl_ext_rsa_set_qinv"

let hex_of_string s = 
  let ret = ref "" in 
  String.iter (fun x -> ret := !ret ^ (Printf.sprintf "%02x" (Char.code x)) ) s;
  !ret

let from_hex s = (* if s = "" then "" else *) C.transform_string (C.Hexa.decode()) s
let to_hex s = (* if s = "" then "" else *) C.transform_string (C.Hexa.encode()) s

let new_rsa_key_from_param param = 
  let ret = new_rsa_key () in 
    rsa_set_n ret (hex_of_string param.n); 
    rsa_set_e ret (hex_of_string param.e); 
    rsa_set_d ret (hex_of_string param.d); 
    rsa_set_p ret (hex_of_string param.p); 
    rsa_set_q ret (hex_of_string param.q); 
    rsa_set_dp ret (hex_of_string param.dp); 
    rsa_set_dq ret (hex_of_string param.dq); 
    rsa_set_qinv ret (hex_of_string param.qinv);
    ret

let sign alg key data =
  failwith "unimplemented rsa sign"
