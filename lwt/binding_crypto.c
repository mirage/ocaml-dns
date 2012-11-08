/*
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
 */

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <caml/alloc.h>
#include <caml/callback.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/memory.h>
#include <caml/mlvalues.h>
#include <caml/signals.h>
#include <caml/unixsupport.h>

#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

#include <openssl/md5.h>
#include <openssl/sha.h>

// SSL
/* Some definitions from Ocaml-SSL */
#define Cert_val(v) (*((X509**)Data_custom_val(v)))
#define RSA_val(v) (*((RSA**)Data_custom_val(v)))
#define EVP_val(v) (*((EVP_PKEY**)Data_custom_val(v)))
#define Ctx_val(v) (*((SSL_CTX**)Data_custom_val(v)))
#define SSL_val(v) (*((SSL**)Data_custom_val(v)))

// RSA

#define RSA_val(v) (*((RSA**)Data_custom_val(v)))

/* Convert a BIGNUM into a string */
char *bn_to_hex(const BIGNUM *bn)
{
    char *res = "";
    caml_enter_blocking_section();
    if (bn != NULL)
        res = BN_bn2hex(bn);
    caml_leave_blocking_section();
    return res;
}

CAMLprim value ocaml_ssl_ext_new_rsa_key(value vfilename) {
    value block;
    RSA *rsa = NULL;
    caml_enter_blocking_section();
    rsa = RSA_new();
    if(rsa == NULL) {
        caml_leave_blocking_section();
        caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
    }
    caml_leave_blocking_section();

    block = caml_alloc(sizeof(RSA*), 0);
    RSA_val(block) = rsa;
    return block;
}

CAMLprim value ocaml_ssl_ext_free_rsa_key(value key) {
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    RSA_free(rsa);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_size(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    int size = 0;
    caml_enter_blocking_section();
    size = RSA_size(rsa);
    caml_leave_blocking_section();
    CAMLreturn(Val_int(size));
}

CAMLprim value ocaml_ssl_ext_rsa_get_n(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->n))));
}

CAMLprim value ocaml_ssl_ext_rsa_set_n(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    caml_enter_blocking_section();
    BN_hex2bn(&rsa->n, hex_val);
    caml_leave_blocking_section();
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_e(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->e))));
}

CAMLprim value ocaml_ssl_ext_rsa_set_e(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->e, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_d(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->d))));
}

CAMLprim value ocaml_ssl_ext_rsa_set_d(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->d, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_p(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->p))));
}
CAMLprim value ocaml_ssl_ext_rsa_set_p(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->p, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_q(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->q))));
}

CAMLprim value ocaml_ssl_ext_rsa_set_q(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->q, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_dp(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->dmp1))));
}
CAMLprim value ocaml_ssl_ext_rsa_set_dp(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->dmp1, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_dq(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->dmq1))));
}

CAMLprim value ocaml_ssl_ext_rsa_set_dq(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->dmq1, hex_val);
    CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_get_qinv(value key)
{
    CAMLparam1(key);
    RSA *rsa = RSA_val(key);
    CAMLreturn(caml_copy_string(String_val(bn_to_hex(rsa->iqmp))));
}
CAMLprim value ocaml_ssl_ext_rsa_set_qinv(value key, value val) {
    CAMLparam2(key, val);
    RSA *rsa = RSA_val(key);
    char *hex_val = String_val(val);
    BN_hex2bn(&rsa->iqmp, hex_val);
    CAMLreturn(Val_unit);
}

unsigned char* 
get_message_digest(const unsigned char *msg, int msg_len,
        int hash_method) {
  switch(hash_method)
  {
    case NID_md5:
      return MD5(msg, msg_len, NULL);
      break;
    case NID_sha1:
      return SHA1(msg, msg_len, NULL);
      break;
    case NID_sha256:
      return SHA256(msg, msg_len, NULL);
      break;
    case NID_sha512:
      return SHA512(msg, msg_len, NULL);
      break;
    default:
      caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
      break;
  }
}

int digest_len(int hash_method) {
  switch(hash_method) {
    case NID_md5: return MD5_DIGEST_LENGTH;
    case NID_sha1: return SHA_DIGEST_LENGTH;
    case NID_sha256: return SHA256_DIGEST_LENGTH;
    case NID_sha512: return SHA512_DIGEST_LENGTH;
    default: return 0;
  }
}

CAMLprim value ocaml_ssl_hash_msg(value hash_alg, value msg) {
  CAMLparam2(hash_alg, msg);
  
  CAMLlocal1(signature);
  int digest_alg;
  int alg = Int_val(hash_alg);
  unsigned char *buf = malloc(caml_string_length(msg));
  memcpy(buf, String_val(msg),caml_string_length(msg));

  switch(alg) {
    case 1:
      digest_alg = NID_sha1;
      break;
    case 2:
      digest_alg = NID_sha256;
      break;
    default:
      caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
      break;
  }

  int dgs_len = digest_len(digest_alg);
  unsigned char * dgs =
    get_message_digest((const unsigned char *)buf,
        caml_string_length(msg), digest_alg);

  signature =  caml_alloc_string(dgs_len);
  memcpy(String_val(signature), dgs, dgs_len);
  CAMLreturn(signature);
}

CAMLprim value ocaml_ssl_sign_msg(value key, value msg,
    value dnssec_alg) {
  CAMLparam3(key, msg, dnssec_alg);
  
  CAMLlocal1(signature);
  RSA *rsa = RSA_val(key);
  int digest_alg, encryption_alg;
  int alg = Int_val(dnssec_alg);
  unsigned char *buf = malloc(caml_string_length(msg));
  memcpy(buf, String_val(msg),caml_string_length(msg));

  switch(alg) {
    case 1:
      digest_alg = NID_md5;
      encryption_alg = NID_rsa;
      break;
    case 5:
      digest_alg = NID_sha1;
      encryption_alg = NID_rsa;
      break;
    case 8:
      digest_alg = NID_sha256;
      encryption_alg = NID_rsa;
      break;
    case 10:
      digest_alg = NID_sha512;
      encryption_alg = NID_rsa;
      break;
    default:
      caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
      break;
  }

  int dgs_len = digest_len(digest_alg);
  unsigned char * dgs =
    get_message_digest((const unsigned char *)buf,
        caml_string_length(msg), digest_alg);
  unsigned char *sign = malloc(RSA_size(rsa));
  unsigned int sig_len;

  if(RSA_sign(digest_alg, dgs, dgs_len,
      sign, &sig_len, rsa) == 0) {
    caml_named_value("ssl_ext_exn_rsa_error");
  }

  signature =  caml_alloc_string(sig_len);
  memcpy(String_val(signature), sign, sig_len);
  CAMLreturn(signature);
}

CAMLprim value ocaml_ssl_verify_msg(value key, value msg,
    value sign, value dnssec_alg) {
  CAMLparam4(key, msg, sign, dnssec_alg);
  
  RSA *rsa = RSA_val(key);
  int digest_alg;
  int alg = Int_val(dnssec_alg);
  unsigned char *buf = malloc(caml_string_length(msg));
  memcpy(buf, String_val(msg),caml_string_length(msg));
  switch(alg) {
    case 1:
      digest_alg = NID_md5;
      break;
    case 5:
      digest_alg = NID_sha1;
      break;
    case 8:
      digest_alg = NID_sha256;
      break;
    case 10:
      digest_alg = NID_sha512;
      break;
   default:
      caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
      break;
  }

  int dgs_len = digest_len(digest_alg);
  unsigned char * dgs =
    get_message_digest((const unsigned char *)buf,
        caml_string_length(msg), digest_alg);
  int ret = RSA_verify(digest_alg, dgs, dgs_len,
      String_val(sign), caml_string_length(sign), 
      rsa);
  printf ("verify %d\n", ret);
  CAMLreturn (Val_int(ret));
}

CAMLprim value ocaml_ssl_ext_rsa_write_pubkey(value vfilename,
    value key) {
  CAMLparam2(vfilename, key);
  RSA *rsa = RSA_val(key);
  char *filename = String_val(vfilename);
  FILE *fh = NULL;

  if((fh = fopen(filename, "w")) == NULL) {
    caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
  }

  caml_enter_blocking_section();
  if((PEM_write_RSAPublicKey(fh, rsa)) == 0){
    fclose(fh);
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
  }
  fclose(fh);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}

CAMLprim value ocaml_ssl_ext_rsa_write_privkey(value vfilename,
    value key) {
  CAMLparam2(vfilename, key);
  RSA *rsa = RSA_val(key);
  char *filename = String_val(vfilename);
  FILE *fh = NULL;

  if((fh = fopen(filename, "w")) == NULL) {
    caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
  }

  caml_enter_blocking_section();
  if((PEM_write_RSAPrivateKey(fh, rsa, NULL, NULL, 0,
          PEM_def_callback, NULL)) == NULL){
    fclose(fh);
    caml_leave_blocking_section();
    caml_raise_constant(*caml_named_value("ssl_ext_exn_rsa_error"));
  }
  fclose(fh);
  caml_leave_blocking_section();

  CAMLreturn(Val_unit);
}
