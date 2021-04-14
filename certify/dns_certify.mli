open Dns

val signing_request : [`host] Domain_name.t ->
  ?more_hostnames:([`raw] Domain_name.t list) ->
  X509.Private_key.t -> X509.Signing_request.t
(** [signing_request name ~more_hostnames key] creates a X509 signing request
    where [name] will be the common name in its subject, and if [more_hostnames]
    is provided and non-empty, [name :: more_hostnames] will be the value of a
    subjectAlternativeName extension. *)

val letsencrypt_name : 'a Domain_name.t ->
  ([ `raw ] Domain_name.t, [> `Msg of string ]) result
(** [letsencrypt_name host] is the service name at which we store let's encrypt
    certificates for the [host]. *)

val is_csr : Dns.Tlsa.t -> bool
(** [is_csr tlsa] is true if [tlsa] is a certificate signing request (cert_usage
    is Domain_issued_certificate, selector is Private, and matching_type is
    No_hash). *)

val csr : X509.Signing_request.t -> Dns.Tlsa.t
(** [csr req] is the signing request [req] encoded as TLSA record. *)

val is_certificate : Dns.Tlsa.t -> bool
(** [is_certificate tlsa] is true if [tlsa] is a certificate (cert_usage is
    Domain_issued_certificate, selector is Full_certificate, and matching_type
    is No_hash). *)

val certificate : X509.Certificate.t -> Dns.Tlsa.t
(** [certificate crt] is the certificate [crt] encoded as TLSA record. *)

val is_ca_certificate : Dns.Tlsa.t -> bool
(** [is_ca_certificate tlsa] is true if [tlsa] is a CA certificate (cert_usage
    is CA_constraint, selector is Full_certificate, and matching_type is
    No_hash). *)

val ca_certificate : Cstruct.t -> Dns.Tlsa.t
(** [ca_certificate data] is the CA certificate [data] encoded as TLSA record. *)

val is_name : 'a Domain_name.t -> bool
(** [is_name domain_name] is true if it contains the prefix used in this
    library ("_letsencrypt._tcp"). *)

type u_err = [
  | `Tsig of Dns_tsig.e
  | `Bad_reply of Packet.mismatch * Packet.t
  | `Unexpected_reply of Packet.reply
]
(** The type of update errors. *)

val pp_u_err : u_err Fmt.t
(** [pp_u_err ppf u] pretty-prints [u] on [ppf]. *)

val nsupdate : (int -> Cstruct.t) -> (unit -> Ptime.t) ->
  host:[ `host ] Domain_name.t -> keyname:'b Domain_name.t ->
  zone:[ `host ] Domain_name.t -> Dns.Dnskey.t -> X509.Signing_request.t ->
  (Cstruct.t * (Cstruct.t -> (unit, [> u_err ]) result),
   [> `Msg of string ]) result
(** [nsupdate rng now ~host ~keyname ~zone dnskey csr] is a buffer with a DNS
   update that removes all TLSA records from the given [host], and adds a single
   TLSA record containing the certificate signing request. It also returns a
   function which decodes a given answer, checks it to be a valid reply, and
   returns either unit or an error. The outgoing packet is signed with the
   provided [dnskey], the answer is checked to be signed by the same key. If
   the sign operation fails, [nsupdate] returns an error. *)

type q_err = [
  | `Decode of Packet.err
  | `Bad_reply of Packet.mismatch * Packet.t
  | `Unexpected_reply of Packet.reply
  | `No_tlsa
]
(** The type for query errors. *)

val pp_q_err : q_err Fmt.t
(** [pp_q_err ppf q] pretty-prints [q] on [ppf]. *)

val cert_matches_csr : ?until:Ptime.t -> Ptime.t -> X509.Signing_request.t ->
  X509.Certificate.t -> bool
(** [cert_matches_csr ~until now csr cert] is [true] if [cert] matches the
    signing request [csr], and is valid from [now] until [until] (defaults to
    [now]). The matching is [true] if the public key matches, and the set of
    hostnames in [csr] and [cert] are equal. A log message on the info level
    is emitted if the return value if [false]. *)

val query : (int -> Cstruct.t) -> Ptime.t -> [ `host ] Domain_name.t ->
  X509.Signing_request.t ->
  (Cstruct.t *
   (Cstruct.t -> (X509.Certificate.t * X509.Certificate.t list, [> q_err ]) result),
   [> `Msg of string ]) result
(** [query rng now csr] is a [buffer] with a DNS TLSA query for the name of
   [csr], and a function that decodes a given answer, either returning a X.509
   certificate valid [now] and matching [csr], and a CA chain, or an error. *)

val generate : ?key_seed:string -> ?bits:int -> ?key_data:string ->
  [ `RSA | `ED25519 | `P256 | `P384 | `P521 ] -> X509.Private_key.t
(** [generate ~key_seed ~bits ~key_data key_type] generates a private key from
    [key_seed] of the provided [key_type]. If no [key_seed] is provided, random
    data is used and the PEM-encoded private key is logged. If [key_type] is a
    EC key and [key_data] is provided, this is used as private key. *)
