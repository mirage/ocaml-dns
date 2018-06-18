(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]

val pp_err : [< Dns_name.err | `BadTTL of int32
             | `BadRRTyp of int | `DisallowedRRTyp of Dns_enum.rr_typ
             | `BadClass of int | `DisallowedClass of Dns_enum.clas | `UnsupportedClass of Dns_enum.clas
             | `BadOpcode of int | `UnsupportedOpcode of Dns_enum.opcode | `BadRcode of int | `BadCaaTag | `LeftOver
             | `NonZeroTTL of int32
             | `NonZeroRdlen of int | `InvalidZoneCount of int
             | `InvalidZoneRR of Dns_enum.rr_typ
             | `InvalidTimestamp of int64 | `InvalidAlgorithm of Domain_name.t
             | `BadProto of int | `BadAlgorithm of int
             | `BadOpt | `BadKeepalive
             | `BadTlsaCertUsage of int | `BadTlsaSelector of int | `BadTlsaMatchingType of int
             | `BadSshfpAlgorithm of int | `BadSshfpType of int
             | `Bad_edns_version of int
             | `Multiple_tsig
             | `Multiple_edns
             | `Tsig_not_last
             ] Fmt.t

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

val pp_header : header Fmt.t

val encode_header : Cstruct.t -> header -> unit

val decode_header : Cstruct.t ->
  (header, [> `Partial | `BadOpcode of int | `BadRcode of int ]) result

type question = {
  q_name : Domain_name.t ;
  q_type : Dns_enum.rr_typ ;
}

val decode_question : (Domain_name.t * int) Dns_name.IntMap.t ->
  Cstruct.t ->
  int ->
  (question * (Domain_name.t * int) Dns_name.IntMap.t * int,
   [> `BadClass of Cstruct.uint16
   | `BadContent of string
   | `BadOffset of int
   | `BadRRTyp of Cstruct.uint16
   | `BadTag of int
   | `Partial
   | `TooLong
   | `UnsupportedClass of Dns_enum.clas ])
    result

val pp_question : question Fmt.t

type soa = {
  nameserver : Domain_name.t ;
  hostmaster : Domain_name.t ;
  serial : int32 ;
  refresh : int32 ;
  retry : int32 ;
  expiry : int32 ;
  minimum : int32 ;
}

val pp_soa : soa Fmt.t

val compare_soa : soa -> soa -> int

type tsig_algo =
  | SHA1
  | SHA224
  | SHA256
  | SHA384
  | SHA512

val pp_tsig_algo : tsig_algo Fmt.t

type tsig = private {
  algorithm : tsig_algo ;
  signed : Ptime.t ;
  fudge : Ptime.Span.t ;
  mac : Cstruct.t ;
  original_id : int ; (* again 16 bit *)
  error : Dns_enum.rcode ;
  other : Ptime.t option ;
}

val valid_time : Ptime.t -> tsig -> bool

val tsig : algorithm:tsig_algo -> signed:Ptime.t -> ?fudge:Ptime.Span.t ->
  ?mac:Cstruct.t -> ?original_id:int -> ?error:Dns_enum.rcode ->
  ?other:Ptime.t -> unit -> tsig option

val with_mac : tsig -> Cstruct.t -> tsig

val with_error : tsig -> Dns_enum.rcode -> tsig

val with_signed : tsig -> Ptime.t -> tsig option

val with_other : tsig -> Ptime.t option -> tsig option

val pp_tsig : tsig Fmt.t

val encode_raw_tsig : Domain_name.t -> tsig -> Cstruct.t
val encode_full_tsig : Domain_name.t -> tsig -> Cstruct.t

type dnskey = {
  flags : int ; (* uint16 *)
  key_algorithm :  Dns_enum.dnskey ; (* u_int8_t *)
  key : Cstruct.t ;
}

val dnskey_of_string : string -> dnskey option

val pp_dnskey : dnskey Fmt.t

val dnskey_to_tsig_algo : dnskey -> tsig_algo option

val compare_dnskey : dnskey -> dnskey -> int

type srv = {
  priority : int ;
  weight : int ;
  port : int ;
  target : Domain_name.t
}

val pp_srv : srv Fmt.t

val compare_srv : srv -> srv -> int

type caa = {
  critical : bool ;
  tag : string ;
  value : string list ;
}

val compare_caa : caa -> caa -> int

val pp_caa : caa Fmt.t

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

val opt : ?extended_rcode:int -> ?version:int -> ?dnssec_ok:bool ->
  ?payload_size:int -> ?extensions:extension list -> unit -> opt

val compare_extension : extension -> extension -> int

val compare_opt : opt -> opt -> int

val pp_extension : extension Fmt.t

val pp_opt : opt Fmt.t

val encode_opt : opt -> Cstruct.t

type tlsa = {
  tlsa_cert_usage : Dns_enum.tlsa_cert_usage ;
  tlsa_selector : Dns_enum.tlsa_selector ;
  tlsa_matching_type : Dns_enum.tlsa_matching_type ;
  tlsa_data : Cstruct.t ;
}

val compare_tlsa : tlsa -> tlsa -> int

val pp_tlsa : tlsa Fmt.t

type sshfp = {
  sshfp_algorithm : Dns_enum.sshfp_algorithm ;
  sshfp_type : Dns_enum.sshfp_type ;
  sshfp_fingerprint : Cstruct.t ;
}

val compare_sshfp : sshfp -> sshfp -> int

val pp_sshfp : sshfp Fmt.t

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

val pp_rdata : rdata Fmt.t

val rdata_name : rdata -> Domain_name.Set.t

val compare_rdata : rdata -> rdata -> int

val rdata_to_rr_typ : rdata -> Dns_enum.rr_typ

type rr = {
  name : Domain_name.t ;
  ttl : int32 ;
  rdata : rdata ;
}

val rr_equal : rr -> rr -> bool

val rr_name : rr -> Domain_name.Set.t

val rr_names : rr list -> Domain_name.Set.t

val pp_rr : rr Fmt.t

val pp_rrs : rr list Fmt.t

type query = {
  question : question list ;
  answer : rr list ;
  authority : rr list ;
  additional : rr list ;
}

val pp_query : query Fmt.t

type rr_prereq =
  | Exists of Domain_name.t * Dns_enum.rr_typ
  | Exists_data of Domain_name.t * rdata
  | Not_exists of Domain_name.t * Dns_enum.rr_typ
  | Name_inuse of Domain_name.t
  | Not_name_inuse of Domain_name.t

type rr_update =
  | Remove of Domain_name.t * Dns_enum.rr_typ
  | Remove_all of Domain_name.t
  | Remove_single of Domain_name.t * rdata
  | Add of rr

val rr_update_name : rr_update -> Domain_name.t

val pp_rr_update : rr_update Fmt.t

type update = {
  zone : question ;
  prereq : rr_prereq list ;
  update : rr_update list ;
  addition : rr list ;
}

val pp_update : update Fmt.t

type v = [ `Query of query | `Update of update | `Notify of query ]
val pp_v : v Fmt.t

type t = header * v * opt option * (Domain_name.t * tsig) option
val pp : t Fmt.t

type tsig_verify = ?mac:Cstruct.t -> Ptime.t -> v -> header ->
  Domain_name.t -> key:dnskey option -> tsig -> Cstruct.t ->
  (tsig * Cstruct.t * dnskey, Cstruct.t) result

type tsig_sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> tsig ->
  key:dnskey -> Cstruct.t -> (Cstruct.t * Cstruct.t) option

val decode : Cstruct.t ->
  (t * int option,
   [> Dns_name.err
   | `BadOpcode of int | `BadRcode of int
   | `UnsupportedOpcode of Dns_enum.opcode
   | `BadTTL of int32
   | `BadRRTyp of int | `DisallowedRRTyp of Dns_enum.rr_typ
   | `BadClass of int | `DisallowedClass of Dns_enum.clas
   | `UnsupportedClass of Dns_enum.clas
   | `BadProto of int | `BadAlgorithm of int | `BadOpt | `BadKeepalive
   | `BadCaaTag
   | `LeftOver
   | `InvalidTimestamp of int64 | `InvalidAlgorithm of Domain_name.t
   | `NonZeroTTL of int32
   | `NonZeroRdlen of int | `InvalidZoneCount of int
   | `InvalidZoneRR of Dns_enum.rr_typ
   | `BadTlsaCertUsage of int | `BadTlsaSelector of int | `BadTlsaMatchingType of int
   | `BadSshfpAlgorithm of int | `BadSshfpType of int
   | `Bad_edns_version of int
   | `Multiple_tsig | `Multiple_edns
   | `Tsig_not_last
   ]) result

val encode : ?max_size:int -> ?edns:opt -> proto -> header -> v -> Cstruct.t * int

val error : header -> v -> Dns_enum.rcode -> (Cstruct.t * int) option
