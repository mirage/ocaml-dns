(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]
(** The type of support protocols (influence maximum packet size, encoding,
   etc.). *)

val pp_err : [< Udns_name.err | `BadTTL of int32
             | `BadRRTyp of int | `DisallowedRRTyp of Udns_enum.rr_typ
             | `BadClass of int | `DisallowedClass of Udns_enum.clas | `UnsupportedClass of Udns_enum.clas
             | `BadOpcode of int | `UnsupportedOpcode of Udns_enum.opcode | `BadRcode of int | `BadCaaTag | `LeftOver
             | `NonZeroTTL of int32
             | `NonZeroRdlen of int | `InvalidZoneCount of int
             | `InvalidZoneRR of Udns_enum.rr_typ
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
(** [pp_err ppf err] pretty-prints the [err] on [ppf]. *)

type header = {
  id : int ;
  query : bool ;
  operation : Udns_enum.opcode ;
  authoritative : bool ;
  truncation : bool ;
  recursion_desired : bool ;
  recursion_available : bool ;
  authentic_data : bool ;
  checking_disabled : bool ;
  rcode : Udns_enum.rcode ;
}
(** The header of a DNS packet: it's identifer, query or response, operation,
   flags, and return code. *)

val pp_header : header Fmt.t
(** [pp_header ppf header] pretty-prints [header] on [ppf]. *)

val encode_header : Cstruct.t -> header -> unit
(** [encode_header buf header] encodes the [header] into [buf] at offset 0.
    Raises an exception if the buffer is too small. *)

val decode_header : Cstruct.t ->
  (header, [> `Partial | `BadOpcode of int | `BadRcode of int ]) result
(** [decode_header buf] decodes the buffer at offset 0 and returns either a
    header or an error. *)

type question = {
  q_name : Domain_name.t ;
  q_type : Udns_enum.rr_typ ;
}
(** The type of DNS questions: a domain-name and a resource record type. The
   class is always IN. *)

val decode_question : (Domain_name.t * int) Udns_name.IntMap.t ->
  Cstruct.t ->
  int ->
  (question * (Domain_name.t * int) Udns_name.IntMap.t * int,
   [> `BadClass of Cstruct.uint16
   | `BadContent of string
   | `BadOffset of int
   | `BadRRTyp of Cstruct.uint16
   | `BadTag of int
   | `Partial
   | `TooLong
   | `UnsupportedClass of Udns_enum.clas ])
    result
(** [decode_question names buffer offset] decodes a question at [offset] from
   [buffer], applying label decompression. The new offset and offset to names
   map are returned together with the question, or an error. *)

val pp_question : question Fmt.t
(** [pp_question ppf question] pretty-prints the [question] on [ppf]. *)

type soa = {
  nameserver : Domain_name.t ;
  hostmaster : Domain_name.t ;
  serial : int32 ;
  refresh : int32 ;
  retry : int32 ;
  expiry : int32 ;
  minimum : int32 ;
}
(** The type of a start of authority (SOA) entry. *)

val pp_soa : soa Fmt.t
(** [pp_soa ppf soa] pretty-prints the [soa] on [ppf]. *)

val compare_soa : soa -> soa -> int
(** [compare_soa soa soa'] compares the serial, nameserver, hostmaster, refresh,
    retry, expiry, and minimum of two SOA records. *)

type tsig_algo =
  | SHA1
  | SHA224
  | SHA256
  | SHA384
  | SHA512
(** The type of TSIG algorithms. *)

val pp_tsig_algo : tsig_algo Fmt.t
(** [pp_tsig_algo ppf algo] pretty-prints the [algo] on [ppf]. *)

type tsig = private {
  algorithm : tsig_algo ;
  signed : Ptime.t ;
  fudge : Ptime.Span.t ;
  mac : Cstruct.t ;
  original_id : int ; (* again 16 bit *)
  error : Udns_enum.rcode ;
  other : Ptime.t option ;
}
(** The type of TSIG signatures. *)

val valid_time : Ptime.t -> tsig -> bool
(** [valid_time now tsig] checks whether the tsig timestamp is within
    [now - fudge < timstamp && timestamp < now + fudge] *)

val tsig : algorithm:tsig_algo -> signed:Ptime.t -> ?fudge:Ptime.Span.t ->
  ?mac:Cstruct.t -> ?original_id:int -> ?error:Udns_enum.rcode ->
  ?other:Ptime.t -> unit -> tsig option
(** [tsig ~algorithm ~signed ~fudge ~mac ~original_id ~error ~other ()]
    constructs a tsig if timestamp and fudge fit into their ranges. *)

val with_mac : tsig -> Cstruct.t -> tsig
(** [with_mac tsig mac] replaces the [mac] field of [tsig] with the provided one. *)

val with_error : tsig -> Udns_enum.rcode -> tsig
(** [with_error tsig error] replaces the [error] field of [tsig] with the provided one. *)

val with_signed : tsig -> Ptime.t -> tsig option
(** [with_signed tsig signed] replaces the [signed] field of [tsig] with the provided one. *)

val with_other : tsig -> Ptime.t option -> tsig option
(** [with_other tsig now] replaces the [other] field of [tsig] with the provided one. *)

val pp_tsig : tsig Fmt.t
(** [pp_tsig ppf tsig] pretty-prints the [tsig] on [ppf]. *)

val encode_raw_tsig : Domain_name.t -> tsig -> Cstruct.t
(** [encode_raw_tsig name tsig] is the encoded header to be used to compute signatures. *)

val encode_full_tsig : Domain_name.t -> tsig -> Cstruct.t
(** [encode_full_tsig name tsig] is the encoded [tsig] resource record. *)

type dnskey = {
  flags : int ; (* uint16 *)
  key_algorithm :  Udns_enum.dnskey ; (* u_int8_t *)
  key : Cstruct.t ;
}
(** The type of dnskey resource records. *)

val dnskey_of_string : string -> dnskey option
(** [dnskey_of_string str] parses [str] from [flags:]algorithm:base64-key. *)

val name_dnskey_of_string : string -> (Domain_name.t * dnskey, [ `Msg of string ]) result
(** [name_dnskey_of_string str] attempts to parse a domain_name, colon (':'),
    and a dnskey (optional flags, algorithm, base64-key). *)

val pp_dnskey : dnskey Fmt.t
(** [pp_dnskey ppf dnskey] pretty-prints the [dnskey] on [ppf]. *)

val dnskey_to_tsig_algo : dnskey -> tsig_algo option
(** [dnskey_to_tsig_algo dnskey] is [Some tsig_algorithm], or [None]. *)

val compare_dnskey : dnskey -> dnskey -> int
(** [compare_dnskey key key'] compares the keys. *)

type srv = {
  priority : int ;
  weight : int ;
  port : int ;
  target : Domain_name.t
}
(** The type for service resource records. *)

val pp_srv : srv Fmt.t
(** [pp_srv ppf srv] pretty-prints [srv] on [ppf]. *)

val compare_srv : srv -> srv -> int
(** [compare_srv srv srv'] compares the service records [srv] and [srv']. *)

type caa = {
  critical : bool ;
  tag : string ;
  value : string list ;
}
(** The type of CAA resource records. *)

val compare_caa : caa -> caa -> int
(** [compare_caa caa caa'] compare the CAA records [caa] and [caa']. *)

val pp_caa : caa Fmt.t
(** [pp_caa ppf caa] pretty-prints the [caa] on [ppf]. *)

type extension =
  | Nsid of Cstruct.t
  | Cookie of Cstruct.t
  | Tcp_keepalive of int option
  | Padding of int
  | Extension of int * Cstruct.t
(** The type of EDNS extensions. *)

type opt = {
  extended_rcode : int ;
  version : int ;
  dnssec_ok : bool ;
  payload_size : int ;
  extensions : extension list ;
}
(** The type of an EDNS resource record. *)

val opt : ?extended_rcode:int -> ?version:int -> ?dnssec_ok:bool ->
  ?payload_size:int -> ?extensions:extension list -> unit -> opt
(** [opt ~extended_rcode ~version ~dnssec_ok ~payload_size ~extensions ()]
    constructs an EDNS resource record type. *)

val reply_opt : opt option -> int option * opt option
(** [reply_opt opt] embeds the payload size from [opt] into a new EDNS record. *)

val compare_extension : extension -> extension -> int
(** [compare_extension e e'] compares [e] with [e']. *)

val compare_opt : opt -> opt -> int
(** [compare_opt opt opt'] compares [opt] with [opt']. *)

val pp_extension : extension Fmt.t
(** [pp_extension ppf extension] pretty-prints the [extension] on [ppf]. *)

val pp_opt : opt Fmt.t
(** [pp_opt ppf opt] pretty-prints the [opt] on [ppf]. *)

val encode_opt : opt -> Cstruct.t
(** [encode_opt opt] encodes [opt] into a freshly allocated buffer. *)

type tlsa = {
  tlsa_cert_usage : Udns_enum.tlsa_cert_usage ;
  tlsa_selector : Udns_enum.tlsa_selector ;
  tlsa_matching_type : Udns_enum.tlsa_matching_type ;
  tlsa_data : Cstruct.t ;
}
(** The type of TLSA resource records. *)

val compare_tlsa : tlsa -> tlsa -> int
(** [compare_tlsa tlsa tlsa'] compares [tlsa] with [tlsa']. *)

val pp_tlsa : tlsa Fmt.t
(** [pp_tlsa ppf tlsa] pretty-prints [tlsa] on [ppf]. *)

type sshfp = {
  sshfp_algorithm : Udns_enum.sshfp_algorithm ;
  sshfp_type : Udns_enum.sshfp_type ;
  sshfp_fingerprint : Cstruct.t ;
}
(** The type of SSHFP resource records. *)

val compare_sshfp : sshfp -> sshfp -> int
(** [compare_sshfp sshfp sshfp'] compares [sshfp] with [sshfp']. *)

val pp_sshfp : sshfp Fmt.t
(** [pp_sshfp ppf sshfp] pretty-prints [sshfp] on [ppf]. *)

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
  | Raw of Udns_enum.rr_typ * Cstruct.t
  (** The type of resource record payload. *)

val pp_rdata : rdata Fmt.t
(** [pp_rdata ppf rdata] pretty-prints [rdata] on [ppf]. *)

val rdata_name : rdata -> Domain_name.Set.t
(** [rdata_name rdata] returns the set of refered names in [rdata]. *)

val compare_rdata : rdata -> rdata -> int
(** [compare_rdata rdata rdata'] compares [rdata] with [rdata']. *)

val rdata_to_rr_typ : rdata -> Udns_enum.rr_typ
(** [rdata_to_rr_typ rdata] is the resource record type of [rdata]. *)

type rr = {
  name : Domain_name.t ;
  ttl : int32 ;
  rdata : rdata ;
}
(** The type of a resource record: name, time-to-live, and rdata. *)

val rr_equal : rr -> rr -> bool
(** [rr_equal rr rr'] is [true] if [rr] and [rr'] are equal, [false] otherwise. *)

val rr_name : rr -> Domain_name.Set.t
(** [rr_name rr] is {!rdata_name rr.rdata}. *)

val rr_names : rr list -> Domain_name.Set.t
(** [rr_names rrs] is [rr_name] folded over [rrs]. *)

val pp_rr : rr Fmt.t
(** [pp_rr ppf rr] pretty-prints the resource record [rr] on [ppf]. *)

val pp_rrs : rr list Fmt.t
(** [pp_rrs ppf rrs] pretty-prints the resource records [rrs] on [ppf]. *)

type query = {
  question : question list ;
  answer : rr list ;
  authority : rr list ;
  additional : rr list ;
}
(** The type of a DNS query. *)

val pp_query : query Fmt.t
(** [pp_query ppf query] pretty-prints [query] on [ppf]. *)

type rr_prereq =
  | Exists of Domain_name.t * Udns_enum.rr_typ
  | Exists_data of Domain_name.t * rdata
  | Not_exists of Domain_name.t * Udns_enum.rr_typ
  | Name_inuse of Domain_name.t
  | Not_name_inuse of Domain_name.t
  (** The type of DNS update prerequisites. *)

type rr_update =
  | Remove of Domain_name.t * Udns_enum.rr_typ
  | Remove_all of Domain_name.t
  | Remove_single of Domain_name.t * rdata
  | Add of rr
  (** The type of DNS update actions. *)

val rr_update_name : rr_update -> Domain_name.t
(** [rr_update_name update] is the name used in the [update]. *)

val pp_rr_update : rr_update Fmt.t
(** [pp_rr_update ppf rr_update] pretty-prints the [rr_update] on [ppf]. *)

type update = {
  zone : question ;
  prereq : rr_prereq list ;
  update : rr_update list ;
  addition : rr list ;
}
(** The type of a DNS update packet. *)

val pp_update : update Fmt.t
(** [pp_update ppf update] pretty-prints [update] on [ppf]. *)

type v = [ `Query of query | `Update of update | `Notify of query ]
(** The type of a DNS packet value. *)

val pp_v : v Fmt.t
(** [pp_v ppf v] pretty-prints the DNS packet value [v] on [ppf]. *)

type t = header * v * opt option * (Domain_name.t * tsig) option
(** The type of a DNS packet: header, value, optionally EDNS, and an optional
    signature (name, tsig). *)

val pp : t Fmt.t
(** [pp ppf t] pretty-prints [t] on [ppf]. *)

type tsig_verify = ?mac:Cstruct.t -> Ptime.t -> v -> header ->
  Domain_name.t -> key:dnskey option -> tsig -> Cstruct.t ->
  (tsig * Cstruct.t * dnskey, Cstruct.t option) result
(** The type of a tsig_verify function. *)

type tsig_sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> tsig ->
  key:dnskey -> Cstruct.t -> (Cstruct.t * Cstruct.t) option
(** The type of a tsig_sign function. *)

val decode : Cstruct.t ->
  (t * int option,
   [> Udns_name.err
   | `BadOpcode of int | `BadRcode of int
   | `UnsupportedOpcode of Udns_enum.opcode
   | `BadTTL of int32
   | `BadRRTyp of int | `DisallowedRRTyp of Udns_enum.rr_typ
   | `BadClass of int | `DisallowedClass of Udns_enum.clas
   | `UnsupportedClass of Udns_enum.clas
   | `BadProto of int | `BadAlgorithm of int | `BadOpt | `BadKeepalive
   | `BadCaaTag
   | `LeftOver
   | `InvalidTimestamp of int64 | `InvalidAlgorithm of Domain_name.t
   | `NonZeroTTL of int32
   | `NonZeroRdlen of int | `InvalidZoneCount of int
   | `InvalidZoneRR of Udns_enum.rr_typ
   | `BadTlsaCertUsage of int | `BadTlsaSelector of int | `BadTlsaMatchingType of int
   | `BadSshfpAlgorithm of int | `BadSshfpType of int
   | `Bad_edns_version of int
   | `Multiple_tsig | `Multiple_edns
   | `Tsig_not_last
   ]) result
(** [decode buf] decodes the buffer into a DNS packet, and optionally an offset
   to the last resource record (TSIG is computed over the encoded packet without
   TSIG). Any error may occur. *)

val encode : ?max_size:int -> ?edns:opt -> proto -> header -> v -> Cstruct.t * int
(** [encode ~max_size ~edns proto header v] encodes [header] and [v] into a
    freshly allocated buffer, [edns] is appended. If the buffer would exceed
    [max_size] or [proto] restrictions, the truncation bit is set. *)

val error : header -> v -> Udns_enum.rcode -> (Cstruct.t * int) option
(** [error hdr v rcode] encodes a DNS error with the given header, and the first
   question taken from [v]. If the query bit in [hdr] is set, nothing is
   returned (never reply to a reply). *)
