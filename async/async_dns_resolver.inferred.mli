module DP :
  sig
    type digest_alg = Dns.Packet.digest_alg = SHA1 | SHA256
    val digest_alg_to_string : digest_alg -> string
    val string_to_digest_alg : string -> digest_alg option
    val digest_alg_to_int : digest_alg -> int
    val int_to_digest_alg : int -> digest_alg option
    type gateway_tc = Dns.Packet.gateway_tc
    type pubkey_alg = Dns.Packet.pubkey_alg
    type ipseckey_alg = Dns.Packet.ipseckey_alg
    type gateway = Dns.Packet.gateway
    type hash_alg = Dns.Packet.hash_alg
    type fp_type = Dns.Packet.fp_type
    type dnssec_alg =
      Dns.Packet.dnssec_alg =
        RSAMD5
      | DH
      | DSA
      | ECC
      | RSASHA1
      | RSANSEC3
      | RSASHA256
      | RSASHA512
      | INDIRECT
      | PRIVATEDNS
      | PRIVATEOID
    val dnssec_alg_to_string : dnssec_alg -> string
    val string_to_dnssec_alg : string -> dnssec_alg option
    val int_to_dnssec_alg : int -> dnssec_alg option
    val dnssec_alg_to_int : dnssec_alg -> int
    type q_type =
      Dns.Packet.q_type =
        Q_A
      | Q_NS
      | Q_MD
      | Q_MF
      | Q_CNAME
      | Q_SOA
      | Q_MB
      | Q_MG
      | Q_MR
      | Q_NULL
      | Q_WKS
      | Q_PTR
      | Q_HINFO
      | Q_MINFO
      | Q_MX
      | Q_TXT
      | Q_RP
      | Q_AFSDB
      | Q_X25
      | Q_ISDN
      | Q_RT
      | Q_NSAP
      | Q_NSAPPTR
      | Q_SIG
      | Q_KEY
      | Q_PX
      | Q_GPOS
      | Q_AAAA
      | Q_LOC
      | Q_NXT
      | Q_EID
      | Q_NIMLOC
      | Q_SRV
      | Q_ATMA
      | Q_NAPTR
      | Q_KM
      | Q_CERT
      | Q_A6
      | Q_DNAME
      | Q_SINK
      | Q_OPT
      | Q_APL
      | Q_DS
      | Q_SSHFP
      | Q_IPSECKEY
      | Q_RRSIG
      | Q_NSEC
      | Q_DNSKEY
      | Q_NSEC3
      | Q_NSEC3PARAM
      | Q_SPF
      | Q_UINFO
      | Q_UID
      | Q_GID
      | Q_UNSPEC
      | Q_AXFR
      | Q_MAILB
      | Q_MAILA
      | Q_ANY_TYP
      | Q_TA
      | Q_DLV
      | Q_UNKNOWN of int
    val q_type_to_int : q_type -> int
    type rr_type =
      Dns.Packet.rr_type =
        RR_UNUSED
      | RR_A
      | RR_NS
      | RR_MD
      | RR_MF
      | RR_CNAME
      | RR_SOA
      | RR_MB
      | RR_MG
      | RR_MR
      | RR_NULL
      | RR_WKS
      | RR_PTR
      | RR_HINFO
      | RR_MINFO
      | RR_MX
      | RR_TXT
      | RR_RP
      | RR_AFSDB
      | RR_X25
      | RR_ISDN
      | RR_RT
      | RR_NSAP
      | RR_NSAPPTR
      | RR_SIG
      | RR_KEY
      | RR_PX
      | RR_GPOS
      | RR_AAAA
      | RR_LOC
      | RR_NXT
      | RR_EID
      | RR_NIMLOC
      | RR_SRV
      | RR_ATMA
      | RR_NAPTR
      | RR_KM
      | RR_CERT
      | RR_A6
      | RR_DNAME
      | RR_SINK
      | RR_OPT
      | RR_APL
      | RR_DS
      | RR_SSHFP
      | RR_IPSECKEY
      | RR_RRSIG
      | RR_NSEC
      | RR_DNSKEY
      | RR_NSEC3
      | RR_NSEC3PARAM
      | RR_SPF
      | RR_UINFO
      | RR_UID
      | RR_GID
      | RR_UNSPEC
    val string_to_rr_type : string -> rr_type option
    val rr_type_to_string : rr_type -> string
    val int_to_rr_type : int -> rr_type option
    val rr_type_to_int : rr_type -> int
    type type_bit_map = Dns.Packet.type_bit_map
    type type_bit_maps = Dns.Packet.type_bit_maps
    type rdata =
      Dns.Packet.rdata =
        A of Ipaddr.V4.t
      | AAAA of Ipaddr.V6.t
      | AFSDB of int * Dns.Name.domain_name
      | CNAME of Dns.Name.domain_name
      | DNSKEY of int * dnssec_alg * string
      | DS of int * dnssec_alg * digest_alg * string
      | HINFO of string * string
      | IPSECKEY of char * gateway_tc * ipseckey_alg * gateway * string
      | ISDN of string * string option
      | MB of Dns.Name.domain_name
      | MD of Dns.Name.domain_name
      | MF of Dns.Name.domain_name
      | MG of Dns.Name.domain_name
      | MINFO of Dns.Name.domain_name * Dns.Name.domain_name
      | MR of Dns.Name.domain_name
      | MX of int * Dns.Name.domain_name
      | NS of Dns.Name.domain_name
      | NSEC of Dns.Name.domain_name * type_bit_maps
      | NSEC3 of hash_alg * char * int * char * string * char * string *
          type_bit_maps
      | NSEC3PARAM of hash_alg * char * int * char * string
      | PTR of Dns.Name.domain_name
      | RP of Dns.Name.domain_name * Dns.Name.domain_name
      | RRSIG of rr_type * dnssec_alg * char * int32 * int32 * int32 * 
          int * Dns.Name.domain_name * string
      | SIG of dnssec_alg * int32 * int32 * int * Dns.Name.domain_name *
          string
      | RT of int * Dns.Name.domain_name
      | SOA of Dns.Name.domain_name * Dns.Name.domain_name * int32 * 
          int32 * int32 * int32 * int32
      | SRV of int * int * int * Dns.Name.domain_name
      | SSHFP of pubkey_alg * fp_type * string
      | TXT of string list
      | UNKNOWN of int * string
      | WKS of Ipaddr.V4.t * char * string
      | X25 of string
      | EDNS0 of (int * int * bool * (int * string) list)
    val hex_of_string : string -> string
    val rdata_to_string : rdata -> string
    val rdata_to_rr_type : rdata -> rr_type
    val marshal_rdata :
      int Dns.Name.Map.t ->
      ?compress:bool ->
      int -> Cstruct.t -> rdata -> rr_type * int Dns.Name.Map.t * int
    val compare_rdata : rdata -> rdata -> int
    exception Not_implemented
    val parse_rdata :
      (int, Dns.Name.label) Hashtbl.t ->
      int -> rr_type -> int -> int32 -> Cstruct.t -> rdata
    type rr_class =
      Dns.Packet.rr_class =
        RR_IN
      | RR_CS
      | RR_CH
      | RR_HS
      | RR_ANY
    val rr_class_to_string : rr_class -> string
    type rr =
      Dns.Packet.rr = {
      name : Dns.Name.domain_name;
      cls : rr_class;
      ttl : int32;
      rdata : rdata;
    }
    val rr_to_string : rr -> string
    val marshal_rr :
      ?compress:bool ->
      int Dns.Name.Map.t * int * Cstruct.t ->
      rr -> int Dns.Name.Map.t * int * Cstruct.t
    val parse_rr :
      (int, Dns.Name.label) Hashtbl.t ->
      int -> Cstruct.t -> rr * (int * Cstruct.t)
    val q_type_matches_rr_type : q_type -> rr_type -> bool
    val q_type_to_string : q_type -> string
    val string_to_q_type : string -> q_type option
    type q_class =
      Dns.Packet.q_class =
        Q_IN
      | Q_CS
      | Q_CH
      | Q_HS
      | Q_NONE
      | Q_ANY_CLS
    val q_class_to_string : q_class -> string
    val string_to_q_class : string -> q_class option
    type question =
      Dns.Packet.question = {
      q_name : Dns.Name.domain_name;
      q_type : q_type;
      q_class : q_class;
    }
    val question_to_string : question -> string
    val parse_question :
      (int, Dns.Name.label) Hashtbl.t ->
      int -> Cstruct.t -> question * (int * Cstruct.t)
    type qr = Dns.Packet.qr = Query | Response
    type opcode =
      Dns.Packet.opcode =
        Standard
      | Inverse
      | Status
      | Reserved
      | Notify
      | Update
    val opcode_to_string : opcode -> string
    type rcode =
      Dns.Packet.rcode =
        NoError
      | FormErr
      | ServFail
      | NXDomain
      | NotImp
      | Refused
      | YXDomain
      | YXRRSet
      | NXRRSet
      | NotAuth
      | NotZone
      | BadVers
      | BadKey
      | BadTime
      | BadMode
      | BadName
      | BadAlg
    val rcode_to_string : rcode -> string
    type detail =
      Dns.Packet.detail = {
      qr : qr;
      opcode : opcode;
      aa : bool;
      tc : bool;
      rd : bool;
      ra : bool;
      rcode : rcode;
    }
    type t =
      Dns.Packet.t = {
      id : int;
      detail : detail;
      questions : question list;
      answers : rr list;
      authorities : rr list;
      additionals : rr list;
    }
    val to_string : t -> string
    val parse : Dns.Buf.t -> t
    val marshal : Dns.Buf.t -> t -> Dns.Buf.t
  end


type result = Answer of DP.t | Error of exn
type commfn = {
  txfn : Dns.Buf.t -> unit Async_kernel.Deferred.t;
  rxfn : (Dns.Buf.t -> Dns.Packet.t option) -> DP.t Async_kernel.Deferred.t;
  timerfn : unit -> unit Async_kernel.Deferred.t;
  cleanfn : unit -> unit Async_kernel.Deferred.t;
}
val stdout_writer : unit -> Async_unix.Writer.t
val stderr_writer : unit -> Async_unix.Writer.t
val message : string -> unit
val warn : string -> unit

val nchoose_split :
  'a Async_kernel.Deferred.t list ->
  ('a list * 'a Async_kernel.Deferred.t list) Async_kernel.Deferred.t

val send_req :
  ('a -> 'b Async_kernel.Deferred.t) ->
  (unit -> unit Async_kernel.Deferred.t) ->
  'a -> int -> unit Async_kernel.Deferred.t

val send_pkt :
  (module Dns.Protocol.CLIENT) ->
  commfn -> DP.t -> DP.t Async_kernel.Deferred.t

val resolve :
  (module Dns.Protocol.CLIENT) ->
  ?dnssec:bool ->
  commfn ->
  DP.q_class ->
  DP.q_type -> Dns.Name.domain_name -> DP.t Async_kernel.Deferred.t
  
val gethostbyname :
  ?q_class:DP.q_class ->
  ?q_type:DP.q_type ->
  commfn ->
  string ->
  (Ipaddr.V4.t, Ipaddr.V6.t) Ipaddr.v4v6 list Async_kernel.Deferred.t
