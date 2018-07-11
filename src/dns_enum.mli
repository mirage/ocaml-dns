(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* retrieved and converted 2017-04-29 from https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml *)

type clas =
  (* Reserved0 [@id 0] RFC6895 *)
  | IN (* RFC1035 *)
  (* 2 Uassigned *)
  | CHAOS (* D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981. *)
  | HESIOD (* Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987. *)
  | NONE (* RFC2136 *)
  | ANY_CLASS (* RFC1035 *)
  (* 256-65279 Unassigned *)
  (* 65280-65534 Reserved for Private Use [RFC6895] *)
  (* ReservedFFFF [@id 65535] *)

val clas_to_int : clas -> int
val int_to_clas : int -> clas option

val pp_clas : clas Fmt.t

type rr_typ =
  | A (* a host address [RFC1035] *)
  | NS (* an authoritative name server,[RFC1035] *)
  | MD (* a mail destination (OBSOLETE - use MX),[RFC1035] *)
  | MF (* a mail forwarder (OBSOLETE - use MX),[RFC1035] *)
  | CNAME (* the canonical name for an alias,[RFC1035] *)
  | SOA (* marks the start of a zone of authority,[RFC1035] *)
  | MB (* a mailbox domain name (EXPERIMENTAL),[RFC1035] *)
  | MG (* a mail group member (EXPERIMENTAL),[RFC1035] *)
  | MR (* a mail rename domain name (EXPERIMENTAL),[RFC1035] *)
  | NULL (* a null RR (EXPERIMENTAL),[RFC1035] *)
  | WKS (* a well known service description,[RFC1035] *)
  | PTR (* a domain name pointer,[RFC1035] *)
  | HINFO (* host information,[RFC1035] *)
  | MINFO (* mailbox or mail list information,[RFC1035] *)
  | MX (* mail exchange,[RFC1035] *)
  | TXT (* text strings,[RFC1035] *)
  | RP (* for Responsible Person,[RFC1183] *)
  | AFSDB (* for AFS Data Base location,[RFC1183][RFC5864] *)
  | X25 (* for X.25 PSDN address,[RFC1183] *)
  | ISDN (* for ISDN address,[RFC1183] *)
  | RT (* for Route Through,[RFC1183] *)
  | NSAP (* "for NSAP address, NSAP style A record",[RFC1706] *)
  | NSAP_PTR (* "for domain name pointer, NSAP style",[RFC1348][RFC1637][RFC1706] *)
  | SIG (* for security signature,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008] *)
  | KEY (* for security key,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110] *)
  | PX (* X.400 mail mapping information,[RFC2163] *)
  | GPOS (* Geographical Position,[RFC1712] *)
  | AAAA (* IP6 Address,[RFC3596] *)
  | LOC (* Location Information,[RFC1876] *)
  | NXT (* Next Domain (OBSOLETE),[RFC3755][RFC2535] *)
  | EID (* Endpoint Identifier,[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],,1995-06 *)
  | NIMLOC (* Nimrod Locator,[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],,1995-06 *)
  | SRV (* Server Selection,[1][RFC2782] *)
  | ATMA (* ATM Address,"[ATM Forum Technical Committee, ""ATM Name System, V2.0"", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]" *)
  | NAPTR (* Naming Authority Pointer,[RFC2915][RFC2168][RFC3403] *)
  | KX (* Key Exchanger,[RFC2230] *)
  | CERT (* CERT,[RFC4398] *)
  | A6 (* A6 (OBSOLETE - use AAAA),[RFC3226][RFC2874][RFC6563] *)
  | DNAME (* ,DNAME,[RFC6672] *)
  | SINK (* SINK,[Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink],,1997-11 *)
  | OPT (* OPT,[RFC6891][RFC3225] *)
  | APL (* APL,[RFC3123] *)
  | DS (* Delegation Signer,[RFC4034][RFC3658] *)
  | SSHFP (* SSH Key Fingerprint,[RFC4255] *)
  | IPSECKEY (* IPSECKEY,[RFC4025] *)
  | RRSIG (* RRSIG,[RFC4034][RFC3755] *)
  | NSEC (* NSEC,[RFC4034][RFC3755] *)
  | DNSKEY (* DNSKEY,[RFC4034][RFC3755] *)
  | DHCID (* ,DHCID,[RFC4701] *)
  | NSEC3 (* NSEC3,[RFC5155] *)
  | NSEC3PARAM (* NSEC3PARAM,[RFC5155] *)
  | TLSA (* TLSA,[RFC6698] *)
  | SMIMEA (* S/MIME cert association,[RFC-ietf-dane-smime-16],SMIMEA/smimea-completed-template,2015-12-01 *)
  (* Unassigned,54 *)
  | HIP (* Host Identity Protocol,[RFC8005] *)
  | NINFO (* NINFO,[Jim_Reid],NINFO/ninfo-completed-template,2008-01-21 *)
  | RKEY (* RKEY,[Jim_Reid],RKEY/rkey-completed-template,2008-01-21 *)
  | TALINK (* Trust Anchor LINK,[Wouter_Wijngaards],TALINK/talink-completed-template,2010-02-17 *)
  | CDS (* Child DS,[RFC7344],CDS/cds-completed-template,2011-06-06 *)
  | CDNSKEY (* DNSKEY(s) the Child wants reflected in DS,[RFC7344],,2014-06-16 *)
  | OPENPGPKEY (* OpenPGP Key,[RFC7929],OPENPGPKEY/openpgpkey-completed-template,2014-08-12 *)
  | CSYNC (* Child-To-Parent Synchronization,[RFC7477],,2015-01-27 *)
  (* Unassigned,63-98 *)
  | SPF (* [RFC7208] *)
  | UINFO (* [IANA-Reserved] *)
  | UID (* [IANA-Reserved] *)
  | GID (* [IANA-Reserved] *)
  | UNSPEC (* [IANA-Reserved] *)
  | NID (* [RFC6742],ILNP/nid-completed-template *)
  | L32 (* [RFC6742],ILNP/l32-completed-template *)
  | L64 (* [RFC6742],ILNP/l64-completed-template *)
  | LP (* [RFC6742],ILNP/lp-completed-template *)
  | EUI48 (* an EUI-48 address,[RFC7043],EUI48/eui48-completed-template,2013-03-27 *)
  | EUI64 (* an EUI-64 address,[RFC7043],EUI64/eui64-completed-template,2013-03-27 *)
  (* Unassigned,110-248 *)
  | TKEY (* Transaction Key,[RFC2930] *)
  | TSIG (* Transaction Signature,[RFC2845] *)
  | IXFR (* incremental transfer,[RFC1995] *)
  | AXFR (* transfer of an entire zone,[RFC1035][RFC5936] *)
  | MAILB (* "mailbox-related RRs (MB, MG or MR)",[RFC1035] *)
  | MAILA (* mail agent RRs (OBSOLETE - see MX),[RFC1035] *)
  | ANY (* A request for all records the server/cache has available,[RFC1035][RFC6895] *)
  | URI (* URI,[RFC7553],URI/uri-completed-template,2011-02-22 *)
  | CAA (* Certification Authority Restriction,[RFC6844],CAA/caa-completed-template,2011-04-07 *)
  | AVC (* Application Visibility and Control,[Wolfgang_Riedel],AVC/avc-completed-template,2016-02-26 *)
  (* Unassigned,259-32767 *)
  | TA (* DNSSEC Trust Authorities,"[Sam_Weiler][http://cameo.library.cmu.edu/][
        Deploying DNSSEC Without a Signed Root.  Technical Report 1999-19,
                      Information Networking Institute, Carnegie Mellon University, April 2004.]",,2005-12-13 *)
  | DLV (* DNSSEC Lookaside Validation,[RFC4431] *)
  (* Unassigned,32770-65279 *)
  (* Private use,65280-65534 *)
  (* Reserved,65535 *)

val rr_typ_to_int : rr_typ -> int
val int_to_rr_typ : int -> rr_typ option
val pp_rr_typ : rr_typ Fmt.t

type opcode =
  | Query (* RFC1035 *)
  | IQuery (* Inverse Query, OBSOLETE) [RFC3425] *)
  | Status (* RFC1035 *)
  (* 3 Unassigned *)
  | Notify (* RFC1996 *)
  | Update (* RFC2136 *)
  (* 6-15 Unassigned *)

val opcode_to_int : opcode -> int
val int_to_opcode : int -> opcode option
val pp_opcode : opcode Fmt.t

type rcode =
  | NoError (* No Error,[RFC1035] *)
  | FormErr (* Format Error,[RFC1035] *)
  | ServFail (* Server Failure,[RFC1035] *)
  | NXDomain (* Non-Existent Domain,[RFC1035] *)
  | NotImp (* Not Implemented,[RFC1035] *)
  | Refused (* Query Refused,[RFC1035] *)
  | YXDomain (* Name Exists when it should not,[RFC2136][RFC6672] *)
  | YXRRSet (* RR Set Exists when it should not,[RFC2136] *)
  | NXRRSet (* RR Set that should exist does not,[RFC2136] *)
  | NotAuth (* Server Not Authoritative for zone,[RFC2136]
               9,NotAuth,Not Authorized,[RFC2845] *)
  | NotZone (* Name not contained in zone,[RFC2136] *)
  (* 11-15,Unassigned *)
  | BadVersOrSig (* 16,BADVERS,Bad OPT Version,[RFC6891]
                    16,BADSIG,TSIG Signature Failure,[RFC2845] *)
  | BadKey (* Key not recognized,[RFC2845] *)
  | BadTime (* Signature out of time window,[RFC2845] *)
  | BadMode (* BADMODE,Bad TKEY Mode,[RFC2930] *)
  | BadName (* BADNAME,Duplicate key name,[RFC2930] *)
  | BadAlg (* BADALG,Algorithm not supported,[RFC2930] *)
  | BadTrunc (* BADTRUNC,Bad Truncation,[RFC4635] *)
  | BadCookie (* BADCOOKIE,Bad/missing Server Cookie,[RFC7873] *)
  (* 24-3840,Unassigned *)
  (* 3841-4095,Reserved for Private Use,,[RFC6895] *)
  (* 4096-65534,Unassigned *)
  (* 65535,"Reserved, can be allocated by Standards Action",,[RFC6895] *)

val rcode_to_int : rcode -> int
val int_to_rcode : int -> rcode option
val pp_rcode : rcode Fmt.t

type edns_opt =
  (* 0,Reserved,,[RFC6891] *)
  | LLQ (* On-hold,[http://files.dns-sd.org/draft-sekar-dns-llq.txt] *)
  | UL (* On-hold,[http://files.dns-sd.org/draft-sekar-dns-ul.txt] *)
  | NSID (* NSID,Standard,[RFC5001] *)
  (* 4,Reserved,,[draft-cheshire-edns0-owner-option] *)
  | DAU (* DAU,Standard,[RFC6975] *)
  | DHU (* DHU,Standard,[RFC6975] *)
  | N3U (* N3U,Standard,[RFC6975] *)
  | Client_subnet (* edns-client-subnet,Optional,[RFC7871] *)
  | Expire (* Optional,[RFC7314] *)
  | Cookie (* COOKIE,Standard,[RFC7873] *)
  | TCP_keepalive (* edns-tcp-keepalive,Standard,[RFC7828] *)
  | Padding (* Padding,Standard,[RFC7830] *)
  | Chain (* CHAIN,Standard,[RFC7901] *)
  | Key_tag (* edns-key-tag,Optional,[RFC8145] *)
  (* 15-26945,Unassigned *)
  | DeviceID (* DeviceID,Optional,[https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2][Brian_Hartvigsen] *)
(* 26947-65000,Unassigned
65001-65534,Reserved for Local/Experimental Use,,[RFC6891]
65535,Reserved for future expansion,,[RFC6891] *)

val edns_opt_to_int : edns_opt -> int
val int_to_edns_opt : int -> edns_opt option
val pp_edns_opt : edns_opt Fmt.t

type dnskey =
  | MD5
  | SHA1
  | SHA224
  | SHA256
  | SHA384
  | SHA512

val dnskey_to_int : dnskey -> int
val int_to_dnskey : int -> dnskey option
val string_to_dnskey : string -> dnskey option
val pp_dnskey : dnskey Fmt.t
val dnskey_len : dnskey -> int

module RRMap : Map.S with type key = rr_typ

type tlsa_cert_usage =
  | CA_constraint
  | Service_certificate_constraint
  | Trust_anchor_assertion
  | Domain_issued_certificate

val tlsa_cert_usage_to_int : tlsa_cert_usage -> int
val int_to_tlsa_cert_usage : int -> tlsa_cert_usage option
val pp_tlsa_cert_usage : tlsa_cert_usage Fmt.t

type tlsa_selector =
  | Tlsa_full_certificate
  | Tlsa_subject_public_key_info
  | Tlsa_selector_private

val tlsa_selector_to_int : tlsa_selector -> int
val int_to_tlsa_selector : int -> tlsa_selector option
val pp_tlsa_selector : tlsa_selector Fmt.t

type tlsa_matching_type =
  | Tlsa_no_hash
  | Tlsa_SHA256
  | Tlsa_SHA512

val tlsa_matching_type_to_int : tlsa_matching_type -> int
val int_to_tlsa_matching_type : int -> tlsa_matching_type option
val pp_tlsa_matching_type : tlsa_matching_type Fmt.t

type sshfp_algorithm =
  | Sshfp_rsa
  | Sshfp_dsa
  | Sshfp_ecdsa
  | Sshfp_ed25519

val sshfp_algorithm_to_int : sshfp_algorithm -> int
val int_to_sshfp_algorithm : int -> sshfp_algorithm option
val pp_sshfp_algorithm : sshfp_algorithm Fmt.t

type sshfp_type =
  | Sshfp_SHA1
  | Sshfp_SHA256

val sshfp_type_to_int : sshfp_type -> int
val int_to_sshfp_type : int -> sshfp_type option
val pp_sshfp_type : sshfp_type Fmt.t
