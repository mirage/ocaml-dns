(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* retrieved and converted 2017-04-29 from https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml *)

[%%cenum
type clas =
  (* Reserved0 [@id 0] RFC6895 *)
  | IN [@id 1] (* RFC1035 *)
  (* 2 Uassigned *)
  | CHAOS [@id 3] (* D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981. *)
  | HESIOD [@id 4] (* Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987. *)
  | NONE [@id 254] (* RFC2136 *)
  | ANY_CLASS [@id 255] (* RFC1035 *)
  (* 256-65279 Unassigned *)
  (* 65280-65534 Reserved for Private Use [RFC6895] *)
  (* ReservedFFFF [@id 65535] *)
[@@uint16_t]
]

val pp_clas : clas Fmt.t

[%%cenum
type rr_typ =
  | A [@id 1] (* a host address [RFC1035] *)
  | NS [@id 2] (* an authoritative name server,[RFC1035] *)
  | MD [@id 3] (* a mail destination (OBSOLETE - use MX),[RFC1035] *)
  | MF [@id 4] (* a mail forwarder (OBSOLETE - use MX),[RFC1035] *)
  | CNAME [@id 5] (* the canonical name for an alias,[RFC1035] *)
  | SOA [@id 6] (* marks the start of a zone of authority,[RFC1035] *)
  | MB [@id 7] (* a mailbox domain name (EXPERIMENTAL),[RFC1035] *)
  | MG [@id 8] (* a mail group member (EXPERIMENTAL),[RFC1035] *)
  | MR [@id 9] (* a mail rename domain name (EXPERIMENTAL),[RFC1035] *)
  | NULL [@id 10] (* a null RR (EXPERIMENTAL),[RFC1035] *)
  | WKS [@id 11] (* a well known service description,[RFC1035] *)
  | PTR [@id 12] (* a domain name pointer,[RFC1035] *)
  | HINFO [@id 13] (* host information,[RFC1035] *)
  | MINFO [@id 14] (* mailbox or mail list information,[RFC1035] *)
  | MX [@id 15] (* mail exchange,[RFC1035] *)
  | TXT [@id 16] (* text strings,[RFC1035] *)
  | RP [@id 17] (* for Responsible Person,[RFC1183] *)
  | AFSDB [@id 18] (* for AFS Data Base location,[RFC1183][RFC5864] *)
  | X25 [@id 19] (* for X.25 PSDN address,[RFC1183] *)
  | ISDN [@id 20] (* for ISDN address,[RFC1183] *)
  | RT [@id 21] (* for Route Through,[RFC1183] *)
  | NSAP [@id 22] (* "for NSAP address, NSAP style A record",[RFC1706] *)
  | NSAP_PTR [@id 23] (* "for domain name pointer, NSAP style",[RFC1348][RFC1637][RFC1706] *)
  | SIG [@id 24] (* for security signature,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008] *)
  | KEY [@id 25] (* for security key,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110] *)
  | PX [@id 26] (* X.400 mail mapping information,[RFC2163] *)
  | GPOS [@id 27] (* Geographical Position,[RFC1712] *)
  | AAAA [@id 28] (* IP6 Address,[RFC3596] *)
  | LOC [@id 29] (* Location Information,[RFC1876] *)
  | NXT [@id 30] (* Next Domain (OBSOLETE),[RFC3755][RFC2535] *)
  | EID [@id 31] (* Endpoint Identifier,[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],,1995-06 *)
  | NIMLOC [@id 32] (* Nimrod Locator,[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],,1995-06 *)
  | SRV [@id 33] (* Server Selection,[1][RFC2782] *)
  | ATMA [@id 34] (* ATM Address,"[ATM Forum Technical Committee, ""ATM Name System, V2.0"", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]" *)
  | NAPTR [@id 35] (* Naming Authority Pointer,[RFC2915][RFC2168][RFC3403] *)
  | KX [@id 36] (* Key Exchanger,[RFC2230] *)
  | CERT [@id 37] (* CERT,[RFC4398] *)
  | A6 [@id 38] (* A6 (OBSOLETE - use AAAA),[RFC3226][RFC2874][RFC6563] *)
  | DNAME [@id 39] (* ,DNAME,[RFC6672] *)
  | SINK [@id 40] (* SINK,[Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink],,1997-11 *)
  | OPT [@id 41] (* OPT,[RFC6891][RFC3225] *)
  | APL [@id 42] (* APL,[RFC3123] *)
  | DS [@id 43] (* Delegation Signer,[RFC4034][RFC3658] *)
  | SSHFP [@id 44] (* SSH Key Fingerprint,[RFC4255] *)
  | IPSECKEY [@id 45] (* IPSECKEY,[RFC4025] *)
  | RRSIG [@id 46] (* RRSIG,[RFC4034][RFC3755] *)
  | NSEC [@id 47] (* NSEC,[RFC4034][RFC3755] *)
  | DNSKEY [@id 48] (* DNSKEY,[RFC4034][RFC3755] *)
  | DHCID [@id 49] (* ,DHCID,[RFC4701] *)
  | NSEC3 [@id 50] (* NSEC3,[RFC5155] *)
  | NSEC3PARAM [@id 51] (* NSEC3PARAM,[RFC5155] *)
  | TLSA [@id 52] (* TLSA,[RFC6698] *)
  | SMIMEA [@id 53] (* S/MIME cert association,[RFC-ietf-dane-smime-16],SMIMEA/smimea-completed-template,2015-12-01 *)
  (* Unassigned,54 *)
  | HIP [@id 55] (* Host Identity Protocol,[RFC8005] *)
  | NINFO [@id 56] (* NINFO,[Jim_Reid],NINFO/ninfo-completed-template,2008-01-21 *)
  | RKEY [@id 57] (* RKEY,[Jim_Reid],RKEY/rkey-completed-template,2008-01-21 *)
  | TALINK [@id 58] (* Trust Anchor LINK,[Wouter_Wijngaards],TALINK/talink-completed-template,2010-02-17 *)
  | CDS [@id 59] (* Child DS,[RFC7344],CDS/cds-completed-template,2011-06-06 *)
  | CDNSKEY [@id 60] (* DNSKEY(s) the Child wants reflected in DS,[RFC7344],,2014-06-16 *)
  | OPENPGPKEY [@id 61] (* OpenPGP Key,[RFC7929],OPENPGPKEY/openpgpkey-completed-template,2014-08-12 *)
  | CSYNC [@id 62] (* Child-To-Parent Synchronization,[RFC7477],,2015-01-27 *)
  (* Unassigned,63-98 *)
  | SPF [@id 99] (* [RFC7208] *)
  | UINFO [@id 100] (* [IANA-Reserved] *)
  | UID [@id 101] (* [IANA-Reserved] *)
  | GID [@id 102] (* [IANA-Reserved] *)
  | UNSPEC [@id 103] (* [IANA-Reserved] *)
  | NID [@id 104] (* [RFC6742],ILNP/nid-completed-template *)
  | L32 [@id 105] (* [RFC6742],ILNP/l32-completed-template *)
  | L64 [@id 106] (* [RFC6742],ILNP/l64-completed-template *)
  | LP [@id 107] (* [RFC6742],ILNP/lp-completed-template *)
  | EUI48 [@id 108] (* an EUI-48 address,[RFC7043],EUI48/eui48-completed-template,2013-03-27 *)
  | EUI64 [@id 109] (* an EUI-64 address,[RFC7043],EUI64/eui64-completed-template,2013-03-27 *)
  (* Unassigned,110-248 *)
  | TKEY [@id 249] (* Transaction Key,[RFC2930] *)
  | TSIG [@id 250] (* Transaction Signature,[RFC2845] *)
  | IXFR [@id 251] (* incremental transfer,[RFC1995] *)
  | AXFR [@id 252] (* transfer of an entire zone,[RFC1035][RFC5936] *)
  | MAILB [@id 253] (* "mailbox-related RRs (MB, MG or MR)",[RFC1035] *)
  | MAILA [@id 254] (* mail agent RRs (OBSOLETE - see MX),[RFC1035] *)
  | ANY [@id 255] (* A request for all records the server/cache has available,[RFC1035][RFC6895] *)
  | URI [@id 256] (* URI,[RFC7553],URI/uri-completed-template,2011-02-22 *)
  | CAA [@id 257] (* Certification Authority Restriction,[RFC6844],CAA/caa-completed-template,2011-04-07 *)
  | AVC [@id 258] (* Application Visibility and Control,[Wolfgang_Riedel],AVC/avc-completed-template,2016-02-26 *)
  (* Unassigned,259-32767 *)
  | TA [@id 32768] (* DNSSEC Trust Authorities,"[Sam_Weiler][http://cameo.library.cmu.edu/][
        Deploying DNSSEC Without a Signed Root.  Technical Report 1999-19,
                      Information Networking Institute, Carnegie Mellon University, April 2004.]",,2005-12-13 *)
  | DLV [@id 32769] (* DNSSEC Lookaside Validation,[RFC4431] *)
  (* Unassigned,32770-65279 *)
  (* Private use,65280-65534 *)
  (* Reserved,65535 *)
[@@uint16_t]
]

val pp_rr_typ : rr_typ Fmt.t

[%%cenum
type opcode =
  | Query [@id 0] (* RFC1035 *)
  | IQuery [@id 1] (* Inverse Query, OBSOLETE) [RFC3425] *)
  | Status [@id 2] (* RFC1035 *)
  (* 3 Unassigned *)
  | Notify [@id 4] (* RFC1996 *)
  | Update [@id 5] (* RFC2136 *)
  (* 6-15 Unassigned *)
[@@uint8_t]
]

val pp_opcode : opcode Fmt.t

[%%cenum
type rcode =
  | NoError [@id 0] (* No Error,[RFC1035] *)
  | FormErr [@id 1] (* Format Error,[RFC1035] *)
  | ServFail [@id 2] (* Server Failure,[RFC1035] *)
  | NXDomain [@id 3] (* Non-Existent Domain,[RFC1035] *)
  | NotImp [@id 4] (* Not Implemented,[RFC1035] *)
  | Refused [@id 5] (* Query Refused,[RFC1035] *)
  | YXDomain [@id 6] (* Name Exists when it should not,[RFC2136][RFC6672] *)
  | YXRRSet [@id 7] (* RR Set Exists when it should not,[RFC2136] *)
  | NXRRSet [@id 8] (* RR Set that should exist does not,[RFC2136] *)
  | NotAuth [@id 9] (* Server Not Authoritative for zone,[RFC2136]
                       9,NotAuth,Not Authorized,[RFC2845] *)
  | NotZone [@id 10] (* Name not contained in zone,[RFC2136] *)
  (* 11-15,Unassigned *)
  | BadVersOrSig [@id 16] (* 16,BADVERS,Bad OPT Version,[RFC6891]
                             16,BADSIG,TSIG Signature Failure,[RFC2845] *)
  | BadKey [@id 17] (* Key not recognized,[RFC2845] *)
  | BadTime [@id 18] (* Signature out of time window,[RFC2845] *)
  | BadMode [@id 19] (* BADMODE,Bad TKEY Mode,[RFC2930] *)
  | BadName [@id 20] (* BADNAME,Duplicate key name,[RFC2930] *)
  | BadAlg [@id 21] (* BADALG,Algorithm not supported,[RFC2930] *)
  | BadTrunc [@id 22] (* BADTRUNC,Bad Truncation,[RFC4635] *)
  | BadCookie [@id 23] (* BADCOOKIE,Bad/missing Server Cookie,[RFC7873] *)
  (* 24-3840,Unassigned *)
  (* 3841-4095,Reserved for Private Use,,[RFC6895] *)
  (* 4096-65534,Unassigned *)
  (* 65535,"Reserved, can be allocated by Standards Action",,[RFC6895] *)
[@@uint8_t]
]

val pp_rcode : rcode Fmt.t

[%%cenum
type edns_opt =
  (* 0,Reserved,,[RFC6891] *)
  | LLQ [@id 1] (* On-hold,[http://files.dns-sd.org/draft-sekar-dns-llq.txt] *)
  | UL [@id 2] (* On-hold,[http://files.dns-sd.org/draft-sekar-dns-ul.txt] *)
  | NSID [@id 3] (* NSID,Standard,[RFC5001] *)
  (* 4,Reserved,,[draft-cheshire-edns0-owner-option] *)
  | DAU [@id 5] (* DAU,Standard,[RFC6975] *)
  | DHU [@id 6] (* DHU,Standard,[RFC6975] *)
  | N3U [@id 7] (* N3U,Standard,[RFC6975] *)
  | Client_subnet [@id 8] (* edns-client-subnet,Optional,[RFC7871] *)
  | Expire [@id 9] (* Optional,[RFC7314] *)
  | Cookie [@id 10] (* COOKIE,Standard,[RFC7873] *)
  | TCP_keepalive [@id 11] (* edns-tcp-keepalive,Standard,[RFC7828] *)
  | Padding [@id 12] (* Padding,Standard,[RFC7830] *)
  | Chain [@id 13] (* CHAIN,Standard,[RFC7901] *)
  | Key_tag [@id 14] (* edns-key-tag,Optional,[RFC8145] *)
  (* 15-26945,Unassigned *)
  | DeviceID [@id 26946] (* DeviceID,Optional,[https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2][Brian_Hartvigsen] *)
(* 26947-65000,Unassigned
65001-65534,Reserved for Local/Experimental Use,,[RFC6891]
65535,Reserved for future expansion,,[RFC6891] *)
[@@uint16_t]
]

val pp_edns_opt : edns_opt Fmt.t

[%%cenum
type dnskey =
  | MD5 [@id 157]
  | SHA1 [@id 161]
  | SHA224 [@id 162]
  | SHA256 [@id 163]
  | SHA384 [@id 164]
  | SHA512 [@id 165]
[@@uint8_t]
]

val dnskey_len : dnskey -> int
val pp_dnskey : dnskey Fmt.t

module RRMap : Map.S with type key = rr_typ

[%%cenum
type tlsa_cert_usage =
  | CA_constraint [@id 0]
  | Service_certificate_constraint [@id 1]
  | Trust_anchor_assertion [@id 2]
  | Domain_issued_certificate [@id 3]
[@@uint8_t]
]

val pp_tlsa_cert_usage : tlsa_cert_usage Fmt.t

[%%cenum
type tlsa_selector =
  | Tlsa_full_certificate [@id 0]
  | Tlsa_subject_public_key_info [@id 1]
  | Tlsa_selector_private [@id 255]
[@@uint8_t]
]

val pp_tlsa_selector : tlsa_selector Fmt.t

[%%cenum
type tlsa_matching_type =
  | Tlsa_no_hash [@id 0]
  | Tlsa_SHA256 [@id 1]
  | Tlsa_SHA512 [@id 2]
[@@uint8_t]
]

val pp_tlsa_matching_type : tlsa_matching_type Fmt.t

[%%cenum
type sshfp_algorithm =
  | Sshfp_rsa [@id 1]
  | Sshfp_dsa [@id 2]
  | Sshfp_ecdsa [@id 3]
  | Sshfp_ed25519 [@id 4]
[@@uint8_t]
]

val pp_sshfp_algorithm : sshfp_algorithm Fmt.t

[%%cenum
type sshfp_type =
  | Sshfp_SHA1 [@id 1]
  | Sshfp_SHA256 [@id 2]
[@@uint8_t]
]

val pp_sshfp_type : sshfp_type Fmt.t
