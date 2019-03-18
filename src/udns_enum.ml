(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* retrieved and converted 2017-04-29 from https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml *)

(* 16 bit *)
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

let clas_to_int = function
  | IN -> 1
  | CHAOS -> 3
  | HESIOD -> 4
  | NONE -> 254
  | ANY_CLASS -> 255

let int_to_clas = function
  | 1 -> Some IN
  | 3 -> Some CHAOS
  | 4 -> Some HESIOD
  | 254 -> Some NONE
  | 255 -> Some ANY_CLASS
  | _ -> None

let clas_to_string = function
  | IN -> "IN"
  | CHAOS -> "CHAOS"
  | HESIOD -> "HESIOD"
  | NONE -> "NONE"
  | ANY_CLASS -> "ANY_CLASS"

let pp_clas ppf c = Fmt.string ppf (clas_to_string c)

(* 16 bit *)
type rr_typ =
  | A (* 1 a host address [RFC1035] *)
  | NS (* 2 an authoritative name server,[RFC1035] *)
  | MD (* 3 a mail destination (OBSOLETE - use MX),[RFC1035] *)
  | MF (* 4 a mail forwarder (OBSOLETE - use MX),[RFC1035] *)
  | CNAME (* 5 the canonical name for an alias,[RFC1035] *)
  | SOA (* 6 marks the start of a zone of authority,[RFC1035] *)
  | MB (* 7 a mailbox domain name (EXPERIMENTAL),[RFC1035] *)
  | MG (* 8 a mail group member (EXPERIMENTAL),[RFC1035] *)
  | MR (* 9 a mail rename domain name (EXPERIMENTAL),[RFC1035] *)
  | NULL (* 10 a null RR (EXPERIMENTAL),[RFC1035] *)
  | WKS (* 11 a well known service description,[RFC1035] *)
  | PTR (* 12 a domain name pointer,[RFC1035] *)
  | HINFO (* 13 host information,[RFC1035] *)
  | MINFO (* 14 mailbox or mail list information,[RFC1035] *)
  | MX (* 15 mail exchange,[RFC1035] *)
  | TXT (* 16 text strings,[RFC1035] *)
  | RP (* 17 for Responsible Person,[RFC1183] *)
  | AFSDB (* 18 for AFS Data Base location,[RFC1183][RFC5864] *)
  | X25 (* 19 for X.25 PSDN address,[RFC1183] *)
  | ISDN (* 20 for ISDN address,[RFC1183] *)
  | RT (* 21 for Route Through,[RFC1183] *)
  | NSAP (* 22 "for NSAP address, NSAP style A record",[RFC1706] *)
  | NSAP_PTR (* 23 "for domain name pointer, NSAP style",[RFC1348][RFC1637][RFC1706] *)
  | SIG (* 24 for security signature,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008] *)
  | KEY (* 25 for security key,[RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110] *)
  | PX (* 26 X.400 mail mapping information,[RFC2163] *)
  | GPOS (* 27 Geographical Position,[RFC1712] *)
  | AAAA (* 28 IP6 Address,[RFC3596] *)
  | LOC (* 29 Location Information,[RFC1876] *)
  | NXT (* 30 Next Domain (OBSOLETE),[RFC3755][RFC2535] *)
  | EID (* 31 Endpoint Identifier,[Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],,1995-06 *)
  | NIMLOC (* 32 Nimrod Locator,[1][Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt],,1995-06 *)
  | SRV (* 33 Server Selection,[1][RFC2782] *)
  | ATMA (* 34 ATM Address,"[ATM Forum Technical Committee, ""ATM Name System, V2.0"", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]" *)
  | NAPTR (* 35 Naming Authority Pointer,[RFC2915][RFC2168][RFC3403] *)
  | KX (* 36 Key Exchanger,[RFC2230] *)
  | CERT (* 37 CERT,[RFC4398] *)
  | A6 (* 38 A6 (OBSOLETE - use AAAA),[RFC3226][RFC2874][RFC6563] *)
  | DNAME (* 39 ,DNAME,[RFC6672] *)
  | SINK (* 40 SINK,[Donald_E_Eastlake][http://tools.ietf.org/html/draft-eastlake-kitchen-sink],,1997-11 *)
  | OPT (* 41 OPT,[RFC6891][RFC3225] *)
  | APL (* 42 APL,[RFC3123] *)
  | DS (* 43 Delegation Signer,[RFC4034][RFC3658] *)
  | SSHFP (* 44 SSH Key Fingerprint,[RFC4255] *)
  | IPSECKEY (* 45 IPSECKEY,[RFC4025] *)
  | RRSIG (* 46 RRSIG,[RFC4034][RFC3755] *)
  | NSEC (* 47 NSEC,[RFC4034][RFC3755] *)
  | DNSKEY (* 48 DNSKEY,[RFC4034][RFC3755] *)
  | DHCID (* 49 ,DHCID,[RFC4701] *)
  | NSEC3 (* 50 NSEC3,[RFC5155] *)
  | NSEC3PARAM (* 51 NSEC3PARAM,[RFC5155] *)
  | TLSA (* 52 TLSA,[RFC6698] *)
  | SMIMEA (* 53 S/MIME cert association,[RFC-ietf-dane-smime-16],SMIMEA/smimea-completed-template,2015-12-01 *)
  (* Unassigned,54 *)
  | HIP (* 55 Host Identity Protocol,[RFC8005] *)
  | NINFO (* 56 NINFO,[Jim_Reid],NINFO/ninfo-completed-template,2008-01-21 *)
  | RKEY (* 57 RKEY,[Jim_Reid],RKEY/rkey-completed-template,2008-01-21 *)
  | TALINK (* 58 Trust Anchor LINK,[Wouter_Wijngaards],TALINK/talink-completed-template,2010-02-17 *)
  | CDS (* 59 Child DS,[RFC7344],CDS/cds-completed-template,2011-06-06 *)
  | CDNSKEY (* 60 DNSKEY(s) the Child wants reflected in DS,[RFC7344],,2014-06-16 *)
  | OPENPGPKEY (* 61 OpenPGP Key,[RFC7929],OPENPGPKEY/openpgpkey-completed-template,2014-08-12 *)
  | CSYNC (* 62 Child-To-Parent Synchronization,[RFC7477],,2015-01-27 *)
  (* Unassigned,63-98 *)
  | SPF (* 99 [RFC7208] *)
  | UINFO (* 100 [IANA-Reserved] *)
  | UID (* 101 [IANA-Reserved] *)
  | GID (* 102 [IANA-Reserved] *)
  | UNSPEC (* 103 [IANA-Reserved] *)
  | NID (* 104 [RFC6742],ILNP/nid-completed-template *)
  | L32 (* 105 [RFC6742],ILNP/l32-completed-template *)
  | L64 (* 106 [RFC6742],ILNP/l64-completed-template *)
  | LP (* 107 [RFC6742],ILNP/lp-completed-template *)
  | EUI48 (* 108 an EUI-48 address,[RFC7043],EUI48/eui48-completed-template,2013-03-27 *)
  | EUI64 (* 109 an EUI-64 address,[RFC7043],EUI64/eui64-completed-template,2013-03-27 *)
  (* Unassigned,110-248 *)
  | TKEY (* 249 Transaction Key,[RFC2930] *)
  | TSIG (* 250 Transaction Signature,[RFC2845] *)
  | IXFR (* 251 incremental transfer,[RFC1995] *)
  | AXFR (* 252 transfer of an entire zone,[RFC1035][RFC5936] *)
  | MAILB (* 253 "mailbox-related RRs (MB, MG or MR)",[RFC1035] *)
  | MAILA (* 254 mail agent RRs (OBSOLETE - see MX),[RFC1035] *)
  | ANY (* 255 A request for all records the server/cache has available,[RFC1035][RFC6895] *)
  | URI (* 256 URI,[RFC7553],URI/uri-completed-template,2011-02-22 *)
  | CAA (* 257 Certification Authority Restriction,[RFC6844],CAA/caa-completed-template,2011-04-07 *)
  | AVC (* 258 Application Visibility and Control,[Wolfgang_Riedel],AVC/avc-completed-template,2016-02-26 *)
  (* Unassigned,259-32767 *)
  | TA (* 32768 DNSSEC Trust Authorities,"[Sam_Weiler][http://cameo.library.cmu.edu/][
        Deploying DNSSEC Without a Signed Root.  Technical Report 1999-19,
                      Information Networking Institute, Carnegie Mellon University, April 2004.]",,2005-12-13 *)
  | DLV (* 32769 DNSSEC Lookaside Validation,[RFC4431] *)
  (* Unassigned,32770-65279 *)
  (* Private use,65280-65534 *)
  (* Reserved,65535 *)

let rr_typ_to_int = function
  | A -> 1 | NS -> 2 | MD -> 3 | MF -> 4 | CNAME -> 5 | SOA -> 6 | MB -> 7
  | MG -> 8 | MR -> 9 | NULL -> 10 | WKS -> 11 | PTR -> 12 | HINFO -> 13
  | MINFO -> 14 | MX -> 15 | TXT -> 16 | RP -> 17 | AFSDB -> 18 | X25 -> 19
  | ISDN -> 20 | RT -> 21 | NSAP -> 22 | NSAP_PTR -> 23 | SIG -> 24 | KEY -> 25
  | PX -> 26 | GPOS -> 27 | AAAA -> 28 | LOC -> 29 | NXT -> 30 | EID -> 31
  | NIMLOC -> 32 | SRV -> 33 | ATMA -> 34 | NAPTR -> 35 | KX -> 36 | CERT -> 37
  | A6 -> 38 | DNAME -> 39 | SINK -> 40 | OPT -> 41 | APL -> 42 | DS -> 43
  | SSHFP -> 44 | IPSECKEY -> 45 | RRSIG -> 46 | NSEC -> 47 | DNSKEY -> 48
  | DHCID -> 49 | NSEC3 -> 50 | NSEC3PARAM -> 51 | TLSA -> 52 | SMIMEA -> 53
  | HIP -> 55 | NINFO -> 56 | RKEY -> 57 | TALINK -> 58 | CDS -> 59
  | CDNSKEY -> 60 | OPENPGPKEY -> 61 | CSYNC -> 62 | SPF -> 99 | UINFO -> 100
  | UID -> 101 | GID -> 102 | UNSPEC -> 103 | NID -> 104 | L32 -> 105
  | L64 -> 106 | LP -> 107 | EUI48 -> 108 | EUI64 -> 109 | TKEY -> 249
  | TSIG -> 250 | IXFR -> 251 | AXFR -> 252 | MAILB -> 253 | MAILA -> 254
  | ANY -> 255 | URI -> 256 | CAA -> 257 | AVC -> 258 | TA -> 32768
  | DLV -> 32769

let int_to_rr_typ = function
  | 1 -> Some A | 2 -> Some NS | 3 -> Some MD | 4 -> Some MF | 5 -> Some CNAME
  | 6 -> Some SOA | 7 -> Some MB | 8 -> Some MG | 9 -> Some MR | 10 -> Some NULL
  | 11 -> Some WKS | 12 -> Some PTR | 13 -> Some HINFO | 14 -> Some MINFO
  | 15 -> Some MX | 16 -> Some TXT | 17 -> Some RP | 18 -> Some AFSDB
  | 19 -> Some X25 | 20 -> Some ISDN | 21 -> Some RT | 22 -> Some NSAP
  | 23 -> Some NSAP_PTR | 24 -> Some SIG | 25 -> Some KEY | 26 -> Some PX
  | 27 -> Some GPOS | 28 -> Some AAAA | 29 -> Some LOC | 30 -> Some NXT
  | 31 -> Some EID | 32 -> Some NIMLOC | 33 -> Some SRV | 34 -> Some ATMA
  | 35 -> Some NAPTR | 36 -> Some KX | 37 -> Some CERT | 38 -> Some A6
  | 39 -> Some DNAME | 40 -> Some SINK | 41 -> Some OPT | 42 -> Some APL
  | 43 -> Some DS | 44 -> Some SSHFP | 45 -> Some IPSECKEY | 46 -> Some RRSIG
  | 47 -> Some NSEC | 48 -> Some DNSKEY | 49 -> Some DHCID | 50 -> Some NSEC3
  | 51 -> Some NSEC3PARAM | 52 -> Some TLSA | 53 -> Some SMIMEA | 55 -> Some HIP
  | 56 -> Some NINFO | 57 -> Some RKEY | 58 -> Some TALINK | 59 -> Some CDS
  | 60 -> Some CDNSKEY | 61 -> Some OPENPGPKEY | 62 -> Some CSYNC
  | 99 -> Some SPF | 100 -> Some UINFO | 101 -> Some UID | 102 -> Some GID
  | 103 -> Some UNSPEC | 104 -> Some NID | 105 -> Some L32 | 106 -> Some L64
  | 107 -> Some LP | 108 -> Some EUI48 | 109 -> Some EUI64 | 249 -> Some TKEY
  | 250 -> Some TSIG | 251 -> Some IXFR | 252 -> Some AXFR | 253 -> Some MAILB
  | 254 -> Some MAILA | 255 -> Some ANY | 256 -> Some URI | 257 -> Some CAA
  | 258 -> Some AVC | 32768 -> Some TA | 32769 -> Some DLV
  | _ -> None

let rr_typ_to_string = function
  | A -> "A" | NS -> "NS" | MD -> "MD" | MF -> "MF" | CNAME -> "CNAME"
  | SOA -> "SOA" | MB -> "MB" | MG -> "MG" | MR -> "MR" | NULL -> "NULL"
  | WKS -> "WKS" | PTR -> "PTR" | HINFO -> "HINFO" | MINFO -> "MINFO"
  | MX -> "MX" | TXT -> "TXT" | RP -> "RP" | AFSDB -> "AFSDB" | X25 -> "X25"
  | ISDN -> "ISDN" | RT -> "RT" | NSAP -> "NSAP" | NSAP_PTR -> "NSAP_PTR"
  | SIG -> "SIG" | KEY -> "KEY" | PX -> "PX" | GPOS -> "GPOS" | AAAA -> "AAAA"
  | LOC -> "LOC" | NXT -> "NXT" | EID -> "EID" | NIMLOC -> "NIMLOC"
  | SRV -> "SRV" | ATMA -> "ATMA" | NAPTR -> "NAPTR" | KX -> "KX"
  | CERT -> "CERT" | A6 -> "A6" | DNAME -> "DNAME" | SINK -> "SINK"
  | OPT -> "OPT" | APL -> "APL" | DS -> "DS" | SSHFP -> "SSHFP"
  | IPSECKEY -> "IPSECKEY" | RRSIG -> "RRSIG" | NSEC -> "NSEC"
  | DNSKEY -> "DNSKEY" | DHCID -> "DHCID" | NSEC3 -> "NSEC3"
  | NSEC3PARAM -> "NSEC3PARAM" | TLSA -> "TLSA" | SMIMEA -> "SMIMEA"
  | HIP -> "HIP" | NINFO -> "NINFO" | RKEY -> "RKEY" | TALINK -> "TALINK"
  | CDS -> "CDS" | CDNSKEY -> "CDNSKEY" | OPENPGPKEY -> "OPENPGPKEY"
  | CSYNC -> "CSYNC" | SPF -> "SPF" | UINFO -> "UINFO" | UID -> "UID"
  | GID -> "GID" | UNSPEC -> "UNSPEC" | NID -> "NID" | L32 -> "L32"
  | L64 -> "L64" | LP -> "LP" | EUI48 -> "EUI48" | EUI64 -> "EUI64"
  | TKEY -> "TKEY" | TSIG -> "TSIG" | IXFR -> "IXFR" | AXFR -> "AXFR"
  | MAILB -> "MAILB" | MAILA -> "MAILA" | ANY -> "ANY" | URI -> "URI"
  | CAA -> "CAA" | AVC -> "AVC" | TA -> "TA" | DLV -> "TLV"

let pp_rr_typ ppf t = Fmt.string ppf (rr_typ_to_string t)

(* 4 bit *)
type opcode =
  | Query (* RFC1035 *)
  | IQuery (* Inverse Query, OBSOLETE) [RFC3425] *)
  | Status (* RFC1035 *)
  (* 3 Unassigned *)
  | Notify (* RFC1996 *)
  | Update (* RFC2136 *)
  (* 6-15 Unassigned *)

let opcode_to_int = function
  | Query -> 0
  | IQuery -> 1
  | Status -> 2
  | Notify -> 4
  | Update -> 5

let int_to_opcode = function
  | 0 -> Some Query
  | 1 -> Some IQuery
  | 2 -> Some Status
  | 4 -> Some Notify
  | 5 -> Some Update
  | _ -> None

let opcode_to_string = function
  | Query -> "Query"
  | IQuery -> "IQuery"
  | Status -> "Status"
  | Notify -> "Notify"
  | Update -> "Update"

let pp_opcode ppf t = Fmt.string ppf (opcode_to_string t)

(* 4 bit + 16 in EDNS/TSIG*)
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

let rcode_to_int = function
  | NoError -> 0 | FormErr -> 1 | ServFail -> 2 | NXDomain -> 3 | NotImp -> 4
  | Refused -> 5 | YXDomain -> 6 | YXRRSet -> 7 | NXRRSet -> 8 | NotAuth -> 9
  | NotZone -> 10 | BadVersOrSig -> 16 | BadKey -> 17 | BadTime -> 18
  | BadMode -> 19 | BadName -> 20 | BadAlg -> 21 | BadTrunc -> 22
  | BadCookie -> 23
let int_to_rcode = function
  | 0 -> Some NoError | 1 -> Some FormErr | 2 -> Some ServFail
  | 3 -> Some NXDomain | 4 -> Some NotImp | 5 -> Some Refused
  | 6 -> Some YXDomain | 7 -> Some YXRRSet | 8 -> Some NXRRSet
  | 9 -> Some NotAuth | 10 -> Some NotZone | 16 -> Some BadVersOrSig
  | 17 -> Some BadKey | 18 -> Some BadTime | 19 -> Some BadMode
  | 20 -> Some BadName | 21 -> Some BadAlg | 22 -> Some BadTrunc
  | 23 -> Some BadCookie
  | _ -> None
let rcode_to_string = function
  | NoError -> "no error" | FormErr -> "form error"
  | ServFail -> "server failure" | NXDomain -> "no such domain"
  | NotImp -> "not implemented" | Refused -> "refused"
  | YXDomain -> "name exists when it should not"
  | YXRRSet -> "resource record set exists when it should not"
  | NXRRSet -> "resource record set that should exist does not"
  | NotAuth -> "server not authoritative for zone or not authorized"
  | NotZone -> "name not contained in zone"
  | BadVersOrSig -> "bad version or signature"
  | BadKey -> "bad TSIG key" | BadTime -> "signature time out of window"
  | BadMode -> "bad TKEY mode" | BadName -> "duplicate key name"
  | BadAlg -> "unsupported algorithm"  | BadTrunc -> "bad truncation"
  | BadCookie -> "bad cookie"

let pp_rcode ppf r = Fmt.string ppf (rcode_to_string r)

(* 16 bit *)
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

let edns_opt_to_int = function
  | LLQ -> 1
  | UL -> 2
  | NSID -> 3
  | DAU -> 5
  | DHU -> 6
  | N3U -> 7
  | Client_subnet -> 8
  | Expire -> 9
  | Cookie -> 10
  | TCP_keepalive -> 11
  | Padding -> 12
  | Chain -> 13
  | Key_tag -> 14
  | DeviceID -> 26946
let int_to_edns_opt = function
  | 1 -> Some LLQ
  | 2 -> Some UL
  | 3 -> Some NSID
  | 5 -> Some DAU
  | 6 -> Some DHU
  | 7 -> Some N3U
  | 8 -> Some Client_subnet
  | 9 -> Some Expire
  | 10 -> Some Cookie
  | 11 -> Some TCP_keepalive
  | 12 -> Some Padding
  | 13 -> Some Chain
  | 14 -> Some Key_tag
  | 26946 -> Some DeviceID
  | _ -> None
let edns_opt_to_string = function
  | LLQ -> "LLQ"
  | UL -> "UL"
  | NSID -> "NSID"
  | DAU -> "DAU"
  | DHU -> "DHU"
  | N3U -> "N3U"
  | Client_subnet -> "Client subnet"
  | Expire -> "Expire"
  | Cookie -> "Cookie"
  | TCP_keepalive -> "TCP keepalive"
  | Padding -> "Padding"
  | Chain -> "Chain"
  | Key_tag -> "Key tag"
  | DeviceID -> "Device ID"

let pp_edns_opt ppf t = Fmt.string ppf (edns_opt_to_string t)

(* 8 bit *)
type dnskey =
  | MD5 [@id 157]
  | SHA1 [@id 161]
  | SHA224 [@id 162]
  | SHA256 [@id 163]
  | SHA384 [@id 164]
  | SHA512 [@id 165]

let dnskey_to_int = function
  | MD5 -> 157
  | SHA1 -> 161
  | SHA224 -> 162
  | SHA256 -> 163
  | SHA384 -> 164
  | SHA512 -> 165
let int_to_dnskey = function
  | 157 -> Some MD5
  | 161 -> Some SHA1
  | 162 -> Some SHA224
  | 163 -> Some SHA256
  | 164 -> Some SHA384
  | 165 -> Some SHA512
  | _ -> None
let dnskey_to_string = function
  | MD5 -> "MD5"
  | SHA1 -> "SHA1"
  | SHA224 -> "SHA224"
  | SHA256 -> "SHA256"
  | SHA384 -> "SHA384"
  | SHA512 -> "SHA512"
let string_to_dnskey = function
  | "MD5" -> Some MD5
  | "SHA1" -> Some SHA1
  | "SHA224" -> Some SHA224
  | "SHA256" -> Some SHA256
  | "SHA384" -> Some SHA384
  | "SHA512" -> Some SHA512
  | _ -> None

let dnskey_len k =
  let b64 bits = (bits / 8 + 2) / 3 * 4 in
  match k with
  | MD5 -> b64 128
  | SHA1 -> b64 160
  | SHA224 -> b64 224
  | SHA256 -> b64 256
  | SHA384 -> b64 384
  | SHA512 -> b64 512

let pp_dnskey ppf k = Fmt.string ppf (dnskey_to_string k)

module RRMap = Map.Make(struct
    type t = rr_typ
    let compare = compare
  end)

(* 8 bit *)
type tlsa_cert_usage =
  | CA_constraint
  | Service_certificate_constraint
  | Trust_anchor_assertion
  | Domain_issued_certificate

let tlsa_cert_usage_to_int = function
  | CA_constraint -> 0
  | Service_certificate_constraint -> 1
  | Trust_anchor_assertion -> 2
  | Domain_issued_certificate -> 3
let int_to_tlsa_cert_usage = function
  | 0 -> Some CA_constraint
  | 1 -> Some Service_certificate_constraint
  | 2 -> Some Trust_anchor_assertion
  | 3 -> Some Domain_issued_certificate
  | _ -> None
let tlsa_cert_usage_to_string = function
  | CA_constraint -> "CA constraint"
  | Service_certificate_constraint -> "service certificate constraint"
  | Trust_anchor_assertion -> "trust anchor assertion"
  | Domain_issued_certificate -> "domain issued certificate"

let pp_tlsa_cert_usage ppf k = Fmt.string ppf (tlsa_cert_usage_to_string k)

(* 8 bit *)
type tlsa_selector =
  | Tlsa_full_certificate
  | Tlsa_subject_public_key_info
  | Tlsa_selector_private

let tlsa_selector_to_int = function
  | Tlsa_full_certificate -> 0
  | Tlsa_subject_public_key_info -> 1
  | Tlsa_selector_private -> 255
let int_to_tlsa_selector = function
  | 0 -> Some Tlsa_full_certificate
  | 1 -> Some Tlsa_subject_public_key_info
  | 255 -> Some Tlsa_selector_private
  | _ -> None
let tlsa_selector_to_string = function
  | Tlsa_full_certificate -> "full certificate"
  | Tlsa_subject_public_key_info -> "subject public key info"
  | Tlsa_selector_private -> "private"

let pp_tlsa_selector ppf k = Fmt.string ppf (tlsa_selector_to_string k)

(* 8 bit *)
type tlsa_matching_type =
  | Tlsa_no_hash
  | Tlsa_SHA256
  | Tlsa_SHA512

let tlsa_matching_type_to_int = function
  | Tlsa_no_hash -> 0
  | Tlsa_SHA256 -> 1
  | Tlsa_SHA512 -> 2
let int_to_tlsa_matching_type = function
  | 0 -> Some Tlsa_no_hash
  | 1 -> Some Tlsa_SHA256
  | 2 -> Some Tlsa_SHA512
  | _ -> None
let tlsa_matching_type_to_string = function
  | Tlsa_no_hash -> "no hash"
  | Tlsa_SHA256 -> "SHA256"
  | Tlsa_SHA512 -> "SHA512"

let pp_tlsa_matching_type ppf k = Fmt.string ppf (tlsa_matching_type_to_string k)

(* 8 bit *)
type sshfp_algorithm =
  | Sshfp_rsa
  | Sshfp_dsa
  | Sshfp_ecdsa
  | Sshfp_ed25519

let sshfp_algorithm_to_int = function
  | Sshfp_rsa -> 1
  | Sshfp_dsa -> 2
  | Sshfp_ecdsa -> 3
  | Sshfp_ed25519 -> 4

let int_to_sshfp_algorithm = function
  | 1 -> Some Sshfp_rsa
  | 2 -> Some Sshfp_dsa
  | 3 -> Some Sshfp_ecdsa
  | 4 -> Some Sshfp_ed25519
  | _ -> None

let sshfp_algorithm_to_string = function
  | Sshfp_rsa -> "RSA"
  | Sshfp_dsa -> "DSA"
  | Sshfp_ecdsa -> "ECDSA"
  | Sshfp_ed25519 -> "ED25519"

let pp_sshfp_algorithm ppf k = Fmt.string ppf (sshfp_algorithm_to_string k)

(* 8 bit *)
type sshfp_type =
  | Sshfp_SHA1
  | Sshfp_SHA256

let sshfp_type_to_int = function
  | Sshfp_SHA1 -> 1
  | Sshfp_SHA256 -> 2

let int_to_sshfp_type = function
  | 1 -> Some Sshfp_SHA1
  | 2 -> Some Sshfp_SHA256
  | _ -> None

let sshfp_type_to_string = function
  | Sshfp_SHA1 -> "SHA1"
  | Sshfp_SHA256 -> "SHA256"

let pp_sshfp_type ppf k = Fmt.string ppf (sshfp_type_to_string k)
