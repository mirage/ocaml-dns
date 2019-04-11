(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]

let andThen v f = match v with 0 -> f | x -> x
let opt_eq f a b = match a, b with
  | Some a, Some b -> f a b
  | None, None -> true
  | _ -> false

let int_compare (a : int) (b : int) = compare a b
let int32_compare (a : int32) (b : int32) = Int32.compare a b

let guard p err = if p then Ok () else Error err

let src = Logs.Src.create "udns" ~doc:"UDNS core"
module Log = (val Logs.src_log src : Logs.LOG)

module Rr = struct
  (* 16 bit *)
  type t =
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

  let to_int = function
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

  let of_int ?(off = 0) = function
    | 1 -> Ok A | 2 -> Ok NS | 3 -> Ok MD | 4 -> Ok MF | 5 -> Ok CNAME
    | 6 -> Ok SOA | 7 -> Ok MB | 8 -> Ok MG | 9 -> Ok MR | 10 -> Ok NULL
    | 11 -> Ok WKS | 12 -> Ok PTR | 13 -> Ok HINFO | 14 -> Ok MINFO
    | 15 -> Ok MX | 16 -> Ok TXT | 17 -> Ok RP | 18 -> Ok AFSDB
    | 19 -> Ok X25 | 20 -> Ok ISDN | 21 -> Ok RT | 22 -> Ok NSAP
    | 23 -> Ok NSAP_PTR | 24 -> Ok SIG | 25 -> Ok KEY | 26 -> Ok PX
    | 27 -> Ok GPOS | 28 -> Ok AAAA | 29 -> Ok LOC | 30 -> Ok NXT
    | 31 -> Ok EID | 32 -> Ok NIMLOC | 33 -> Ok SRV | 34 -> Ok ATMA
    | 35 -> Ok NAPTR | 36 -> Ok KX | 37 -> Ok CERT | 38 -> Ok A6
    | 39 -> Ok DNAME | 40 -> Ok SINK | 41 -> Ok OPT | 42 -> Ok APL
    | 43 -> Ok DS | 44 -> Ok SSHFP | 45 -> Ok IPSECKEY | 46 -> Ok RRSIG
    | 47 -> Ok NSEC | 48 -> Ok DNSKEY | 49 -> Ok DHCID | 50 -> Ok NSEC3
    | 51 -> Ok NSEC3PARAM | 52 -> Ok TLSA | 53 -> Ok SMIMEA | 55 -> Ok HIP
    | 56 -> Ok NINFO | 57 -> Ok RKEY | 58 -> Ok TALINK | 59 -> Ok CDS
    | 60 -> Ok CDNSKEY | 61 -> Ok OPENPGPKEY | 62 -> Ok CSYNC
    | 99 -> Ok SPF | 100 -> Ok UINFO | 101 -> Ok UID | 102 -> Ok GID
    | 103 -> Ok UNSPEC | 104 -> Ok NID | 105 -> Ok L32 | 106 -> Ok L64
    | 107 -> Ok LP | 108 -> Ok EUI48 | 109 -> Ok EUI64 | 249 -> Ok TKEY
    | 250 -> Ok TSIG | 251 -> Ok IXFR | 252 -> Ok AXFR | 253 -> Ok MAILB
    | 254 -> Ok MAILA | 255 -> Ok ANY | 256 -> Ok URI | 257 -> Ok CAA
    | 258 -> Ok AVC | 32768 -> Ok TA | 32769 -> Ok DLV
    | x -> Error (`Not_implemented (off, Fmt.strf "rrtype 0x%02X" x))

  let compare a b = int_compare (to_int a) (to_int b)

  let to_string = function
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

  let pp ppf t = Fmt.string ppf (to_string t)
end

module Clas = struct
  (* 16 bit *)
  type t =
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

  let to_int = function
    | IN -> 1
    | CHAOS -> 3
    | HESIOD -> 4
    | NONE -> 254
    | ANY_CLASS -> 255

  let compare a b = int_compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 1 -> Ok IN
    | 3 -> Ok CHAOS
    | 4 -> Ok HESIOD
    | 254 -> Ok NONE
    | 255 -> Ok ANY_CLASS
    | c -> Error (`Not_implemented (off, Fmt.strf "class %X" c))

  let to_string = function
    | IN -> "IN"
    | CHAOS -> "CHAOS"
    | HESIOD -> "HESIOD"
    | NONE -> "NONE"
    | ANY_CLASS -> "ANY_CLASS"

  let pp ppf c = Fmt.string ppf (to_string c)
end

module Opcode = struct
  (* 4 bit *)
  type t =
    | Query (* RFC1035 *)
    | IQuery (* Inverse Query, OBSOLETE) [RFC3425] *)
    | Status (* RFC1035 *)
    (* 3 Unassigned *)
    | Notify (* RFC1996 *)
    | Update (* RFC2136 *)
  (* 6-15 Unassigned *)

  let to_int = function
    | Query -> 0
    | IQuery -> 1
    | Status -> 2
    | Notify -> 4
    | Update -> 5

  let compare a b = int_compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 0 -> Ok Query
    | 1 -> Ok IQuery
    | 2 -> Ok Status
    | 4 -> Ok Notify
    | 5 -> Ok Update
    | x -> Error (`Not_implemented (off, Fmt.strf "opcode 0x%X" x))

  let to_string = function
    | Query -> "Query"
    | IQuery -> "IQuery"
    | Status -> "Status"
    | Notify -> "Notify"
    | Update -> "Update"

  let pp ppf t = Fmt.string ppf (to_string t)
end

module Rcode = struct
  (* 4 bit + 16 in EDNS/TSIG*)
  type t =
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

  let to_int = function
    | NoError -> 0 | FormErr -> 1 | ServFail -> 2 | NXDomain -> 3
    | NotImp -> 4 | Refused -> 5 | YXDomain -> 6 | YXRRSet -> 7
    | NXRRSet -> 8 | NotAuth -> 9 | NotZone -> 10 | BadVersOrSig -> 16
    | BadKey -> 17 | BadTime -> 18 | BadMode -> 19 | BadName -> 20
    | BadAlg -> 21 | BadTrunc -> 22 | BadCookie -> 23
  let compare a b = int_compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 0 -> Ok NoError | 1 -> Ok FormErr | 2 -> Ok ServFail
    | 3 -> Ok NXDomain | 4 -> Ok NotImp | 5 -> Ok Refused
    | 6 -> Ok YXDomain | 7 -> Ok YXRRSet | 8 -> Ok NXRRSet
    | 9 -> Ok NotAuth | 10 -> Ok NotZone | 16 -> Ok BadVersOrSig
    | 17 -> Ok BadKey | 18 -> Ok BadTime | 19 -> Ok BadMode
    | 20 -> Ok BadName | 21 -> Ok BadAlg | 22 -> Ok BadTrunc
    | 23 -> Ok BadCookie
    | x -> Error (`Not_implemented (off, Fmt.strf "rcode 0x%04X" x))
  let to_string = function
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

  let pp ppf r = Fmt.string ppf (to_string r)
end

module Name = struct
  module Int_map = Map.Make(struct
      type t = int
      let compare = int_compare
    end)
  type name_offset_map = int Domain_name.Map.t

  type err = [
    | `Bad_edns_version of int
    | `Leftover of int * string
    | `Malformed of int * string
    | `Not_implemented of int * string
    | `Notify_ack_answer_count of int
    | `Notify_ack_authority_count of int
    | `Notify_answer_count of int
    | `Notify_authority_count of int
    | `Partial
    | `Query_answer_count of int
    | `Query_authority_count of int
    | `Rcode_cant_change of Rcode.t
    | `Rcode_error_cant_noerror of Rcode.t
    | `Request_rcode of Rcode.t
    | `Truncated_request
    | `Update_ack_answer_count of int
    | `Update_ack_authority_count of int
  ]

  let pp_err ppf = function
    | `Bad_edns_version version -> Fmt.pf ppf "bad edns version %d" version
    | `Leftover (off, n) -> Fmt.pf ppf "leftover %s at %d" n off
    | `Malformed (off, n) -> Fmt.pf ppf "malformed at %d: %s" off n
    | `Not_implemented (off, msg) -> Fmt.pf ppf "not implemented at %d: %s" off msg
    | `Notify_ack_answer_count an -> Fmt.pf ppf "notify ack answer count is %d" an
    | `Notify_ack_authority_count au -> Fmt.pf ppf "notify ack authority count is %d" au
    | `Notify_answer_count an -> Fmt.pf ppf "notify answer count is %d" an
    | `Notify_authority_count au -> Fmt.pf ppf "notify authority count is %d" au
    | `Partial -> Fmt.string ppf "partial"
    | `Query_answer_count an -> Fmt.pf ppf "query answer count is %d" an
    | `Query_authority_count au -> Fmt.pf ppf "query authority count is %d" au
    | `Rcode_cant_change rc -> Fmt.pf ppf "edns tried to change rcode from noerror to %a" Rcode.pp rc
    | `Rcode_error_cant_noerror rc -> Fmt.pf ppf "edns tried to change rcode from %a to noerror" Rcode.pp rc
    | `Request_rcode rc -> Fmt.pf ppf "query with rcode %a (must be noerr)" Rcode.pp rc
    | `Truncated_request -> Fmt.string ppf "truncated request"
    | `Update_ack_answer_count an -> Fmt.pf ppf "update ack answer count is %d" an
    | `Update_ack_authority_count au -> Fmt.pf ppf "update ack authority count is %d" au

  let ptr_tag = 0xC0 (* = 1100 0000 *)

  let decode ?(hostname = true) names buf ~off =
    let open Rresult.R.Infix in
    (* first collect all the labels (and their offsets) *)
    let rec aux offsets off =
      match Cstruct.get_uint8 buf off with
      | 0 -> Ok ((`Z, off), offsets, succ off)
      | i when i >= ptr_tag ->
        let ptr = (i - ptr_tag) lsl 8 + Cstruct.get_uint8 buf (succ off) in
        Ok ((`P ptr, off), offsets, off + 2)
      | i when i >= 64 -> Error (`Malformed (off, Fmt.strf "label tag 0x%x" i)) (* bit patterns starting with 10 or 01 *)
      | i -> (* this is clearly < 64! *)
        let name = Cstruct.to_string (Cstruct.sub buf (succ off) i) in
        aux ((name, off) :: offsets) (succ off + i)
    in
    (* Cstruct.xxx can raise, and we'll have a partial parse then *)
    (try aux [] off with _ -> Error `Partial) >>= fun (l, offs, foff) ->
    (* treat last element special -- either Z or P *)
    (match l with
     | `Z, off -> Ok (off, Domain_name.root, 1)
     | `P p, off -> match Int_map.find p names with
       | exception Not_found ->
         Error (`Malformed (off, "bad label offset: " ^ string_of_int p))
       | (exp, size) -> Ok (off, exp, size)) >>= fun (off, name, size) ->
    (* insert last label into names Map*)
    let names = Int_map.add off (name, size) names in
    (* fold over offs, insert into names Map, and reassemble the actual name *)
    let t = Array.(append (Domain_name.to_array name) (make (List.length offs) "")) in
    let names, _, size =
      List.fold_left (fun (names, idx, size) (label, off) ->
          let s = succ size + String.length label in
          Array.set t idx label ;
          let sub = Domain_name.of_array (Array.sub t 0 (succ idx)) in
          Int_map.add off (sub, s) names, succ idx, s)
        (names, Array.length (Domain_name.to_array name), size) offs
    in
    let t = Domain_name.of_array t in
    if size > 255 then
      Error (`Malformed (off, "name too long"))
    else if hostname && not (Domain_name.is_hostname t) then
      Error (`Malformed (off, Fmt.strf "name is not a hostname %a" Domain_name.pp t))
    else
      Ok (t, names, foff)

  let encode ?(compress = true) name names buf off =
    let encode_lbl lbl off =
      let l = String.length lbl in
      Cstruct.set_uint8 buf off l ;
      Cstruct.blit_from_string lbl 0 buf (succ off) l ;
      off + succ l
    and z off =
      Cstruct.set_uint8 buf off 0 ;
      succ off
    in
    let names, off =
      if compress then
        let rec one names off name =
          let arr = Domain_name.to_array name in
          let l = Array.length arr in
          if l = 0 then
            names, z off
          else
            match Domain_name.Map.find name names with
            | None ->
              let last = Array.get arr (pred l)
              and rem = Array.sub arr 0 (pred l)
              in
              let l = encode_lbl last off in
              one (Domain_name.Map.add name off names) l
                (Domain_name.of_array rem)
            | Some ptr ->
              let data = ptr_tag lsl 8 + ptr in
              Cstruct.BE.set_uint16 buf off data ;
              names, off + 2
        in
        one names off name
      else
        let rec one names off name =
          let arr = Domain_name.to_array name in
          let l = Array.length arr in
          if l = 0 then
            names, z off
          else
            let last = Array.get arr (pred l)
            and rem = Array.sub arr 0 (pred l)
            in
            let l = encode_lbl last off in
            one (Domain_name.Map.add name off names) l
              (Domain_name.of_array rem)
        in
        one names off name
    in
    names, off

  (*
  (* enable once https://github.com/ocaml/dune/issues/897 is resolved *)
  let%expect_test "decode_name" =
    let test ?hostname ?(map = Int_map.empty) ?(off = 0) data rmap roff =
      match decode ?hostname map (Cstruct.of_string data) ~off with
      | Error _ -> Format.printf "decode error"
      | Ok (name, omap, ooff) ->
        begin match Int_map.equal (fun (n, off) (n', off') ->
            Domain_name.equal n n' && off = off') rmap omap, roff = ooff
          with
          | true, true -> Format.printf "%a" Domain_name.pp name
          | false, _ -> Format.printf "map mismatch"
          | _, false -> Format.printf "offset mismatch"
        end
    in
    let test_err ?hostname ?(map = Int_map.empty) ?(off = 0) data =
      match decode ?hostname map (Cstruct.of_string data) ~off with
      | Error _ -> Format.printf "error (as expected)"
      | Ok _ -> Format.printf "expected error, got ok"
    in
    let n_of_s = Domain_name.of_string_exn in
    let map =
      Int_map.add 0 (n_of_s "foo.com", 9)
        (Int_map.add 4 (n_of_s "com", 5)
           (Int_map.add 8 (Domain_name.root, 1) Int_map.empty))
    in
    test "\003foo\003com\000" map 9;
    [%expect {|foo.com|}];
    test ~map ~off:9 "\003foo\003com\000\xC0\000" (Int_map.add 9 (n_of_s "foo.com", 9) map) 11;
    [%expect {|foo.com|}];
    let map' =
      Int_map.add 13 (n_of_s "foo.com", 9)
        (Int_map.add 9 (n_of_s "bar.foo.com", 13) map)
    in
    test ~map ~off:9 "\003foo\003com\000\003bar\xC0\000" map' 15;
    [%expect {|bar.foo.com|}];
    let map' =
      Int_map.add 14 (n_of_s "foo.com", 9)
        (Int_map.add 9 (n_of_s "bar-.foo.com", 14) map)
    in
    test ~map ~off:9 "\003foo\003com\000\004bar-\xC0\000" map' 16;
    [%expect {|bar-.foo.com|}];
    let map' =
      Int_map.add 0 (n_of_s "f23", 5) Int_map.(add 4 (Domain_name.root, 1) empty)
    in
    test "\003f23\000" map' 5;
    [%expect {|f23|}];
    let map' =
      Int_map.add 0 (n_of_s ~hostname:false "23", 4)
        (Int_map.add 3 (Domain_name.root, 1) Int_map.empty)
    in
    test ~hostname:false "\00223\000" map' 4;
    [%expect {|23|}];
    test_err "\003bar"; (* incomplete label *)
    [%expect {|error (as expected)|}];
    test_err "\xC0"; (* incomplete ptr *)
    [%expect {|error (as expected)|}];
    test_err "\005foo"; (* incomplete label *)
    [%expect {|error (as expected)|}];
    test_err "\xC0\x0A"; (* bad pointer *)
    [%expect {|error (as expected)|}];
    test_err "\xC0\x00"; (* cyclic pointer *)
    [%expect {|error (as expected)|}];
    test_err "\xC0\x01"; (* pointer to middle of pointer *)
    [%expect {|error (as expected)|}];
    test_err "\x40"; (* bad tag 0x40 *)
    [%expect {|error (as expected)|}];
    test_err "\x80"; (* bad tag 0x80 *)
    [%expect {|error (as expected)|}];
    test_err "\001-\000"; (* bad content "-" at start of label *)
    [%expect {|error (as expected)|}];
    test_err "\005foo-+\000"; (* bad content foo-+ in label *)
    [%expect {|error (as expected)|}];
    test_err "\00223\000"; (* bad content 23 in label *)
    [%expect {|error (as expected)|}];
    (* longest allowed domain name *)
    let open Astring in
    let max = "s23456789012345678901234567890123456789012345678901234567890123" in
    let lst, _ = String.span ~max:61 max in
    let full = n_of_s (String.concat ~sep:"." [ max ; max ; max ; lst ]) in
    let map' =
      Int_map.add 0 (full, 255)
        (Int_map.add 64 (n_of_s (String.concat ~sep:"." [ max ; max ; lst ]), 191)
           (Int_map.add 128 (n_of_s (String.concat ~sep:"." [ max ; lst ]), 127)
              (Int_map.add 192 (n_of_s lst, 63)
                 (Int_map.add 254 (Domain_name.root, 1) Int_map.empty))))
    in
    test ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3D" ^ lst ^ "\000")
      map' 255 ;
    [%expect {|s23456789012345678901234567890123456789012345678901234567890123.s23456789012345678901234567890123456789012345678901234567890123.s23456789012345678901234567890123456789012345678901234567890123.s234567890123456789012345678901234567890123456789012345678901|}];
    test_err ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3E" ^ lst ^ "1\000"); (* name too long *)
    [%expect {|error (as expected)|}];
    test_err ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\000"); (* domain name really too long *)
    [%expect {|error (as expected)|}]

  let%expect_test "encode_name" =
    let cs = Cstruct.create 30 in
    let test_cs ?(off = 0) len =
      Format.printf "%a" Cstruct.hexdump_pp (Cstruct.sub cs off len)
    in
    let test ?compress ?(map = Domain_name.Map.empty) ?(off = 0) name rmap roff =
      let omap, ooff = encode ?compress name map cs off in
      if Domain_name.Map.equal (fun a b -> int_compare a b = 0) rmap omap && roff = ooff then
        Format.printf "ok"
      else
        Format.printf "error"
    in
    let n_of_s = Domain_name.of_string_exn in
    test Domain_name.root Domain_name.Map.empty 1; (* compressed encode of root is good *)
    [%expect {|ok|}];
    test_cs 1;
    [%expect {|00|}];
    test ~compress:false Domain_name.root Domain_name.Map.empty 1;
    [%expect {|ok|}];
    test_cs 1;
    [%expect {|00|}];
    let map =
      Domain_name.Map.add (n_of_s "foo.bar") 0
        (Domain_name.Map.add (n_of_s "bar") 4 Domain_name.Map.empty)
    in
    test (n_of_s "foo.bar") map 9; (* encode of foo.bar is good *)
    [%expect {|ok|}];
    test_cs 9;
    [%expect {|03 66 6f 6f 03 62 61 72  00|}];
    test ~compress:false (n_of_s "foo.bar") map 9; (* uncompressed foo.bar is good *)
    [%expect {|ok|}];
    test_cs 9;
    [%expect {|03 66 6f 6f 03 62 61 72  00|}];
    let emap = Domain_name.Map.add (n_of_s "baz.foo.bar") 9 map in
    test ~map ~off:9 (n_of_s "baz.foo.bar") emap 15; (* encode of baz.foo.bar is good *)
    [%expect {|ok|}];
    test_cs 15;
    [%expect {|03 66 6f 6f 03 62 61 72  00 03 62 61 7a c0 00|}];
    let map' =
      Domain_name.Map.add (n_of_s "baz.foo.bar") 9
        (Domain_name.Map.add (n_of_s "foo.bar") 13
           (Domain_name.Map.add (n_of_s "bar") 17 Domain_name.Map.empty))
    in
    test ~compress:false ~map ~off:9 (n_of_s "baz.foo.bar") map' 22;
    [%expect {|ok|}];
    test_cs 22;
    [%expect {|
03 66 6f 6f 03 62 61 72  00 03 62 61 7a 03 66 6f
6f 03 62 61 72 00|}]
*)
end

(* start of authority *)
module Soa = struct
  type t = {
    nameserver : Domain_name.t ;
    hostmaster : Domain_name.t ;
    serial : int32 ;
    refresh : int32 ;
    retry : int32 ;
    expiry : int32 ;
    minimum : int32 ;
  }

  let default_refresh = 86400l (* 24 hours *)
  let default_retry = 7200l (* 2 hours *)
  let default_expiry = 3600000l (* 1000 hours *)
  let default_minimum = 3600l (* 1 hour *)

  let create ?(serial = 0l) ?(refresh = default_refresh) ?(retry = default_retry)
      ?(expiry = default_expiry) ?(minimum = default_minimum) ?hostmaster nameserver =
    let hostmaster = match hostmaster with
      | None -> Domain_name.(prepend_exn (drop_labels_exn nameserver) "hostmaster")
      | Some x -> x
    in
    { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }

  let pp ppf soa =
    Fmt.pf ppf "SOA %a %a %lu %lu %lu %lu %lu"
      Domain_name.pp soa.nameserver Domain_name.pp soa.hostmaster
      soa.serial soa.refresh soa.retry soa.expiry soa.minimum

  let compare soa soa' =
    andThen (int32_compare soa.serial soa'.serial)
      (andThen (Domain_name.compare soa.nameserver soa'.nameserver)
         (andThen (Domain_name.compare soa.hostmaster soa'.hostmaster)
            (andThen (int32_compare soa.refresh soa'.refresh)
               (andThen (int32_compare soa.retry soa'.retry)
                  (andThen (int32_compare soa.expiry soa'.expiry)
                     (int32_compare soa.minimum soa'.minimum))))))

  let newer ~old soa = Int32.sub soa.serial old.serial > 0l

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let hostname = false in
    Name.decode ~hostname names buf ~off >>= fun (nameserver, names, off) ->
    Name.decode ~hostname names buf ~off >>| fun (hostmaster, names, off) ->
    let serial = Cstruct.BE.get_uint32 buf off in
    let refresh = Cstruct.BE.get_uint32 buf (off + 4) in
    let retry = Cstruct.BE.get_uint32 buf (off + 8) in
    let expiry = Cstruct.BE.get_uint32 buf (off + 12) in
    let minimum = Cstruct.BE.get_uint32 buf (off + 16) in
    let soa =
      { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }
    in
    (soa, names, off + 20)

  let encode soa names buf off =
    let names, off = Name.encode soa.nameserver names buf off in
    let names, off = Name.encode soa.hostmaster names buf off in
    Cstruct.BE.set_uint32 buf off soa.serial ;
    Cstruct.BE.set_uint32 buf (off + 4) soa.refresh ;
    Cstruct.BE.set_uint32 buf (off + 8) soa.retry ;
    Cstruct.BE.set_uint32 buf (off + 12) soa.expiry ;
    Cstruct.BE.set_uint32 buf (off + 16) soa.minimum ;
    names, off + 20
end

(* name server *)
module Ns = struct
  type t = Domain_name.t

  let pp ppf ns = Fmt.pf ppf "NS %a" Domain_name.pp ns

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ = Name.decode ~hostname:true names buf ~off

  let encode = Name.encode
end

(* mail exchange *)
module Mx = struct
  type t = {
    preference : int ;
    mail_exchange : Domain_name.t ;
  }

  let pp ppf { preference ; mail_exchange } =
    Fmt.pf ppf "MX %u %a" preference Domain_name.pp mail_exchange

  let compare mx mx' =
    andThen (int_compare mx.preference mx'.preference)
      (Domain_name.compare mx.mail_exchange mx'.mail_exchange)

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let preference = Cstruct.BE.get_uint16 buf off in
    Name.decode ~hostname:false names buf ~off:(off + 2) >>| fun (mx, names, off) ->
    { preference ; mail_exchange = mx }, names, off

  let encode { preference ; mail_exchange } names buf off =
    Cstruct.BE.set_uint16 buf off preference ;
    Name.encode mail_exchange names buf (off + 2)
end

(* canonical name *)
module Cname = struct
  type t = Domain_name.t

  let pp ppf alias = Fmt.pf ppf "CNAME %a" Domain_name.pp alias

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_= Name.decode ~hostname:false names buf ~off

  let encode = Name.encode
end

(* address record *)
module A = struct
  type t = Ipaddr.V4.t

  let pp ppf address = Fmt.pf ppf "A %a" Ipaddr.V4.pp address

  let compare = Ipaddr.V4.compare

  let decode names buf ~off ~len:_ =
    let ip = Cstruct.BE.get_uint32 buf off in
    Ok (Ipaddr.V4.of_int32 ip, names, off + 4)

  let encode ip names buf off =
    let ip = Ipaddr.V4.to_int32 ip in
    Cstruct.BE.set_uint32 buf off ip ;
    names, off + 4
end

(* quad-a record *)
module Aaaa = struct
  type t = Ipaddr.V6.t

  let pp ppf address = Fmt.pf ppf "AAAA %a" Ipaddr.V6.pp address

  let compare = Ipaddr.V6.compare

  let decode names buf ~off ~len:_ =
    let iph = Cstruct.BE.get_uint64 buf off
    and ipl = Cstruct.BE.get_uint64 buf (off + 8)
    in
    Ok (Ipaddr.V6.of_int64 (iph, ipl), names, off + 16)

  let encode ip names buf off =
    let iph, ipl = Ipaddr.V6.to_int64 ip in
    Cstruct.BE.set_uint64 buf off iph ;
    Cstruct.BE.set_uint64 buf (off + 8) ipl ;
    names, off + 16
end

(* domain name pointer - reverse entries *)
module Ptr = struct
  type t = Domain_name.t

  let pp ppf rev = Fmt.pf ppf "PTR %a" Domain_name.pp rev

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ = Name.decode ~hostname:true names buf ~off

  let encode = Name.encode
end

(* service record *)
module Srv = struct
  type t = {
    priority : int ;
    weight : int ;
    port : int ;
    target : Domain_name.t
  }

  let pp ppf t =
    Fmt.pf ppf
      "SRV priority %d weight %d port %d target %a"
      t.priority t.weight t.port Domain_name.pp t.target

  let compare a b =
    andThen (int_compare a.priority b.priority)
      (andThen (int_compare a.weight b.weight)
         (andThen (int_compare a.port b.port)
            (Domain_name.compare a.target b.target)))

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let priority = Cstruct.BE.get_uint16 buf off
    and weight = Cstruct.BE.get_uint16 buf (off + 2)
    and port = Cstruct.BE.get_uint16 buf (off + 4)
    in
    Name.decode names buf ~off:(off + 6) >>= fun (target, names, off) ->
    Ok ({ priority ; weight ; port ; target }, names, off)

  let encode t names buf off =
    Cstruct.BE.set_uint16 buf off t.priority ;
    Cstruct.BE.set_uint16 buf (off + 2) t.weight ;
    Cstruct.BE.set_uint16 buf (off + 4) t.port ;
    Name.encode t.target names buf (off + 6)
end

(* DNS key *)
module Dnskey = struct

  (* 8 bit *)
  type algorithm =
    | MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512

  let algorithm_to_int = function
    | MD5 -> 157
    | SHA1 -> 161
    | SHA224 -> 162
    | SHA256 -> 163
    | SHA384 -> 164
    | SHA512 -> 165
  let int_to_algorithm ?(off = 0) = function
    | 157 -> Ok MD5
    | 161 -> Ok SHA1
    | 162 -> Ok SHA224
    | 163 -> Ok SHA256
    | 164 -> Ok SHA384
    | 165 -> Ok SHA512
    | x -> Error (`Not_implemented (off, Fmt.strf "DNSKEY algorithm 0x%X" x))
  let algorithm_to_string = function
    | MD5 -> "MD5"
    | SHA1 -> "SHA1"
    | SHA224 -> "SHA224"
    | SHA256 -> "SHA256"
    | SHA384 -> "SHA384"
    | SHA512 -> "SHA512"
  let string_to_algorithm = function
    | "MD5" -> Ok MD5
    | "SHA1" -> Ok SHA1
    | "SHA224" -> Ok SHA224
    | "SHA256" -> Ok SHA256
    | "SHA384" -> Ok SHA384
    | "SHA512" -> Ok SHA512
    | x -> Error (`Msg ("DNSKEY algorithm not implemented " ^ x))

  let algorithm_b64_len k =
    let b64 bits = (bits / 8 + 2) / 3 * 4 in
    match k with
    | MD5 -> b64 128
    | SHA1 -> b64 160
    | SHA224 -> b64 224
    | SHA256 -> b64 256
    | SHA384 -> b64 384
    | SHA512 -> b64 512

  let pp_algorithm ppf k = Fmt.string ppf (algorithm_to_string k)

  type t = {
    flags : int ; (* uint16 *)
    algorithm : algorithm ; (* u_int8_t *)
    key : Cstruct.t ;
  }

  let pp ppf t =
    Fmt.pf ppf "DNSKEY flags %u algo %a key %a"
      t.flags pp_algorithm t.algorithm
      Cstruct.hexdump_pp t.key

  let compare a b =
    andThen (compare a.algorithm b.algorithm)
      (Cstruct.compare a.key b.key)

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let flags = Cstruct.BE.get_uint16 buf off
    and proto = Cstruct.get_uint8 buf (off + 2)
    and algo = Cstruct.get_uint8 buf (off + 3)
    in
    guard (proto = 3) (`Not_implemented (off + 2, Fmt.strf "dnskey protocol 0x%x" proto)) >>= fun () ->
    int_to_algorithm ~off algo >>= fun algorithm ->
    let len = algorithm_b64_len algorithm in
    let key = Cstruct.sub buf (off + 4) len in
    Ok ({ flags ; algorithm ; key }, names, off + len + 4)

  let encode t names buf off =
    Cstruct.BE.set_uint16 buf off t.flags ;
    Cstruct.set_uint8 buf (off + 2) 3 ;
    Cstruct.set_uint8 buf (off + 3) (algorithm_to_int t.algorithm) ;
    let kl = Cstruct.len t.key in
    Cstruct.blit t.key 0 buf (off + 4) kl ;
    names, off + 4 + kl

  let of_string key =
    let open Rresult.R.Infix in
    let parse flags algo key =
      let key = Cstruct.of_string key in
      string_to_algorithm algo >>| fun algorithm ->
      { flags ; algorithm ; key }
    in
    match Astring.String.cuts ~sep:":" key with
    | [ flags ; algo ; key ] ->
      (try Ok (int_of_string flags) with Failure _ ->
         Error (`Msg ("couldn't parse flags " ^ flags))) >>= fun flags ->
      parse flags algo key
    | [ algo ; key ] -> parse 0 algo key
    | _ -> Error (`Msg ("invalid DNSKEY string " ^ key))

  let name_key_of_string str =
    let open Rresult.R.Infix in
    match Astring.String.cut ~sep:":" str with
    | None -> Error (`Msg ("couldn't parse name:key in " ^ str))
    | Some (name, key) ->
      Domain_name.of_string ~hostname:false name >>= fun name ->
      of_string key >>| fun dnskey ->
      (name, dnskey)
end

(* certificate authority authorization *)
module Caa = struct
  type t = {
    critical : bool ;
    tag : string ;
    value : string list ;
  }

  let pp ppf t =
    Fmt.pf ppf "CAA critical %b tag %s value %a"
      t.critical t.tag Fmt.(list ~sep:(unit "; ") string) t.value

  let compare a b =
    andThen (compare a.critical b.critical)
      (andThen (String.compare a.tag b.tag)
         (List.fold_left2
            (fun r a b -> match r with 0 -> String.compare a b | x -> x)
            0 a.value b.value))

  let decode names buf ~off ~len =
    let open Rresult.R.Infix in
    let critical = Cstruct.get_uint8 buf off = 0x80
    and tl = Cstruct.get_uint8 buf (succ off)
    in
    guard (tl > 0 && tl < 16) (`Not_implemented (succ off, Fmt.strf "caa tag 0x%x" tl)) >>= fun () ->
    let tag = Cstruct.sub buf (off + 2) tl in
    let tag = Cstruct.to_string tag in
    let vs = 2 + tl in
    let value = Cstruct.sub buf (off + vs) (len - vs) in
    let value = Astring.String.cuts ~sep:";" (Cstruct.to_string value) in
    Ok ({ critical ; tag ; value }, names, off + len)

  let encode t names buf off =
    Cstruct.set_uint8 buf off (if t.critical then 0x80 else 0x0) ;
    let tl = String.length t.tag in
    Cstruct.set_uint8 buf (succ off) tl ;
    Cstruct.blit_from_string t.tag 0 buf (off + 2) tl ;
    let value = Astring.String.concat ~sep:";" t.value in
    let vl = String.length value in
    Cstruct.blit_from_string value 0 buf (off + 2 + tl) vl ;
    names, off + tl + 2 + vl
end

(* transport layer security A *)
module Tlsa = struct

  (* 8 bit *)
  type cert_usage =
    | CA_constraint
    | Service_certificate_constraint
    | Trust_anchor_assertion
    | Domain_issued_certificate

  let cert_usage_to_int = function
    | CA_constraint -> 0
    | Service_certificate_constraint -> 1
    | Trust_anchor_assertion -> 2
    | Domain_issued_certificate -> 3
  let int_to_cert_usage ?(off = 0) = function
    | 0 -> Ok CA_constraint
    | 1 -> Ok Service_certificate_constraint
    | 2 -> Ok Trust_anchor_assertion
    | 3 -> Ok Domain_issued_certificate
    | x -> Error (`Not_implemented (off, Fmt.strf "TLSA cert usage %X" x))
  let cert_usage_to_string = function
    | CA_constraint -> "CA constraint"
    | Service_certificate_constraint -> "service certificate constraint"
    | Trust_anchor_assertion -> "trust anchor assertion"
    | Domain_issued_certificate -> "domain issued certificate"

  let pp_cert_usage ppf k = Fmt.string ppf (cert_usage_to_string k)

  (* 8 bit *)
  type selector =
    | Full_certificate
    | Subject_public_key_info
    | Private

  let selector_to_int = function
    | Full_certificate -> 0
    | Subject_public_key_info -> 1
    | Private -> 255
  let int_to_selector ?(off = 0) = function
    | 0 -> Ok Full_certificate
    | 1 -> Ok Subject_public_key_info
    | 255 -> Ok Private
    | x -> Error (`Not_implemented (off, Fmt.strf "TLSA selector %x" x))
  let selector_to_string = function
    | Full_certificate -> "full certificate"
    | Subject_public_key_info -> "subject public key info"
    | Private -> "private"

  let pp_selector ppf k = Fmt.string ppf (selector_to_string k)

  (* 8 bit *)
  type matching_type =
    | No_hash
    | SHA256
    | SHA512

  let matching_type_to_int = function
    | No_hash -> 0
    | SHA256 -> 1
    | SHA512 -> 2
  let int_to_matching_type ?(off = 0) = function
    | 0 -> Ok No_hash
    | 1 -> Ok SHA256
    | 2 -> Ok SHA512
    | x -> Error (`Not_implemented (off, Fmt.strf "TLSA matching type %X" x))
  let matching_type_to_string = function
    | No_hash -> "no hash"
    | SHA256 -> "SHA256"
    | SHA512 -> "SHA512"

  let pp_matching_type ppf k = Fmt.string ppf (matching_type_to_string k)

  type t = {
    cert_usage : cert_usage ;
    selector : selector ;
    matching_type : matching_type ;
    data : Cstruct.t ;
  }

  let pp ppf tlsa =
    Fmt.pf ppf "TLSA @[<v>%a %a %a@ %a@]"
      pp_cert_usage tlsa.cert_usage
      pp_selector tlsa.selector
      pp_matching_type tlsa.matching_type
      Cstruct.hexdump_pp tlsa.data

  let compare t1 t2 =
    andThen (compare t1.cert_usage t2.cert_usage)
      (andThen (compare t1.selector t2.selector)
         (andThen (compare t1.matching_type t2.matching_type)
            (Cstruct.compare t1.data t2.data)))

  let decode names buf ~off ~len =
    let open Rresult.R.Infix in
    let usage, selector, matching_type =
      Cstruct.get_uint8 buf off,
      Cstruct.get_uint8 buf (off + 1),
      Cstruct.get_uint8 buf (off + 2)
    in
    let data = Cstruct.sub buf (off + 3) (len - 3) in
    int_to_cert_usage ~off usage >>= fun cert_usage ->
    int_to_selector ~off:(off + 1) selector >>= fun selector ->
    int_to_matching_type ~off:(off + 2) matching_type >>| fun matching_type ->
    let tlsa = { cert_usage ; selector ; matching_type ; data } in
    tlsa, names, off + len

  let encode tlsa names buf off =
    Cstruct.set_uint8 buf off (cert_usage_to_int tlsa.cert_usage) ;
    Cstruct.set_uint8 buf (off + 1) (selector_to_int tlsa.selector) ;
    Cstruct.set_uint8 buf (off + 2) (matching_type_to_int tlsa.matching_type) ;
    let l = Cstruct.len tlsa.data in
    Cstruct.blit tlsa.data 0 buf (off + 3) l ;
    names, off + 3 + l
end

(* secure shell fingerprint *)
module Sshfp = struct

  (* 8 bit *)
  type algorithm =
    | Rsa
    | Dsa
    | Ecdsa
    | Ed25519

  let algorithm_to_int = function
    | Rsa -> 1
    | Dsa -> 2
    | Ecdsa -> 3
    | Ed25519 -> 4

  let int_to_algorithm ?(off = 0) = function
    | 1 -> Ok Rsa
    | 2 -> Ok Dsa
    | 3 -> Ok Ecdsa
    | 4 -> Ok Ed25519
    | x -> Error (`Not_implemented (off, Fmt.strf "SSHFP algorithm %X" x))

  let algorithm_to_string = function
    | Rsa -> "RSA"
    | Dsa -> "DSA"
    | Ecdsa -> "ECDSA"
    | Ed25519 -> "ED25519"

  let pp_algorithm ppf k = Fmt.string ppf (algorithm_to_string k)

  (* 8 bit *)
  type typ =
    | SHA1
    | SHA256

  let typ_to_int = function
    | SHA1 -> 1
    | SHA256 -> 2

  let int_to_typ ?(off = 0) = function
    | 1 -> Ok SHA1
    | 2 -> Ok SHA256
    | x -> Error (`Not_implemented (off, Fmt.strf "SSHFP type %X" x))

  let typ_to_string = function
    | SHA1 -> "SHA1"
    | SHA256 -> "SHA256"

  let pp_typ ppf k = Fmt.string ppf (typ_to_string k)

  type t = {
    algorithm : algorithm ;
    typ : typ ;
    fingerprint : Cstruct.t ;
  }

  let pp ppf sshfp =
    Fmt.pf ppf "SSHFP %a %a %a"
      pp_algorithm sshfp.algorithm
      pp_typ sshfp.typ
      Cstruct.hexdump_pp sshfp.fingerprint

  let compare s1 s2 =
    andThen (compare s1.algorithm s2.algorithm)
      (andThen (compare s1.typ s2.typ)
         (Cstruct.compare s1.fingerprint s2.fingerprint))

  let decode names buf ~off ~len =
    let open Rresult.R.Infix in
    let algo, typ = Cstruct.get_uint8 buf off, Cstruct.get_uint8 buf (succ off) in
    let fingerprint = Cstruct.sub buf (off + 2) (len - 2) in
    int_to_algorithm ~off algo >>= fun algorithm ->
    int_to_typ ~off:(succ off) typ >>| fun typ ->
    let sshfp = { algorithm ; typ ; fingerprint } in
    sshfp, names, off + len

  let encode sshfp names buf off =
    Cstruct.set_uint8 buf off (algorithm_to_int sshfp.algorithm) ;
    Cstruct.set_uint8 buf (succ off) (typ_to_int sshfp.typ) ;
    let l = Cstruct.len sshfp.fingerprint in
    Cstruct.blit sshfp.fingerprint 0 buf (off + 2) l ;
    names, off + l + 2
end

(* Text record *)
module Txt = struct
  type t = string

  let pp ppf txt = Fmt.pf ppf "TXT %s" txt

  let compare = String.compare

  let decode names buf ~off ~len =
    let decode_character_str buf off =
      let len = Cstruct.get_uint8 buf off in
      let data = Cstruct.to_string (Cstruct.sub buf (succ off) len) in
      (data, off + len + 1)
    in
    let sub = Cstruct.sub buf off len in
    let rec more acc off =
      if len = off then
        List.rev acc
      else
        let d, off = decode_character_str sub off in
        more (d::acc) off
    in
    let txts = more [] 0 in
    Ok (txts, names, off + len)

  let encode txt names buf off =
    let len = String.length txt in
    Cstruct.set_uint8 buf off len ;
    Cstruct.blit_from_string txt 0 buf (succ off) len ;
    names, off + len + 1
end

module Tsig = struct
  type algorithm =
    | SHA1
    | SHA224
    | SHA256
    | SHA384
    | SHA512

  type t = {
    algorithm : algorithm ;
    signed : Ptime.t ;
    fudge : Ptime.Span.t ;
    mac : Cstruct.t ;
    original_id : int ; (* again 16 bit *)
    error : Rcode.t ;
    other : Ptime.t option
  }

  let equal a b =
    a.algorithm = b.algorithm &&
    Ptime.equal a.signed b.signed &&
    Ptime.Span.equal a.fudge b.fudge &&
    Cstruct.equal a.mac b.mac &&
    a.original_id = b.original_id &&
    a.error = b.error &&
    opt_eq Ptime.equal a.other b.other

  let algorithm_to_name, algorithm_of_name =
    let of_s = Domain_name.of_string_exn in
    let map =
      [ (* of_s "HMAC-MD5.SIG-ALG.REG.INT", MD5 ; *)
        of_s "hmac-sha1", SHA1 ;
        of_s "hmac-sha224", SHA224 ;
        of_s "hmac-sha256", SHA256 ;
        of_s "hmac-sha384", SHA384 ;
        of_s "hmac-sha512", SHA512 ]
    in
    (fun a -> fst (List.find (fun (_, t) -> t = a) map)),
    (fun ?(off = 0) b ->
       try Ok (snd (List.find (fun (n, _) -> Domain_name.equal b n) map))
       with Not_found ->
         Error (`Not_implemented (off, Fmt.strf "algorithm name %a" Domain_name.pp b)))

  let pp_algorithm ppf a = Domain_name.pp ppf (algorithm_to_name a)

  (* this is here because I don't like float, and rather convert Ptime.t to int64 *)
  let s_in_d = 86_400L
  let ps_in_s = 1_000_000_000_000L

  let ptime_span_to_int64 ts =
    let d_min, d_max = Int64.(div min_int s_in_d, div max_int s_in_d) in
    let d, ps = Ptime.Span.to_d_ps ts in
    let d = Int64.of_int d in
    if d < d_min || d > d_max then
      None
    else
      let s = Int64.mul d s_in_d in
      let s' = Int64.(add s (div ps ps_in_s)) in
      if s' < s then
        None
      else
        Some s'

  let ptime_of_int64 ?(off = 0) s =
    let d, ps = Int64.(div s s_in_d, mul (rem s s_in_d) ps_in_s) in
    if d < Int64.of_int min_int || d > Int64.of_int max_int then
      Error (`Malformed (off, Fmt.strf "timestamp does not fit in time range %Ld" s))
    else
      Ok (Ptime.v (Int64.to_int d, ps))

  let valid_time now tsig =
    let ts = tsig.signed
    and fudge = tsig.fudge
    in
    match Ptime.add_span now fudge, Ptime.sub_span now fudge with
    | None, _ -> false
    | _, None -> false
    | Some late, Some early ->
      Ptime.is_earlier ts ~than:late && Ptime.is_later ts ~than:early

  let tsig ~algorithm ~signed ?(fudge = Ptime.Span.of_int_s 300)
      ?(mac = Cstruct.create 0) ?(original_id = 0) ?(error = Rcode.NoError)
      ?other () =
    match ptime_span_to_int64 (Ptime.to_span signed), ptime_span_to_int64 fudge with
    | None, _ | _, None -> None
    | Some ts, Some fu ->
      if
        Int64.logand 0xffff_0000_0000_0000L ts = 0L &&
        Int64.logand 0xffff_ffff_ffff_0000L fu = 0L
      then
        Some { algorithm ; signed ; fudge ; mac ; original_id ; error ; other }
      else
        None

  let with_mac tsig mac = { tsig with mac }

  let with_error tsig error = { tsig with error }

  let with_signed tsig signed =
    match ptime_span_to_int64 (Ptime.to_span signed) with
    | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
      Some { tsig with signed }
    | _ -> None

  let with_other tsig other =
    match other with
    | None -> Some { tsig with other }
    | Some ts ->
      match ptime_span_to_int64 (Ptime.to_span ts) with
      | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
        Some { tsig with other }
      | _ -> None

  let pp ppf t =
    Fmt.pf ppf
      "TSIG %a signed %a fudge %a mac %a original id %04X err %a other %a"
      pp_algorithm t.algorithm
      (Ptime.pp_rfc3339 ()) t.signed Ptime.Span.pp t.fudge
      Cstruct.hexdump_pp t.mac t.original_id Rcode.pp t.error
      Fmt.(option ~none:(unit "none") (Ptime.pp_rfc3339 ())) t.other

  let decode_48bit_time buf off =
    let a = Cstruct.BE.get_uint16 buf off
    and b = Cstruct.BE.get_uint16 buf (off + 2)
    and c = Cstruct.BE.get_uint16 buf (off + 4)
    in
    Int64.(add
             (add (shift_left (of_int a) 32) (shift_left (of_int b) 16))
             (of_int c))

  (* TODO maybe revise, esp. all the guards *)
  let decode names buf ~off =
    let open Rresult.R.Infix in
    guard (Cstruct.len buf - off >= 6) `Partial >>= fun () ->
    let ttl = Cstruct.BE.get_uint32 buf off in
    guard (ttl = 0l) (`Malformed (off, Fmt.strf "tsig ttl is not zero %lu" ttl)) >>= fun () ->
    let len = Cstruct.BE.get_uint16 buf (off + 4) in
    let rdata_start = off + 6 in
    guard (Cstruct.len buf - rdata_start >= len) `Partial >>= fun () ->
    Name.decode ~hostname:false names buf ~off:rdata_start >>= fun (algorithm, names, off') ->
    guard (Cstruct.len buf - off' >= 10) `Partial >>= fun () ->
    let signed = decode_48bit_time buf off'
    and fudge = Cstruct.BE.get_uint16 buf (off' + 6)
    and mac_len = Cstruct.BE.get_uint16 buf (off' + 8)
    in
    guard (Cstruct.len buf - off' >= 10 + mac_len + 6) `Partial >>= fun () ->
    let mac = Cstruct.sub buf (off' + 10) mac_len
    and original_id = Cstruct.BE.get_uint16 buf (off' + 10 + mac_len)
    and error = Cstruct.BE.get_uint16 buf (off' + 12 + mac_len)
    and other_len = Cstruct.BE.get_uint16 buf (off' + 14 + mac_len)
    in
    let rdata_end = off' + 10 + mac_len + 6 + other_len in
    guard (rdata_end - rdata_start = len) `Partial >>= fun () ->
    guard (Cstruct.len buf >= rdata_end) `Partial >>= fun () ->
    guard (other_len = 0 || other_len = 6)
      (`Malformed (off' + 14 + mac_len, "other timestamp should be 0 or 6 bytes!")) >>= fun () ->
    algorithm_of_name ~off algorithm >>= fun algorithm ->
    ptime_of_int64 ~off:off' signed >>= fun signed ->
    Rcode.of_int ~off:(off' + 12 + mac_len) error >>= fun error ->
    (if other_len = 0 then
       Ok None
     else
       let other = decode_48bit_time buf (off + 16 + mac_len) in
       ptime_of_int64 ~off:(off' + 14 + mac_len + 2) other >>| fun x ->
       Some x) >>| fun other ->
    let fudge = Ptime.Span.of_int_s fudge in
    { algorithm ; signed ; fudge ; mac ; original_id ; error ; other },
    names,
    off + 16 + mac_len + other_len

  let encode_48bit_time buf ?(off = 0) ts =
    match ptime_span_to_int64 (Ptime.to_span ts) with
    | None ->
      Log.warn (fun m -> m "couldn't convert (to_span %a) to int64" Ptime.pp ts)
    | Some secs ->
      if Int64.logand secs 0xffff_0000_0000_0000L > 0L then
        Log.warn (fun m -> m "secs %Lu > 48 bit" secs)
      else
        let a, b, c =
          let f s = Int64.(to_int (logand 0xffffL (shift_right secs s))) in
          f 32, f 16, f 0
        in
        Cstruct.BE.set_uint16 buf off a ;
        Cstruct.BE.set_uint16 buf (off + 2) b ;
        Cstruct.BE.set_uint16 buf (off + 4) c

  let encode_16bit_time buf ?(off = 0) ts =
    match ptime_span_to_int64 ts with
    | None ->
      Log.warn (fun m -> m "couldn't convert span %a to int64" Ptime.Span.pp ts)
    | Some secs ->
      if Int64.logand secs 0xffff_ffff_ffff_0000L > 0L then
        Log.warn (fun m -> m "secs %Lu > 16 bit" secs)
      else
        let a = Int64.(to_int (logand 0xffffL secs)) in
        Cstruct.BE.set_uint16 buf off a

  (* TODO unused -- why? *)
  let _encode t names buf off =
    let algo = algorithm_to_name t.algorithm in
    let names, off = Name.encode ~compress:false algo names buf off in
    encode_48bit_time buf ~off t.signed ;
    encode_16bit_time buf ~off:(off + 6) t.fudge ;
    let mac_len = Cstruct.len t.mac in
    Cstruct.BE.set_uint16 buf (off + 8) mac_len ;
    Cstruct.blit t.mac 0 buf (off + 10) mac_len ;
    Cstruct.BE.set_uint16 buf (off + 10 + mac_len) t.original_id ;
    Cstruct.BE.set_uint16 buf (off + 12 + mac_len) (Rcode.to_int t.error) ;
    let other_len = match t.other with None -> 0 | Some _ -> 6 in
    Cstruct.BE.set_uint16 buf (off + 14 + mac_len) other_len ;
    (match t.other with
     | None -> ()
     | Some t -> encode_48bit_time buf ~off:(off + 16 + mac_len) t) ;
    names, off + 16 + mac_len + other_len

  let canonical_name name =
    let buf = Cstruct.create 255
    and emp = Domain_name.Map.empty
    and nam = Domain_name.canonical name
    in
    let _, off = Name.encode ~compress:false nam emp buf 0 in
    Cstruct.sub buf 0 off

  let encode_raw_tsig_base name t =
    let name = canonical_name name
    and aname = canonical_name (algorithm_to_name t.algorithm)
    in
    let clttl = Cstruct.create 6 in
    Cstruct.BE.set_uint16 clttl 0 Clas.(to_int ANY_CLASS) ;
    Cstruct.BE.set_uint32 clttl 2 0l ;
    let time = Cstruct.create 8 in
    encode_48bit_time time t.signed ;
    encode_16bit_time time ~off:6 t.fudge ;
    let other =
      let buf = match t.other with
        | None ->
          let buf = Cstruct.create 4 in
          Cstruct.BE.set_uint16 buf 2 0 ;
          buf
        | Some t ->
          let buf = Cstruct.create 10 in
          Cstruct.BE.set_uint16 buf 2 6 ;
          encode_48bit_time buf ~off:4 t ;
          buf
      in
      Cstruct.BE.set_uint16 buf 0 (Rcode.to_int t.error) ;
      buf
    in
    name, clttl, [ aname ; time ], other

  let encode_raw name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    Cstruct.concat (name :: clttl :: mid @ [ fin ])

  let encode_full name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    let typ =
      let typ = Cstruct.create 2 in
      Cstruct.BE.set_uint16 typ 0 Rr.(to_int TSIG) ;
      typ
    and mac =
      let len = Cstruct.len t.mac in
      let l = Cstruct.create 2 in
      Cstruct.BE.set_uint16 l 0 len ;
      let orig = Cstruct.create 2 in
      Cstruct.BE.set_uint16 orig 0 t.original_id ;
      [ l ; t.mac ; orig ]
    in
    let rdata = Cstruct.concat (mid @ mac @ [ fin ]) in
    let len =
      let buf = Cstruct.create 2 in
      Cstruct.BE.set_uint16 buf 0 (Cstruct.len rdata) ;
      buf
    in
    Cstruct.concat [ name ; typ ; clttl ; len ; rdata ]

  let dnskey_to_tsig_algo key =
    match key.Dnskey.algorithm with
    | Dnskey.MD5 -> Error (`Msg "TSIG algorithm MD5 is not supported")
    | Dnskey.SHA1 -> Ok SHA1
    | Dnskey.SHA224 -> Ok SHA224
    | Dnskey.SHA256 -> Ok SHA256
    | Dnskey.SHA384 -> Ok SHA384
    | Dnskey.SHA512 -> Ok SHA512
end

module Edns = struct

  type extension =
    | Nsid of Cstruct.t
    | Cookie of Cstruct.t
    | Tcp_keepalive of int option
    | Padding of int
    | Extension of int * Cstruct.t

  let pp_extension ppf = function
    | Nsid cs -> Fmt.pf ppf "nsid %a" Cstruct.hexdump_pp cs
    | Cookie cs -> Fmt.pf ppf "cookie %a" Cstruct.hexdump_pp cs
    | Tcp_keepalive i -> Fmt.pf ppf "keepalive %a" Fmt.(option ~none:(unit "none") int) i
    | Padding i -> Fmt.pf ppf "padding %d" i
    | Extension (t, v) -> Fmt.pf ppf "unknown option %d: %a" t Cstruct.hexdump_pp v

  let compare_extension a b = match a, b with
    | Nsid a, Nsid b -> Cstruct.compare a b
    | Nsid _, _ -> 1 | _, Nsid _ -> -1
    | Cookie a, Cookie b -> Cstruct.compare a b
    | Cookie _, _ -> 1 | _, Cookie _ -> -1
    | Tcp_keepalive a, Tcp_keepalive b ->
      begin match a, b with
        | None, None -> 0
        | None, Some _ -> -1
        | Some _, None -> 1
        | Some a, Some b -> int_compare a b
      end
    | Tcp_keepalive _, _ -> 1 | _, Tcp_keepalive _ -> -1
    | Padding a, Padding b -> int_compare a b
    | Padding _, _ -> 1 | _, Padding _ -> -1
    | Extension (t, v), Extension (t', v') ->
      andThen (int_compare t t') (Cstruct.compare v v')

  (* tag is 16 bit, we don't support many *)
  let extension_to_int = function
    | Nsid _ -> 3
    | Cookie _ -> 10
    | Tcp_keepalive _ -> 11
    | Padding _ -> 12
    | Extension (tag, _) -> tag

  let int_to_extension = function
    | 3 -> Some `nsid
    | 10 -> Some `cookie
    | 11 -> Some `tcp_keepalive
    | 12 -> Some `padding
    | _ -> None

  let extension_payload = function
    | Nsid cs -> cs
    | Cookie cs -> cs
    | Tcp_keepalive i -> (match i with None -> Cstruct.create 0 | Some i -> let buf = Cstruct.create 2 in Cstruct.BE.set_uint16 buf 0 i ; buf)
    | Padding i -> Cstruct.create i
    | Extension (_, v) -> v

  let encode_extension t buf off =
    let code = extension_to_int t in
    let v = extension_payload t in
    let l = Cstruct.len v in
    Cstruct.BE.set_uint16 buf off code ;
    Cstruct.BE.set_uint16 buf (off + 2) l ;
    Cstruct.blit v 0 buf (off + 4) l ;
    off + 4 + l

  let decode_extension buf ~off ~len =
    let open Rresult.R.Infix in
    let code = Cstruct.BE.get_uint16 buf off
    and tl = Cstruct.BE.get_uint16 buf (off + 2)
    in
    let v = Cstruct.sub buf (off + 4) tl in
    guard (len >= tl + 4) `Partial >>= fun () ->
    let len = tl + 4 in
    match int_to_extension code with
    | Some `nsid -> Ok (Nsid v, len)
    | Some `cookie -> Ok (Cookie v, len)
    | Some `tcp_keepalive ->
      (begin match tl with
         | 0 -> Ok None
         | 2 -> Ok (Some (Cstruct.BE.get_uint16 v 0))
         | _ -> Error (`Not_implemented (off, Fmt.strf "edns keepalive 0x%x" tl))
       end >>= fun i ->
       Ok (Tcp_keepalive i, len))
    | Some `padding -> Ok (Padding tl, len)
    | None -> Ok (Extension (code, v), len)

  type t = {
    extended_rcode : int ;
    version : int ;
    dnssec_ok : bool ;
    payload_size : int ;
    extensions : extension list ;
  }

  let min_payload_size = 512 (* from RFC 6891 Section 6.2.3 *)

  let create ?(extended_rcode = 0) ?(version = 0) ?(dnssec_ok = false)
      ?(payload_size = min_payload_size) ?(extensions = []) () =
    let payload_size =
      if payload_size < min_payload_size then begin
        Logs.warn (fun m -> m "requested payload size %d is too small, using %d"
                      payload_size min_payload_size);
        min_payload_size
      end else
        payload_size
    in
    { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions }

  (* once we handle cookies, dnssec, or other extensions, need to adjust *)
  let reply = function
    | None -> None, None
    | Some opt ->
      let payload_size = opt.payload_size in
      Some payload_size, Some (create ~payload_size ())

  let compare a b =
    andThen (int_compare a.extended_rcode b.extended_rcode)
      (andThen (int_compare a.version b.version)
         (andThen (compare a.dnssec_ok b.dnssec_ok)
            (andThen (int_compare a.payload_size b.payload_size)
               (List.fold_left2
                  (fun r a b -> if r = 0 then compare_extension a b else r)
                  (compare (List.length a.extensions) (List.length b.extensions))
                  a.extensions b.extensions))))

  let pp ppf opt =
    Fmt.(pf ppf "EDNS rcode %u version %u dnssec_ok %b payload_size %u extensions %a"
           opt.extended_rcode opt.version opt.dnssec_ok opt.payload_size
           (list ~sep:(unit ", ") pp_extension) opt.extensions)

  let decode_extensions buf ~len =
    let open Rresult.R.Infix in
    let rec one acc pos =
      if len = pos then
        Ok (List.rev acc)
      else
        decode_extension buf ~off:pos ~len:(len - pos) >>= fun (opt, len) ->
        one (opt :: acc) (pos + len)
    in
    one [] 0

  let decode buf ~off =
    let open Rresult.R.Infix in
    (* EDNS is special -- the incoming off points to before name type clas *)
    (* name must be the root, typ is OPT, class is used for length *)
    guard (Cstruct.len buf - off >= 11) `Partial >>= fun () ->
    guard (Cstruct.get_uint8 buf off = 0) (`Malformed (off, "bad edns (must be 0)")) >>= fun () ->
    (* crazyness: payload_size is encoded in class *)
    let payload_size = Cstruct.BE.get_uint16 buf (off + 3)
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    and extended_rcode = Cstruct.get_uint8 buf (off + 5)
    and version = Cstruct.get_uint8 buf (off + 6)
    and flags = Cstruct.BE.get_uint16 buf (off + 7)
    and len = Cstruct.BE.get_uint16 buf (off + 9)
    in
    let off = off + 11 in
    let dnssec_ok = flags land 0x8000_0000 = 0x8000_0000 in
    guard (version = 0) (`Bad_edns_version version) >>= fun () ->
    let payload_size =
      if payload_size < min_payload_size then begin
        Log.warn (fun m -> m "EDNS payload size is too small %d, using %d"
                     payload_size min_payload_size);
        min_payload_size
      end else
        payload_size
    in
    let exts_buf = Cstruct.sub buf off len in
    (try decode_extensions exts_buf ~len with _ -> Error `Partial) >>= fun extensions ->
    let opt = { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions } in
    Ok (opt, off + len)

  let encode_extensions t buf off =
    List.fold_left (fun off opt -> encode_extension opt buf off) off t

  let encode t buf off =
    (* name is . *)
    Cstruct.set_uint8 buf off 0 ;
    (* type *)
    Cstruct.BE.set_uint16 buf (off + 1) Rr.(to_int OPT) ;
    (* class is payload size! *)
    Cstruct.BE.set_uint16 buf (off + 3) t.payload_size ;
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    Cstruct.set_uint8 buf (off + 5) t.extended_rcode ;
    Cstruct.set_uint8 buf (off + 6) t.version ;
    Cstruct.BE.set_uint16 buf (off + 7) (if t.dnssec_ok then 0x8000_0000 else 0) ;
    let ext_start = off + 11 in
    let ext_end = encode_extensions t.extensions buf ext_start in
    Cstruct.BE.set_uint16 buf (off + 9) (ext_end - ext_start) ;
    ext_end

  let allocate_and_encode edns =
    (* this is unwise! *)
    let buf = Cstruct.create 128 in
    let off = encode edns buf 0 in
    Cstruct.sub buf 0 off
end

let encode_ntc names buf off (n, t, c) =
  let names, off = Name.encode n names buf off in
  Cstruct.BE.set_uint16 buf off (Rr.to_int t) ;
  Cstruct.BE.set_uint16 buf (off + 2) c ;
  names, off + 4

(* resource record map *)
module Rr_map = struct
  module Mx_set = Set.Make(Mx)
  module Txt_set = Set.Make(Txt)
  module Ipv4_set = Set.Make(Ipaddr.V4)
  module Ipv6_set = Set.Make(Ipaddr.V6)
  module Srv_set = Set.Make(Srv)
  module Dnskey_set = Set.Make(Dnskey)
  module Caa_set = Set.Make(Caa)
  module Tlsa_set = Set.Make(Tlsa)
  module Sshfp_set = Set.Make(Sshfp)

  type _ k =
    | Soa : Soa.t k
    | Ns : (int32 * Domain_name.Set.t) k
    | Mx : (int32 * Mx_set.t) k
    | Cname : (int32 * Domain_name.t) k
    | A : (int32 * Ipv4_set.t) k
    | Aaaa : (int32 * Ipv6_set.t) k
    | Ptr : (int32 * Domain_name.t) k
    | Srv : (int32 * Srv_set.t) k
    | Dnskey : (int32 * Dnskey_set.t) k
    | Caa : (int32 * Caa_set.t) k
    | Tlsa : (int32 * Tlsa_set.t) k
    | Sshfp : (int32 * Sshfp_set.t) k
    | Txt : (int32 * Txt_set.t) k

  let equal_k : type a b . a k -> a -> b k -> b -> bool = fun k v k' v' ->
    match k, v, k', v' with
    | Cname, (_, alias), Cname, (_, alias') -> Domain_name.equal alias alias'
    | Mx, (_, mxs), Mx, (_, mxs') -> Mx_set.equal mxs mxs'
    | Ns, (_, ns), Ns, (_, ns') -> Domain_name.Set.equal ns ns'
    | Ptr, (_, name), Ptr, (_, name') -> Domain_name.equal name name'
    | Soa, soa, Soa, soa' -> Soa.compare soa soa' = 0
    | Txt, (_, txts), Txt, (_, txts') -> Txt_set.equal txts txts'
    | A, (_, aas), A, (_, aas') -> Ipv4_set.equal aas aas'
    | Aaaa, (_, aaaas), Aaaa, (_, aaaas') -> Ipv6_set.equal aaaas aaaas'
    | Srv, (_, srvs), Srv, (_, srvs') -> Srv_set.equal srvs srvs'
    | Dnskey, (_, keys), Dnskey, (_, keys') -> Dnskey_set.equal keys keys'
    | Caa, (_, caas), Caa, (_, caas') -> Caa_set.equal caas caas'
    | Tlsa, (_, tlsas), Tlsa, (_, tlsas') -> Tlsa_set.equal tlsas tlsas'
    | Sshfp, (_, sshfps), Sshfp, (_, sshfps') -> Sshfp_set.equal sshfps sshfps'
    | _, _, _, _ -> false

  let k_to_rr_typ : type a. a k -> Rr.t = function
    | Cname -> Rr.CNAME
    | Mx -> Rr.MX
    | Ns -> Rr.NS
    | Ptr -> Rr.PTR
    | Soa -> Rr.SOA
    | Txt -> Rr.TXT
    | A -> Rr.A
    | Aaaa -> Rr.AAAA
    | Srv -> Rr.SRV
    | Dnskey -> Rr.DNSKEY
    | Caa -> Rr.CAA
    | Tlsa -> Rr.TLSA
    | Sshfp -> Rr.SSHFP

  let encode : type a. ?clas:Clas.t -> Domain_name.t -> a k -> a -> Name.name_offset_map -> Cstruct.t -> int ->
    (Name.name_offset_map * int) * int = fun ?(clas = Clas.IN) name k v names buf off ->
    let typ = k_to_rr_typ k
    and clas = Clas.to_int clas
    in
    let rr names f off ttl =
      let names, off' = encode_ntc names buf off (name, typ, clas) in
      (* leave 6 bytes space for TTL and length *)
      let rdata_start = off' + 6 in
      let names, rdata_end = f names buf rdata_start in
      let rdata_len = rdata_end - rdata_start in
      Cstruct.BE.set_uint32 buf off' ttl ;
      Cstruct.BE.set_uint16 buf (off' + 4) rdata_len ;
      names, rdata_end
    in
    match k, v with
    | Soa, soa -> rr names (Soa.encode soa) off soa.minimum, 1
    | Ns, (ttl, ns) ->
      Domain_name.Set.fold (fun name ((names, off), count) ->
          rr names (Ns.encode name) off ttl, succ count)
        ns ((names, off), 0)
    | Mx, (ttl, mx) ->
      Mx_set.fold (fun mx ((names, off), count) ->
          rr names (Mx.encode mx) off ttl, succ count)
        mx ((names, off), 0)
    | Cname, (ttl, alias) -> rr names (Cname.encode alias) off ttl, 1
    | A, (ttl, addresses) ->
      Ipv4_set.fold (fun address ((names, off), count) ->
        rr names (A.encode address) off ttl, succ count)
        addresses ((names, off), 0)
    | Aaaa, (ttl, aaaas) ->
      Ipv6_set.fold (fun address ((names, off), count) ->
          rr names (Aaaa.encode address) off ttl, succ count)
        aaaas ((names, off), 0)
    | Ptr, (ttl, rev) -> rr names (Ptr.encode rev) off ttl, 1
    | Srv, (ttl, srvs) ->
      Srv_set.fold (fun srv ((names, off), count) ->
          rr names (Srv.encode srv) off ttl, succ count)
        srvs ((names, off), 0)
    | Dnskey, (ttl, dnskeys) ->
      Dnskey_set.fold (fun dnskey ((names, off), count) ->
        rr names (Dnskey.encode dnskey) off ttl, succ count)
        dnskeys ((names, off), 0)
    | Caa, (ttl, caas) ->
      Caa_set.fold (fun caa ((names, off), count) ->
          rr names (Caa.encode caa) off ttl, succ count)
        caas ((names, off), 0)
    | Tlsa, (ttl, tlsas) ->
      Tlsa_set.fold (fun tlsa ((names, off), count) ->
          rr names (Tlsa.encode tlsa) off ttl, succ count)
        tlsas ((names, off), 0)
    | Sshfp, (ttl, sshfps) ->
      Sshfp_set.fold (fun sshfp ((names, off), count) ->
          rr names (Sshfp.encode sshfp) off ttl, succ count)
        sshfps ((names, off), 0)
    | Txt, (ttl, txts) ->
      Txt_set.fold (fun txt ((names, off), count) ->
          rr names (Txt.encode txt) off ttl, succ count)
        txts ((names, off), 0)

  let combine_k : type a. a k -> a -> a -> a = fun k old v ->
    match k, old, v with
    | Cname, _, cname -> cname
    | Mx, (_, mxs), (ttl, mxs') -> (ttl, Mx_set.union mxs mxs')
    | Ns, (_, ns), (ttl, ns') -> (ttl, Domain_name.Set.union ns ns')
    | Ptr, _, ptr -> ptr
    | Soa, _, soa -> soa
    | Txt, (_, txts), (ttl, txts') -> (ttl, Txt_set.union txts txts')
    | A, (_, ips), (ttl, ips') -> (ttl, Ipv4_set.union ips ips')
    | Aaaa, (_, ips), (ttl, ips') -> (ttl, Ipv6_set.union ips ips')
    | Srv, (_, srvs), (ttl, srvs') -> (ttl, Srv_set.union srvs srvs')
    | Dnskey, (_, keys), (ttl, keys') -> (ttl, Dnskey_set.union keys keys')
    | Caa, (_, caas), (ttl, caas') -> (ttl, Caa_set.union caas caas')
    | Tlsa, (_, tlsas), (ttl, tlsas') -> (ttl, Tlsa_set.union tlsas tlsas')
    | Sshfp, (_, sshfps), (ttl, sshfps') -> (ttl, Sshfp_set.union sshfps sshfps')

  let combine_opt : type a. a k -> a -> a option -> a option = fun k v old ->
    match v, old with
    | v, None -> Some v
    | v, Some old -> Some (combine_k k old v)

  let subtract_k : type a. a k -> a -> a -> a option = fun k v rem ->
    match k, v, rem with
    | Cname, _, _ -> None
    | Mx, (ttl, mxs), (_, rm) ->
      let s = Mx_set.diff mxs rm in
      if Mx_set.is_empty s then None else Some (ttl, s)
    | Ns, (ttl, ns), (_, rm) ->
      let s = Domain_name.Set.diff ns rm in
      if Domain_name.Set.is_empty s then None else Some (ttl, s)
    | Ptr, _, _ -> None
    | Soa, _, _ -> None
    | Txt, (ttl, txts), (_, rm) ->
      let s = Txt_set.diff txts rm in
      if Txt_set.is_empty s then None else Some (ttl, s)
    | A, (ttl, ips), (_, rm) ->
      let s = Ipv4_set.diff ips rm in
      if Ipv4_set.is_empty s then None else Some (ttl, s)
    | Aaaa, (ttl, ips), (_, rm) ->
      let s = Ipv6_set.diff ips rm in
      if Ipv6_set.is_empty s then None else Some (ttl, s)
    | Srv, (ttl, srvs), (_, rm) ->
      let s = Srv_set.diff srvs rm in
      if Srv_set.is_empty s then None else Some (ttl, s)
    | Dnskey, (ttl, keys), (_, rm) ->
      let s = Dnskey_set.diff keys rm in
      if Dnskey_set.is_empty s then None else Some (ttl, s)
    | Caa, (ttl, caas), (_, rm) ->
      let s = Caa_set.diff caas rm in
      if Caa_set.is_empty s then None else Some (ttl, s)
    | Tlsa, (ttl, tlsas), (_, rm) ->
      let s = Tlsa_set.diff tlsas rm in
      if Tlsa_set.is_empty s then None else Some (ttl, s)
    | Sshfp, (ttl, sshfps), (_, rm) ->
      let s = Sshfp_set.diff sshfps rm in
      if Sshfp_set.is_empty s then None else Some (ttl, s)

  let text : type a. ?origin:Domain_name.t -> ?default_ttl:int32 ->
    Domain_name.t -> a k -> a -> string = fun ?origin ?default_ttl n t v ->
    let hex cs =
      let buf = Bytes.create (Cstruct.len cs * 2) in
      for i = 0 to pred (Cstruct.len cs) do
        let byte = Cstruct.get_uint8 cs i in
        let up, low = byte lsr 4, byte land 0x0F in
        let to_hex_char v = char_of_int (if v < 10 then 0x30 + v else 0x37 + v) in
        Bytes.set buf (i * 2) (to_hex_char up) ;
        Bytes.set buf (i * 2 + 1) (to_hex_char low)
      done;
      Bytes.unsafe_to_string buf
    in
    let origin = match origin with
      | None -> None
      | Some n -> Some (n, Array.length (Domain_name.to_array n))
    in
    let name n = match origin with
      | Some (domain, amount) when Domain_name.sub ~subdomain:n ~domain ->
        let n' = Domain_name.drop_labels_exn ~back:true ~amount n in
        if Domain_name.equal n' Domain_name.root then
          "@"
        else
          Domain_name.to_string n'
      | _ -> Domain_name.to_string ~trailing:true n
    in
    let ttl_opt ttl = match default_ttl with
      | Some d when Int32.compare ttl d = 0 -> None
      | _ -> Some ttl
    in
    let ttl_fmt = Fmt.(option (suffix (unit "\t") uint32)) in
    let str_name = name n in
    let strs =
      match t, v with
      | Cname, (ttl, alias) ->
        [ Fmt.strf "%s\t%aCNAME\t%s" str_name ttl_fmt (ttl_opt ttl) (name alias) ]
      | Mx, (ttl, mxs) ->
        Mx_set.fold (fun { preference ; mail_exchange } acc ->
            Fmt.strf "%s\t%aMX\t%u\t%s" str_name ttl_fmt (ttl_opt ttl) preference (name mail_exchange) :: acc)
          mxs []
      | Ns, (ttl, ns) ->
        Domain_name.Set.fold (fun ns acc ->
            Fmt.strf "%s\t%aNS\t%s" str_name ttl_fmt (ttl_opt ttl) (name ns) :: acc)
          ns []
      | Ptr, (ttl, ptr) ->
        [ Fmt.strf "%s\t%aPTR\t%s" str_name ttl_fmt (ttl_opt ttl) (name ptr) ]
      | Soa, soa ->
        [ Fmt.strf "%s\t%aSOA\t%s\t%s\t%lu\t%lu\t%lu\t%lu\t%lu" str_name
            ttl_fmt (ttl_opt soa.minimum)
            (name soa.nameserver)
            (name soa.hostmaster)
            soa.serial soa.refresh soa.retry
            soa.expiry soa.minimum ]
      | Txt, (ttl, txts) ->
        Txt_set.fold (fun txt acc ->
            Fmt.strf "%s\t%aTXT\t\"%s\"" str_name ttl_fmt (ttl_opt ttl) txt :: acc)
          txts []
      | A, (ttl, a) ->
        Ipv4_set.fold (fun ip acc ->
          Fmt.strf "%s\t%aA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V4.to_string ip) :: acc)
          a []
      | Aaaa, (ttl, aaaa) ->
        Ipv6_set.fold (fun ip acc ->
            Fmt.strf "%s\t%aAAAA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V6.to_string ip) :: acc)
          aaaa []
      | Srv, (ttl, srvs) ->
        Srv_set.fold (fun srv acc ->
            Fmt.strf "%s\t%aSRV\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              srv.priority srv.weight srv.port
              (name srv.target) :: acc)
          srvs []
      | Dnskey, (ttl, keys) ->
        Dnskey_set.fold (fun key acc ->
            Fmt.strf "%s%a\tDNSKEY\t%u\t3\t%d\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              key.flags
              (Dnskey.algorithm_to_int key.algorithm)
              (hex key.key) :: acc)
          keys []
      | Caa, (ttl, caas) ->
        Caa_set.fold (fun caa acc ->
            Fmt.strf "%s\t%aCAA\t%s\t%s\t\"%s\""
              str_name ttl_fmt (ttl_opt ttl)
              (if caa.critical then "128" else "0")
              caa.tag (String.concat ";" caa.value) :: acc)
          caas []
      | Tlsa, (ttl, tlsas) ->
        Tlsa_set.fold (fun tlsa acc ->
            Fmt.strf "%s\t%aTLSA\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              (Tlsa.cert_usage_to_int tlsa.cert_usage)
              (Tlsa.selector_to_int tlsa.selector)
              (Tlsa.matching_type_to_int tlsa.matching_type)
              (hex tlsa.data) :: acc)
          tlsas []
      | Sshfp, (ttl, sshfps) ->
        Sshfp_set.fold (fun sshfp acc ->
            Fmt.strf "%s\t%aSSHFP\t%u\t%u\t%s" str_name ttl_fmt (ttl_opt ttl)
              (Sshfp.algorithm_to_int sshfp.algorithm)
              (Sshfp.typ_to_int sshfp.typ)
              (hex sshfp.fingerprint) :: acc)
          sshfps []
    in
    String.concat "\n" strs

  module K = struct
    type 'a t = 'a k

    let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
      let open Gmap.Order in
      match t, t' with
      | Soa, Soa -> Eq | Soa, _ -> Lt | _, Soa -> Gt
      | Ns, Ns -> Eq | Ns, _ -> Lt | _, Ns -> Gt
      | Mx, Mx -> Eq | Mx, _ -> Lt | _, Mx -> Gt
      | Cname, Cname -> Eq | Cname, _ -> Lt | _, Cname -> Gt
      | A, A -> Eq | A, _ -> Lt | _, A -> Gt
      | Aaaa, Aaaa -> Eq | Aaaa, _ -> Lt | _, Aaaa -> Gt
      | Ptr, Ptr -> Eq | Ptr, _ -> Lt | _, Ptr -> Gt
      | Srv, Srv -> Eq | Srv, _ -> Lt | _, Srv -> Gt
      | Dnskey, Dnskey -> Eq | Dnskey, _ -> Lt | _, Dnskey -> Gt
      | Caa, Caa -> Eq | Caa, _ -> Lt | _, Caa -> Gt
      | Tlsa, Tlsa -> Eq | Tlsa, _ -> Lt | _, Tlsa -> Gt
      | Sshfp, Sshfp -> Eq | Sshfp, _ -> Lt | _, Sshfp -> Gt
      | Txt, Txt -> Eq (* | Txt, _ -> Lt | _, Txt -> Gt *)

    let pp : type a. Format.formatter -> a t -> a -> unit = fun ppf t v ->
      match t, v with
      | Cname, (ttl, cname) -> Fmt.pf ppf "ttl %lu %a" ttl Cname.pp cname
      | Mx, (ttl, mxs) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Mx.pp) (Mx_set.elements mxs)
      | Ns, (ttl, names) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Ns.pp) (Domain_name.Set.elements names)
      | Ptr, (ttl, name) -> Fmt.pf ppf "ttl %lu %a" ttl Ptr.pp name
      | Soa, soa -> Fmt.pf ppf "%a" Soa.pp soa
      | Txt, (ttl, txts) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Txt.pp) (Txt_set.elements txts)
      | A, (ttl, a) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") A.pp) (Ipv4_set.elements a)
      | Aaaa, (ttl, aaaas) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Aaaa.pp) (Ipv6_set.elements aaaas)
      | Srv, (ttl, srvs) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Srv.pp) (Srv_set.elements srvs)
      | Dnskey, (ttl, keys) ->
        Fmt.pf ppf "%lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Dnskey.pp) (Dnskey_set.elements keys)
      | Caa, (ttl, caas) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Caa.pp) (Caa_set.elements caas)
      | Tlsa, (ttl, tlsas) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Tlsa.pp) (Tlsa_set.elements tlsas)
      | Sshfp, (ttl, sshfps) ->
        Fmt.pf ppf "ttl %lu %a" ttl
          Fmt.(list ~sep:(unit ";@,") Sshfp.pp) (Sshfp_set.elements sshfps)
  end

  include Gmap.Make(K)

  let get_ttl : b -> int32 = fun (B (k, v)) ->
    match k, v with
    | Cname, (ttl, _) -> ttl
    | Mx, (ttl, _) -> ttl
    | Ns, (ttl, _) -> ttl
    | Ptr, (ttl, _) -> ttl
    | Soa, soa -> soa.minimum
    | Txt, (ttl, _) -> ttl
    | A, (ttl, _) -> ttl
    | Aaaa, (ttl, _) -> ttl
    | Srv, (ttl, _) -> ttl
    | Dnskey, (ttl, _) -> ttl
    | Caa, (ttl, _) -> ttl
    | Tlsa, (ttl, _) -> ttl
    | Sshfp, (ttl, _) -> ttl

  let with_ttl : b -> int32 -> b = fun (B (k, v)) ttl ->
    match k, v with
    | Cname, (_, cname) -> B (k, (ttl, cname))
    | Mx, (_, mxs) -> B (k, (ttl, mxs))
    | Ns, (_, ns) -> B (k, (ttl, ns))
    | Ptr, (_, ptr) -> B (k, (ttl, ptr))
    | Soa, soa -> B (k, soa)
    | Txt, (_, txts) -> B (k, (ttl, txts))
    | A, (_, ips) -> B (k, (ttl, ips))
    | Aaaa, (_, ips) -> B (k, (ttl, ips))
    | Srv, (_, srvs) -> B (k, (ttl, srvs))
    | Dnskey, keys -> B (k, keys)
    | Caa, (_, caas) -> B (k, (ttl, caas))
    | Tlsa, (_, tlsas) -> B (k, (ttl, tlsas))
    | Sshfp, (_, sshfps) -> B (k, (ttl, sshfps))

  let pp_b ppf (B (k, v)) = K.pp ppf k v

  let equal_b (B (k, v)) (B (k', v')) = equal_k k v k' v'

  let names : type a. a k -> a -> Domain_name.Set.t = fun k v ->
    match k, v with
    | Cname, (_, alias) -> Domain_name.Set.singleton alias
    | Mx, (_, mxs) ->
      Mx_set.fold (fun { mail_exchange ; _} acc ->
          Domain_name.Set.add mail_exchange acc)
        mxs Domain_name.Set.empty
    | Ns, (_, names) -> names
    | Srv, (_, srvs) ->
      Srv_set.fold (fun x acc -> Domain_name.Set.add x.target acc)
        srvs Domain_name.Set.empty
    | _ -> Domain_name.Set.empty

  let names_b (B (k, v)) = names k v

  let to_rr_typ (B (k, _)) = k_to_rr_typ k

  let lookup_rr : Rr.t -> t -> b option = fun rr t ->
    match rr with
    | Rr.MX -> findb Mx t
    | Rr.NS -> findb Ns t
    | Rr.PTR -> findb Ptr t
    | Rr.SOA -> findb Soa t
    | Rr.TXT -> findb Txt t
    | Rr.A -> findb A t
    | Rr.AAAA -> findb Aaaa t
    | Rr.SRV -> findb Srv t
    | Rr.DNSKEY -> findb Dnskey t
    | Rr.CAA -> findb Caa t
    | Rr.TLSA -> findb Tlsa t
    | Rr.SSHFP -> findb Sshfp t
    | _ -> None

  let remove_rr : Rr.t -> t -> t = fun rr t ->
    match rr with
    | Rr.MX -> remove Mx t
    | Rr.NS -> remove Ns t
    | Rr.PTR -> remove Ptr t
    | Rr.SOA -> remove Soa t
    | Rr.TXT -> remove Txt t
    | Rr.A -> remove A t
    | Rr.AAAA -> remove Aaaa t
    | Rr.SRV -> remove Srv t
    | Rr.DNSKEY -> remove Dnskey t
    | Rr.CAA -> remove Caa t
    | Rr.TLSA -> remove Tlsa t
    | Rr.SSHFP -> remove Sshfp t
    | _ -> t

  let decode names buf off typ =
    let open Rresult.R.Infix in
    guard (Cstruct.len buf - off >= 6) `Partial >>= fun () ->
    let ttl = Cstruct.BE.get_uint32 buf off
    and len = Cstruct.BE.get_uint16 buf (off + 4)
    and rdata_start = off + 6
    in
    guard (Int32.logand ttl 0x8000_0000l = 0l)
      (`Malformed (off, Fmt.strf "bad TTL (high bit set) %lu" ttl)) >>= fun () ->
    guard (Cstruct.len buf - rdata_start >= len) `Partial >>= fun () ->
    (match typ with
     | Rr.SOA ->
       Soa.decode names buf ~off:rdata_start ~len >>| fun (soa, names, off) ->
       (B (Soa, soa), names, off)
     | Rr.NS ->
       Ns.decode names buf ~off:rdata_start ~len >>| fun (ns, names, off) ->
       (B (Ns, (ttl, Domain_name.Set.singleton ns)), names, off)
     | Rr.MX ->
       Mx.decode names buf ~off:rdata_start ~len >>| fun (mx, names, off) ->
       (B (Mx, (ttl, Mx_set.singleton mx)), names, off)
     | Rr.CNAME ->
       Cname.decode names buf ~off:rdata_start ~len >>| fun (alias, names, off) ->
       (B (Cname, (ttl, alias)), names, off)
     | Rr.A ->
       A.decode names buf ~off:rdata_start ~len >>| fun (address, names, off) ->
       (B (A, (ttl, Ipv4_set.singleton address)), names, off)
     | Rr.AAAA ->
       Aaaa.decode names buf ~off:rdata_start ~len >>| fun (address, names, off) ->
       (B (Aaaa, (ttl, Ipv6_set.singleton address)), names, off)
     | Rr.PTR ->
       Ptr.decode names buf ~off:rdata_start ~len >>| fun (rev, names, off) ->
       (B (Ptr, (ttl, rev)), names, off)
     | Rr.SRV ->
       Srv.decode names buf ~off:rdata_start ~len >>| fun (srv, names, off) ->
       (B (Srv, (ttl, Srv_set.singleton srv)), names, off)
     | Rr.DNSKEY ->
       Dnskey.decode names buf ~off:rdata_start ~len >>| fun (dnskey, names, off) ->
       (B (Dnskey, (ttl, Dnskey_set.singleton dnskey)), names, off)
     | Rr.CAA ->
       Caa.decode names buf ~off:rdata_start ~len >>| fun (caa, names, off) ->
       (B (Caa, (ttl, Caa_set.singleton caa)), names, off)
     | Rr.TLSA ->
       Tlsa.decode names buf ~off:rdata_start ~len >>| fun (tlsa, names, off) ->
       (B (Tlsa, (ttl, Tlsa_set.singleton tlsa)), names, off)
     | Rr.SSHFP ->
       Sshfp.decode names buf ~off:rdata_start ~len >>| fun (sshfp, names, off) ->
       (B (Sshfp, (ttl, Sshfp_set.singleton sshfp)), names, off)
     | Rr.TXT ->
       Txt.decode names buf ~off:rdata_start ~len >>| fun (txt, names, off) ->
       (B (Txt, (ttl, Txt_set.of_list txt)), names, off)
     | other -> Error (`Not_implemented (off, Fmt.strf "unsupported RR typ %a" Rr.pp other))) >>= fun (b, names, rdata_end) ->
    guard (len = rdata_end - rdata_start) (`Leftover (rdata_end, "rdata")) >>| fun () ->
    (b, names, rdata_end)

  let text_b ?origin ?default_ttl name (B (key, v)) =
    text ?origin ?default_ttl name key v
end

module Name_rr_map = struct
  type t = Rr_map.t Domain_name.Map.t

  let empty = Domain_name.Map.empty

  let equal a b =
    Domain_name.Map.equal (Rr_map.equal Rr_map.equal_b) a b

  let pp ppf map =
    Fmt.(list ~sep:(unit ";@ ") (pair ~sep:(unit " ") Domain_name.pp Rr_map.pp))
      ppf (Domain_name.Map.bindings map)

  let add name (Rr_map.B (k, v)) dmap =
    let m = match Domain_name.Map.find name dmap with
      | None -> Rr_map.empty
      | Some map -> map
    in
    let m' = Rr_map.update k (Rr_map.combine_opt k v) m in
    Domain_name.Map.add name m' dmap

  let find : type a . Domain_name.t -> a Rr_map.k -> t -> a option =
    fun name k dmap ->
    match Domain_name.Map.find name dmap with
    | None -> None
    | Some rrmap -> Rr_map.find k rrmap

  let remove_sub map sub =
    (* remove all entries which are in sub from map *)
    (* we don't compare values, just do it based on rrtype! *)
    Domain_name.Map.fold (fun name rrmap map ->
        match Domain_name.Map.find name map with
        | None -> map
        | Some rrs ->
          let rrs' = Rr_map.fold (fun (B (k, _)) map -> Rr_map.remove k map) rrmap rrs in
          Domain_name.Map.add name rrs' map)
      sub map
end

let decode_ntc names buf off =
  let open Rresult.R.Infix in
  Name.decode ~hostname:false names buf ~off >>= fun (name, names, off) ->
  guard (Cstruct.len buf - off >= 4) `Partial >>= fun () ->
  let typ = Cstruct.BE.get_uint16 buf off
  and cls = Cstruct.BE.get_uint16 buf (off + 2)
  (* CLS is interpreted differently by OPT, thus no int_to_clas called here *)
  in
  Rr.of_int ~off typ >>= function
  | Rr.(DNSKEY | TSIG | TXT | CNAME as t) -> Ok ((name, t, cls), names, off + 4)
  | Rr.(TLSA | SRV as t) when Domain_name.is_service name -> Ok ((name, t, cls), names, off + 4)
  | Rr.SRV -> (* MUST be service name *)
    Error (`Malformed (off, Fmt.strf "SRV must be a service name %a"
                         Domain_name.pp name))
  | t when Domain_name.is_hostname name -> Ok ((name, t, cls), names, off + 4)
  | _ ->
    Error (`Malformed (off, Fmt.strf "record must be a hostname %a"
                         Domain_name.pp name))

module Packet = struct

  type err = Name.err

  let pp_err = Name.pp_err

  module Header = struct
    module Flags = struct
      type t = [
        | `Authoritative
        | `Truncation
        | `Recursion_desired
        | `Recursion_available
        | `Authentic_data
        | `Checking_disabled
      ]

      let all = [
        `Authoritative ; `Truncation ; `Recursion_desired ;
        `Recursion_available ; `Authentic_data ; `Checking_disabled
      ]

      let compare a b = match a, b with
        | `Authoritative, `Authoritative -> 0
        | `Authoritative, _ -> 1 | _, `Authoritative -> -1
        | `Truncation, `Truncation -> 0
        | `Truncation, _ -> 1 | _, `Truncation -> -1
        | `Recursion_desired, `Recursion_desired -> 0
        | `Recursion_desired, _ -> 1 | _, `Recursion_desired -> -1
        | `Recursion_available, `Recursion_available -> 0
        | `Recursion_available, _ -> 1 | _, `Recursion_available -> -1
        | `Authentic_data, `Authentic_data -> 0
        | `Authentic_data, _ -> 1 | _, `Authentic_data -> -1
        | `Checking_disabled, `Checking_disabled -> 0
      (* | `Checking_disabled, _ -> 1 | _, `Checking_disabled -> -1 *)

      let pp ppf = function
        | `Authoritative -> Fmt.string ppf "authoritative"
        | `Truncation -> Fmt.string ppf "truncation"
        | `Recursion_desired -> Fmt.string ppf "recursion desired"
        | `Recursion_available -> Fmt.string ppf "recursion available"
        | `Authentic_data -> Fmt.string ppf "authentic data"
        | `Checking_disabled -> Fmt.string ppf "checking disabled"

      let pp_short ppf = function
        | `Authoritative -> Fmt.string ppf "AA"
        | `Truncation -> Fmt.string ppf "TC"
        | `Recursion_desired -> Fmt.string ppf "RD"
        | `Recursion_available -> Fmt.string ppf "RA"
        | `Authentic_data -> Fmt.string ppf "AD"
        | `Checking_disabled -> Fmt.string ppf "CD"

      let bit = function
        | `Authoritative -> 5
        | `Truncation -> 6
        | `Recursion_desired -> 7
        | `Recursion_available -> 8
        | `Authentic_data -> 10
        | `Checking_disabled -> 11

      let number f = 1 lsl (15 - bit f)
    end

    module FS = Set.Make(Flags)

    type t = int * FS.t

    let compare_id (id, _) (id', _) = int_compare id id'

    let compare (id, flags) (id', flags') =
      andThen (int_compare id id') (FS.compare flags flags')

    let pp ppf ((id, flags), query, operation, rcode) =
      Fmt.pf ppf "%04X (%s) operation %a rcode @[%a@] flags: @[%a@]"
        id (if query then "query" else "response")
        Opcode.pp operation
        Rcode.pp rcode
        Fmt.(list ~sep:(unit ", ") Flags.pp) (FS.elements flags)

    let len = 12

    (* header is:
       0  QR - 0 for query, 1 for response
       1-4   operation
       5  AA Authoritative Answer [RFC1035]                             \
       6  TC Truncated Response   [RFC1035]                             |
       7  RD Recursion Desired    [RFC1035]                             |
       8  RA Recursion Available  [RFC1035]                             |-> flags
       9     Reserved                                                   |
       10 AD Authentic Data       [RFC4035][RFC6840][RFC Errata 4924]   |
       11 CD Checking Disabled    [RFC4035][RFC6840][RFC Errata 4927]   /
       12-15 rcode *)

    let decode_flags hdr =
      List.fold_left (fun flags flag ->
          if Flags.number flag land hdr > 0 then FS.add flag flags else flags)
        FS.empty Flags.all

    let decode buf =
      let open Rresult.R.Infix in
      (* we only access the first 4 bytes, but anything <12 is a bad DNS frame *)
      guard (Cstruct.len buf >= len) `Partial >>= fun () ->
      let hdr = Cstruct.BE.get_uint16 buf 2 in
      let op = (hdr land 0x7800) lsr 11
      and rc = hdr land 0x000F
      in
      Opcode.of_int ~off:2 op >>= fun operation ->
      Rcode.of_int ~off:3 rc >>= fun rcode ->
      let id = Cstruct.BE.get_uint16 buf 0
      and query = hdr lsr 15 = 0
      and flags = decode_flags hdr
      in
      Ok ((id, flags), query, operation, rcode)

    let encode_flags flags =
      FS.fold (fun f acc -> acc + Flags.number f) flags 0

    let encode buf ((id, flags), query, operation, rcode) =
      let query = if query then 0x0000 else 0x8000 in
      let flags = encode_flags flags in
      let op = (Opcode.to_int operation) lsl 11 in
      let rcode = (Rcode.to_int rcode) land 0x000F in
      let header = query lor flags lor op lor rcode in
      Cstruct.BE.set_uint16 buf 0 id ;
      Cstruct.BE.set_uint16 buf 2 header

(*    let%expect_test "encode_decode_header" =
      let eq (hdr, query, op, rc) (hdr', query', op', rc') =
        compare hdr hdr' = 0 && rc = rc' && query = query' && op = op'
      and cs = Cstruct.create 12
      in
      let test_cs ?(off = 0) len =
        Format.printf "%a" Cstruct.hexdump_pp (Cstruct.sub cs off len)
      and test_hdr a b =
        match b with
        | Error e -> Format.printf "%a" pp_err e
        | Ok b -> if eq a b then Format.printf "ok" else Format.printf "not ok"
      in
      let hdr = (1, FS.empty), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* basic query encoding works *)
      test_cs 4;
      [%expect {|00 01 00 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x1010, FS.empty), false, Opcode.Query, Rcode.NXDomain in
      encode cs hdr; (* second encoded header works *)
      test_cs 4;
      [%expect {|10 10 80 03|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x0101, FS.singleton `Authentic_data), true, Opcode.Update, Rcode.NoError in
      encode cs hdr; (* flags look nice *)
      test_cs 4;
      [%expect {|01 01 28 20|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x0080, FS.singleton `Truncation), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* truncation flag *)
      test_cs 4;
      [%expect {|00 80 02 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x8080, FS.singleton `Checking_disabled), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* checking disabled flag *)
      test_cs 4;
      [%expect {|80 80 00 10|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x1234, FS.singleton `Authoritative), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* authoritative flag *)
      test_cs 4;
      [%expect {|12 34 04 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0xFFFF, FS.singleton `Recursion_desired), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* rd flag *)
      test_cs 4;
      [%expect {|ff ff 01 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr =
        let flags = FS.(add `Recursion_desired (singleton `Authoritative)) in
        (0xE0E0, flags), true, Opcode.Query, Rcode.NoError
      in
      encode cs hdr; (* rd + auth *)
      test_cs 4;
      [%expect {|e0 e0 05 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0xAA00, FS.singleton `Recursion_available), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* ra *)
      test_cs 4;
      [%expect {|aa 00 00 80|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let test_err = function
        | Ok _ -> Format.printf "ok, expected error"
        | Error _ -> Format.printf "ok"
      in
      let data = Cstruct.of_hex "0000 7000 0000 0000 0000 0000" in
      test_err (decode data);
      [%expect {|ok|}];
      let data = Cstruct.of_hex "0000 000e 0000 0000 0000 0000" in
      test_err (decode data);
      [%expect {|ok|}] *)
  end

  module Question = struct
    type t = Domain_name.t * Rr.t

    let pp ppf (name, typ) =
      Fmt.pf ppf "%a %a?" Domain_name.pp name Rr.pp typ

    let compare (name, typ) (name', typ') =
      andThen (Domain_name.compare name name')
        (Rr.compare typ typ')

    let decode ?(names = Name.Int_map.empty) ?(off = Header.len) buf =
      let open Rresult.R.Infix in
      decode_ntc names buf off >>= fun ((name, typ, c), names, off) ->
      Clas.of_int ~off c >>= function
      | Clas.IN -> Ok ((name, typ), names, off)
      | _ -> Error (`Not_implemented (off, Fmt.strf "bad class in question 0x%x" c))

    let encode names buf off (name, typ) =
      encode_ntc names buf off (name, typ, Clas.to_int Clas.IN)
  end


  let encode_data map names buf off =
    Domain_name.Map.fold (fun name rrmap acc ->
        Rr_map.fold (fun (Rr_map.B (k, v)) ((names, off), count) ->
            let r, amount = Rr_map.encode name k v names buf off in
            (r, amount + count))
          rrmap acc)
      map ((names, off), 0)

  let decode_rr names buf off =
    let open Rresult.R.Infix in
    decode_ntc names buf off >>= fun ((name, typ, clas), names, off) ->
    guard (clas = Clas.(to_int IN))
      (`Not_implemented (off, Fmt.strf "rr class not IN 0x%x" clas)) >>= fun () ->
    Rr_map.decode names buf off typ >>| fun (b, names, off) ->
    (name, b, names, off)

  let rec decode_n_aux add f names buf off acc = function
    | 0 -> acc, Ok (names, off)
    | n -> match f names buf off with
      | Ok (name, b, names, off') ->
        let acc' = add name b acc in
        decode_n_aux add f names buf off' acc' (pred n)
      | Error e -> acc, Error e

  let decode_n add f names buf off acc c =
    let acc, r = decode_n_aux add f names buf off acc c in
    match r with
    | Ok (names, off) -> Ok (names, off, acc)
    | Error e -> Error e

  let decode_n_partial add f names buf off acc c =
    let acc, r = decode_n_aux add f names buf off acc c in
    match r with
    | Ok (names, off) -> Ok (`Full (names, off, acc))
    | Error `Partial -> Ok (`Partial acc)
    | Error e -> Error e

  let decode_one_additional map edns ~tsig names buf off =
    let open Rresult.R.Infix in
    decode_ntc names buf off >>= fun ((name, typ, clas), names, off') ->
    match typ with
    | Rr.OPT when edns = None ->
      (* OPT is special and needs class! (also, name is guarded to be .) *)
      Edns.decode buf ~off >>| fun (edns, off') ->
      (map, Some edns, None), names, off'
    | Rr.TSIG when tsig ->
      guard (clas = Clas.(to_int ANY_CLASS))
        (`Malformed (off, Fmt.strf "tsig class must be ANY 0x%x" clas)) >>= fun () ->
      Tsig.decode names buf ~off:off' >>| fun (tsig, names, off') ->
      (map, edns, Some (name, tsig, off)), names, off'
    | _ ->
      guard (clas = Clas.(to_int IN))
        (`Malformed (off, Fmt.strf "additional class must be IN 0x%x" clas)) >>= fun () ->
      Rr_map.decode names buf off' typ >>| fun (b, names, off') ->
      (Name_rr_map.add name b map, edns, None), names, off'

  let rec decode_n_additional names buf off map edns tsig = function
    | 0 -> Ok (`Full (off, map, edns, tsig))
    | n -> match decode_one_additional map edns ~tsig:(n = 1) names buf off with
      | Error `Partial -> Ok (`Partial (map, edns, tsig))
      | Error e -> Error e
      | Ok ((map, edns, tsig), names, off') ->
        decode_n_additional names buf off' map edns tsig (pred n)

  module Query = struct

    type t = Name_rr_map.t * Name_rr_map.t

    let empty = Name_rr_map.empty, Name_rr_map.empty

    let is_empty (a, b) =
      Domain_name.Map.is_empty a && Domain_name.Map.is_empty b

    let equal (answer, authority) (answer', authority') =
      Name_rr_map.equal answer answer' &&
      Name_rr_map.equal authority authority'

    let pp ppf (answer, authority) =
      Fmt.pf ppf "answer %a@ authority %a"
        Name_rr_map.pp answer Name_rr_map.pp authority

    let decode (_, flags) buf names off =
      let open Rresult.R.Infix in
      let truncated = Header.FS.mem `Truncation flags in
      let ancount = Cstruct.BE.get_uint16 buf 6
      and aucount = Cstruct.BE.get_uint16 buf 8
      in
      let empty = Domain_name.Map.empty in
      decode_n_partial Name_rr_map.add decode_rr names buf off empty ancount >>= function
      | `Partial answer -> guard truncated `Partial >>| fun () -> (answer, empty), names, off, false, truncated
      | `Full (names, off, answer) ->
        decode_n_partial Name_rr_map.add decode_rr names buf off empty aucount >>= function
        | `Partial authority -> guard truncated `Partial >>| fun () -> (answer, authority), names, off, false, truncated
        | `Full (names, off, authority) -> Ok ((answer, authority), names, off, true, truncated)

    let encode_answer (qname, qtyp) map names buf off =
      Log.debug (fun m -> m "trying to encode the answer, following question %a %a"
                     Question.pp (qname, qtyp) Name_rr_map.pp map) ;
      (* A foo.com? foo.com CNAME bar.com ; bar.com A 127.0.0.1 *)
      let rec encode_one names off count name =
        match Domain_name.Map.find name map with
        | None -> (names, off), count
        | Some rrmap ->
          let (names, off), count, alias =
            Rr_map.fold (fun (Rr_map.B (k, v)) ((names, off), count, alias) ->
                let alias' = match k, v with
                  | Cname, (_, alias) -> Some alias
                  | _ -> alias
                in
                let r, amount = Rr_map.encode name k v names buf off in
                (r, amount + count, alias'))
              rrmap ((names, off), count, None)
          in
          match alias with
          | None -> (names, off), count
          | Some n -> encode_one names off count n
      in
      encode_one names off 0 qname

    let encode names buf off question (answer, authority) =
      let (names, off), ancount = encode_answer question answer names buf off in
      Cstruct.BE.set_uint16 buf 6 ancount ;
      let (names, off), aucount = encode_data authority names buf off in
      Cstruct.BE.set_uint16 buf 8 aucount ;
      names, off
  end

  module Axfr = struct

    type t = Soa.t * Name_rr_map.t

    let equal (soa, entries) (soa', entries') =
      Soa.compare soa soa' = 0 && Name_rr_map.equal entries entries'

    let pp ppf (soa, entries) =
        Fmt.pf ppf "soa %a data %a" Soa.pp soa Name_rr_map.pp entries

    let decode (_, flags) buf names off ancount =
      let open Rresult.R.Infix in
      guard (not (Header.FS.mem `Truncation flags)) `Partial >>= fun () ->
      let empty = Domain_name.Map.empty in
      (* TODO handle partial AXFR:
         - only first frame must have the question, subsequent may have empty questions
         - only first frame starts with SOA
         - last one ends with SOA *)
      guard (ancount >= 2)
        (`Malformed (6, Fmt.strf "AXFR needs at least two RRs in answer %d" ancount)) >>= fun () ->
      decode_rr names buf off >>= fun (name, B (k, v), names, off) ->
      (* TODO: verify name == zname in question, also all RR sub of zname *)
      match k, v with
      | Soa, soa ->
        decode_n Name_rr_map.add decode_rr names buf off empty (ancount - 2) >>= fun (names, off, answer) ->
        decode_rr names buf off >>= fun (name', B (k', v'), names, off) ->
        begin
          match k', v' with
          | Soa, soa' ->
            (* TODO: verify that answer does not contain a SOA!? *)
            guard (Domain_name.equal name name')
              (`Malformed (off, "AXFR SOA RRs do not use the same name")) >>= fun () ->
            guard (Soa.compare soa soa' = 0)
              (`Malformed (off, "AXFR SOA RRs are not equal")) >>| fun () ->
            ((soa, answer) : Soa.t * Name_rr_map.t), names, off
          | _ -> Error (`Malformed (off, "AXFR last RR in answer must be SOA"))
        end
      | _ -> Error (`Malformed (off, "AXFR first RR in answer must be SOA"))

    let encode names buf off question (soa, entries) =
      (* TODO if this would truncate, should create another packet --
         how does this interact with TSIG, is each individual packet signed? *)
      (* serialise: SOA .. other data .. SOA *)
      let (names, off), _ = Rr_map.encode (fst question) Soa soa names buf off in
      let (names, off), count = encode_data entries names buf off in
      let (names, off), _ = Rr_map.encode (fst question) Soa soa names buf off in
      Cstruct.BE.set_uint16 buf 6 (count + 2) ;
      names, off
  end

  module Update = struct

    type prereq =
      | Exists of Rr.t
      | Exists_data of Rr_map.b
      | Not_exists of Rr.t
      | Name_inuse
      | Not_name_inuse

    let equal_prereq a b = match a, b with
      | Exists t, Exists t' -> Rr.compare t t' = 0
      | Exists_data b, Exists_data b' -> Rr_map.equal_b b b'
      | Not_exists t, Not_exists t' -> Rr.compare t t' = 0
      | Name_inuse, Name_inuse -> true
      | Not_name_inuse, Not_name_inuse -> true
      | _ -> false

    let pp_prereq ppf = function
      | Exists typ -> Fmt.pf ppf "exists? %a" Rr.pp typ
      | Exists_data rd -> Fmt.pf ppf "exists data? %a" Rr_map.pp_b rd
      | Not_exists typ -> Fmt.pf ppf "doesn't exists? %a" Rr.pp typ
      | Name_inuse -> Fmt.string ppf "name inuse?"
      | Not_name_inuse -> Fmt.string ppf "name not inuse?"

    let decode_prereq names buf off =
      let open Rresult.R.Infix in
      decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
      let off' = off + 6 in
      guard (Cstruct.len buf >= off') `Partial >>= fun () ->
      let ttl = Cstruct.BE.get_uint32 buf off in
      guard (ttl = 0l) (`Malformed (off, Fmt.strf "prereq TTL not zero %lu" ttl)) >>= fun () ->
      let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
      let r0 = guard (rlen = 0) (`Malformed (off + 4, Fmt.strf "prereq rdlength must be zero %d" rlen)) in
      Clas.of_int cls >>= function
      | ANY_CLASS when typ = ANY -> r0 >>= fun () -> Ok (name, Name_inuse, names, off')
      | NONE when typ = ANY -> r0 >>= fun () -> Ok (name, Not_name_inuse, names, off')
      | ANY_CLASS -> r0 >>= fun () -> Ok (name, Exists typ, names, off')
      | NONE -> r0 >>= fun () -> Ok (name, Not_exists typ, names, off')
      | IN->
        Rr_map.decode names buf off typ >>= fun (rdata, names, off'') ->
        Ok (name, Exists_data rdata, names, off'')
      | _ -> Error (`Malformed (off, Fmt.strf "prereq bad class 0x%x" cls))

    let encode_prereq names buf off count name = function
      | Exists typ ->
        let names, off =
          encode_ntc names buf off (name, typ, Clas.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Exists_data (B (k, v)) ->
        let ret, count' = Rr_map.encode name k v names buf off in
        ret, count' + count
      | Not_exists typ ->
        let names, off =
          encode_ntc names buf off (name, typ, Clas.(to_int NONE))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Name_inuse ->
        let names, off =
          encode_ntc names buf off (name, Rr.ANY, Clas.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Not_name_inuse ->
        let names, off =
          encode_ntc names buf off (name, Rr.ANY, Clas.(to_int NONE))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count

    type update =
      | Remove of Rr.t
      | Remove_all
      | Remove_single of Rr_map.b
      | Add of Rr_map.b

    let equal_update a b = match a, b with
      | Remove t, Remove t' -> Rr.compare t t' = 0
      | Remove_all, Remove_all -> true
      | Remove_single b, Remove_single b' -> Rr_map.equal_b b b'
      | Add b, Add b' -> Rr_map.equal_b b b'
      | _ -> false

    let pp_update ppf = function
      | Remove typ -> Fmt.pf ppf "remove! %a" Rr.pp typ
      | Remove_all -> Fmt.string ppf "remove all!"
      | Remove_single rd -> Fmt.pf ppf "remove single! %a" Rr_map.pp_b rd
      | Add rr -> Fmt.pf ppf "add! %a" Rr_map.pp_b rr

    let decode_update names buf off =
      let open Rresult.R.Infix in
      decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
      let off' = off + 6 in
      guard (Cstruct.len buf >= off') `Partial >>= fun () ->
      let ttl = Cstruct.BE.get_uint32 buf off in
      let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
      let r0 = guard (rlen = 0) (`Malformed (off + 4, Fmt.strf "update rdlength must be zero %d" rlen)) in
      let ttl0 = guard (ttl = 0l) (`Malformed (off, Fmt.strf "update ttl must be zero %lu" ttl)) in
      Clas.of_int cls >>= function
      | ANY_CLASS when typ = ANY ->
        ttl0 >>= fun () ->
        r0 >>= fun () ->
        Ok (name, Remove_all, names, off')
      | ANY_CLASS ->
        ttl0 >>= fun () ->
        r0 >>= fun () ->
        Ok (name, Remove typ, names, off')
      | NONE ->
        ttl0 >>= fun () ->
        Rr_map.decode names buf off typ >>= fun (rdata, names, off) ->
        Ok (name, Remove_single rdata, names, off)
      | IN ->
        Rr_map.decode names buf off typ >>= fun (rdata, names, off) ->
        Ok (name, Add rdata, names, off)
      | _ -> Error (`Malformed (off, Fmt.strf "bad update class 0x%x" cls))

    let encode_update names buf off count name = function
      | Remove typ ->
        let names, off =
          encode_ntc names buf off (name, typ, Clas.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Remove_all ->
        let names, off =
          encode_ntc names buf off (name, Rr.ANY, Clas.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Remove_single (B (k, v)) ->
        let ret, count' = Rr_map.encode ~clas:NONE name k v names buf off in
        ret, count + count'
      | Add (B (k, v)) ->
        let ret, count' = Rr_map.encode name k v names buf off in
        ret, count + count'

    type t = prereq list Domain_name.Map.t * update list Domain_name.Map.t

    let empty = Domain_name.Map.empty, Domain_name.Map.empty

    let equal (prereq, update) (prereq', update') =
      let eq_list f a b =
        List.length a = List.length b &&
        List.fold_left2 (fun acc a b -> acc && f a b) true a b
      in
      Domain_name.Map.equal (eq_list equal_prereq) prereq prereq' &&
      Domain_name.Map.equal (eq_list equal_update) update update'

    let pp ppf (prereq, update) =
      Fmt.pf ppf "%a@ %a"
        Fmt.(list ~sep:(unit ";@ ")
               (pair ~sep:(unit ":") Domain_name.pp
                  (list ~sep:(unit ", ") pp_prereq)))
        (Domain_name.Map.bindings prereq)
        Fmt.(list ~sep:(unit ";@ ")
               (pair ~sep:(unit ":") Domain_name.pp
                  (list ~sep:(unit ", ") pp_update)))
        (Domain_name.Map.bindings update)

    let decode _header question buf names off =
      let open Rresult.R.Infix in
      let prcount = Cstruct.BE.get_uint16 buf 6
      and upcount = Cstruct.BE.get_uint16 buf 8
      in
      let add_to_list name a map =
        let base = match Domain_name.Map.find name map with None -> [] | Some x -> x in
        Domain_name.Map.add name (base @ [a]) map
      in
      guard (snd question = Rr.SOA) (`Malformed (off, Fmt.strf "update question not SOA %a" Rr.pp (snd question))) >>= fun () ->
      decode_n add_to_list decode_prereq names buf off Domain_name.Map.empty prcount >>= fun (names, off, prereq) ->
      decode_n add_to_list decode_update names buf off Domain_name.Map.empty upcount >>= fun (names, off, update) ->
      Ok ((prereq, update), names, off)

    let encode_map map f names buf off =
      Domain_name.Map.fold (fun name v ((names, off), count) ->
          List.fold_left (fun ((names, off), count) p ->
              f names buf off count name p) ((names, off), count) v)
        map ((names, off), 0)

    let encode names buf off _question (prereq, update) =
      let (names, off), prereq_count = encode_map prereq encode_prereq names buf off in
      Cstruct.BE.set_uint16 buf 6 prereq_count ;
      let (names, off), update_count = encode_map update encode_update names buf off in
      Cstruct.BE.set_uint16 buf 8 update_count ;
      names, off
  end

  type request = [
    | `Query
    | `Notify of Soa.t option
    | `Axfr_request
    | `Update of Update.t
  ]

  let equal_request a b = match a, b with
    | `Query, `Query -> true
    | `Notify soa, `Notify soa' -> opt_eq (fun a b -> Soa.compare a b = 0) soa soa'
    | `Axfr_request, `Axfr_request -> true
    | `Update u, `Update u' -> Update.equal u u'
    | _ -> false

  let pp_request ppf = function
    | `Query -> Fmt.string ppf "query"
    | `Notify soa -> Fmt.pf ppf "notify %a" Fmt.(option ~none:(unit "no") Soa.pp) soa
    | `Axfr_request -> Fmt.string ppf "axfr request"
    | `Update u -> Fmt.pf ppf "update %a" Update.pp u

  type reply = [
    | `Answer of Query.t
    | `Notify_ack
    | `Axfr_reply of Axfr.t
    | `Update_ack
    | `Rcode_error of Rcode.t * Opcode.t * Query.t option
  ]

  let equal_reply a b = match a, b with
    | `Answer q, `Answer q' -> Query.equal q q'
    | `Notify_ack, `Notify_ack -> true
    | `Axfr_reply a, `Axfr_reply b -> Axfr.equal a b
    | `Update_ack, `Update_ack -> true
    | `Rcode_error (rc, op, q), `Rcode_error (rc', op', q') ->
      Rcode.compare rc rc' = 0 && Opcode.compare op op' = 0 && opt_eq Query.equal q q'
    | _ -> false

  let pp_reply ppf = function
    | `Answer a -> Fmt.pf ppf "answer %a" Query.pp a
    | `Notify_ack -> Fmt.string ppf "notify ack"
    | `Axfr_reply a -> Fmt.pf ppf "AXFR %a" Axfr.pp a
    | `Update_ack -> Fmt.string ppf "update ack"
    | `Rcode_error (rc, op, q) ->
      Fmt.pf ppf "rcode %a op %a q %a" Rcode.pp rc Opcode.pp op
        Fmt.(option ~none:(unit "no data") Query.pp) q

  type data = [ request | reply ]

  let opcode_data = function
    | `Query | `Axfr_request | `Answer _ | `Axfr_reply _ -> Opcode.Query
    | `Notify _ | `Notify_ack -> Notify
    | `Update _ | `Update_ack -> Update
    | `Rcode_error (_, op, _) -> op

  let rcode_data = function
    | `Rcode_error (rc, _, _) -> rc
    | _ -> Rcode.NoError

  let with_rcode data rcode = match rcode, data with
    | Rcode.NoError, `Rcode_error (rc, _, _) -> Error (`Rcode_error_cant_noerror rc)
    | Rcode.NoError, x -> Ok x
    | _, `Rcode_error (_, op, data) -> Ok (`Rcode_error (rcode, op, data))
    | _ -> Error (`Rcode_cant_change rcode)

  let equal_data a b =
    match a with
    | #reply as replya ->
      begin match b with
        | #reply as replyb -> equal_reply replya replyb
        | #request -> false
      end
    | #request as reqa ->
      match b with
      | #request as reqb -> equal_request reqa reqb
      | #reply -> false

  let pp_data ppf = function
    | #request as r -> pp_request ppf r
    | #reply as r -> pp_reply ppf r

  type t = {
    header : Header.t ;
    question : Question.t ;
    data : data ;
    additional : Name_rr_map.t ;
    edns : Edns.t option ;
    tsig : (Domain_name.t * Tsig.t * int) option ;
  }

  let pp_tsig ppf (name, tsig, off) =
    Fmt.pf ppf "tsig %a %a %d" Domain_name.pp name Tsig.pp tsig off
  let eq_tsig (name, tsig, off) (name', tsig', off') =
    Domain_name.equal name name' && Tsig.equal tsig tsig' && off = off'

  let create ?max_size:_ ?(additional = Name_rr_map.empty) ?edns header question data =
    (* TODO!? max size edns reply stuff!? *)
    { header ; question ; data ; additional ; edns ; tsig = None }

  let with_edns t edns = { t with edns }

  let pp_header ppf t =
    let opcode = opcode_data t.data
    and query = match t.data with #request -> true | #reply -> false
    and rcode = rcode_data t.data
    in
    Header.pp ppf (t.header, query, opcode, rcode)

  let pp ppf t =
    Fmt.pf ppf "header %a@ question %a@ data %a@ additional %a@ EDNS %a TSIG %a"
      pp_header t
      Question.pp t.question
      pp_data t.data
      Name_rr_map.pp t.additional
      Fmt.(option ~none:(unit "no") Edns.pp) t.edns
      Fmt.(option ~none:(unit "no") pp_tsig) t.tsig

  let equal a b =
    Header.compare a.header b.header = 0 &&
    Question.compare a.question b.question = 0 &&
    Name_rr_map.equal a.additional b.additional &&
    opt_eq (fun a b -> Edns.compare a b = 0) a.edns b.edns &&
    opt_eq eq_tsig a.tsig b.tsig &&
    equal_data a.data b.data

  let decode_additional names buf off allow_trunc adcount =
    let open Rresult.R.Infix in
    decode_n_additional names buf off Domain_name.Map.empty None None adcount >>= function
    | `Partial (additional, edns, tsig) ->
      Log.warn (fun m -> m "truncated packet (allowed? %B)" allow_trunc) ;
      guard allow_trunc `Partial >>= fun () ->
      Ok (additional, edns, tsig)
    | `Full (off, additional, edns, tsig) ->
      (if Cstruct.len buf > off then
         let n = Cstruct.len buf - off in
         Log.warn (fun m -> m "received %d extra bytes %a"
                       n Cstruct.hexdump_pp (Cstruct.sub buf off n))) ;
      Ok (additional, edns, tsig)

  let ext_rcode ?off rcode = function
    | Some e when e.Edns.extended_rcode > 0 ->
      begin
        let rcode' =
          Rcode.to_int rcode + e.extended_rcode lsl 4
        in
        Rcode.of_int ?off rcode'
      end
    | _ -> Ok rcode

  let decode buf =
    let open Rresult.R.Infix in
    Header.decode buf >>= fun (header, query, operation, rcode) ->
    let q_count = Cstruct.BE.get_uint16 buf 4
    and an_count = Cstruct.BE.get_uint16 buf 6
    and au_count = Cstruct.BE.get_uint16 buf 8
    and ad_count = Cstruct.BE.get_uint16 buf 10
    in
    guard (q_count = 1) (`Malformed (4, "question count not one")) >>= fun () ->
    Question.decode buf >>= fun (question, names, off) ->
    begin
      if query then begin
        (* guard noerror - what's the point in handling error requests *)
        guard (rcode = Rcode.NoError) (`Request_rcode rcode) >>= fun () ->
        (* also guard for it not being truncated!? *)
        guard (not (Header.FS.mem `Truncation (snd header)))
          `Truncated_request >>= fun () ->
        begin match operation with
          | Opcode.Query ->
            guard (an_count = 0) (`Query_answer_count an_count) >>= fun () ->
            guard (au_count = 0) (`Query_authority_count au_count) >>| fun () ->
            begin match snd question with
             | Rr.AXFR -> `Axfr_request, names, off
             | _ -> `Query, names, off
            end
          | Opcode.Notify ->
            (* TODO notify has some restrictions: Q=1, AN>=0 (must be SOA) *)
            guard (an_count = 0 || an_count = 1) (`Notify_answer_count an_count) >>= fun () ->
            guard (au_count = 0) (`Notify_authority_count au_count) >>= fun () ->
            Query.decode header buf names off >>| fun ((ans, _), names, off, _, _) ->
            let soa = Name_rr_map.find (fst question) Rr_map.Soa ans in
            `Notify soa, names, off
          | Opcode.Update ->
            Update.decode header question buf names off >>| fun (update, names, off) ->
            `Update update, names, off
          | x -> Error (`Not_implemented (2, Fmt.strf "unsupported opcode %a" Opcode.pp x))
        end >>| fun (request, names, off) ->
        request, names, off, true, false
      end else begin match rcode with
        | Rcode.NoError -> begin match operation with
            | Opcode.Query -> begin match snd question with
                | Rr.AXFR ->
                  guard (au_count = 0) (`Malformed (8, Fmt.strf "AXFR with aucount %d > 0" au_count)) >>= fun () ->
                  Axfr.decode header buf names off an_count >>| fun (axfr, names, off) ->
                  `Axfr_reply axfr, names, off, true, false
                | _ ->
                  Query.decode header buf names off >>| fun (answer, names, off, cont, allow_trunc) ->
                  `Answer answer, names, off, cont, allow_trunc
              end
            | Opcode.Notify ->
              guard (an_count = 0) (`Notify_ack_answer_count an_count) >>= fun () ->
              guard (au_count = 0) (`Notify_ack_authority_count au_count) >>| fun () ->
              `Notify_ack, names, off, true, false
            | Opcode.Update ->
              guard (an_count = 0) (`Update_ack_answer_count an_count) >>= fun () ->
              guard (au_count = 0) (`Update_ack_authority_count au_count) >>| fun () ->
              `Update_ack, names, off, true, false
            | x -> Error (`Not_implemented (2, Fmt.strf "unsupported opcode %a"
                                              Opcode.pp x))
          end
        | x ->
          Query.decode header buf names off >>| fun (query, names, off, cont, allow_trunc) ->
          let query = if Query.is_empty query then None else Some query in
          `Rcode_error (x, operation, query), names, off, cont, allow_trunc
      end >>| fun (reply, names, off, cont, allow_trunc) ->
        reply, names, off, cont, allow_trunc
    end >>= fun (data, names, off, cont, allow_trunc) ->
    (if cont then
       decode_additional names buf off allow_trunc ad_count
     else
       Ok (Name_rr_map.empty, None, None)) >>= fun (additional, edns, tsig) ->
    (* now in case of error, we may switch the rcode *)
    ext_rcode ~off:off rcode edns >>= with_rcode data >>| fun data ->
    { header ; question ; data ; additional ; edns ; tsig }

  let opcode_match request reply =
    let opa = opcode_data request
    and opb = opcode_data reply
    in
    Opcode.compare opa opb = 0

  type mismatch = [ `Not_a_reply of request
                  | `Id_mismatch of int * int
                  | `Operation_mismatch of request * reply
                  | `Question_mismatch of Question.t * Question.t
                  | `Expected_request ]

  let pp_mismatch ppf = function
    | `Not_a_reply req ->
      Fmt.pf ppf "expected a reply, got a request %a" pp_request req
    | `Id_mismatch (id, id') ->
      Fmt.pf ppf "id mismatch, expected %04X got %04X" id id'
    | `Operation_mismatch (req, reply) ->
      Fmt.pf ppf "operation mismatch, request %a reply %a" pp_request req pp_reply reply
    | `Question_mismatch (q, q') ->
      Fmt.pf ppf "question mismatch, expected %a got %a" Question.pp q Question.pp  q'
    | `Expected_request -> Fmt.string ppf "expected request"

  let reply_matches_request ~request reply =
    match request.data with
    | #reply -> Error `Expected_request
    | #request as req -> match reply.data with
      | #request as r -> Error (`Not_a_reply r)
      | #reply as data ->
        match
          Header.compare_id request.header reply.header = 0,
          opcode_match req data,
          Question.compare request.question reply.question = 0
        with
      | true, true, true ->
        (* TODO: make this strict? configurable? *)
        if not (Domain_name.equal ~case_sensitive:true (fst request.question) (fst reply.question)) then
          Log.warn (fun m -> m "question is not case sensitive equal %a = %a"
                       Domain_name.pp (fst request.question) Domain_name.pp (fst reply.question));
        Ok data
      | false, _ ,_ -> Error (`Id_mismatch (fst request.header, fst reply.header))
      | _, false, _ -> Error (`Operation_mismatch (req, data))
      | _, _, false -> Error (`Question_mismatch (request.question, reply.question))

  let max_udp = 1484 (* in MirageOS. using IPv4 this is max UDP payload via ethernet *)
  let max_reply_udp = 400 (* we don't want anyone to amplify! *)
  let max_tcp = 1 lsl 16 - 1 (* DNS-over-TCP is 2 bytes len ++ payload *)

  let size_edns max_size edns protocol query =
    let maximum, payload_size = match protocol, max_size, query with
      | `Tcp, _, _ -> max_tcp, 4096
      | `Udp, None, true -> max_udp, 4096
      | `Udp, None, false -> max_reply_udp, 512
      | `Udp, Some x, true -> x, x
      | `Udp, Some x, false -> min x max_reply_udp, 512
    in
    let edns = match edns with
      | None -> None
      | Some opts -> Some ({ opts with Edns.payload_size })
    in
    maximum, edns

  let encode_t names buf off question = function
    | `Query | `Axfr_request
    | `Notify_ack | `Update_ack
    | `Rcode_error (_, _, None) -> names, off
    | `Notify soa ->
      begin match soa with
        | None -> names, off
        | Some soa ->
          Cstruct.BE.set_uint16 buf 6 1;
          let query = Domain_name.Map.singleton (fst question) Rr_map.(singleton Soa soa) in
          Query.encode names buf off question (query, Name_rr_map.empty)
      end
    | `Update u -> Update.encode names buf off question u
    | `Answer q -> Query.encode names buf off question q
    | `Axfr_reply data -> Axfr.encode names buf off question data
    | `Rcode_error (_, _, Some q) -> Query.encode names buf off question q

  let encode_edns rcode edns buf off = match edns with
    | None -> off
    | Some edns ->
      let extended_rcode = (Rcode.to_int rcode) lsr 4 in
      let adcount = Cstruct.BE.get_uint16 buf 10 in
      let off = Edns.encode { edns with Edns.extended_rcode } buf off in
      Cstruct.BE.set_uint16 buf 10 (adcount + 1) ;
      off

  let encode ?max_size protocol t =
    let query = match t.data with #request -> true | #reply -> false in
    let max, edns = size_edns max_size t.edns protocol query in
    let try_encoding buf =
      let off, trunc =
        try
          let opcode = opcode_data t.data
          and rcode = rcode_data t.data
          in
          Header.encode buf (t.header, query, opcode, rcode);
          let names, off = Question.encode Domain_name.Map.empty buf Header.len t.question in
          Cstruct.BE.set_uint16 buf 4 1 ;
          let names, off = encode_t names buf off t.question t.data in
          (* TODO we used to drop all other additionals if rcode <> 0 *)
          let (_names, off), adcount = encode_data t.additional names buf off in
          Cstruct.BE.set_uint16 buf 10 adcount ;
          (* TODO if edns embedding would truncate, we used to drop all other additionals and only encode EDNS *)
          (* TODO if additional would truncate, drop them (do not set truncation) *)
          encode_edns Rcode.NoError edns buf off, false
        with Invalid_argument _ -> (* set truncated *)
          (* if we failed to store data into buf, set truncation bit! *)
          Cstruct.set_uint8 buf 2 (0x02 lor (Cstruct.get_uint8 buf 2)) ;
          Cstruct.len buf, true
      in
      Cstruct.sub buf 0 off, trunc
    in
    let rec doit s =
      let cs = Cstruct.create s in
      match try_encoding cs with
      | (cs, false) -> (cs, max)
      | (cs, true) ->
        let next = min max (s * 2) in
        if next = s then
          (cs, max)
        else
          doit next
    in
    doit (min max 4000) (* (mainly for TCP) we use a page as initial allocation *)

  let raw_error buf rcode =
    (* copy id from header, retain opcode, set rcode to ServFail
       if we receive a fragment < 12 bytes, it's not worth bothering *)
    if Cstruct.len buf < 12 then
      None
    else
      let query = Cstruct.get_uint8 buf 2 lsr 7 = 0 in
      if not query then (* never reply to an answer! *)
        None
      else
        let hdr = Cstruct.create 12 in
        (* manually copy the id from the incoming buf *)
        Cstruct.BE.set_uint16 hdr 0 (Cstruct.BE.get_uint16 buf 0) ;
        (* manually copy the opcode from the incoming buf, and set response *)
        Cstruct.set_uint8 hdr 2 (0x80 lor ((Cstruct.get_uint8 buf 2) land 0x78)) ;
        (* set rcode *)
        Cstruct.set_uint8 hdr 3 ((Rcode.to_int rcode) land 0xF) ;
        let extended_rcode = Rcode.to_int rcode lsr 4 in
        if extended_rcode = 0 then
          Some hdr
        else
          (* need an edns! *)
          let edns = Edns.create ~extended_rcode () in
          let buf = Edns.allocate_and_encode edns in
          Cstruct.BE.set_uint16 hdr 10 1 ;
          Some (Cstruct.append hdr buf)
end

module Tsig_op = struct
  type e = [
    | `Bad_key of Domain_name.t * Tsig.t
    | `Bad_timestamp of Domain_name.t * Tsig.t * Dnskey.t
    | `Bad_truncation of Domain_name.t * Tsig.t
    | `Invalid_mac of Domain_name.t * Tsig.t
  ]

  let pp_e ppf = function
    | `Bad_key (name, tsig) -> Fmt.pf ppf "bad key %a: %a" Domain_name.pp name Tsig.pp tsig
    | `Bad_timestamp (name, tsig, key) -> Fmt.pf ppf "bad timestamp: %a %a %a" Domain_name.pp name Tsig.pp tsig Dnskey.pp key
    | `Bad_truncation (name, tsig) -> Fmt.pf ppf "bad truncation %a %a" Domain_name.pp name Tsig.pp tsig
    | `Invalid_mac (name, tsig) -> Fmt.pf ppf "invalid mac %a %a" Domain_name.pp name Tsig.pp tsig

  type verify = ?mac:Cstruct.t -> Ptime.t -> Packet.t ->
    Domain_name.t -> ?key:Dnskey.t -> Tsig.t -> Cstruct.t ->
    (Tsig.t * Cstruct.t * Dnskey.t, e * Cstruct.t option) result

  type sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> Tsig.t ->
    key:Dnskey.t -> Packet.t -> Cstruct.t -> (Cstruct.t * Cstruct.t) option
end
