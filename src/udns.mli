(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)
(** µDNS - an opinionated Domain Name System (DNS) library

    The Domain Name System is a hierarchical and decentralized naming system
   used on the Internet. It associates domain names with nearly arbitrary
   information. Best known is the translation of easily memoizable domain names
   to numerical IP addresses, which are used by computers for establishing
   communication channels - so called {{!A}address} records. DNS has been
   deployed since 1985 on the Internet. It is a widely deployed, fault-tolerant,
   distributed key-value store with built-in caching mechanisms. The keys
   are {{!Domain_name}domain names} and {{!Udns_enum.rr_typ}record type}, the
   values are record sets. Each record set has a time-to-live associated with
   it: the maximum time this entry may be cached. The
   {{:https://github.com/hannesm/domain-name}domain name} library provides
   operations on domain names, which have a restricted character set (letters,
   digits, hyphen), and comparison is defined case-insensitively.

    A set of 13 authoritative name servers form the root zone which delegate
   authority for subdomains to registrars (using country codes, etc.), which
   delegate domains to individuals who host their Internet presence there.

    The delegation mechanism utilizes the DNS protocol itself, using
   {{!Ns}name server} records, and {{!Soa}start of authority} records. The
   globally federated eMail system uses {{!Mx}mail exchange} records.

    Each Internet domain has at least two authoritative name servers registered
   to enable fault tolerance. To keep these synchronised, a zone transfer
   mechanism is part of DNS. In-protocol DNS extension mechanisms include
   dynamic updates, authentication, and notifications, which allow arbitrary
   synchronized, authenticated modifications.

    From a client perspective, the C library functions [gethostbyname] or
   [getaddrinfo] are mainly used, which receive a string (and a record type)
   and return a reply. A client requests a caching recursive resolver hosted
   close to the client - e.g. at their ISP, and awaits an answer. The recursive
   resolver iterates over the domain name parts, and requests the registered
   authoritative name servers, until the name server responsible for the
   requested domain name is found.

    The core µDNS library includes type definitions of supported record types,
   decoding and encoding thereof to the binary protocol used on the Internet,
   also serialising and parsing of the standardized text form. The record types
   and their values are defined by the {{!Rr_map.k}key} type, which has for
   each record type a specific value type, using a generalized algebraic data
   type -- i.e. an address record may only contain a time-to-live and a set of
   IPv4 addresses. This is used to construct a {{!Gmap}map} data structure.

    This core µDNS library is used by various DNS components:
    {ul
    {- {!Udns_tsig} implements TSIG authentication}
    {- {!Udns_server} implements the authoritative server logic}
    {- {!Udns_client} implements a client API}
    {- {!Udns_zonesfile} implements the zone file parser}
    {- {!Udns_resolver} implements the resolver logic}}

    These core libraries are pure, i.e. it is independent of network
   communnication, uses immutable values, and errors are explicit as {!result}
   type. Timestamps are passed in to the main handle functions. Some components,
   such as a secondary server, which needs to check freshness of its data in
   regular intervals. The logic is implemented and exposed as function, which
   needs to be called from a side-effecting layer.

    For the client library, several side-effecting layers are implemented:
   [udns-client-unix] uses the blocking {!Unix} API, [udns-client-lwt] uses the
   non-blocking {!Lwt}, and [udns-mirage-client] using MirageOS interfaces.
   Unix command line utilities are provided in the [udns-cli] package.

    For the server and resolver components, side-effecting implementations
   using MirageOS interfaces are provided in [udns-mirage-server] and
   [udns-mirage-resolver]. Some
   {{:https://github.com/roburio/unikernels}example unikernels} are provided
   externally, including authoritative primary and secondary servers, recursive
   and stub resolvers.

    The DNS protocol ({{!Txt}TXT} records) are used by the certificate authority
   {{:https://letsencrypt}Let's Encrypt} to provision X.509 certificates which
   are trusted by web browsers. µDNS together with
   {{:https://github.com/mmaker/ocaml-letsencrypt}ocaml-letsencrypt} can be
   used to provision certificate signing requests for your domain. The
   certificate signing request and certificate are both stored as {{!Tlsa}TLSA}
   records in DNS.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}} *)

type proto = [ `Tcp | `Udp ]
(** The type of supported protocols. Used by {!Packet.encode} to decide on
     maximum buffer length, etc. *)

module Rr : sig
  type t =
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

  val pp : t Fmt.t
  val compare : t -> t -> int
end

module Clas : sig
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
  val pp : t Fmt.t
  val compare : t -> t -> int
end

module Opcode : sig
  type t =
    | Query (* RFC1035 *)
    | IQuery (* Inverse Query, OBSOLETE) [RFC3425] *)
    | Status (* RFC1035 *)
    (* 3 Unassigned *)
    | Notify (* RFC1996 *)
    | Update (* RFC2136 *)
      (* 6-15 Unassigned *)
  val pp : t Fmt.t
  val compare : t -> t -> int
end

module Rcode : sig
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
  val pp : t Fmt.t
  val compare : t -> t -> int
end

(** Start of authority

    The start of authority (SOA) is a resource record at domain boundaries. It
    contains metadata (serial number, refresh interval, hostmaster) of the domain. *)
module Soa : sig
  type t = {
    nameserver : Domain_name.t ;
    hostmaster : Domain_name.t ;
    serial : int32 ;
    refresh : int32 ;
    retry : int32 ;
    expiry : int32 ;
    minimum : int32 ;
  }

  val create : ?serial:int32 -> ?refresh:int32 -> ?retry:int32 ->
    ?expiry:int32 -> ?minimum:int32 -> ?hostmaster:Domain_name.t ->
    Domain_name.t -> t
  (** [create ~serial ~refresh ~retry ~expiry ~minimum ~hostmaster nameserver]
      returns a start of authority. The default for [hostmaster] is replacing
      the first domain name part of [nameserver] with "hostmaster" (to result
      in hostmaster@foo.com if ns1.foo.com is the [nameserver]. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the start of authority. *)

  val compare : t -> t -> int
  (** [compare a b] compare all fields of [a] with [b]. *)

  val newer : old:t -> t -> bool
  (** [newer ~old new] checks if the serial of [old] is smaller than [new].
      To accomodate wraparounds, the formula used is [new - old > 0]. *)
end

(** Name server

    A name server (NS) record specifies authority over the domain. Each domain
    may have multiple name server records, at least two. *)
module Ns : sig
  type t = Domain_name.t
  (** The type of a nameserver record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the nameserver. *)

  val compare : t -> t -> int
  (** [compare a b] compares the nameserver [a] with [b]. *)
end

(** Mail exchange

    A mail exchange (MX) record specifies the mail server where mail for this
   domain should be delivered to. A domain may have multiple MX records, each
   has a 16bit preference. *)
module Mx : sig
  type t = {
    preference : int ;
    mail_exchange : Domain_name.t ;
  }
  (** The type of a mail exchange. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the mail exchange. *)

  val compare : t -> t -> int
  (** [compare a b] compares the name and preference of [a] with [b]. *)
end

(** Canonical name

    A canonical name (CNAME) is an alias. [host.example.com CNAME foo.com]
    redirects all record sets of [host.example.com] to [foo.com]. *)
module Cname : sig
  type t = Domain_name.t
  (** The type of a canonical name. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the canonical name. *)

  val compare : t -> t -> int
  (** [compare a b] compares the canonical name [a] and [b]. *)
end

(** Adress record

    An address record (A) is an Internet protocol v4 address. *)
module A : sig
  type t = Ipaddr.V4.t
  (** The type of an A record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the address. *)

  val compare : t -> t -> int
  (** [compare a b] compares the address [a] with [b]. *)
end

(** Quad A record

    An AAAA record is an Internet protocol v6 address. *)
module Aaaa : sig
  type t = Ipaddr.V6.t
  (** The type of an AAAA record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the address. *)

  val compare : t -> t -> int
  (** [compare a b] compares the address [a] with [b]. *)
end

(** Domain name pointer

    A domain name pointer (PTR) record specifies the name for an IP address.
    This allows reverse lookups, instead of asking "which address is
    [example.com] located at?", you can ask "who is located at
    [3.4.5.6.in-addr.arpa.]?" ([ip6.arpa] for IPv6 addresses). *)
module Ptr : sig
  type t = Domain_name.t
  (** The type of a PTR record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the domain name pointer. *)

  val compare : t -> t -> int
  (** [compare a b] compares the domain pointer pointer [a] with [b]. *)
end

(** Service record

    A Service record (SRV) specifies a target, its priority, weight and port. *)
module Srv : sig
  type t = {
    priority : int ;
    weight : int ;
    port : int ;
    target : Domain_name.t
  }
  (** The type for a service record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the service record. *)

  val compare : t -> t -> int
  (** [compare a b] compares the service record [a] with [b]. *)
end

(** DNS keys

    A DNS key record (DNSKEY) specifies flags, algorithm, and key data. *)
module Dnskey : sig

  type algorithm =
    | MD5
    | SHA1
    | SHA224
    | SHA256
    | SHA384
    | SHA512
    (** The type of supported algorithms. *)

  val int_to_algorithm : ?off:int -> int -> (algorithm, [> `Not_implemented of int * string ]) result
  (** [int_to_algorithm ~off i] tries to decode [i] to an [algorithm]. *)

  val algorithm_to_int : algorithm -> int
  (** [algorithm_to_int a] encodes [a] to an integer. *)

  val pp_algorithm : algorithm Fmt.t
  (** [pp_algorithm ppf a] pretty-prints the algorithm. *)

  type t = {
    flags : int ; (* uint16 *)
    algorithm :  algorithm ; (* u_int8_t *)
    key : Cstruct.t ;
  }
  (** The type of a DNSKEY record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the DNSKEY. *)

  val compare : t -> t -> int
  (** [comapre a b] compares the DNSKEY [a] with [b]. *)

  val of_string : string -> (t, [> `Msg of string ]) result
  (** [of_string str] attempts to parse [str] to a dnskey. The colon character
      ([:]) is used as separator, supported formats are: [algo:keydata] and
      [flags:algo:keydata], where keydata is a base64 string. *)

  val name_key_of_string : string -> (Domain_name.t * t, [> `Msg of string ]) result
  (** [name_key_of_string str] attempts to parse [str] to a domain name and a
      dnskey. The colon character ([:]) is used as separator. *)
end

(** Certificate authority authorization

    A certificate authority authorization (CAA) record can restrict usage of
    certain certificate authorities for an entire domain. *)
module Caa : sig
  type t = {
    critical : bool ;
    tag : string ;
    value : string list ;
  }
  (** The type of a CAA record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the CAA record. *)

  val compare : t -> t -> int
  (** [compare a b] compares the CAA record [a] with [b]. *)
end

(** Transport layer security authentication *)
module Tlsa : sig
  type cert_usage =
    | CA_constraint
    | Service_certificate_constraint
    | Trust_anchor_assertion
    | Domain_issued_certificate

  val cert_usage_to_int : cert_usage -> int
  val int_to_cert_usage : ?off:int -> int ->
    (cert_usage, [> `Not_implemented of int * string ]) result
  val pp_cert_usage : cert_usage Fmt.t

  type selector =
    | Full_certificate
    | Subject_public_key_info
    | Private

  val selector_to_int : selector -> int
  val int_to_selector : ?off:int -> int ->
    (selector, [> `Not_implemented of int * string ]) result
  val pp_selector : selector Fmt.t

  type matching_type =
    | No_hash
    | SHA256
    | SHA512

  val matching_type_to_int : matching_type -> int
  val int_to_matching_type : ?off:int -> int ->
    (matching_type, [> `Not_implemented of int * string ]) result
  val pp_matching_type : matching_type Fmt.t

  type t = {
    cert_usage : cert_usage ;
    selector : selector ;
    matching_type : matching_type ;
    data : Cstruct.t ;
  }

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(** Secure shell fingerprint

    The secure shell (SSH) applies trust on first use, and can store
   fingerprints as SSHFP records in DNS, which is then used as a second
   channel. *)
module Sshfp : sig
  type algorithm =
    | Rsa
    | Dsa
    | Ecdsa
    | Ed25519

  val algorithm_to_int : algorithm -> int
  val int_to_algorithm : ?off:int -> int ->
    (algorithm, [> `Not_implemented of int * string ]) result
  val pp_algorithm : algorithm Fmt.t

  type typ =
    | SHA1
    | SHA256

  val typ_to_int : typ -> int
  val int_to_typ : ?off:int -> int ->
    (typ, [> `Not_implemented of int * string ]) result
  val pp_typ : typ Fmt.t

  type t = {
    algorithm : algorithm ;
    typ : typ ;
    fingerprint : Cstruct.t ;
  }

  val pp : t Fmt.t

  val compare : t -> t -> int
end

(** Text records *)
module Txt : sig
  type t = string

  val pp : t Fmt.t

  val compare : t -> t -> int
end


(** Transaction signature

    A transaction signature is a resource record that authenticates a DNS
    packet. Its nature is not to persist in databases, but it is handled
    specially during decoding and encoding. *)
module Tsig : sig
  type algorithm =
    | SHA1
    | SHA224
    | SHA256
    | SHA384
    | SHA512

  type t = private {
    algorithm : algorithm ;
    signed : Ptime.t ;
    fudge : Ptime.Span.t ;
    mac : Cstruct.t ;
    original_id : int ; (* again 16 bit *)
    error : Rcode.t ;
    other : Ptime.t option
  }

  val algorithm_to_name : algorithm -> Domain_name.t

  val algorithm_of_name : ?off:int -> Domain_name.t ->
    (algorithm, [> `Not_implemented of int * string ]) result

  val pp_algorithm : algorithm Fmt.t

  val tsig : algorithm:algorithm -> signed:Ptime.t ->
    ?fudge:Ptime.span -> ?mac:Cstruct.t -> ?original_id:int ->
    ?error:Rcode.t -> ?other:Ptime.t -> unit -> t option

  val with_mac : t -> Cstruct.t -> t

  val with_error : t -> Rcode.t -> t

  val with_signed : t -> Ptime.t -> t option

  val with_other : t -> Ptime.t option -> t option

  val pp : t Fmt.t

  val equal : t -> t -> bool

  val encode_raw : Domain_name.t -> t -> Cstruct.t

  val encode_full : Domain_name.t -> t -> Cstruct.t

  val dnskey_to_tsig_algo : Dnskey.t -> (algorithm, [> `Msg of string ]) result

  val valid_time : Ptime.t -> t -> bool
end

(** Extensions to DNS

    An extension record (EDNS) is extendable, includes a version number, payload
    size restrictions, TCP keepalive timers, etc. This is only used in
    transaction, and not persisted to a store. It is treat specially in decode
    and encode. *)
module Edns : sig
  type extension =
    | Nsid of Cstruct.t
    | Cookie of Cstruct.t
    | Tcp_keepalive of int option
    | Padding of int
    | Extension of int * Cstruct.t

  type t = private {
    extended_rcode : int ;
    version : int ;
    dnssec_ok : bool ;
    payload_size : int ;
    extensions : extension list ;
  }

  val create : ?extended_rcode:int -> ?version:int -> ?dnssec_ok:bool ->
    ?payload_size:int -> ?extensions:extension list -> unit -> t

  (* once we handle cookies, dnssec, or other extensions, need to adjust *)
  val reply : t option -> int option * t option

  val compare : t -> t -> int

  val pp : t Fmt.t

  val allocate_and_encode : t -> Cstruct.t

end

(** A map whose key are record types and their values are the time-to-live and
    the record set. The relation between key and value type is restricted by the
    below defined GADT. *)
module Rr_map : sig

  module Mx_set : Set.S with type elt = Mx.t
  module Txt_set : Set.S with type elt = Txt.t
  module Ipv4_set : Set.S with type elt = A.t
  module Ipv6_set : Set.S with type elt = Aaaa.t
  module Srv_set : Set.S with type elt = Srv.t
  module Dnskey_set : Set.S with type elt = Dnskey.t
  module Caa_set : Set.S with type elt = Caa.t
  module Tlsa_set : Set.S with type elt = Tlsa.t
  module Sshfp_set : Set.S with type elt = Sshfp.t

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

  val equal_k : 'a k -> 'a -> 'b k -> 'b -> bool
  (** [equal_k k v k' v'] is [true] if [k = k'] and [v = v'], [false] otherwise. *)

  include Gmap.S with type 'a key = 'a k

  val to_rr_typ : b -> Rr.t
  (** [to_rr_typ b] is the resource record typ of [b]. *)

  val k_to_rr_typ : 'a k -> Rr.t
  (** [k_to_rr_typ k] is the resource record typ of [k]. *)

  val names : 'a k -> 'a -> Domain_name.Set.t
  (** [names k v] are the referenced domain names in the given binding. *)

  val names_b : b -> Domain_name.Set.t
  (** [names_b binding] are the referenced domain names in the given binding. *)

  val lookup_rr : Rr.t -> t -> b option
  (** [lookup_rr typ t] looks up the [typ] in [t]. *)

  val remove_rr : Rr.t -> t -> t
  (** [remove_rr typ t] removes the [typ] in [t]. *)

  val pp_b : b Fmt.t
  (** [pp_b ppf b] pretty-prints the binding [b]. *)

  val equal_b : b -> b -> bool
  (** [equal_b b b'] is [true] if the bindings are equal. *)

  val text_b : ?origin:Domain_name.t -> ?default_ttl:int32 -> Domain_name.t -> b -> string
  (** [text ~origin ~default_ttl domain-name binding] is the zone file format of [binding] using
      [domain-name]. *)

  val subtract_k : 'a k -> 'a -> 'a -> 'a option
  (** [subtract_k k v rem] removes [rem] from [v]. If the result is an empty set,
     [None] is returned. *)

  val combine_k : 'a k -> 'a -> 'a -> 'a
  (** [combine_k k old new] combines [old] with [new]. [new] always wins. *)

  val combine_opt : 'a k -> 'a -> 'a option -> 'a option
  (** [combine_opt k new old] is [new] if [old] is [None], otherwise [combine_k k old v]. *)

  val text : ?origin:Domain_name.t -> ?default_ttl:int32 -> Domain_name.t -> 'a k -> 'a -> string
  (** [text ~origin ~default_ttl name k v] is the zone file data for [k, v]. *)

  val get_ttl : b -> int32
  (** [get_ttl b] returns the time-to-live of [b]. *)

  val with_ttl : b -> int32 -> b
  (** [with_ttl b ttl] updates [ttl] in [b]. *)

end

(** Name resource record map

    This map uses the resource record map above as value in a domain name map.
    Common DNS queries and answers have this structure as their value. *)
module Name_rr_map : sig

  type t = Rr_map.t Domain_name.Map.t

  val empty : t
  val equal : t -> t -> bool

  val pp : t Fmt.t

  val add : Domain_name.t -> Rr_map.b -> t -> t

  val find : Domain_name.t -> 'a Rr_map.k -> t -> 'a option

  val remove_sub : t -> t -> t
end

(** The DNS packet.

    Encoding and decoding from binary. Definition of types for multiple DNS
   operations.  *)
module Packet : sig

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

  val pp_err : err Fmt.t

  module Header : sig
    module Flags : sig
      type t = [
        | `Authoritative
        | `Truncation
        | `Recursion_desired
        | `Recursion_available
        | `Authentic_data
        | `Checking_disabled
      ]

      val compare : t -> t -> int
      val pp : t Fmt.t
      val pp_short : t Fmt.t
    end

    module FS : Set.S with type elt = Flags.t

    type t = int * FS.t

    val compare : t -> t -> int
  end

  module Question : sig
    type t = Domain_name.t * Rr.t

    val pp : t Fmt.t
    val compare : t -> t -> int
  end

  module Query : sig
    type t = Name_rr_map.t * Name_rr_map.t
    val empty : t
    val is_empty : t -> bool
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  module Axfr : sig
    type t = Soa.t * Name_rr_map.t
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  module Update : sig
    type prereq =
      | Exists of Rr.t
      | Exists_data of Rr_map.b
      | Not_exists of Rr.t
      | Name_inuse
      | Not_name_inuse
    val pp_prereq : prereq Fmt.t
    val equal_prereq : prereq -> prereq -> bool

    type update =
      | Remove of Rr.t
      | Remove_all
      | Remove_single of Rr_map.b
      | Add of Rr_map.b
    val pp_update : update Fmt.t
    val equal_update : update -> update -> bool

    type t = prereq list Domain_name.Map.t * update list Domain_name.Map.t
    val empty : t
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  type request = [
    | `Query
    | `Notify of Soa.t option
    | `Axfr_request
    | `Update of Update.t
  ]

  val equal_request : request -> request -> bool

  val pp_request : request Fmt.t

  type reply = [
    | `Answer of Query.t
    | `Notify_ack
    | `Axfr_reply of Axfr.t
    | `Update_ack
    | `Rcode_error of Rcode.t * Opcode.t * Query.t option
  ]

  val equal_reply : reply -> reply -> bool

  val pp_reply : reply Fmt.t

  type data = [ request | reply ]

  val opcode_data : data -> Opcode.t

  val rcode_data : data -> Rcode.t

  val equal_data : data -> data -> bool

  val pp_data : data Fmt.t

  type t = private {
    header : Header.t ;
    question : Question.t ;
    data : data ;
    additional : Name_rr_map.t ;
    edns : Edns.t option ;
    tsig : (Domain_name.t * Tsig.t * int) option ;
  }

  val create : ?max_size:int -> ?additional:Name_rr_map.t -> ?edns:Edns.t ->
    Header.t -> Question.t -> data -> t

  val with_edns : t -> Edns.t option -> t

  val pp : t Fmt.t

  val pp_header : t Fmt.t

  val equal : t -> t -> bool

  val decode : Cstruct.t -> (t, err) result

  type mismatch = [ `Not_a_reply of request
                  | `Id_mismatch of int * int
                  | `Operation_mismatch of request * reply
                  | `Question_mismatch of Question.t * Question.t
                  | `Expected_request ]

  val pp_mismatch : mismatch Fmt.t

  val reply_matches_request : request:t -> t -> (reply, mismatch) result
  (** [reply_matches_request ~request reply] validates
      that the [reply] match the [request], and returns either
      [Ok data] or an [Error]. The following basic checks are
      performed:
      {ul
      {- Is the header identifier of [request] and [reply] equal?}
      {- Does the [request] operation match the [reply] operation?}
      {- Is [question] and the question of [response] equal?}} *)

  val size_edns : int option -> Edns.t option -> proto -> bool -> int * Edns.t option

  val encode : ?max_size:int -> proto -> t -> Cstruct.t * int

  val raw_error : Cstruct.t -> Rcode.t -> Cstruct.t option
end

module Tsig_op : sig
  type e = [
    | `Bad_key of Domain_name.t * Tsig.t
    | `Bad_timestamp of Domain_name.t * Tsig.t * Dnskey.t
    | `Bad_truncation of Domain_name.t * Tsig.t
    | `Invalid_mac of Domain_name.t * Tsig.t
  ]

  val pp_e : e Fmt.t

  type verify = ?mac:Cstruct.t -> Ptime.t -> Packet.t ->
    Domain_name.t -> ?key:Dnskey.t -> Tsig.t -> Cstruct.t ->
    (Tsig.t * Cstruct.t * Dnskey.t, e * Cstruct.t option) result

  type sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> Tsig.t ->
    key:Dnskey.t -> Packet.t -> Cstruct.t -> (Cstruct.t * Cstruct.t) option
end
