(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)
(** µDNS - an opinionated Domain Name System (DNS) library

    The Domain Name System is a hierarchical and decentralized naming system
   used on the Internet. It associates domain names with nearly arbitrary
   information. Best known is the translation of easily memoizable domain names
   to numerical IP addresses, which are used by computers for establishing
   communication channels - so called {{!A}address} records. DNS has been
   deployed since 1985 on the Internet. It is a widely deployed, fault-tolerant,
   distributed key-value store with built-in caching mechanisms. The keys
   are {{!Domain_name}domain names} and {{!Rr_map.k}record types}, the
   values are {{!Rr_map.rr}record sets}. Each record set has a time-to-live
   associated with it: the maximum time this entry may be cached. The
   {{:https://github.com/hannesm/domain-name}domain name} library provides
   operations on domain names. Hostnames are domain names with further
   restrictions: Only letters, digits, and hyphen are allowed. Domain name
   comparison is usually done ignoring the case.

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
    {- {!Dns_tsig} implements TSIG authentication}
    {- {!Dns_server} implements an authoritative server}
    {- {!Dns_client} implements a client}
    {- {!Dns_zone} implements a zone file parser}
    {- {!Dns_resolver} implements a recursive resolver}}

    These core libraries are pure, i.e. it is independent of network
   communnication, uses immutable values, and errors are explicit as {!result}
   type. Timestamps are passed in to the main handle functions. Some components,
   such as a secondary server, which needs to check freshness of its data in
   regular intervals. The logic is implemented and exposed as function, which
   needs to be called from a side-effecting layer.

    For the client library, several side-effecting layers are implemented:
   [dns-client.unix] uses the blocking [Unix] API (distributed with the OCaml
   runtime), [dns-client.lwt] uses the non-blocking [Lwt] API, and
   [dns-client.mirage] using MirageOS interfaces. Unix command line utilities
   are provided in the [dns-cli] package.

    For the server and resolver components, side-effecting implementations
   using MirageOS interfaces are provided in [dns-server.mirage] and
   [dns-resolver.mirage].
   {{:https://github.com/roburio/unikernels}Example unikernels} are provided
   externally, including authoritative primary and secondary servers, recursive
   and stub resolvers. The certificate authority
   {{:https://letsencrypt}Let's Encrypt} implements a protocol (ACME) which
   automatically provisions X.509 certificates (which are trusted by common
   web browsers); one of the methods to produce proof of ownership is with a DNS
   {{!Txt}TXT} record. Together with
   {{:https://github.com/mmaker/ocaml-letsencrypt}ocaml-letsencrypt}, this DNS
   library can be used to provision certificate signing requests for the
   domain where you run an authoritative server. The
   certificate signing request and certificate are both stored as {{!Tlsa}TLSA}
   records in DNS.

    {e %%VERSION%% - {{:%%PKG_HOMEPAGE%% }homepage}} *)

type proto = [ `Tcp | `Udp ]
(** The type of supported protocols. Used by {!Packet.encode} to decide on
     maximum buffer length, etc. *)

val max_rdata_length : int
(** Maximum size of resource data. This limitation is close to (2 ^ 16) - 1 (the
    limit of DNS-over-TCP and EDNS payload size, but slightly smaller, since an
    rdata must fit into this DNS message together with a DNS header, a question,
    and a TSIG signature (for e.g. zone transfer). *)

(** Opcode

    Each DNS packet includes the kind of query, identified by a 4bit opcode.
   This value is set by the originator of a query and copied into the
   response. *)
module Opcode : sig
  type t =
    | Query
    | IQuery
    | Status
    | Notify
    | Update
  (** The type of opcodes. *)

  val pp : t Fmt.t
  (** [pp ppf opcode] pretty-prints the [opcode] on [ppf]. *)

  val compare : t -> t -> int
  (** [compare a b] compares the opcode [a] with [b], using the RFC-specified
      integer representation of each opcode. *)
end

(** Response code

    Each DNS reply includes a 4bit response code which signals the status of
   the request. *)
module Rcode : sig
  type t =
    | NoError
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
    | BadVersOrSig
    | BadKey
    | BadTime
    | BadMode
    | BadName
    | BadAlg
    | BadTrunc
    | BadCookie
  (** The type of response codes. *)

  val pp : t Fmt.t
  (** [pp ppf rcode] pretty-prints the [rcode] on [ppf]. *)

  val compare : t -> t -> int
  (** [compare a b] compares the response code [a] with [b] using the
      RFC-specified integer representation of response codes. *)

  val to_string : t -> string
  (** [to_string t] is a string representation of [t]. *)
end

(** Start of authority

    The start of authority (SOA) is a resource record at domain boundaries. It
    contains metadata (serial number, refresh interval, hostmaster) of the domain. *)
module Soa : sig
  type t = {
    nameserver : [ `raw ] Domain_name.t ;
    hostmaster : [ `raw ] Domain_name.t ;
    serial : int32 ;
    refresh : int32 ;
    retry : int32 ;
    expiry : int32 ;
    minimum : int32 ;
  }
  (** The type of a start of authority. *)

  val create : ?serial:int32 -> ?refresh:int32 -> ?retry:int32 ->
    ?expiry:int32 -> ?minimum:int32 -> ?hostmaster:'a Domain_name.t ->
    'b Domain_name.t -> t
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
  type t = [ `host ] Domain_name.t
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
    mail_exchange : [ `host ] Domain_name.t ;
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
  type t = [ `raw ] Domain_name.t
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
  type t = [ `host ] Domain_name.t
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
    target : [ `host ] Domain_name.t
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
    | Unknown of int
  (** The type of currently supported DNS key algorithms. *)

  val int_to_algorithm : int -> algorithm
  (** [int_to_algorithm i] decodes [i] to an [algorithm].

      @raise Invalid_argument if [i] does not fit in one octet.
 *)

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

  val name_key_of_string : string -> ([ `raw ] Domain_name.t * t, [> `Msg of string ]) result
  (** [name_key_of_string str] attempts to parse [str] to a domain name and a
      dnskey. The colon character ([:]) is used as separator. *)

  val pp_name_key : ([ `raw ] Domain_name.t * t) Fmt.t
  (** [pp_name_key (name, key)] pretty-prints the dnskey and name pair. *)
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
    | Unknown of int
  (** The type of the certificate usage field. *)

  val cert_usage_to_int : cert_usage -> int
  (** [cert_usage_to_int cu] is the 8 bit integer representation of [cu]. *)

  val int_to_cert_usage : int -> cert_usage
  (** [int_to_cert_usage i] decodes [i] to a certificate usage constructor.

      @raise Invalid_argument if [i] does not fit in one octet.
  *)

  val pp_cert_usage : cert_usage Fmt.t
  (** [pp_cert_usage ppf cu] pretty-prints the certificate usage on [ppf]. *)

  type selector =
    | Full_certificate
    | Subject_public_key_info
    | Private
    | Unknown of int
  (** The type of the selector. *)

  val selector_to_int : selector -> int
  (** [selector_to_int s] is the 8 bit integer representation of [s]. *)

  val int_to_selector : int -> selector
  (** [int_to_selector i] decodes [i] to a selector.

      @raise Invalid_argument if [i] does not fit in one octet.
  *)

  val pp_selector : selector Fmt.t
  (** [pp_selector ppf s] pretty-prints the selector [s] on [ppf]. *)

  type matching_type =
    | No_hash
    | SHA256
    | SHA512
    | Unknown of int
  (** The type of matching type. *)

  val matching_type_to_int : matching_type -> int
  (** [matching_type_to_int m] is the 8 bit integer representation of [m]. *)

  val int_to_matching_type : int -> matching_type
  (** [int_to_matching_type i] decodes [i] to a matching type constructor.

      @raise Invalid_argument if [i] does not fit in one octet.
  *)

  val pp_matching_type : matching_type Fmt.t
  (** [pp_matching_type ppf m] pretty-prints the matching type [m] on [ppf]. *)

  type t = {
    cert_usage : cert_usage ;
    selector : selector ;
    matching_type : matching_type ;
    data : Cstruct.t ;
  }
  (** The type of a TLSA record: certificate usage, selector, matching type,
      and data. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the TLSA record [t] on [ppf]. *)

  val compare : t -> t -> int
  (** [compare a b] compare the TLSA record [a] with [b], comparing the
      integer representations of the individual fields in order. *)
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
    | Unknown of int
  (** The type of supported algorithms. *)

  val algorithm_to_int : algorithm -> int
  (** [algorithm_to_int a] is the 8 bit integer representation of algorithm
     [a]. *)

  val int_to_algorithm : int -> algorithm
  (** [int_to_algorithm i] decodes [i] to the algorithm constructor.

      @raise Invalid_argument if [i] does not fit in one octet.
  *)

  val pp_algorithm : algorithm Fmt.t
  (** [pp_algorithm ppf a] pretty-prints the algorithm [a] on [ppf]. *)

  type typ =
    | SHA1
    | SHA256
    | Unknown of int
  (** The type of supported SSH fingerprint types. *)

  val typ_to_int : typ -> int
  (** [typ_to_int t] is the 8 bit integer representation of typ [t]. *)

  val int_to_typ : int -> typ
  (** [int_to_typ i] decodes [i] to the typ constructor.

      @raise Invalid_argument if [i] does not fit in one octet.
 *)

  val pp_typ : typ Fmt.t
  (** [pp_typ ppf t] pretty-prints the typ [t] on [ppf]. *)

  type t = {
    algorithm : algorithm ;
    typ : typ ;
    fingerprint : Cstruct.t ;
  }
  (** The type of a SSH fingerprint record, consisting of algorithm, typ, and
     actual fingerprint. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the SSH fingerprint record [t] on [ppf]. *)

  val compare : t -> t -> int
  (** [compare a b] compares the SSH fingerprint record [a] with [b] by
      comparing the individual fields in order. *)
end

(** Text records *)
module Txt : sig
  type t = string
  (** The type of a Text record. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the Text record [t] on [ppf]. *)

  val compare : t -> t -> int
  (** [compare a b] compares the Text record [a] with [b] (using
     [String.compare]). *)
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
  (** The type of supported signature algorithms. *)

  val algorithm_to_name : algorithm -> [ `host ] Domain_name.t
  (** [algorithm_to_name a] is the hostname of the algorithm. *)

  val algorithm_of_name : ?off:int -> [ `host ] Domain_name.t ->
    (algorithm, [> `Not_implemented of int * string ]) result
  (** [algorithm_of_name ~off name] is the algorithm represented by [name], or
     an Error if no such algorithm exist. *)

  val pp_algorithm : algorithm Fmt.t
  (** [pp_algorithm ppf a] pretty-prints the algorithm [a] on [ppf]. *)

  type t = private {
    algorithm : algorithm ;
    signed : Ptime.t ;
    fudge : Ptime.Span.t ;
    mac : Cstruct.t ;
    original_id : int ; (* again 16 bit *)
    error : Rcode.t ;
    other : Ptime.t option
  }
  (** The type of a transaction signature: algorithm, timestamp when it was
     signed, the span it is valid for, the actual signature (mac), the original
     DNS identifier, a potential error, and optionally the other timestamp (used
     to signal non-synchronized clocks). *)

  val tsig : algorithm:algorithm -> signed:Ptime.t ->
    ?fudge:Ptime.span -> ?mac:Cstruct.t -> ?original_id:int ->
    ?error:Rcode.t -> ?other:Ptime.t -> unit -> t option
  (** [tsig ~algorithm ~signed ~fudge ~mac ~original_id ~error ~other ()]
     constructs a transaction signature [t] if possible (timestamp needs to
     fit into 48 bit as seconds since Unix epoch). *)

  val with_mac : t -> Cstruct.t -> t
  (** [with_mac t mac] updates [t] with [mac]. *)

  val with_error : t -> Rcode.t -> t
  (** [with_error t err] updates [t] with [err]. *)

  val with_signed : t -> Ptime.t -> t option
  (** [with_signed t ts] updates [t] with signed timestamp [ts], if [ts] fits
     in the representation (seconds since Unix epoch in 48 bit). *)

  val with_other : t -> Ptime.t option -> t option
  (** [with_other t ts] updates [t] with other timestamp [ts], if [ts] fits
     in the representation (seconds since Unix epoch in 48 bit). *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the transaction signature [t] on [ppf]. *)

  val equal : t -> t -> bool
  (** [equal a b] compares the transaction signature [a] with [b], and is [true]
     if they are equal, [false] otherwise. *)

  val encode_raw : [ `raw ] Domain_name.t -> t -> Cstruct.t
  (** [encode_raw name t] encodes the transaction signature [t] as resource
     record using [name]. The mac is not included, this is used for computing
     the signature. *)

  val encode_full : [ `raw ] Domain_name.t -> t -> Cstruct.t
  (** [encode_full name t] encodes the transaction signature [t] as resource
     record using [name]. *)

  val dnskey_to_tsig_algo : Dnskey.t -> (algorithm, [> `Msg of string ]) result
  (** [dnskey_to_tsig_algo dnskey] is the TSIG algorithm of [dnskey], or an
     Error. *)

  val valid_time : Ptime.t -> t -> bool
  (** [valid_time ts t] checks whether the [signed] timestamp (within [fudge])
     matches [ts]. *)
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
  (** The type of supported extensions. *)

  type t = private {
    extended_rcode : int ;
    version : int ;
    dnssec_ok : bool ;
    payload_size : int ;
    extensions : extension list ;
  }
  (** The type of an EDNS record. *)

  val create : ?extended_rcode:int -> ?version:int -> ?dnssec_ok:bool ->
    ?payload_size:int -> ?extensions:extension list -> unit -> t
  (** [create ~extended_rcode ~version ~dnssec_ok ~payload_size ~extensions ()]
     constructs an EDNS record with the optionally provided data. The
     [extended_rcode] defaults to 0, [version] defaults to 0, [dnssec_ok] to
     false, [payload_size] to the minimum payload size (512 byte), [extensions]
     to the empty list. *)

  val reply : t option -> int option * t option
  (** [reply edns] either constructs an EDNS record and returns a maximum payload
     size, or [None] (if no EDNS is provided). *)

  val compare : t -> t -> int
  (** [compare a b] compares the EDNS record [a] with [b] by comparing
      individual fields in-order. The extension list must be exactly in the
      same order. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the EDNS record [t] on [ppf]. *)

  val allocate_and_encode : t -> Cstruct.t
  (** [allocate_and_encode t] allocates a buffer and encodes [t] into that
      buffer. *)
end

 (** A map whose keys are record types and their values are the time-to-live and
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

  module I : sig
    type t
    val of_int : ?off:int -> int -> (t, [> `Malformed of int * string ]) result
    val to_int : t -> int
    val compare : t -> t -> int
  end

  type 'a with_ttl = int32 * 'a
  (** A tuple type whose first component is a time-to-live counter in seconds. *)

  type _ rr =
    | Soa : Soa.t rr
    | Ns : Domain_name.Host_set.t with_ttl rr
    | Mx : Mx_set.t with_ttl rr
    | Cname : Cname.t with_ttl rr
    | A : Ipv4_set.t with_ttl rr
    | Aaaa : Ipv6_set.t with_ttl rr
    | Ptr : Ptr.t with_ttl rr
    | Srv : Srv_set.t with_ttl rr
    | Dnskey : Dnskey_set.t with_ttl rr
    | Caa : Caa_set.t with_ttl rr
    | Tlsa : Tlsa_set.t with_ttl rr
    | Sshfp : Sshfp_set.t with_ttl rr
    | Txt : Txt_set.t with_ttl rr
    | Unknown : I.t -> Txt_set.t with_ttl rr
  (** The type of resource record sets, as GADT: the value depends on the
     specific constructor. There may only be a single SOA and Cname and Ptr
     record, while other constructors, such as address (A), contain a set of
     the respective types. The Unknown constructor is used for not specifically
     supported records. These resource records are usually persisted to disk by
     a server or resolver. Resource records that are only meant for a single
     transaction (such as EDNS or TSIG) are not in this GADT, neither is the
     query type ANY (which answer is computed on the fly), or zone transfer
      operations (AXFR/IXFR). *)

  module K : Gmap.KEY with type 'a t = 'a rr

  include Gmap.S with type 'a key = 'a rr

  val equal_rr : 'a key -> 'a -> 'a -> bool
  (** [equal_rr k v v'] is [true] if [v = v'], [false] otherwise. *)

  val equalb : b -> b -> bool
  (** [equalb b b'] is [true] if the bindings are equal. *)

  type k = K : 'a key -> k
  (** The monomorphic type of keys. *)

  val comparek : k -> k -> int
  (** [comparek k k'] compares [k] with [k'] using the defined ordering. *)

  val ppk : k Fmt.t
  (** [ppk ppf k] pretty-prints [k]. *)

  val names : 'a key -> 'a -> Domain_name.Host_set.t
  (** [names k v] are the referenced domain names in the given binding. *)

  val pp_b : b Fmt.t
  (** [pp_b ppf b] pretty-prints the binding [b]. *)

  val text_b : ?origin:'a Domain_name.t -> ?default_ttl:int32 -> 'b Domain_name.t -> b -> string
  (** [text_b ~origin ~default_ttl domain-name binding] is the zone file format of [binding] using
      [domain-name]. *)

  val remove_rr : 'a key -> 'a -> 'a -> 'a option
  (** [remove_rr k v rem] removes [rem] from [v]. If the result is an empty set,
      [None] is returned. *)

  val union_rr : 'a key -> 'a -> 'a -> 'a
  (** [union_rr k l r] builds the union of [l] with [r]. A potential [r] Soa or
      Cname overwrites its [l] counterpart. *)

  val unionee : 'a key -> 'a -> 'a -> 'a option
  (** [unionee k l r] unions [l] with [r] using {!union_rr}. *)

  val diff : old:t -> t -> (t option * t option)
  (** [diff ~old m] computes the difference between [old] and [m]. The left
      projection are the deleted entries, the right projection are the added
      entries. [Soa] entries are ignored. *)

  val text : ?origin:'a Domain_name.t -> ?default_ttl:int32 -> 'b Domain_name.t -> 'c rr -> 'c -> string
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
  (** The type of a Domain_name map whose values are resource record sets.
      Observable in the answer and authority sections of a DNS packet. *)

  val empty : t
  (** [empty] is the empty map. *)

  val equal : t -> t -> bool
  (** [equal a b] is [true] when [a] and [b] contain the same keys and values,
     [false] otherwise. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the name resource record map [t] on [ppf]. *)

  val add : [ `raw ] Domain_name.t -> 'a Rr_map.key -> 'a -> t -> t
  (** [add name rr_typ rr_set map] adds the binding [name -> rr_typ, rr_set] to
     [map], if already present, {!Rr_map.union_rr} is applied for merging. *)

  val find : [ `raw ] Domain_name.t -> 'a Rr_map.key -> t -> 'a option
  (** [find name rr_typ map] returns the [rr_set] for [name, rr_typ] if present,
     [None] otherwise. *)

  val remove_sub : t -> t -> t
  (** [remove_sub map sub] removes all [name, rr_key] from [map] that are
     present in [sub]. Their values [rr_set] are not compared. *)

  val singleton : [ `raw ] Domain_name.t -> 'a Rr_map.key -> 'a -> t
  (** [singleton name rr_typ rr_set] constructs a [t] with the single entry
     [name, rr_typ] mapped to [rr_set]. *)

  val union : t -> t -> t
  (** [union a b] is union of [a] and [b], using {!Rr_map.unionee}. *)
end

(** The DNS packet.

    Encoding and decoding from binary. Definition of types for multiple DNS
   operations.  *)
module Packet : sig

  module Flag : sig
    type t = [
      | `Authoritative
      | `Truncation
      | `Recursion_desired
      | `Recursion_available
      | `Authentic_data
      | `Checking_disabled
    ]
    (** The type of DNS packet flags. *)

    val compare : t -> t -> int
    (** [compare a b] compares the flag [a] with [b]. *)

    val pp : t Fmt.t
    (** [pp ppf f] pretty-prints the flag [f] on [ppf]. *)

    val pp_short : t Fmt.t
    (** [pp_short ppf f] pretty-prints the flag in two letters on [ppf]. *)
  end

  (** The set of flags *)
  module Flags : Set.S with type elt = Flag.t

  (** A DNS header *)
  module Header : sig
    type t = int * Flags.t
    (** The type of a DNS header, its 16 bit identifier and a flag set. *)

    val compare : t -> t -> int
    (** [compare a b] compares the header [a] with [b]. *)
  end

  (** A DNS Question - the first section of a DNS packet *)
  module Question : sig
    type qtype = [ `Any | `K of Rr_map.k ]
    (** The question type, either Any or a concrete RR type. *)

    val pp_qtype : qtype Fmt.t
    (** [pp_qtype ppf q] pretty-prints the question type [q] on [ppf]. *)

    val compare_qtype : qtype -> qtype -> int
    (** [compare_qtype a b] compares the question type [a] with [b]. *)

    type t = [ `raw ] Domain_name.t * [ qtype | `Axfr | `Ixfr ]
    (** The type in a DNS question: its name and question type or a zone
       full or incremental transfer. *)

    val qtype : t -> qtype option
    (** [qtype t] is the question type of [t], if any, or [None]. *)

    val create : 'a Domain_name.t -> 'b Rr_map.key -> t
    (** [create name key] is a DNS question. *)

    val pp : t Fmt.t
    (** [pp ppf t] pretty-prints the question [t] on [ppf]. *)

    val compare : t -> t -> int
    (** [compare a b] compares the question [a] with [b] by first comparing the
        domain name for equality, and if equal the query type. *)
  end

  (** A DNS answer, consisting of the answer and authority sections. *)
  module Answer : sig
    type t = Name_rr_map.t * Name_rr_map.t
    (** The type of an answer: answer and authority section, each represented
       as Domain_name maps with resource record sets. *)

    val empty : t
    (** [empty] is the empty answer. *)

    val is_empty : t -> bool
    (** [is_empty t] is [true] if [t] is empty, [false] otherwise. *)

    val pp : t Fmt.t
    (** [pp ppf t] pretty-prints the answer [t] on [ppf]. *)

    val equal : t -> t -> bool
    (** [equal a b] is [true] if the answer [a] contains the same resource
       record sets as the answer [b], [false] otherwise. *)
  end

  (** A DNS zone transfer. *)
  module Axfr : sig
    type t = Soa.t * Name_rr_map.t
    (** The type of a zone transfer: a start of authority record and the
       complete zone, may include glue records. *)

    val pp : t Fmt.t
    (** [pp ppf t] pretty-prints the zone transfer [t] on [ppf]. *)

    val equal : t -> t -> bool
    (** [equal a b] is [true] if the zone transfer [a] contains the same
       resource records as [b], and the start of authority is equal. Otherwise
       [false]. *)
  end

  (** Incremental DNS zone transfer. *)
  module Ixfr : sig
    type t = Soa.t *
             [ `Empty
             | `Full of Name_rr_map.t
             | `Difference of Soa.t * Name_rr_map.t * Name_rr_map.t ]
   (** The type of an incremental zone transfer between two serials, consisting
      of the new start of authority and:
      {ul
      {- Empty, if there are no changes}
      {- Full zone transfer, same as AXFR}
      {- Difference, with the old start of authority, the resource record sets
          to be removed, and the resource record sets to be added.}} *)

    val pp : t Fmt.t
    (** [pp ppf t] pretty-prints the incremental zone transfer [t] on [ppf]. *)

    val equal : t -> t -> bool
    (** [equal a b] compares the incremental zone transfer [a] with [b], and is
       [true] if they are the same. *)
  end

  (** DNS update packets. *)
  module Update : sig
    type prereq =
      | Exists of Rr_map.k
      | Exists_data of Rr_map.b
      | Not_exists of Rr_map.k
      | Name_inuse
      | Not_name_inuse
    (** The type of Update prerequisites. *)

    val pp_prereq : prereq Fmt.t
    (** [pp_prereq ppf t] pretty-prints the prerequisite [t] on [ppf]. *)

    val equal_prereq : prereq -> prereq -> bool
    (** [equal_prereq a b] is [true] if [a] and [b] are equal, [false]
       otherwise. *)

    type update =
      | Remove of Rr_map.k
      | Remove_all
      | Remove_single of Rr_map.b
      | Add of Rr_map.b
    (** The type of an update. *)

    val pp_update : update Fmt.t
    (** [pp_update ppf t] pretty-prints the update [t] on [ppf]. *)

    val equal_update : update -> update -> bool
    (** [equal_update a b] is [true] if [a] is equal to [b], [false]
       otherwise. *)

    type t = prereq list Domain_name.Map.t * update list Domain_name.Map.t
    (** The type of a DNS update: a map indexed by domain name with a list of
       prerequisites, and a map indexed by domain name of a list of updates. *)

    val empty : t
    (** [empty] is the empty update. *)

    val pp : t Fmt.t
    (** [pp ppf t] pretty-prints the update [t] on [ppf]. *)

    val equal : t -> t -> bool
    (** [equal a b] is [true] if [a] is equal to [b], [false] otherwise. *)
  end

  type request = [
    | `Query
    | `Notify of Soa.t option
    | `Axfr_request
    | `Ixfr_request of Soa.t
    | `Update of Update.t
  ]
  (** The type of a DNS request: depending on opcode and rr_typ. *)

  val equal_request : request -> request -> bool
  (** [equal_request a b] is [true] if the request [a] is the same as [b],
     [false] otherwise. *)

  val pp_request : request Fmt.t
  (** [pp_request ppf r] pretty-prints the request [r] on [ppf]. *)

  type reply = [
    | `Answer of Answer.t
    | `Notify_ack
    | `Axfr_reply of Axfr.t
    | `Axfr_partial_reply of [ `First of Soa.t | `Mid | `Last of Soa.t ] * Name_rr_map.t
    | `Ixfr_reply of Ixfr.t
    | `Update_ack
    | `Rcode_error of Rcode.t * Opcode.t * Answer.t option
  ]
  (** The type of a DNS reply: depending on opcode, rr_typ, and rcode. *)

  val equal_reply : reply -> reply -> bool
  (** [equal_reply a b] is [true] if the reply [a] is the same as [b], [false]
     otherwise. *)

  val pp_reply : reply Fmt.t
  (** [pp_reply ppf r] pretty-prints the reply [r] on [ppf]. *)

  type data = [ request | reply ]
  (** The type of either request or reply. *)

  val opcode_data : data -> Opcode.t
  (** [opcode_data data] is the opcode of [data]. *)

  val rcode_data : data -> Rcode.t
  (** [rcode_data data] is the response code of [data]. *)

  val equal_data : data -> data -> bool
  (** [equal_data a b] is [true] if [a] and [b] are the same, [false]
     otherwise. *)

  val pp_data : data Fmt.t
  (** [pp_data ppf data] pretty-prints [data] on [ppf]. *)

  type t = private {
    header : Header.t ;
    question : Question.t ;
    data : data ;
    additional : Name_rr_map.t ;
    edns : Edns.t option ;
    tsig : ([ `raw ] Domain_name.t * Tsig.t * int) option ;
  }
  (** The type of a DNS packet: its header, question, data, additional section,
     and optional EDNS and TSIG records. *)

  val create : ?max_size:int -> ?additional:Name_rr_map.t -> ?edns:Edns.t ->
    ?tsig:([ `raw ] Domain_name.t * Tsig.t * int) ->
    Header.t -> Question.t -> data -> t
  (** [create ~max_size ~additional ~edns ~tsig hdr q data] is a DNS packet. *)

  val with_edns : t -> Edns.t option -> t
  (** [with_edns t edns] is [t] with the edns field set to [edns]. *)

  val pp : t Fmt.t
  (** [pp ppf t] pretty-prints the DNS packet [t] on [ppf]. *)

  val pp_header : t Fmt.t
  (** [pp_header ppf t] pretty-prints the header of the DNS packet on [ppf]. *)

  val equal : t -> t -> bool
  (** [equal a b] is [true] if the DNS packet [a] and [b] are equal, [false]
     otherwise. *)

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
  (** The type of decode errors. *)

  val pp_err : err Fmt.t
  (** [pp_err ppf err] pretty-prints the decode error [err] on [ppf]. *)

  val decode : Cstruct.t -> (t, err) result
  (** [decode cs] decode the binary data [cs] to a DNS packet [t] or an error. *)

  type mismatch = [ `Not_a_reply of request
                  | `Id_mismatch of int * int
                  | `Operation_mismatch of request * reply
                  | `Question_mismatch of Question.t * Question.t
                  | `Expected_request ]
  (** The type of request / reply mismatches. *)

  val pp_mismatch : mismatch Fmt.t
  (** [pp_mismatch ppf m] pretty-prints the mismatch [m] on [ppf]. *)

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
  (** [size_edns max_size edns protocol query] computes the size of the reply
     packet, and optionally an EDNS record. *)

  val encode : ?max_size:int -> proto -> t -> Cstruct.t * int
  (** [encode ~max_size protocol t] allocates a buffer and encodes the DNS
     packet [t] into it. If the maximum size (depending on [max_size] and
     [protocol]) is reached, the truncation flag is set. The last component of
     the result is the maximum size. *)

  val encode_axfr_reply : ?max_size:int -> int -> proto -> t -> Axfr.t ->
    Cstruct.t list * int
  (** [encode_axfr_reply ~max_size tsig_size protocol t axfr] encodes the [axfr]
      into a list of buffers to be sent out (each with at least [tsig_size]
      space for a tsig signature. The second component of the result is the
      maximum size (dependent on [max_size] and [protocol]). *)

  val raw_error : Cstruct.t -> Rcode.t -> Cstruct.t option
  (** [raw_error cs rcode] is an error reply with [rcode] to [cs], or None if
     [cs] is already a reply. *)
end

(** Signature operations and their errors. *)
module Tsig_op : sig
  type e = [
    | `Bad_key of [ `raw ] Domain_name.t * Tsig.t
    | `Bad_timestamp of [ `raw ] Domain_name.t * Tsig.t * Dnskey.t
    | `Bad_truncation of [ `raw ] Domain_name.t * Tsig.t
    | `Invalid_mac of [ `raw ] Domain_name.t * Tsig.t
  ]
  (** The type of a verification error. *)

  val pp_e : e Fmt.t
  (** [pp_e ppf e] pretty-prints the verification error [e] on [ppf]. *)

  type verify = ?mac:Cstruct.t -> Ptime.t -> Packet.t ->
    [ `raw ] Domain_name.t -> ?key:Dnskey.t -> Tsig.t -> Cstruct.t ->
    (Tsig.t * Cstruct.t * Dnskey.t, e * Cstruct.t option) result
  (** The type of a verification function. The [mac] contains data for a reply
     to a signed request. *)

  val no_verify : verify
  (** [no_verify] always returns an error. *)

  type sign = ?mac:Cstruct.t -> ?max_size:int -> [ `raw ] Domain_name.t ->
    Tsig.t -> key:Dnskey.t -> Packet.t -> Cstruct.t ->
    (Cstruct.t * Cstruct.t) option
  (** The type of a signature function. The [mac] contains data for a reply to
     a signed request. *)

  val no_sign : sign
  (** [no_sign] always returns [None]. *)
end

(**/**)
val counter_metrics : f:('a -> string) ->
  string -> (Metrics.field list, 'a -> Metrics.Data.t) Metrics.src
