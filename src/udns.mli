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

  val int_to_algorithm : int -> algorithm option
  (** [int_to_algorithm i] tries to decode [i] to an [algorithm]. *)

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

  val of_string : string -> t option
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
  val int_to_cert_usage : int -> cert_usage option
  val pp_cert_usage : cert_usage Fmt.t

  type selector =
    | Full_certificate
    | Subject_public_key_info
    | Private

  val selector_to_int : selector -> int
  val int_to_selector : int -> selector option
  val pp_selector : selector Fmt.t

  type matching_type =
    | No_hash
    | SHA256
    | SHA512

  val matching_type_to_int : matching_type -> int
  val int_to_matching_type : int -> matching_type option
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
  val int_to_algorithm : int -> algorithm option
  val pp_algorithm : algorithm Fmt.t

  type typ =
    | SHA1
    | SHA256

  val typ_to_int : typ -> int
  val int_to_typ : int -> typ option
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
    error : Udns_enum.rcode ;
    other : Ptime.t option
  }

  val algorithm_to_name : algorithm -> Domain_name.t

  val algorithm_of_name : Domain_name.t -> algorithm option

  val pp_algorithm : algorithm Fmt.t

  val tsig : algorithm:algorithm -> signed:Ptime.t ->
    ?fudge:Ptime.span -> ?mac:Cstruct.t -> ?original_id:int ->
    ?error:Udns_enum.rcode -> ?other:Ptime.t -> unit -> t option

  val with_mac : t -> Cstruct.t -> t

  val with_error : t -> Udns_enum.rcode -> t

  val with_signed : t -> Ptime.t -> t option

  val with_other : t -> Ptime.t option -> t option

  val pp : t Fmt.t

  val encode_raw : Domain_name.t -> t -> Cstruct.t

  val encode_full : Domain_name.t -> t -> Cstruct.t

  val dnskey_to_tsig_algo : Dnskey.t -> algorithm option

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

  type t = {
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

  val to_rr_typ : b -> Udns_enum.rr_typ
  (** [to_rr_typ b] is the resource record typ of [b]. *)

  val k_to_rr_typ : 'a k -> Udns_enum.rr_typ
  (** [k_to_rr_typ k] is the resource record typ of [k]. *)

  val names : 'a k -> 'a -> Domain_name.Set.t
  (** [names k v] are the referenced domain names in the given binding. *)

  val names_b : b -> Domain_name.Set.t
  (** [names_b binding] are the referenced domain names in the given binding. *)

  val lookup_rr : Udns_enum.rr_typ -> t -> b option
  (** [lookup_rr typ t] looks up the [typ] in [t]. *)

  val remove_rr : Udns_enum.rr_typ -> t -> t
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
    | `Not_implemented of int * string
    | `Leftover of int * string
    | `Malformed of int * string
    | `Partial
    | `Bad_edns_version of int
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

    type t = {
      id : int ;
      query : bool ;
      operation : Udns_enum.opcode ;
      rcode : Udns_enum.rcode ;
      flags : FS.t
    }

    val compare : t -> t -> int

    val pp : t Fmt.t

    val decode : Cstruct.t -> (t, err) result

    val encode : Cstruct.t -> t -> unit
  end

  module Question : sig
    type t = Domain_name.t * Udns_enum.rr_typ

    val pp : t Fmt.t
    val compare : t -> t -> int
  end

  module Query : sig
    type t = Name_rr_map.t * Name_rr_map.t
    val empty : t
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  module Axfr : sig
    type t = (Soa.t * Name_rr_map.t) option
    val empty : t
    val pp : t Fmt.t
    val equal : t -> t -> bool
  end

  module Update : sig
    type prereq =
      | Exists of Udns_enum.rr_typ
      | Exists_data of Rr_map.b
      | Not_exists of Udns_enum.rr_typ
      | Name_inuse
      | Not_name_inuse
    val pp_prereq : prereq Fmt.t
    val equal_prereq : prereq -> prereq -> bool

    type update =
      | Remove of Udns_enum.rr_typ
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

  type t = [
    | `Query of Query.t
    | `Notify of Query.t
    | `Axfr of Axfr.t
    | `Update of Update.t
  ]

  val pp : t Fmt.t

  val equal : t -> t -> bool

  type res = Header.t * Question.t * t * Name_rr_map.t * Edns.t option * (Domain_name.t * Tsig.t * int) option

  val pp_res : res Fmt.t

  val decode : Cstruct.t -> (res, err) result

  val is_reply : ?not_error:bool -> ?not_truncated:bool -> Header.t -> Question.t -> res -> bool
  (** [is_reply ~not_error ~not_truncated header question response] validates the reply, and returns either
      [true] or [false] and logs the failure. The following basic checks are
      performed:
      {ul
      {- Is the header identifier of [header] and [response] equal?}
      {- Is [res] a reply (first bit set)?}
      {- Is the operation of [header] and [res] the same?}
      {- If [not_error] is [true] (the default): is the rcode of [header] NoError?}
      {- If [not_truncated] is [true] (the default): is the [truncation] flag not set?}
      {- Is the [question] and the question of [response] equal?}} *)

  val size_edns : int option -> Edns.t option -> proto -> bool -> int * Edns.t option

  val encode : ?max_size:int -> ?additional:Name_rr_map.t -> ?edns:Edns.t ->
    proto -> Header.t -> Question.t -> t -> Cstruct.t * int

  val error : Header.t -> Question.t -> Udns_enum.rcode -> (Cstruct.t * int) option

  val raw_error : Cstruct.t -> Udns_enum.rcode -> Cstruct.t option
end

module Tsig_op : sig
  type e = [
    | `Bad_key of Domain_name.t * Tsig.t
    | `Bad_timestamp of Domain_name.t * Tsig.t * Dnskey.t
    | `Bad_truncation of Domain_name.t * Tsig.t
    | `Invalid_mac of Domain_name.t * Tsig.t
  ]

  val pp_e : e Fmt.t

  type verify = ?mac:Cstruct.t -> Ptime.t -> Packet.Header.t -> Packet.Question.t ->
    Domain_name.t -> key:Dnskey.t option -> Tsig.t -> Cstruct.t ->
    (Tsig.t * Cstruct.t * Dnskey.t, e * Cstruct.t option) result

  type sign = ?mac:Cstruct.t -> ?max_size:int -> Domain_name.t -> Tsig.t ->
    key:Dnskey.t -> Packet.Header.t -> Packet.Question.t -> Cstruct.t ->
    (Cstruct.t * Cstruct.t) option
end
