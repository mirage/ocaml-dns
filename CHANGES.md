### v9.1.0 (2024-10-22)

* Dns.Dnskey: provide to_string and name_key_to_string (@hannesm, @dinosaure,
  #356 - fixes #355)
* BREAKING: Dns.Dnskey remove pp_name_key (unused, irritating, #356)
* BREAKING Dns_certify_mirage.retrieve_certificate use separate dns_key_name
  and dns_key arguments, avoid string decoding in that function (#356)

### v9.0.1 (2024-09-27)

* dns-client-miou: use String.get_uint16_be instead of String.get_int16_be
  (#354 @dinosaure)

### v9.0.0 (2024-08-26)

* Remove `Cstruct.t` and use `string`/`bytes` (@hannesm, @dinosaure, @palainp, #351)
* Add a Miou implementation of `ocaml-dns` (@dinosaure, @hannesm, #352)

### v8.0.0 (2024-05-29)

* dns-client (lwt, mirage): depend on happy-eyeballs-{lwt,mirage} instead of
  duplicating the code. This requires happy-eyeballs 1.1.0, and now the same
  Happy_eyeballs_{lwt,mirage}.t is used for DNS (connecting to the nameserver)
  and for the application (connecting to a remote host)
  (@dinosaure @hannesm #346)
* server: improve API documentation (@hannesm
  1a80bd4080e597687152cf351d035ef5f00c5946
  000ae02dfc477d91c05891e3891a447328ae448a)
* server: add a `packet_callback` to `handle_packet` and `handle_buf`
  (@RyanGibb #349)
* server: expose `update_data` (@RyanGibb #350)
* resolver: b root name server IP change (@hannesm #348)
* secondary server [mirage]: avoid infinite loop in connect (avoids SYN floods)
  (@hannesm @reynir #347)
* resolver, dns_zone: use consistently `Log` instead of `Logs` (@palainp #342)

### v7.0.3 (2023-06-15)

* dns-client-lwt, dns-client-mirage: adapt to happy-eyeballs 0.6 changes,
  also avoid unnecessary recursion (#340 @hannesm, @reynir)

### v7.0.2 (2023-06-13)

* dns-server: for secondary servers use the right zone transfers and keys, fixed
  in #339 by @hannesm
* dns: add support for null record (arbitrary binary data) (#338 @RyanGibb)

### v7.0.1 (2023-02-27)

* dns-server.zone: fix parsing of zone files that contain tokens such as
  `N` `S` `E` `W` `-<number>` `<number>m` `DS` `CAA` `TYPE<number>`.
  There was an inconsistency in the Dns_zone_parser.keyword_or_number rule.
  Test cases have been added, a comment has been added to the
  Dns_zone_lexer.kw_or_cs function. Discovered while updating the primary NS
  with an entry of "e.ns", fixed in #336 @hannesm
  Broken since the early days of this development

### v7.0.0 (2023-02-16)

* BREAKING: dns-client is split into 3 packages: dns-client-lwt,
  dns-client-mirage. If your dune file contains dns-client.lwt, use
  dns-client-lwt now. If your dune file contains dns-client.mirage, use
  dns-client-mirage now (#331 @hannesm)
* update to mirage-crypto 0.11.0 API changes and tls 0.16.0 packaging changes
  (#331 @hannesm)
* dns-client.resolvconf: add line number to parser (#334 @hannesm, inspired by
  #328 @bikallem)
* dns-client.resolvconf: allow zone idx (RFC 4007) for IPv6 entries
  (#334 @hannesm, inspired by #328 @bikallem)
* dns-server.zone: allow zone files without final newline (add a newline to the
  buffer if the last character is not \n) (#333 @hannesm)
* dns-client-{lwt,mirage}: do not log when the resolver closed the connection,
  but there are no pending requests (#332 @reynir)
* dns-certify: in Dns_certify_mirage use X509.Private_key.of_string, the
  behaviour when both key_data and key_seed is provided changed, and leads to
  an exception now (#330 @hannesm)

### v6.4.1 (2022-12-02)

* dns-client: adapt to happy eyeballs 0.4.0 (#329 @reynir @hannesm)
* dns-resolver: dnssec validation is optional via a labeled parameter ~dnssec
  passed to Dns_resolver.create (#325 @hannesm)
* upgrade to dune 2 (#327 @reynir)

### v6.4.0 (2022-10-24)

* dns-client: demote log level of response to debug (#317 @hannesm)
* dns-client: use DNS-over-TLS for uncensoreddns.org only (#320 @hannesm)
* API: dns-client: connect returns the protocol (UDP/TCP), allowing mixed UDP
  and TCP namerservers being used (#322 @hannesm)
* dns-client-mirage: allow hostname in authenticator, improve error message and
  documentation (#319 #322 @hannesm)
* dns-client-mirage: support UDP nameservers as "udp:<IP>" in
  nameserver_of_string (#322 @reynir @hannesm)
* API: dns-client, dns-stub, dns-resolver: ?size is now ?cache_size (#322
  @hannesm, suggested by @reynir)

### v6.3.0 (2022-07-26)

* dns-server: demote log level for various messages (#309 @hannesm)
* dns-zone: add additional glue: only add if authoritative for nameserver domain
  (#309 @hannesm)
* BUGFIX: dns-trie: fix lookup when delegations are present, add tests
  (#309 @hannesm)
* ozone: be more explicit when showing errors (#311 @psafont)
* dns: avoid polymorphic comparison (#314 @hannesm, reported by @RyanGibb)
* FEATURE: dns: add LOC resource records (RFC 1876) (#310 @RyanGibb)

### v6.2.2 (2022-04-08)

* BUGFIX dns-trie: the collect_entries function jumped over zone boundaries.
  This lead dns-primary-git to detect changes in zones with subdomains delegated
  to the same name servers, leading to dropping of zones (#308 @hannesm,
  reported by @reynir)
* BUGFIX dns-server.text: add address glue records for name servers out of the
  authority of this server. This is crucial since dns-primary-git supports
  such glue records to notify these about zone updates (#307 @hannesm)
* New functionality in dns-zone (dns-server.zone): decode_keys, decode_zones,
  and decode_zones_keys copied from dns-primary-git for reusing in other
  projects (#307 @hannesm)

### v6.2.1 (2022-04-01)

* BUGFIX dns: RTYPE is 16 bit, previously 15 bit were accepted, also check for
  being positive (#304, @hannesm @reynir)
* dns-server: dns-trie zone check no longer enforces that the nameserver is in
  the nameserve set of the zone, this enables hidden primary setups (fixes #303,
  @hannesm)

### v6.2.0 (2022-03-09)

* New opam package "dnssec" implementing dnssec validation (@reynir @hannesm)
* Use custom log sources, not the default one from Logs (@reynir @hannesm)
* BUGFIX dns-resolver: unlisten on the listen port, not the packet src_port
  (#290 @hannesm)
* dns-resolver: add IPv6 addresses of root servers (fixes #262, @hannesm)
* dns-resolver: preliminary support for DNSSec (#262 @reynir @hannesm)
* dns-client: when /etc/resolv.conf modifies, update the list of nameservers
  (#291 @hannesm @reynir)
* dns-cli: update to cmdliner 1.1.0 (#300 @hannesm)
* dns-client-mirage: add module type and nameserver_of_string and connect to
  allow creation of a MirageOS device (#297 @dinosaure)
* dns-cache: add size, capacity, and weight to metrics (#301, fixes #299,
  @hannesm)

### v6.1.4 (2022-01-11)

* dns-client-{mirage,lwt}: avoid multiple simultaneous connection attempts
  to the same resolver. Now, before a connection is initiated, a Lwt_condition
  is put into the client state which subsequent resolution requests wait for
  (#285 @hannesm, review by @reynir, reported by @kit-ty-kate in
  roburio/http-lwt-client#8)

### v6.1.3 (2021-12-17)

* dns-mirage: use tcpip >= 7.0.0 instead of deprecated mirage-stack and
  mirage-protocols (#283 @dinosaure)

### v6.1.2 (2021-11-27)

* dns: avoid exceptions when decoding resource records (#282 @reynir @hannesm)

### v6.1.1 (2021-11-19)

* dns-client: by default, do not send EDNS (#280 @reynir @hannesm)
* BREAKING dns-certify.mirage: treat key_data as base64 encoded data
  (#280 @reynir @hannesm)
* mirage: update to mirage-protocols 6.0.0 API (use TCP.listen / UDP.listen)
  resolver: unlisten on UDP port after response has been received (#280 @reynir
  @hannesm)

### v6.1.0 (2021-11-10)

* BUGFIX dns-client: avoid exception on TLS handshake failure (reported by @reynir)
* FEATURE dns-client: optionally send a edns in the query (reported by @orbitz #276)
* dns-client: combine send and recv, avoid resource leaks on timeout

### v6.0.2 (2021-10-27)

* dns: remove astring dependency (@hannesm)
* dns-client: adapt to happy-eyeballs 0.1.0 API (#274 @hannesm)
* dns-client: avoid List.concat_map, make it available on OCaml 4.08 (@hannesm)

### v6.0.1 (2021-10-25)

* remove rresult dependency (#273 @hannesm, review by @reynir)

### v6.0.0 (2021-10-19)

* use Cstruct.length instead of deprecated Cstruct.len
* avoid deprecated fmt functions

* dns-client: send EDNS tcp keepalive with a timeout of 120 seconds if TCP
  is used (@reynir @hannesm)
* BREAKING dns: Rr_map.get_ttl is now ttl, and takes 'a key -> 'a -> int32
  (instead of b -> int32), Rr_map.with_ttl now is 'a key -> 'a -> int32 -> 'a
  (instead of b -> int32 -> b) (#264 @hannesm)
* BREAKING dns: Rr_map.A now uses Ipaddr.V4.Set.t, Aaaa uses Ipaddr.V6.Set.t
  (requires ipaddr 5.2.0) (#268 @hannesm)

* BREAKING dns.cache: type entry now is polymorphic ('a entry = `Entry of 'a ...)
  (instead of `Entry of Rr_map.b) (#263 @reynir and @hannesm)
* BREAKING dns.cache: use a LRU.F.t instead of LRU.M.t (#256 @hannesm)
* dns.cache: provide get_or_cname and get_any function (#256 #257 @hannesm)
* BUGFIX dns.cache: update if time to live of cached entry expired
  (reported in #259 by @dinosaure, fix by @reynir and @hannesm)

* dns-client support DNS-over-TLS (RFC 7858): the type io_addr is now a variant
  of `Plaintext (Ipaddr.t * int) or `Tls (Tls.Config.client * Ipaddr.t * int)
  By default, ca-certs (ca-certs-nss for MirageOS) are used as trust anchors,
  and the certificate is expected to contain the IP address of the resolver.
  The default resolver (anycast.uncensoreddns.org) certificate is verified by
  hostname, since the let's encrypt certificate does not include an IP address
  in SubjectAlternativeNames (#270 @hannesm)
* BREAKING dns-client.mirage.Make is extended by a Mirage_clock.PCLOCK
  (#270 @hannesm)
* BREAKING dns-client, dns-stub: use Dns.proto instead of custom [`TCP|`UDP]
  (#266 @hannesm)
* dns-client: use a `mutable timeout_ns : int64` instead of
  `timeout_ns : int64 ref` (#269 @hannesm)
* BREAKING dns-client: remove `?nameserver` from
  getaddrinfo/gethostbyname/gehostbyname6/get_resource_record - if a custom
  nameserver should be queried, a distinct Dns_client.t can be constructed
  (#269 @reynir and @hannesm)
* dns-client: multiplex over TCP connections (#269 @reynir and @hannesm)
* dns-client: use happy-eyeballs to connect to all nameservers from
  /etc/resolv.conf sequentially (lwt and mirage) (#269 @reynir and @hannesm)
* BREAKING dns-client remove UDP support from lwt (#270 @reynir and @hannesm)

* BREAKING dns-resolver.mirage add DNS-over-TLS support (@reynir @hannesm)
* BREAKING dns-resolver remove "mode" from codebase, default to recursive
  (a stub resolver is available as dns-stub) (#260 @hannesm)
* dns-resolver: use dns.cache instead of copy in Dns_resolver_cache
  (#256 @hannesm)
* BUGFIX dns-resolver: fix responses to queries (reported in #255 by @dinosaure,
  fix in #258 by @reynir and @hannesm)
* dns-resolver: refactor and cleanup code, remove statistics, remove dead code
  (#258 #261 @reynir @hannesm)

* dns-stub: reconnect to resolver, resend all outstanding queries
  (#269 @hannesm)

### v5.0.1 (2021-04-22)

* dns-certify: adapt to X.509 0.13.0 API changes (#254 @hannesm)

### v5.0.0 (2021-04-14)

* IPv6 support for client and server (Mirage, Unix, Lwt) (#249 #252 @hannesm)
  This results in breaking changes, especially in the Mirage boilerplate,
  since now a Mirage_stack.V4V6 is needed instead of a Mirage_stack.V4.
* dns-certify: support EC private keys, now that X509 0.12.0 supports them
  (#252 @hannesm)

### v4.6.3 (2021-01-11)

* dns-server: wildcard support (#248 @hannesm)
* dns-certify: only dnskey needs to be a valid hostname (#247 @hannesm),
  allow [`raw] Domain_name.t in signing requests (#249 @hannesm)
* dns-client.resolvconf provides a parser for /etc/resolv.conf (#240 @hannesm),
  used in dns-client.unix and dns-client.lwt (#241 @hannesm)
* BUGFIX dns-cli notify keys are accepted in namekey_c (#242 @hannesm)
* BUGFIX dns: revise TXT resource record encoding and storage (for DKIM usage)
  previously RR were cut at 255 characters (fixes #244, #245 @hannesm)
* BUGFIX dns: decoding of TSIG packets (#250 @hannesm)
* BUGFIX ocertify: pem file may contain a certificate chain (#246 @hannesm)

### v4.6.2 (2020-08-07)

* fixes for 32 bit support (OCaml-CI now runs on 32 bit) in test suite and EDNS
* dns: fix EDNS flag decoding and encoding (16 bit only)
  reported in #234 by @dinosaure, fix #235 by @hannesm
* dns-server: reply to unsupported EDNS version (not 0) with
  rcode=16 (BadVersOrSig), as required by RFC 6891, and tested by DNS flag day
  issue #166, fix in #237 by @hannesm

### v4.6.1 (2020-06-20)

* dns-client.lwt, dns-client.unix: initialize RNG (#232 @hannesm)
* dns-cli: compatible with mirage-crypto-rng 0.8 (#232 @hannesm)

### v4.6.0 (2020-06-02)

* dns: bugfix for name compression when encoding names at offset > (2 ^ 14) - 1
  (#225 @hannesm)
* dns: allow unknown DNSKEY algorithm, TLSA certificate usage, selector,
  matching type, SSHFP algorithm and typ. This makes the DNS library
  future-proof for when new values are assigned (#228 @hannesm)
* dns: enforce a max_rdata_length for all resource records. This ensures that
  when a resource record is loaded into the server, it can be extracted via a
  DNS query and transferred via IXFR/AXFR
  (#230 @hannesm, reported in #229 via #225)
* AXFR: encode and decode support for AXFR transfers spanning multiple messages
  (#225 @hannesm)
* client: do not initialize the Mirage_crypto_rng in the library, initialize
  the RNG in applications (#227 @hannesm)
* certify: provide cert_matches_csr function and use it (cleans up partial
  ad-hoc matches which did not verify that all hostnames of the CSR are present
  in the certificate) (#226 @hannesm, reported in #224)

### v4.5.0 (2020-04-23)

* client: add timeout for DNS requests (defaults to 5 seconds, as in resolv.h).
* dns-client-mirage functor requires a Mirage_time.S implementation (changes API).
  Update your code as in this commit:
  https://github.com/roburio/unikernels/commit/201e980f458ebb515298392227294e7b508a1009
  #223 @linse @hannesm, review by @cfcs

### v4.4.1 (2020-03-29)

* client: treat '*.localhost' and '*.invalid' special, as specified in RFC 6761
  and let-localhost-be-localhost. #221 @hannesm, review by @cfcs (who reported
  #220, original report roburio/openvpn#28)

### v4.4.0 (2020-03-13)

* dns-stub, a new opam package, is a stub resolver #209 @hannesm, review by
  @cfcs
* embed IP address of recursive resolver only once #214 @hannesm, fixes #210,
  review by @cfcs
* Dns_trie.lookup returns NotAuthoritative if no SOA is present #217 @hannesm,
  review by @cfcs
* Secondary server is looked up in trie properly (may be in another zone, which
  primary is not authoritative for the other zone) #217 @hannesm, review by
  @cfcs
* new function Dns.Dnskey.pp_name_key #218 @hannesm, review by @cfcs
* dns-certify uses new ACME protocol (where the intermediate certificate is
  part of the issuance process) #219 @hannesm, review by @cfcs
* dns-certify/dns-tsig/dns-cli: use mirage-crypto #219 @hannesm, review by @cfcs

### v4.3.1 (2020-01-21)

* server (#207, @hannesm, review by @cfcs)
  - provide return code and request vs reply statistics
  - BUGFIX update only increase SOA.serial of zones which changed (including regression tests)
  - expose Authentication.access_granted, Authentication.zone_and_operation, Authentication.operation_to_string
* dns (#207, @hannesm, review by @cfcs)
  - expose Rcode.to_string for metrics above

### v4.3.0 (2020-01-09)

* dns
  - BUGFIX Name_rr_map.remove_sub remove empty maps (#205, @hannesm)
* server (#205, @hannesm)
  - authentication refactoring: given a key by its Domain_name.t (name._op.zone),
    this is valid for operation `op` for `zone` and subdomains thereof. The
    operation may be one of `update`, `transfer`, and `notify`, with an `update`
    key being valid for any operation, and a `transfer` key valid for
    notifications as well
  - Primary.create has a new optional argument `unauthenticated_zone_transfer`
    to allow unsigned zone transfer requests
  - the type `Authentication.a` and value `Authentication.tsig_auth` are removed
    - Primary.create and Secondary.create no longer have the `a` argument
  - authentication uniformly uses `Authentication.access`
  - handle_update / handle_axfr_request / handle_ixfr_request are provided and
    under test
  - tests for authentication and handle_question
* client (#204, @hannesm)
  - introduce get_resource_record which is the same as getaddrinfo, but returns
    the error as variant instead of [ `Msg of string ]
  - BUGFIX follow_cname handles replies with a cname and no data for the alias
    appropriately (and a regression test has been developed)

### v4.2.0 (2019-11-20)

* dns
  relax resource record parsing, don't require the name to be a hostname it
  used to be strict on the parser, but that violates RFC 2181 Sec 11
  > The DNS itself places only one restriction on the particular labels that can
  > be used to identify resource records.  That one restriction relates to the
  > length of the label and the full name.
  previous code had already exceptions for DNSKEY, TXT, CNAME, TLSA (service
  name or host name), SRV (service name) (#201 @hannesm)
* dns-certify
  BUGFIX provide signing_request to create certificate signing requests,
         now including all hostnames in subjectAlternativeName (previously, the
         common name was left out which is not what RFC 5280 recommends)
         (#198 @hannesm)
* dns-server.mirage
  - provide metrics (using the metrics library) of connections and actions (#199 @hannesm)
  - BREAKING the `on_update` callback passed to `primary` has more arguments (#200 @hannesm)
    `~authenticated_key` : [`raw] Domain_name.t option
    `~update_source` : Ipaddr.V4.t
* dns-server
  - BREAKING handle_buf: returns Domain_name.t of key used for authentication (#200 @hannesm)
  - BUGFIX handle_update: allow modification of multiple zones at once
           still, each name must be within the zone given in Query.name (which
           is authenticated against), allowing hidden let's encrypt secondary
           for multiple zones, using a keys authorized for the root zone (#200 @hannesm)
  - BUGFIX Dns_trie.zone returns the zone (Domain_name.t * Soa.t) of a
           provided Domain_name.t, it now works for non-existing names, tests
           were added (#200 @hannesm)
* dns-mirage: log packets on debug level instead of info (#198 @hannesm)

### v4.1.0 (2019-11-01)

* Client improvements (#191 #192 @olleolleolle @linse @cfcs @hannesm in marrakesh September)
 - new sublibrary dns.cache providing an LRU cache, mostly copied from resolver
 - it uses a LRU cache now (defaults to 32 entries) from dns.cache
   - since #195 a mutable LRU.M.t
 - tests were added
 - Dns_client_flow has been migrated to Dns_client
 - various code cleanups (extracted functions), better naming, improved docstrings
 - Uflow is now known as Transport
 - requires a monotonic clock on creation
* adapt to x509 0.8.0 API changes (#193 @hannesm)
* adapt to newer MirageOS interfaces (#196 @hannesm)

### v4.0.0 (2019-08-15)

* Switch to uDNS implementation, developed from scratch since 2017, primarily
  focusing on a recursive caching resolver. The server part supports dynamic
  updates (RFC 2135), transaction authentication with HMAC (RFC 2845), zone
  transfer (RFC 5936), incremental zone transfer (RFC 1995), change
  notifications (RFC 1996) amongst others.
* The core library uses a GADT for resource record sets, where the key (resource
  record type) specifies the value type.
* The API does not leak exceptions, but uses the result type where appropriate.
* TCP transport is well supported and used widely (client uses it by default)
* Naming: client is a DNS client, resolver is the recursive resolver library
* The DNS library is split into the following opam packages and sublibraries:
  - `dns` - the core library
  - `dns-tsig` - transaction signatures
  - `dns-cli` - command line utilities (odig, onotify, ..)
  - `dns-client` - pure client implementation
    - `.unix` - DNS client using the Unix module for communication
    - `.lwt` - DNS client using Lwt_unix for communication
    - `.mirage` - DNS client using MirageOS for communication
  - `dns-certify` - helpers for let's encrypt provisioning
    - `.mirage` - certificate provisioning with MirageOS
  - `dns-mirage` - generic MirageOS communication layer
  - `dns-server` - pure server implementation
    - `.mirage` - MirageOS primary and secondary server
    - `.zone` - zone file parser (mostly taken from the 1.x series)
  - `dns-resolver` - pure recursive resolver implementation
    - `.mirage` - MirageOS recursive resolver
* Only OCaml 4.07.0 and above are supported
* Multicast DNS has been dropped for now
* A client using async from JS has not been implemented yet
* The default recursive resolver, used by the client implementations, is
  uncensoreddns.org

### v1.1.3 (2019-07-16)

* Support domain-name.0.3.0 interface, which bumps the minimum
  OCaml version supported to 4.04 due to that dependency (@avsm)
* Fix tests with recent OCaml (use mmap/bigarray-compat) (@avsm)

### v1.1.2 (2019-02-28)

* Mirage: adapt to mirage-kv 2.0.0 interface (#156 by @samoht)

### v1.1.1 (2019-01-25)

* Support Base64.3.0.0 interface (@avsm)

### v1.1.0 (2019-01-05)

* Improve parsing robustness with:
  - invalid pointers in packets
  - taking total packet size limitations into account
  - handling unknown opcodes gracefully without an exception
  Work done by @Willy-Tan in #154.
* Port build from jbuilder to Dune (#155 #152 #153 by @paurkedal @samoht)
* Update opam metadata to the 2.0 format.

### v1.0.1 (2017-11-06)

* dns-lwt-unix: add missing dependency on cmdliner (#145 by @avsm)
* async: close reader and writer properly (#147 by @1yefuwang1)
* fix build with OCaml 4.06 (and -safe-string) (#148 by @djs55)

### v1.0.0 (2017-06-23)

Rearrange the `opam` packages to eliminate optional dependencies,
and have explicit and separate packages for the Lwt, Async and
Mirage implementations.  The `opam` and `ocamlfind` layouts now
have the same names:

- `dns`: the core package
- `dns-lwt`: Lwt implementation
- `dns-lwt-unix`: Lwt Unix, including servers
- `dns-async`: Async implementation (this currently uses Unix)

This layout is not compatible with the older releases which had
ocamlfind subpackages, so an upper bound will be needed in OPAM
for those. However, porting should be relatively straightforward
to the new release, and in return your users will not have to deal
with specifying a myriad of optional dependencies in OPAM.

- This release also ports the build to use Jbuilder, which speeds
  it up quite a bit and removes boilerplate files.

- Depend on Lwt 3.0.0 interfaces, including the blocking bind.

### v0.20.2 (2017-06-01)

* Depend explicitly on `Ipaddr_unix` and `Uri_services` modules.
* Add a basic server example which has a static lookup table and
  does not use the Trie structure.  It is in [examples/server.ml].

### v0.20.1 (2017-05-16)

* Port to lwt >= 3.0 (#136, @djs55)

### v0.20.0 (2017-03-23)

* Remove the `Dns.Buf` module that formerly wrapped Cstruct, now that the
  latter is a mature library.
* Add an `?alloc` optional argument to functions that would formerly accept
  a `Dns.Buf`.  By default, this allocates a single page, but consumers of
  this library can override it in order to supply their own allocation
  logic (e.g. a pool allocator).
* Remove dependency on `io-page` to follow the `Dns.Buf` removal.

All these changes were part of #132 by @hannesm.

### v0.19.1 (2017-02-15)

* Use topkg instead of oasis (#126
* Do not reverse the order of resource records in the parser (#109 by @djs55)
* Restrict to OCaml 4.03.0+.
* Fix bug parsing pointers to pointers to DNS name labels (#129 by @yeungda-rea)

### v0.19.0 (2017-01-20)

* Port to MirageOS 3 module types.
* Remove runtime dependency on PPX from META file
* Bugfixes and improvements for async backend compilation (#100 by @vbmithr).

### v0.18.1 (2016-04-17)

* Clear AA bit on requests, as some servers will drop these otherwise

### v0.18.0 (2016-03-12)

* Remove dependency on camlp4, switch to ppx

### v0.17.0 (2016-03-11)

* This library now depends on the `hashcons` package rather than
  containing a fork of it. Now that there is no LGPL (+ linking exception
  code left, clarify that the license is ISC. Previously the `opam`
  file claimed a mixture of licenses (#86 via @djs55)).
* Add multi-distro Travis testing support.
* Library now depends on OCaml 4.02+

### v0.16.0 (2015-10-21)

* Change source port randomization to avoid overflow in the port range
  (#83 from @yomimono).

Improve mDNS support (#82 from Luke Dunstan):

* Add `Dns.Probe` to implement the unique name probing portion of mDNS.
* Expose the `Dns.Name.Set` construct.
* Added a functor `Mdns_resolver_mirage.Chain` that is intended to compose
  an mDNS resolver with a normal DNS resolver such that `*.local` is resolved
  via mDNS and everything else is done with DNS.
* Changed `Dns.Query` to not respond to queries for classes other than IN.
* Fixed mDNS legacy responses to use TTL <= 10 sec
* Fixed mDNS responses to use RD=0.

### v0.15.3 (2015-07-30)

* Fix regression in 0.15.2 which prevented `Dns_server_unix.listen` from
  answering more than one query (#80 from Magnus Skjegstad)

### v0.15.2 (2015-07-04)

* Fix incorrect mirage dependency on tcpip
* Improve clarity and formatting of Lwt use
* Remove camlp4 dependency
* Now requires lwt >2.4.7

### v0.15.1 (2015-07-02)

* Fix critical DNS resolver timeout bug causing unexpected exceptions

### v0.15.0 (2015-05-14)

* Name.domain_name has been renamed to Name.t and is now abstract
* Name.domain_name_to_string has been renamed to Name.to_string
* Name.string_to_domain_name has been deprecated for Name.of_string
* Name.parse_name has been renamed to Name.parse
* Name.marshal_name has been renamed to Name.marshal
* Name.hashcons_charstring has been renamed to Name.hashcons_string
* Name.hashcons_domainname has been renamed to Name.hashcons
* Name.canon2key has been renamed to Name.to_key
* Name.for_reverse has been replaced by Name.of_ipaddr
* Name.of_ipaddr accepts a Ipaddr.t and produces a name suitable for reverse DNS
* We now require >= ipaddr.2.6.0 to support Name.of_ipaddr
* uri 1.7.0+ is now required for its uri.services service registry
* Named service lookups are now supported in zone files
* Dig string serializations are now in Dns.Dig (#61 from Heidi Howard

### v0.14.1 (2015-03-29)

* Reduce namespace pollution in `name.ml` to avoid breaking with Cstruct 1.6.0+.
* Add a `Dns_server.compose` function to make it easier to build
  resolution pipelines (#58).
* Add a `Dns_server_mirage` functor (#55).
* Add `Dns_resolver.resolve_pkt` to support custom query packets (#49).
* Split out the experimental Async_resolver into a `Async_kernel` and
  Unix libraries. This introduces the `dns.async-unix` library.

### v0.14.0 (2015-01-29)

* Renamed `Packet.QM` to `Packet.Q_Normal` and `QU` to `Q_mDNS_Unicast` for
  clarity and added more detailed doc comments. Added constructor function
  `Packet.make_question` for convenience. (#41
* Support `io-page` 1.3.0+ interface. (#40

### v0.13.0 (2015-01-26)

* Add support for multicast DNS (RFC6762) in the trie. (#35 from Luke Dunstan
* mDNS doesn't use SOA nor delegation (RFC 6762 section 12), so some minor changes
  to Trie are required to handle this.
* mDNS doesn't echo the questions in the response (RFC 6762 section 6), except
  in legacy mode, so a `bool` argument was added to `Query.response_of_answer`.
* `Query.answer` still exists but now `Query.answer_multiple` is also available
  for answering multiple questions in one query to produce a single answer
  (RFC 6762 section 5.3). One caveat is that responses may exceed the maximum
  message length, but that is not really specific to mDNS. Also, in
  theory multiple questions might require multiple separate response
  messages in unusual cases, but that is complicated and the library
  does not deal with that yet.
* `Query.answer_multiple` takes an optional function to allow the caller
  to control the `cache-flush` bit. This bit is only set for records
  that have been "confirmed as unique". Using a callback requires
  minimal changes here but puts the burden of maintaining uniqueness
  state elsewhere.
* `Query.answer_multiple` takes an optional function to filter the
  answer, in order to support "known answer suppression" (RFC 6762
  section 7.1). Again, using a callback requires minimal change to the
  core, but later on the mDNS-specific known answer suppression logic
  could move into the `Query` module if that turns out to be simpler.
* A query for `PTR` returns additional records for `SRV` and `TXT`, to
  support efficient service discovery.
* `Trie.iter` was added to support mDNS announcements.
* Switch to `Bytes` instead of `String` for eventual `-safe-string` support.
* Partially remove some error printing to stderr. (#36

Unit tests were added for some of the changes above, including a test-only
dependency on `pcap-format`.

### v0.12.0 (2014-12-24)

* Parse and marshal the mDNS unicast-response bit (#29).
* Add OUnit tests for `Dns.Packet.parse` using `pcap` files.
* Fix parsing of `SRV` records (#30).
* Use `Bytes` instead of `String` for mutable buffers.
* Switch to `Base64` v2, which uses `B64` as the toplevel module name
  to avoid linking conflicts with other community libraries.

### v0.11.0 (2014-11-02)

* Do not depend in Io_page; instead `Dns.Buf.create` now accepts an
  optional `alloc` parameter to use a custom allocator such as `Io_page`.
* Add Async DNS resolver modules from @marklrh (#22).
* Add a Dns_resolver_mirage.Static for a static DNS interface.

### v0.10.0 (2014-08-20)

* Add `Dns_resolver_mirage` module for making stub resolution requests
  using the Mirage module types.
* `Dns.Resolvconf` parses `/etc/resolv.conf` entries using `Ipaddr.t`
  instead of `string` values now.
* Adapt `Dns_resolver` and `Dns_resolver_unix` to use `Ipaddr.t` more.
* Improve `mldig` to use `Ipaddr` more and add more RR printing to
  match the conventional `dig` tool behaviour.
* Expose `Dns.Packet.Not_implemented` exception rather than a pattern
  match failure.
* Depend on external `Base64` package instead of bundling one inside
  the `Dns` packed module.
* Add a local `opam` file for easier pinning.
* Add an `examples/` directory with a DNS forwarder sample (#21).

### v0.9.1 (2014-07-29)

* Fix file descriptor leak in resolver (#15, #16) by expanding `commfn`
  with a cleanup function.

### v0.9.0 (2014-06-16)

* Ensure that all `Dns.Buf.t` buffers are page-aligned, via `Io_page`.
* Remove a Unix dependency that snuck into the `Dns_resolver` portable
  core, by adding a timeout argument to the `commfn` type.
* Improve ocamldoc in `Dns_resolver_unix`.

### v0.8.1 (2014-04-19)

* Add `process_of_zonebufs` to handle multiple zone files.
* Adapt `Dns_server_unix` to expose multiple zonebuf functions.

### v0.8.0 (2014-02-21)

* Use `Ipaddr.V6` to restore IPv6/AAAA RR support.
* `process_query` now takes an output buffer so it doesn't have to
  overwrite the input buffer it just parsed.
* Add Travis continuous integration scripts.
* Regenerate with OASIS 0.4.1
* Split the `dns.lwt` into a portable `dns.lwt-core` that doesn't
  require Unix (from which a Mirage version can be built).  The only
  change to existing applications is that Unix-specific functions
  have shifted into `Dns_resolver_unix` or `Dns_server_unix`, with
  the module types for `PROCESSOR` and `CLIENT` unchanged.

### v0.7.0 (2013-08-26)

* Add path argument to `Resolv_conf in Dns_resolver.config.
* `Dns_resolver.t` is now a record type rather than a first-class module.
* Fix `mldig` server and port options.
* Change `Zone.load_zone` to `Zone.load` and make it functional over `Loader.db`.
* Use `Ipaddr.V4.t` addresses in favor of Cstruct or Uri_IP representations.
* Fix `RRSIG` signed type to be of the answer rather than the question.
* Fix `ANY` queries.
* Add `Buf` to provide a nickname for `char Bigarray`s.
* Change `Packet.{parse,marshal}` to use Buf.t rather than exposing Cstruct.t
* Change `Packet.parse` to remove name map parameter
* Factor protocol modules into `Protocol` with default DNS implementations
* Add first-class `PROCESSOR` module to `Dns_server` for contextual
  protocol extensions
* Change `Dns_server.listen` to accept processor
* Rename `Dns_server.listen_with_zonebuf` and `Dns_server.listen_with_zonefile`
  to `Dns_server.serve_with_zonebuf` and `Dns_server.serve_with_zonefile` resp.
* Add `processor_of_process`, `process_of_zonebuf`,
  `eventual_process_of_zonefile`, and `serve_with_processor` to `Dns_server`
* Rename `Query.query_answer` to `Query.answer`
* Add `Query.response_of_answer` and `Query.answer_of_response`
* Move `Dns_resolver.build_query` to `Query.create`
* By default, DNS packet IDs are randomly generated with Random
* `Dns_resolver` now supports simultaneous resolver protocol requests
* Fix reversed multiple TXT parse bug
* Move DNSSEC implementation to <//github.com/dsheets/ocaml-dnssec>

### v0.6.2 (2013-02-13)

* Fix Lwt compilation after switch to `Dns.Names.Map` instead of `Hashtbl`.
* Fix Lwt Makefile detection (`Lwt.unix` instead of `Lwt.ssl`

### v0.6.1 (2013-02-12)

* Improve performance of packet marshalling.
* Add a Mirage `Dns_server` subpackage.

### v0.6.0 (2012-12-31)

* (Very) experimental DNSSEC support.
* Use cstruct-0.6.0 API.
* Improve robustness of `Dns_resolver`.
* Add EDNS0 support for larger packet sizes.

### v0.5.2 (2012-11-28)

* Fix the server interface to be fully asynchronous.
* Correct `q_type`/`q_class` arguments being ignored in the Lwt
  Dns_resolver (from Pierre Chambart).

### v0.5.1 (2012-10-05)

* Remain compatible with OCaml-3.12.1 with the more verbose
  first-class module syntax.

### v0.5.0 (2012-09-29)

* Add mldig as a full(ish)-featured dig clone, with similar
  output format.
* Add `Dns.Resolvconf` for parsing `/etc/resolv.conf` files on
  POSIX hosts.
* Move the Lwt bits (resolver, server, cmdline client) into
  a separate directory, to follow the Cohttp convention.

### v0.4.0 (2012-09-18)

* Initial public release.
