v1.1.1
------

* Support Base64.3.0.0 interface (@avsm)

v1.1.0 2019-01-05
-----------------

* Improve parsing robustness with:
  - invalid pointers in packets
  - taking total packet size limitations into account
  - handling unknown opcodes gracefully without an exception
  Work done by @Willy-Tan in #154.
* Port build from jbuilder to Dune (#155 #152 #153 by @paurkedal @samoht)
* Update opam metadata to the 2.0 format.

v1.0.1 2017-11-06
-----------------

* dns-lwt-unix: add missing dependency on cmdliner (#145 by @avsm)
* async: close reader and writer properly (#147 by @1yefuwang1)
* fix build with OCaml 4.06 (and -safe-string) (#148 by @djs55)

v1.0.0 2017-06-23
-----------------

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

v0.20.2 2017-06-01
------------------

* Depend explicitly on `Ipaddr_unix` and `Uri_services` modules.
* Add a basic server example which has a static lookup table and
  does not use the Trie structure.  It is in [examples/server.ml].

v0.20.1 2017-05-16
------------------

* Port to lwt >= 3.0 (#136, @djs55)

v0.20.0 2017-03-23
------------------

* Remove the `Dns.Buf` module that formerly wrapped Cstruct, now that the
  latter is a mature library.
* Add an `?alloc` optional argument to functions that would formerly accept
  a `Dns.Buf`.  By default, this allocates a single page, but consumers of
  this library can override it in order to supply their own allocation
  logic (e.g. a pool allocator).
* Remove dependency on `io-page` to follow the `Dns.Buf` removal.

All these changes were part of #132 by @hannesm.

v0.19.1 2017-02-15
------------------

* Use topkg instead of oasis (#126
* Do not reverse the order of resource records in the parser (#109
* Restrict to OCaml 4.03.0+.
* Fix bug parsing pointers to pointers to DNS name labels (#129

v0.19.0 2017-01-20
------------------

* Port to MirageOS 3 module types.
* Remove runtime dependency on PPX from META file
* Bugfixes and improvements for async backend compilation (#100 by @vbmithr).

v0.18.1 2016-04-17
------------------

* Clear AA bit on requests, as some servers will drop these otherwise

v0.18.0 2016-03-12
------------------

* Remove dependency on camlp4, switch to ppx

v0.17.0 2016-03-11
------------------

* This library now depends on the `hashcons` package rather than
  containing a fork of it. Now that there is no LGPL (+ linking exception
  code left, clarify that the license is ISC. Previously the `opam`
  file claimed a mixture of licenses (#86 via @djs55).
* Add multi-distro Travis testing support.
* Library now depends on OCaml 4.02+

v0.16.0 2015-10-21
------------------

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

v0.15.3 2015-07-30
------------------

* Fix regression in 0.15.2 which prevented `Dns_server_unix.listen` from
  answering more than one query (#80 from Magnus Skjegstad)

v0.15.2 2015-07-04
------------------

* Fix incorrect mirage dependency on tcpip
* Improve clarity and formatting of Lwt use
* Remove camlp4 dependency
* Now requires lwt >2.4.7

v0.15.1 2015-07-02
------------------

* Fix critical DNS resolver timeout bug causing unexpected exceptions

v0.15.0 2015-05-14
------------------

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

v0.14.1 2015-03-29
------------------

* Reduce namespace pollution in `name.ml` to avoid breaking with Cstruct 1.6.0+.
* Add a `Dns_server.compose` function to make it easier to build
  resolution pipelines (#58).
* Add a `Dns_server_mirage` functor (#55).
* Add `Dns_resolver.resolve_pkt` to support custom query packets (#49).
* Split out the experimental Async_resolver into a `Async_kernel` and
  Unix libraries. This introduces the `dns.async-unix` library.

v0.14.0 2015-01-29
------------------

* Renamed `Packet.QM` to `Packet.Q_Normal` and `QU` to `Q_mDNS_Unicast` for
  clarity and added more detailed doc comments. Added constructor function
  `Packet.make_question` for convenience. (#41
* Support `io-page` 1.3.0+ interface. (#40

v0.13.0 2015-01-26
------------------

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

v0.12.0 2014-12-24
------------------

* Parse and marshal the mDNS unicast-response bit (#29).
* Add OUnit tests for `Dns.Packet.parse` using `pcap` files.
* Fix parsing of `SRV` records (#30).
* Use `Bytes` instead of `String` for mutable buffers.
* Switch to `Base64` v2, which uses `B64` as the toplevel module name
  to avoid linking conflicts with other community libraries.

v0.11.0 2014-11-02
------------------

* Do not depend in Io_page; instead `Dns.Buf.create` now accepts an
  optional `alloc` parameter to use a custom allocator such as `Io_page`.
* Add Async DNS resolver modules from @marklrh (#22).
* Add a Dns_resolver_mirage.Static for a static DNS interface.

v0.10.0 2014-08-20
------------------

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

v0.9.1 2014-07-29
------------------

* Fix file descriptor leak in resolver (#15, #16) by expanding `commfn`
  with a cleanup function.

v0.9.0 2014-06-16
------------------

* Ensure that all `Dns.Buf.t` buffers are page-aligned, via `Io_page`.
* Remove a Unix dependency that snuck into the `Dns_resolver` portable
  core, by adding a timeout argument to the `commfn` type.
* Improve ocamldoc in `Dns_resolver_unix`.

v0.8.1 2014-04-19
------------------

* Add `process_of_zonebufs` to handle multiple zone files.
* Adapt `Dns_server_unix` to expose multiple zonebuf functions.

v0.8.0 2014-02-21
------------------

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

v0.7.0 2013-08-26
------------------

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

v0.6.2 2013-02-13
------------------

* Fix Lwt compilation after switch to `Dns.Names.Map` instead of `Hashtbl`.
* Fix Lwt Makefile detection (`Lwt.unix` instead of `Lwt.ssl`

v0.6.1 2013-02-12
------------------

* Improve performance of packet marshalling.
* Add a Mirage `Dns_server` subpackage.

v0.6.0 2012-12-31
------------------

* (Very) experimental DNSSEC support.
* Use cstruct-0.6.0 API.
* Improve robustness of `Dns_resolver`.
* Add EDNS0 support for larger packet sizes.

v0.5.2 2012-11-28
------------------

* Fix the server interface to be fully asynchronous.
* Correct `q_type`/`q_class` arguments being ignored in the Lwt
  Dns_resolver (from Pierre Chambart).

v0.5.1 2012-10-05
------------------

* Remain compatible with OCaml-3.12.1 with the more verbose
  first-class module syntax.

v0.5.0 2012-09-29
------------------

* Add mldig as a full(ish)-featured dig clone, with similar
  output format.
* Add `Dns.Resolvconf` for parsing `/etc/resolv.conf` files on
  POSIX hosts.
* Move the Lwt bits (resolver, server, cmdline client) into
  a separate directory, to follow the Cohttp convention.

v0.4.0 2012-09-18
------------------

* Initial public release.
