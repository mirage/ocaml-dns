# ocaml-dns - a Domain Name System (DNS) library

[![Build Status](https://travis-ci.org/mirage/ocaml-dns.svg?branch=master)](https://travis-ci.org/roburio/udns)

(c) 2017-2019 Hannes Mehnert (robur.io, Center for the Cultivation of Technology)

%%VERSION%%

This library supports most of the domain name system used in the wild.  It
adheres to strict conventions.  Failing early and hard.  It is mostly
implemented in the pure fragment of OCaml (no mutation, isolated IO, no
exceptions).

It all started out as an experiment to run a recursive resolver, but after
initial prototypes it turned out that every configurable recursive resolver
needs a fully-fledged authoritative nameserver as well (for overriding various
zones such as `.localhost` and reverse lookups of RFC 1918 IP ranges).

Legacy resource record types are not dealt with, and there is no plan to support
`ISDN`, `MAILA`, `MAILB`, `WKS`, `MB`, `NULL`, `HINFO`, ... .  `AXFR`, `IXFR`,
and `UPDATE` is only handled via TCP connections.  The only resource class
supported is `IN` (the Internet).  In a similar vein, wildcard records are _not_
supported, and it is unlikely they'll ever be in this library.  Truncated hmac
in `TSIG` are not supported (always the full length of the hash algorithm is
used).

Please read [the blog article](https://hannes.nqsb.io/Posts/DNS) for a more
detailed overview.

This library is published under the 2 clause BSD license.

## Supported RFCs

* [RFC 1034](https://tools.ietf.org/html/rfc1034) Domain Names - Concepts and Facilities
* [RFC 1035](https://tools.ietf.org/html/rfc1035) Domain Names - Implementation and Specification
* [RFC 1912](https://tools.ietf.org/html/rfc1912) Common DNS Operational and Configuration Errors
* [RFC 1995](https://tools.ietf.org/html/rfc1995) Incremental Zone Transfer in DNS
* [RFC 1996](https://tools.ietf.org/html/rfc1996) A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
* [RFC 2136](https://tools.ietf.org/html/rfc2136) Dynamic Updates in the domain name system (DNS UPDATE)
* [RFC 2181](https://tools.ietf.org/html/rfc2181) Clarifications to the DNS Specification
* [RFC 2308](https://tools.ietf.org/html/rfc2308) Negative Caching of DNS Queries (DNS NCACHE)
* [RFC 2782](https://tools.ietf.org/html/rfc2782) A DNS RR for specifying the location of services (DNS SRV)
* [RFC 2845](https://tools.ietf.org/html/rfc2845) Secret Key Transaction Authentication for DNS (TSIG)
* [RFC 3596](https://tools.ietf.org/html/rfc3596) DNS Extensions to Support IP Version 6
* [RFC 4034](https://tools.ietf.org/html/rfc4034) Resource Records for the DNS Security Extensions
* [RFC 4255](https://tools.ietf.org/html/rfc4255) Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
* [RFC 4343](https://tools.ietf.org/html/rfc4343) Domain Name System (DNS) Case Insensitivity Clarification
* [RFC 4635](https://tools.ietf.org/html/rfc4635) HMAC SHA TSIG Algorithm Identifiers
* `*` [RFC 5001](https://tools.ietf.org/html/rfc5001) DNS Name Server Identifier (NSID) Option
* [RFC 5358](https://tools.ietf.org/html/rfc5358) Preventing Use of Recursive Nameservers in Reflector Attacks
* [RFC 5452](https://tools.ietf.org/html/rfc5452) Measures for Making DNS More Resilient against Forged Answers
* [RFC 5936](https://tools.ietf.org/html/rfc5936) DNS Zone Transfer Protocol (AXFR)
* [RFC 6594](https://tools.ietf.org/html/rfc6594) Use of the SHA-256 Algorithm with RSA, Digital Signature Algorithm (DSA), and Elliptic Curve DSA (ECDSA) in SSHFP Resource Records
* [RFC 6698](https://tools.ietf.org/html/rfc6698.html) The DNS-Based Authentication of Named Entities (DANE) Transport Layer Security (TLS) Protocol: TLSA
* [RFC 6761](https://tools.ietf.org/html/rfc6761) Special-Use Domain Names
* `*` [RFC 6762](https://tools.ietf.org/html/rfc6762) Multicast DNS
* [RFC 6844](https://tools.ietf.org/html/rfc6844) DNS Certification Authority Authorization (CAA) Resource Record
* [RFC 6890](https://tools.ietf.org/html/rfc6890) Special-Purpose IP Address Registries
* [RFC 6891](https://tools.ietf.org/html/rfc6891) Extension Mechanisms for DNS (EDNS(0))
* [RFC 6895](https://tools.ietf.org/html/rfc6895) Domain Name System (DNS) IANA Considerations (BCP 42)
* [RFC 7479](https://tools.ietf.org/html/rfc7479) Using Ed25519 in SSHFP Resource Records
* [RFC 7626](https://tools.ietf.org/html/rfc7626) DNS Privacy Considerations
* [RFC 7766](https://tools.ietf.org/html/rfc7766) DNS Transport over TCP - Implementation Requirements
* [RFC 7816](https://tools.ietf.org/html/rfc7816) DNS Query Name Minimisation to Improve Privacy
* `*` [RFC 7828](https://tools.ietf.org/html/rfc7828) The edns-tcp-keepalive EDNS0 Option
* `*` [RFC 7830](https://tools.ietf.org/html/rfc7830) The EDNS(0) Padding Option
* `*` [RFC 7873](https://tools.ietf.org/html/rfc7873) Domain Name System (DNS) Cookies
* [RFC 8109](https://tools.ietf.org/html/rfc8109) Initializing a DNS Resolver with Priming Queries
* [draft-ietf-dnsop-let-localhost-be-localhost-02](https://tools.ietf.org/html/draft-ietf-dnsop-let-localhost-be-localhost-02) Let 'localhost' be localhost.

`*`: Please note that the RFCs marked with `*` are only partially implemented
(i.e. only wire format, but no logic handling the feature).

## Installation

You first need to install [OCaml](https://ocaml.org) (at least 4.07.0) and
[opam](https://opam.ocaml.org), the OCaml package manager (at least 2.0.0) on
your machine (you can use opam to install an up-to-date OCaml (`opam switch
4.07.1`)).

You may want to follow the [mirage installation
instructions](https://mirage.io/wiki/install) to get `mirage` installed on your
computer.

To lower the amount of run-time dependencies for each individual functionality,
the library is split across a number of opam packages.

µDNS is not released yet, but you can install it and its dependencies via opam,
see [Development](#Development).

Now the µDNS library is installed, and you can try out the examples.  Find some
examples at the [unikernel repository](https://github.com/roburio/unikernels).

## Documentation

API documentation [is available online](https://mirage.github.io/ocaml-dns/).

## Transition from older versions

The pre-2.0.0 versions of ocaml-dns had a significantly different interface,
and so applications using them will need to be rewritten to follow the
stricter coding style used in the post-2.0.0 branches.  The major improvements
from 1.x to the 2.x series are:

- data (rrset) is defined in a single GADT in `Rr_map`
- add support for: notify, dynamic update, zone transfer, tsig (hmac authentication), edns
- no mutable datastructures to make reasoning about library state easier
- switches to an independent `domain_name` library which uses a faster and more
  compact `string array` instead of `string list` for storing domain names
- integration with LetsEncrypt for provisioning valid X.509 certificates
- more strict hostname validation
- no use of exceptions, instead preferring explicit result values from API functions

Please get in touch on <mirageos-devel@lists.xenproject.org> or on the Discuss forum
at <https://discuss.ocaml.org> (with the `mirageos` tag) if you have any questions
about migrating (or just general questions).

## Development

To work with the [opam](https://opam.ocaml.org/) packages provided when
developing modifications to DNS, or when pinning a specific version,
you will have to pin the same *version* for all of them:

```csh
: csh syntax
set version=2.0.0
set repo=git+https://github.com/mirage/ocaml-dns.git

# the -y parameter means "force" or
# "do go ahead and register a new package"

# the -n parameter means
# "just register the pin, don't actually install it yet"

foreach pkg ( dns dns-{certify,cli,client{,-lwt,-unix}} \
              dns-mirage{,-certify,-client,-resolver,-server} \
              dns-{resolver,server,tsig,zone} )
  opam pin add -y -n $pkg.$version --dev $repo
end
```

```bash
: bash syntax
version=2.0.0
repo=git+https://github.com/mirage/ocaml-dns.git

for pkg in dns dns-{certify,cli,client{,-lwt,-unix}} \
           dns-mirage{,-certify,-client,-resolver,-server} \
           dns-{resolver,server,tsig,zone}
do
  opam pin add -y -n $pkg.$version --dev $repo
done
```

Now you can install the packages you need, for instance:
```shell
opam install dns-client-lwt
```
or
```shell
opam install dns-resolver
```
