# µDNS - an opinionated Domain Name System (DNS) library

[![Build Status](https://travis-ci.org/roburio/udns.svg?branch=master)](https://travis-ci.org/roburio/udns)

(c) 2017,2018 Hannes Mehnert (robur.io, Center for the Cultivation of Technology)

%%VERSION%%

µDNS supports most of the domain name system used in the wild.  It adheres to
strict conventions.  Failing early and hard.  It is mostly implemented in the
pure fragment of OCaml (no mutation, isolated IO, no exceptions).

It all started out as an experiment to run a recursive resolver, but after
initial prototypes it turned out that every configurable recursive resolver
needs a fully-fledged authoritative nameserver as well (for overriding various
zones such as `.localhost` and reverse lookups of RFC 1918 IP ranges).

Legacy resource record types are not dealt with, and there is no plan to support
`ISDN`, `MAILA`, `MAILB`, `WKS`, `MB`, `NULL`, `HINFO`, ... .  `AXFR` is only
handled via TCP connections.  The only resource class supported is `IN` (the
Internet).  In a similar vein, wildcard records are _not_ supported, and it is
unlikely they'll ever be in this library.  Truncated hmac in `TSIG` are not
supported (always the full length of the hash algorithm is used).

Please read [the blog article](https://hannes.nqsb.io/Posts/DNS) for a more
detailed overview.

## Supported RFCs

* [RFC 1034](https://tools.ietf.org/html/rfc1034) Domain Names - Concepts and Facilities
* [RFC 1035](https://tools.ietf.org/html/rfc1035) Domain Names - Implementation and Specification
* [RFC 1912](https://tools.ietf.org/html/rfc1912) Common DNS Operational and Configuration Errors
* [RFC 1996](https://tools.ietf.org/html/rfc1996) A Mechanism for Prompt Notification of Zone Changes (DNS NOTIFY)
* [RFC 2136](https://tools.ietf.org/html/rfc2136) Dynamic Updates in the domain name system (DNS UPDATE)
* [RFC 2181](https://tools.ietf.org/html/rfc2181) Clarifications to the DNS Specification
* [RFC 2308](https://tools.ietf.org/html/rfc2308) Negative Caching of DNS Queries (DNS NCACHE)
* [RFC 2782](https://tools.ietf.org/html/rfc2782) A DNS RR for specifying the location of services (DNS SRV)
* [RFC 2845](https://tools.ietf.org/html/rfc2845) Secret Key Transaction Authentication for DNS (TSIG)
* [RFC 3596](https://tools.ietf.org/html/rfc3596) DNS Extensions to Support IP Version 6
* `*` [RFC 4034](https://tools.ietf.org/html/rfc4034) Resource Records for the DNS Security Extensions
* [RFC 4343](https://tools.ietf.org/html/rfc4343) Domain Name System (DNS) Case Insensitivity Clarification
* [RFC 4635](https://tools.ietf.org/html/rfc4635) HMAC SHA TSIG Algorithm Identifiers
* `*` [RFC 5001](https://tools.ietf.org/html/rfc5001) DNS Name Server Identifier (NSID) Option
* [RFC 5358](https://tools.ietf.org/html/rfc5358) Preventing Use of Recursive Nameservers in Reflector Attacks
* [RFC 5452](https://tools.ietf.org/html/rfc5452) Measures for Making DNS More Resilient against Forged Answers
* [RFC 5936](https://tools.ietf.org/html/rfc5936) DNS Zone Transfer Protocol (AXFR)
* [RFC 6761](https://tools.ietf.org/html/rfc6761) Special-Use Domain Names
* `*` [RFC 6762](https://tools.ietf.org/html/rfc6762) Multicast DNS
* [RFC 6844](https://tools.ietf.org/html/rfc6844) DNS Certification Authority Authorization (CAA) Resource Record
* [RFC 6890](https://tools.ietf.org/html/rfc6890) Special-Purpose IP Address Registries
* [RFC 6891](https://tools.ietf.org/html/rfc6891) Extension Mechanisms for DNS (EDNS(0))
* [RFC 6895](https://tools.ietf.org/html/rfc6895) Domain Name System (DNS) IANA Considerations (BCP 42)
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

You first need to install [OCaml](https://ocaml.org) (at least 4.04.0) and
[opam](https://opam.ocaml.org), the OCaml package manager (at least 1.2.2) on
your machine (you can use opam to install an up-to-date OCaml (`opam switch
4.06.0`)).  You may want to follow the [mirage installation
instructions](https://mirage.io/wiki/install) to get `mirage` installed on your
computer.

µDNS is not released yet, but you can install it and its dependencies via opam:
`opam pin add udns https://github.com/roburio/udns.git`

Now the µDNS library is installed, and you can try out the examples.  For this,
you need to clone this git repository (`git clone
https://github.com/roburio/udns.git`) and try the provided examples
(located in `mirage/examples`):
- `primary` - a primary nameserver with its zone embedded in OCaml code
- `primary-with-zone` - a primary nameserver where the zone is embedded as a zonefile
- `secondary` - a secondary nameserver
- `resolver` - a recursive resolver
- `stub` - a stub resolver (with 141.1.1.1 preconfigured)

In either of the directories, run `mirage configure` (see `mirage help
configure` for options), followed by `make depend` and `make` (read more
information [Hello MirageOS world](https://mirage.io/wiki/hello-world)).

Depending on the target, the name and type of the resulting binary varies. In
the default target, `unix`, its name is `./main.native`, and which requires
superuser privileges to listen on port 53 (e.g. `doas ./main.native -l
\*:debug`).

## Documentation

Is unfortunately only in the code at the moment.
