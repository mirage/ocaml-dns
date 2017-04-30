# udns - an opinionated Domain Name System (DNS) library

(c) 2017,2018 Hannes Mehnert (Centre for the Cultivation of Technology), all rights reserved

%%VERSION%%

µDNS supports most of the domain name system used in the wild.  It adheres to
strict conventions.  Failing early and hard.  It is mostly implemented in the
pure fragment of OCaml (no mutation, isolated IO, no exceptions).

It all started out as an experiment to run a recursive resolver, but after
initial prototypes it turned out that every configurable recursive resolver
needs a fully-fledged authoritative nameserver as well (for overriding various
zones such as `.localhost` and reverse lookups of RFC 1918 IP ranges).

Legacy resource record types are not dealt with, and there is no plan to support
`ISDN`, `MAILA`, `MAILB`, `WKS`, `MB`, `NULL`, `HINFO`, ... .  `ANY` and `AXFR`
are only handled via a TCP connection.  The only resource class supported is
`IN` (the Internet).  In a similar vein, wildcard records are _not_ supported,
and it is unlikely they'll ever be in this library.  Truncated hmac in `TSIG`
are not supported (always full length of the hash algorithm).  `EDNS` is not yet
supported (but planned).  The resolver code is not yet ready (and disconnected
from the build system).

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
* [RFC 4343](https://tools.ietf.org/html/rfc4343) Domain Name System (DNS) Case Insensitivity Clarification
* [RFC 4398](https://tools.ietf.org/html/rfc4398) Storing Certificates in the Domain Name System (DNS)
* [RFC 4635](https://tools.ietf.org/html/rfc4635) HMAC SHA TSIG Algorithm Identifiers
* [RFC 5358](https://tools.ietf.org/html/rfc5358) Preventing Use of Recursive Nameservers in Reflector Attacks
* [RFC 5452](https://tools.ietf.org/html/rfc5452) Measures for Making DNS More Resilient against Forged Answers
* [RFC 5936](https://tools.ietf.org/html/rfc5936) DNS Zone Transfer Protocol (AXFR)
* [RFC 6844](https://tools.ietf.org/html/rfc6844) DNS Certification Authority Authorization (CAA) Resource Record
* [RFC 6895](https://tools.ietf.org/html/rfc6895) Domain Name System (DNS) IANA Considerations (BCP 42)
* [RFC 7626](https://tools.ietf.org/html/rfc7626) DNS Privacy Considerations
* [RFC 7766](https://tools.ietf.org/html/rfc7766) DNS Transport over TCP - Implementation Requirements

## Installation

For now, you have to manually `pin` this library, since this library is not yet
released:

`opam pin add udns https://github.com/roburio/udns.git`

There are three examples in this repository (see the `mirage/examples` directory):
- a primary nameserver with its zone embedded in OCaml code
- a primary nameserver where the zone is parsed at startup from a zonefile
- a secondary nameserver

## Documentation

Is unfortunately only in the code at the moment.
