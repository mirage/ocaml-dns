[![Build Status](https://travis-ci.org/mirage/ocaml-dns.svg?branch=master)](https://travis-ci.org/mirage/ocaml-dns)

This is a pure OCaml implementation of the DNS protocol.  It is intended to be
a reasonably high-performance implementation, but clarity is preferred rather
than low-level performance hacks.

To build it, please use the [OPAM](https://opam.ocaml.org) package manager (1.2+):

    opam pin add dns .

This will install the dependencies needed and give you a working development
version of the library.

Packages:

* `lib/` contains the core DNS protocol, which is packed into the `Dns` module.
* `lib_test/` contains unit tests and sample uses of the library.
  In particular, `time_server` is a simple dynamic responder.

Areas that need work:

* We need a Lwt-based client resolver, preferably both recursive
  and iterative. Patches for this are highly welcome!
* EDNS0 extensions.
* DNSSEC extensions (using Cryptokit).
