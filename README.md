This is a pure OCaml implementation of the DNS protocol.  It is intended to be
a reasonably high-performance implementation, but clarity is preferred rather
than low-level performance hacks.

To build it, the following packages are required:

* OCaml 3.12.0 or higher.
* Lwt 2.3.2 or higher: http://ocsigen.org/lwt/
* Bitstring 2.0.3 or higher: http://code.google.com/p/bitstring/
  If you are on MacOS X, then you will need to apply a small source code
  patch to fix the configure script.
  See http://code.google.com/p/bitstring/issues/detail?id=6
* Uri: http://github.com/avsm/ocaml-uri
  This is not packaged up officially yet, so just grab the Github trunk.
* Re: http://github.com/avsm/ocaml-re
  This is not packaged up officially yet, so just grab the Github trunk.
* Extlib: http://github.com/mor1/ocaml-extlib
  This is not packaged up officially yet, so just grab the Github trunk.

Packages:

* `lib/` contains the core DNS protocol, which is packed into the `Dns` module.
* `lib_test/` contains unit tests and sample uses of the library.
  In particular, `time_server` is a simple dynamic responder.
* `server/` contains an Lwt-based server library that can act as an
  authoritative server.
* `client/` contains the beginnings of a `dig`-like client.

Areas that need work:

* We need a Lwt-based client resolver, preferably both recursive
  and iterative. Patches for this are highly welcome!
* EDNS0 extensions.
* DNSSEC extensions (using Cryptokit).
