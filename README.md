This is a pure OCaml implementation of the DNS protocol.  It is intended to be
a reasonably high-performance implementation, but clarity is preferred rather
than low-level performance hacks.

To build it, the following packages are required:

* OCaml 4.00.1 or higher.
* Lwt 2.3.2 or higher: http://ocsigen.org/lwt/
* Cstruct: http://github.com/mirage/ocaml-cstruct
* Re: http://github.com/mirage/ocaml-re

Packages:

* `lib/` contains the core DNS protocol, which is packed into the `Dns` module.
* `lib_test/` contains unit tests and sample uses of the library.
  In particular, `time_server` is a simple dynamic responder.

Areas that need work:

* We need a Lwt-based client resolver, preferably both recursive
  and iterative. Patches for this are highly welcome!
* EDNS0 extensions.
* DNSSEC extensions (using Cryptokit).
