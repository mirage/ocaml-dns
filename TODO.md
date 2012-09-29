Before a 1.0 release, we need:

* Swap the lib/packet.mli signatures with cenum declarations, now that
  cstruct supports signature generation (since 0.5.0+).
* Need resolver lib_tests.
* Parameterise on Lwt/Mirage/Async by functorising lib/
* Bitstring vs cstruct vs OS gethostbyname performance tests.
* Test cases for odd compression: forward refs, back refs, infinite cycles
