Before a 1.0 release, we need:

* Need resolver lib_tests.
* Parameterise on Lwt/Mirage/Async by functorising lib/
* Bitstring vs cstruct vs OS gethostbyname performance tests.
* Test cases for odd compression: forward refs, back refs, infinite cycles
