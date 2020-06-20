(** [Unix] helper module for {!Dns_client}.
    For more information see the {!Dns_client.Make} functor.

    It initializes the RNG (using Mirage_crypto_rng_unix.initialize ()).
*)


(** A flow module based on blocking I/O on top of the Unix socket API.

    TODO: Implement the connect timeout.
*)
module Transport : Dns_client.S
  with type io_addr = Unix.inet_addr * int
   and type stack = unit
   and type +'a io = 'a

include module type of Dns_client.Make(Transport)
