(** {!Lwt_unix} helper module for {!Dns_client}.
    For more information see the {!Dns_client.Make} functor.

    The {!Dns_client} is available as Dns_client_lwt after
    linking to dns-client.lwt in your dune file.

    It initializes the RNG (using Mirage_crypto_rng_lwt.initialize ()).
*)


(** A flow module based on non-blocking I/O on top of the
    Lwt_unix socket API. *)
module Transport : Dns_client.S
   with type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
   and type +'a io = 'a Lwt.t
   and type stack = Happy_eyeballs_lwt.t

include module type of Dns_client.Make(Transport)
