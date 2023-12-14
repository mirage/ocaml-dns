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

val create_happy_eyeballs :
  ?cache_size:int ->
  ?edns:[ `None | `Auto | `Manual of Dns.Edns.t ] ->
  ?nameservers:(Dns.proto * Transport.io_addr list) ->
  ?timeout:int64 ->
  Happy_eyeballs_lwt.t ->
  t * Happy_eyeballs_lwt.t
(** [create_happy_eyeballs he] returns and inject the [ocaml-dns] implementation
    into the given happy-eyeballs instance. By default, an happy-eyeballs
    instance use the system DNS resolver (via {!val:Unix.getaddrinfo}). However,
    the user is able to use the [ocaml-dns] implementation to resolve
    domain-name. By this way, when the user wants to connect to a domain-name,
    the happy-eyeballs instance will use the {!val:getaddrinfo} provided above. *)
