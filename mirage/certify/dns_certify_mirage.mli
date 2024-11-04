(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
module Make (R : Mirage_crypto_rng_mirage.S) (P : Mirage_clock.PCLOCK) (T : Mirage_time.S) (S : Tcpip.Stack.V4V6) : sig

  val retrieve_certificate :
    S.t -> ([`raw ] Domain_name.t * Dns.Dnskey.t) ->
    hostname:[ `host ] Domain_name.t ->
    ?additional_hostnames:[ `raw ] Domain_name.t list ->
    ?key_type:X509.Key_type.t -> ?key_data:string -> ?key_seed:string ->
    ?bits:int -> S.TCP.ipaddr -> int ->
    (X509.Certificate.t list * X509.Private_key.t, [ `Msg of string ]) result Lwt.t
  (** [retrieve_certificate stack dns_key ~hostname ~key_type ~key_data ~key_seed ~bits server_ip port]
      generates a private key (using [key_type], [key_data], [key_seed], and
      [bits]), a certificate signing request for the given [hostname] and
      [additional_hostnames], and sends [server_ip] an nsupdate (DNS-TSIG with
      [dns_key]) with the csr as TLSA record, awaiting for a matching
      certificate as TLSA record. Requires a service that interacts with let's
      encrypt to transform the CSR into a signed certificate. If something
      fails, an exception (via [Lwt.fail]) is raised. This is meant for
      unikernels that require a valid TLS certificate before they can start
      their service (i.e. most web servers, mail servers). *)
end
