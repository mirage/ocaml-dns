(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)
module Make (R : Mirage_random.S) (P : Mirage_clock.PCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4V6) : sig

  val retrieve_certificate :
    S.t -> dns_key:string -> hostname:[ `host ] Domain_name.t ->
    ?additional_hostnames:[ `host ] Domain_name.t list -> ?key_seed:string ->
    S.TCP.ipaddr -> int -> (Tls.Config.own_cert, [ `Msg of string ]) result Lwt.t
  (** [retrieve_certificate stack ~dns_key ~hostname ~key_seed server_ip port]
     generates a RSA private key (using the [key_seed]), a certificate
     signing request for the given [hostname] and [additional_hostnames], and
     sends [server_ip] an nsupdate (DNS-TSIG with [dns_key]) with the csr as
     TLSA record, awaiting for a matching certificate as TLSA record. Requires a
     service that interacts with let's encrypt to transform the CSR into a
     signed certificate. If something fails, an exception (via [Lwt.fail]) is
     raised. This is meant for unikernels that require a valid TLS certificate
     before they can start their service (i.e. most web servers, mail
     servers). *)
end
