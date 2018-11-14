(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (R : RANDOM) (P : PCLOCK) (T : TIME) (S : STACKV4) : sig

  val retrieve_certificate :
    ?ca:[ `Production | `Staging ] ->
    S.t -> P.t -> dns_key:string -> hostname:Domain_name.t ->
    ?additional_hostnames:Domain_name.t list -> ?key_seed:string -> S.TCPV4.ipaddr ->
    int -> Tls.Config.own_cert Lwt.t
end
