(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (R : RANDOM) (P : PCLOCK) (T : TIME) (S : STACKV4) : sig

  val retrieve_certificate :
    S.t -> P.t -> dns_key:string -> hostname:string -> key_seed:string ->
    S.TCPV4.ipaddr -> int ->
    Tls.Config.own_cert Lwt.t
end
