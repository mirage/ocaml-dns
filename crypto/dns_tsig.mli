(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

val compute_tsig : Domain_name.t -> Dns_packet.tsig -> key:Cstruct.t ->
  Cstruct.t -> Cstruct.t

val sign : Dns_packet.tsig_sign

val verify : Dns_packet.tsig_verify

val encode_and_sign : ?proto:Dns_packet.proto -> Dns_packet.header ->
  Dns_packet.v -> Ptime.t -> Dns_packet.dnskey -> Domain_name.t ->
  (Cstruct.t * Cstruct.t, string) result

val decode_and_verify : Ptime.t -> Dns_packet.dnskey -> Domain_name.t ->
  ?mac:Cstruct.t -> Cstruct.t ->
  (Dns_packet.t * Cstruct.t, string) result
