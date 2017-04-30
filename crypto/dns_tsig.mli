(* (c) 2017 Hannes Mehnert, all rights reserved *)

val compute_tsig : Dns_name.t -> Dns_packet.tsig -> key:Cstruct.t ->
  Cstruct.t -> Cstruct.t

val sign : Dns_packet.tsig_sign

val verify : Dns_packet.tsig_verify
