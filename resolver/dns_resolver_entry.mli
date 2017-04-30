(* (c) 2017 Hannes Mehnert, all rights reserved *)

type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer
  | AuthoritativeAuthority
  | ZoneGlue
  | NonAuthoritativeAnswer
  | Additional

val compare_rank : rank -> rank -> [ `Equal | `Smaller | `Bigger ]

val pp_rank : rank Fmt.t

type res =
  | NoErr of Dns_packet.rr list
  | NoData of Dns_packet.rr
  | NoDom of Dns_packet.rr
  | ServFail of Dns_packet.rr

val pp_res : res Fmt.t
