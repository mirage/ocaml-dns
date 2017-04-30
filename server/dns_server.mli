(* (c) 2017 Hannes Mehnert, all rights reserved *)

(* just for convenience... *)
type proto = [ `Tcp | `Udp ]

type a = Dns_trie.t -> proto -> Dns_name.t option -> string -> Dns_name.t -> bool

val tsig_auth : a

module Primary : sig
  type t

  (* TODO: could make the Dns_trie.t optional, and have an optional key *)
  val create : int64 -> ?a:a list -> tsig_verify:Dns_packet.tsig_verify ->
    tsig_sign:Dns_packet.tsig_sign -> rng:(int -> Cstruct.t) ->
    ?zones:Dns_name.t list -> Dns_trie.t -> t

  val handle : t -> Ptime.t -> int64 -> proto -> Ipaddr.V4.t -> Cstruct.t ->
    t * Cstruct.t option * (Ipaddr.V4.t * Cstruct.t) list

  val timer : t -> int64 -> t * (Ipaddr.V4.t * Cstruct.t) list
end

module Secondary : sig
  type t

  val create : ?a:a list -> tsig_verify:Dns_packet.tsig_verify ->
    tsig_sign:Dns_packet.tsig_sign -> rng:(int -> Cstruct.t) ->
    (Dns_name.t * Dns_packet.dnskey) list -> t

  val handle : t -> Ptime.t -> int64 -> proto -> Ipaddr.V4.t -> Cstruct.t ->
    t * Cstruct.t option * (proto * Ipaddr.V4.t * Cstruct.t) list

  val timer : t -> Ptime.t -> int64 -> t * (proto * Ipaddr.V4.t * Cstruct.t) list
end
