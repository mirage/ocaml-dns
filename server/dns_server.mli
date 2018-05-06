(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

type a = Dns_trie.t -> Dns_packet.proto -> Dns_name.t option -> string -> Dns_name.t -> bool

val tsig_auth : a

type t = private {
  data : Dns_trie.t ;
  authorised : a list ;
  rng : int -> Cstruct.t ;
  tsig_verify : Dns_packet.tsig_verify ;
  tsig_sign : Dns_packet.tsig_sign ;
}

val create : Dns_trie.t -> a list -> (int -> Cstruct.t) ->
  Dns_packet.tsig_verify -> Dns_packet.tsig_sign -> t

val handle_query : t -> Dns_packet.proto -> Dns_name.t option -> Dns_packet.header ->
  Dns_packet.query ->
  (Dns_packet.t, Dns_enum.rcode) result

module IPS : (Set.S with type elt = Ipaddr.V4.t)

val notify : (int -> Cstruct.t) -> int64 -> Dns_trie.t -> Dns_name.t ->
  Dns_packet.soa ->
  (int64 * int * IPS.elt * Dns_packet.header * Dns_packet.query) list

val handle_tsig : ?mac:Cstruct.t -> t -> Ptime.t -> Dns_packet.t ->
  int option -> Cstruct.t ->
  ((Dns_name.t * Dns_packet.tsig * Cstruct.t * Dns_packet.dnskey) option,
   Cstruct.t) result

module Primary : sig
  type s

  val server : s -> t

  val data : s -> Dns_trie.t

  val with_data : s -> Dns_trie.t -> s

  (* TODO: could make the Dns_trie.t optional, and have an optional key *)
  val create : ?a:a list -> tsig_verify:Dns_packet.tsig_verify ->
    tsig_sign:Dns_packet.tsig_sign -> rng:(int -> Cstruct.t) ->
    Dns_trie.t -> s

  val handle_frame : s -> int64 -> Ipaddr.V4.t -> Dns_packet.proto ->
    Dns_name.t option -> Dns_packet.t ->
    (s * Dns_packet.t option * (Ipaddr.V4.t * Cstruct.t) list,
     Dns_enum.rcode) result

  val handle : s -> Ptime.t -> int64 -> Dns_packet.proto -> Ipaddr.V4.t -> Cstruct.t ->
    s * Cstruct.t option * (Ipaddr.V4.t * Cstruct.t) list

  val timer : s -> int64 -> s * (Ipaddr.V4.t * Cstruct.t) list
end

module Secondary : sig
  type s

  val create : ?a:a list -> tsig_verify:Dns_packet.tsig_verify ->
    tsig_sign:Dns_packet.tsig_sign -> rng:(int -> Cstruct.t) ->
    (Dns_name.t * Dns_packet.dnskey) list -> s

  val handle_frame : s -> Ptime.t -> int64 -> Ipaddr.V4.t -> Dns_packet.proto ->
    Dns_name.t option -> Dns_packet.dnskey option -> Dns_packet.t ->
    (s * Dns_packet.t option * (Dns_packet.proto * Ipaddr.V4.t * Cstruct.t) list,
     Dns_enum.rcode) result

  val handle : s -> Ptime.t -> int64 -> Dns_packet.proto -> Ipaddr.V4.t -> Cstruct.t ->
    s * Cstruct.t option * (Dns_packet.proto * Ipaddr.V4.t * Cstruct.t) list

  val timer : s -> Ptime.t -> int64 ->
    s * (Dns_packet.proto * Ipaddr.V4.t * Cstruct.t) list
end
