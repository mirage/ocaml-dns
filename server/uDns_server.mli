(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module Authentication : sig
  type a = Dns_trie.t -> Dns_packet.proto -> Domain_name.t option -> string -> Domain_name.t -> bool

  val tsig_auth : a

  type operation = [
    | `Key_management
    | `Update
    | `Transfer
  ]

  type t = Dns_trie.t * a list
end

type t = private {
  data : Dns_trie.t ;
  auth : Authentication.t ;
  rng : int -> Cstruct.t ;
  tsig_verify : Dns_packet.tsig_verify ;
  tsig_sign : Dns_packet.tsig_sign ;
}

val create : Dns_trie.t -> Authentication.t -> (int -> Cstruct.t) ->
  Dns_packet.tsig_verify -> Dns_packet.tsig_sign -> t

val text : Domain_name.t -> t -> (string, string) result

val handle_query : t -> Dns_packet.proto -> Domain_name.t option -> Dns_packet.header ->
  Dns_packet.query ->
  (Dns_packet.header * Dns_packet.v, Dns_enum.rcode) result

val notify : t -> (Domain_name.t * Ipaddr.V4.t * int) list -> int64 -> Domain_name.t ->
  Dns_packet.soa ->
  (int64 * int * Ipaddr.V4.t * int * Dns_packet.header * Dns_packet.query) list

val handle_tsig : ?mac:Cstruct.t -> t -> Ptime.t -> Dns_packet.header ->
  Dns_packet.v -> (Domain_name.t * Dns_packet.tsig) option -> int option -> Cstruct.t ->
  ((Domain_name.t * Dns_packet.tsig * Cstruct.t * Dns_packet.dnskey) option,
   Cstruct.t option) result

module Primary : sig
  type s

  val server : s -> t

  val data : s -> Dns_trie.t

  val with_data : s -> Dns_trie.t -> s

  (* TODO: could make the Dns_trie.t optional, and have an optional key *)
  val create :
    ?keys:(Domain_name.t * Dns_packet.dnskey) list ->
    ?a:Authentication.a list -> tsig_verify:Dns_packet.tsig_verify ->
    tsig_sign:Dns_packet.tsig_sign -> rng:(int -> Cstruct.t) ->
    Dns_trie.t -> s

  val handle_frame : s -> int64 -> Ipaddr.V4.t -> int -> Dns_packet.proto ->
    Domain_name.t option -> Dns_packet.header -> Dns_packet.v ->
    (s * (Dns_packet.header * Dns_packet.v) option * (Ipaddr.V4.t * int * Cstruct.t) list,
     Dns_enum.rcode) result

  val handle : s -> Ptime.t -> int64 -> Dns_packet.proto -> Ipaddr.V4.t -> int -> Cstruct.t ->
    s * Cstruct.t option * (Ipaddr.V4.t * int * Cstruct.t) list

  val closed : s -> Ipaddr.V4.t -> int -> s

  val timer : s -> int64 -> s * (Ipaddr.V4.t * int * Cstruct.t) list
end

module Secondary : sig
  type s

  val server : s -> t

  val data : s -> Dns_trie.t

  val with_data : s -> Dns_trie.t -> s

  val zones : s -> Domain_name.t list

  val create : ?a:Authentication.a list -> tsig_verify:Dns_packet.tsig_verify ->
    tsig_sign:Dns_packet.tsig_sign -> rng:(int -> Cstruct.t) ->
    (Domain_name.t * Dns_packet.dnskey) list -> s

  val handle_frame : s -> Ptime.t -> int64 -> Ipaddr.V4.t -> Dns_packet.proto ->
    Domain_name.t option -> Dns_packet.header -> Dns_packet.v ->
    (s * (Dns_packet.header * Dns_packet.v) option * (Dns_packet.proto * Ipaddr.V4.t * int * Cstruct.t) list,
     Dns_enum.rcode) result

  val handle : s -> Ptime.t -> int64 -> Dns_packet.proto -> Ipaddr.V4.t -> Cstruct.t ->
    s * Cstruct.t option * (Dns_packet.proto * Ipaddr.V4.t * int * Cstruct.t) list

  val timer : s -> Ptime.t -> int64 ->
    s * (Dns_packet.proto * Ipaddr.V4.t * int * Cstruct.t) list

  val closed : s -> Ptime.t -> int64 -> Ipaddr.V4.t -> int ->
    s * (Dns_packet.proto * Ipaddr.V4.t * int * Cstruct.t) list
end
