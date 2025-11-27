(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module type S = sig
  type t

  val resolve_external : t -> Ipaddr.t * int -> string -> (int32 * string) Lwt.t
  (** [resolve_external t (ip, port) data] resolves for [(ip, port)] the query
      [data] and returns a pair of the minimum TTL and a response. *)

  val primary_data : t -> Dns_trie.t
  (** [primary_data t] is the DNS trie of the primary for the resolver [t]. *)

  val update_primary_data : t -> Dns_trie.t -> unit
  (** [update_primary_data t data] updates the primary for the resolver [t]
      with the DNS trie [data]. Any 'notify's to secondaries are discarded -
      secondary name servers are not supported in this setup. *)

  val update_tls : t -> Tls.Config.server -> unit
  (** [update_tls t tls_config] updates the tls configuration to [tls_config].
      If the resolver wasn't already listening for TLS connections it will
      start listening. *)

  val queries : t -> (Ptime.t * Dns.Packet.Question.t * Ipaddr.t * Dns.Rcode.t * int64 * string) Lwt_condition.t
  (** [queries t] returns the stream of resolved DNS queries and their replies. *)
end
