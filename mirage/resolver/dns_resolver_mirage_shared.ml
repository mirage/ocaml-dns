(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module type S = sig
  type t

  val resolve_external : t -> Ipaddr.t * int -> string -> (int32 * string) Lwt.t
  val primary_data : t -> Dns_trie.t
  val update_primary_data : t -> Dns_trie.t -> unit
  val update_tls : t -> Tls.Config.server -> unit
end
