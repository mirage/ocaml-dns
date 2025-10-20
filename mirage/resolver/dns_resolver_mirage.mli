(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module Make (S : Tcpip.Stack.V4V6) : sig
  type t

  val resolver
    :  S.t -> ?root:bool -> ?timer:int -> ?udp:bool -> ?tcp:bool -> ?tls:Tls.Config.server -> ?port:int -> ?tls_port:int
    -> Dns_resolver.t -> t
  (** [resolver stack ~root ~timer ~udp ~tcp ~tls ~port ~tls_port resolver]
      registers a caching resolver on the provided protocols [udp], [tcp], [tls]
      using [port] for udp and tcp (defaults to 53), [tls_port] for tls (defaults
      to 853) using the [resolver] configuration. The [timer] is in milliseconds
      and defaults to 500 milliseconds.*)

  include Dns_resolver_mirage_shared.S with type t := t
end
