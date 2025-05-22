(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module Make (S : Tcpip.Stack.V4V6) : sig
  type t = Dns_resolver.t ref

  val connect : Dns_resolver.t -> t
  val handle : dst:Ipaddr.t -> port:int -> string -> t ->
    (Dns.proto * Ipaddr.t * int * string) list * (Dns.proto * Ipaddr.t * string) list

  val resolver : S.t -> ?root:bool -> ?timer:int -> ?udp:bool -> ?tcp:bool -> ?tls:Tls.Config.server -> ?port:int -> ?tls_port:int -> t -> unit
  (** [resolver stack ~root ~timer ~udp ~tcp ~tls ~port ~tls_port resolver]
     registers a caching resolver on the provided protocols [udp], [tcp], [tls]
     using [port] for udp and tcp (defaults to 53), [tls_port] for tls (defaults
     to 853) using the [resolver] configuration. The [timer] is in milliseconds
     and defaults to 500 milliseconds.*)
end
