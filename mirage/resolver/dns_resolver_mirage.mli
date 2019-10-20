(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module Make (R : Mirage_random.S) (P : Mirage_clock.PCLOCK) (M : Mirage_clock.MCLOCK) (T : Mirage_time.S) (S : Mirage_stack.V4) : sig

  val resolver : S.t -> ?root:bool -> ?timer:int -> ?port:int -> Dns_resolver.t -> unit
  (** [resolver stack ~root ~timer ~port resolver] registers a caching resolver
     on the provided [port] (both udp and tcp) using the [resolver]
     configuration. The [timer] is in milliseconds and defaults to 500
     milliseconds.*)
end
