(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module Make (P : Mirage_clock_lwt.PCLOCK) (M : Mirage_clock_lwt.MCLOCK) (T : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) : sig

  val primary : S.t -> ?timer:int -> ?port:int -> Udns_server.Primary.s -> unit
  (** [primary stack ~timer ~port primary] starts a primary server on [port]
     (default 53, both TCP and UDP) with the given [primary] configuration. [timer] is the
     DNS notify timer in seconds, and defaults to 2 seconds. *)

  val secondary :
    ?on_update:(Udns_server.Secondary.s -> unit Lwt.t) ->
    S.t -> ?timer:int -> ?port:int -> Udns_server.Secondary.s ->
    unit
  (** [secondary ~on_update stack ~timer ~port secondary] starts a secondary
     server on [port] (default 53). The [on_update] callback is executed when
     the zone changes. The [timer] (in seconds, defaults to 5 seconds) is used
     for refreshing zones. *)
end
