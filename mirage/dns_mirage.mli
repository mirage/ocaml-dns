(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) : sig

  type f

  val of_flow : S.TCPV4.flow -> f

  val flow : f -> S.TCPV4.flow

  val read_tcp : f -> (Cstruct.t, unit) result Lwt.t

  val send_tcp : S.TCPV4.flow -> Cstruct.t -> (unit, unit) result Lwt.t

  val primary : S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> UDns_server.Primary.s -> unit

  val secondary :
    ?on_update:(UDns_server.Secondary.s -> unit Lwt.t) ->
    S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> UDns_server.Secondary.s ->
    unit

  val resolver : S.t -> P.t -> M.t -> ?root:bool -> ?timer:int -> ?port:int -> UDns_resolver.t -> unit

end
