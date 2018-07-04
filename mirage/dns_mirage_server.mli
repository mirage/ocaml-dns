(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) : sig

  val primary : S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> UDns_server.Primary.s -> unit

  val secondary :
    ?on_update:(UDns_server.Secondary.s -> unit Lwt.t) ->
    S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> UDns_server.Secondary.s ->
    unit
end
