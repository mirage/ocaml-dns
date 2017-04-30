(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) : sig

  val primary : S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> Dns_server.Primary.t -> unit

  val secondary : S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> Dns_server.Secondary.t -> unit
end
