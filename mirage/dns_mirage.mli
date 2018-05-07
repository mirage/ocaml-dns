(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) : sig

  val primary : S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> UDns_server.Primary.s -> unit

  val secondary : S.t -> P.t -> M.t -> ?timer:int -> ?port:int -> UDns_server.Secondary.s -> unit

  val resolver : S.t -> P.t -> M.t -> ?root:bool -> ?timer:int -> ?port:int -> Dns_resolver.t -> unit

end
