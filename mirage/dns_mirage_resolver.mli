(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) : sig
  val resolver : S.t -> P.t -> M.t -> ?root:bool -> ?timer:int -> ?port:int -> UDns_resolver.t -> unit
end
