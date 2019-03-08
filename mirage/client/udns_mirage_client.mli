
module Make (S : Mirage_stack_lwt.V4) : sig
  module Uflow : Udns_client_flow.S
    with type flow = S.TCPV4.flow
     and type io_addr = Ipaddr.V4.t * int
     and type (+'a, +'b) io = ('a, 'b) Lwt_result.t
     and type stack = S.tcpv4

  include module type of Udns_client_flow.Make(Uflow)
end

(*
type udns_ty

val config : udns_ty Mirage.impl
(** [config] is the *)

module Make :
  functor (Time:Mirage_time_lwt.S) ->
  functor (IPv4:Mirage_stack_lwt.V4) ->
    S

*)
