module type S = sig
  type t
  type stack

  val create : stack -> t

  val getaddrinfo : Domain_name.t -> unit Lwt.t

end

type udns_ty

val config : udns_ty Mirage.impl
(** [config] is the *)

module Make :
  functor (Time:Mirage_time_lwt.S) ->
  functor (IPv4:Mirage_stack_lwt.V4) ->
    S

