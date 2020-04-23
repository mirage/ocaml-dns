
module Make (R : Mirage_random.S) (T : Mirage_time.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4) : sig
  module Transport : Dns_client.S
    with type io_addr = Ipaddr.V4.t * int
     and type +'a io = 'a Lwt.t
     and type stack = S.t

  include module type of Dns_client.Make(Transport)

  val create : ?size:int -> ?nameserver:Transport.ns_addr -> ?timeout:int64 -> S.t -> t
  (** [create ~size ~nameserver stack] uses [R.generate] and [C.elapsed_ns] as
      random number generator and timestamp source, and calls the generic
      {!Dns_client.Make.create}. *)
end

(*
type dns_ty

val config : dns_ty Mirage.impl
(** [config] is the *)

module Make :
  functor (Time:Mirage_time_lwt.S) ->
  functor (IPv4:Mirage_stack_lwt.V4) ->
    S

*)
