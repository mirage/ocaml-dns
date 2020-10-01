
module Make (R : Mirage_random.S) (T : Mirage_time.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4V6) : sig
  module Transport : Dns_client.S
    with type io_addr = Ipaddr.t * int
     and type +'a io = 'a Lwt.t
     and type stack = S.t

  include module type of Dns_client.Make(Transport)

  val create : ?size:int -> ?nameserver:Transport.ns_addr -> ?timeout:int64 -> S.t -> t
  (** [create ~size ~nameserver stack] uses [R.generate] and [C.elapsed_ns] as
      random number generator and timestamp source, and calls the generic
      {!Dns_client.Make.create}. *)
end
