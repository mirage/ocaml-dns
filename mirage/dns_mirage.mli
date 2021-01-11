(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

module Make (S : Mirage_stack.V4V6) : sig

  module IS : Set.S with type elt = Ipaddr.t
  (** [IS] is a set of [ipaddr]. *)

  module IM : sig
    include Map.S with type key = Ipaddr.t
    val find : Ipaddr.t -> 'a t -> 'a option
  end
  (** [IM] is a map using [ipaddr] as key. *)

  module IPM : sig
    include Map.S with type key = Ipaddr.t * int
    val find : Ipaddr.t * int -> 'a t -> 'a option
  end
  (** [IPM] is a map using [ip * port] as key. *)

  type f
  (** A 2byte-length per message flow abstraction, the embedding of DNS frames
     via TCP. *)

  val of_flow : S.TCP.flow -> f
  (** [of_flow flow] is [f]. *)

  val flow : f -> S.TCP.flow
  (** [flow f] is the underlying flow. *)

  val read_tcp : f -> (Cstruct.t, unit) result Lwt.t
  (** [read_tcp f] returns either a buffer or an error (logs actual error). *)

  val send_tcp : S.TCP.flow -> Cstruct.t -> (unit, unit) result Lwt.t
  (** [send_tcp flow buf] sends the buffer, either succeeds or fails (logs
      actual error). *)

  val send_tcp_multiple : S.TCP.flow -> Cstruct.t list ->
    (unit, unit) result Lwt.t
  (** [send_tcp_multiple flow bufs] sends the buffers, either succeeds or fails
      (logs actual error). *)

  val send_udp : S.t -> int -> Ipaddr.t -> int -> Cstruct.t -> unit Lwt.t
  (** [send_udp stack source_port dst dst_port buf] sends the [buf] as UDP
     packet to [dst] on [dst_port]. *)
end
