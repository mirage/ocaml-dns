(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

module Make (S : STACKV4) : sig

  module IM : sig
    include Map.S with type key = Ipaddr.V4.t
    val find : Ipaddr.V4.t -> 'a t -> 'a option
  end

  module IPM : sig
    include Map.S with type key = Ipaddr.V4.t * int
    val find : Ipaddr.V4.t * int -> 'a t -> 'a option
  end

  type f

  val of_flow : S.TCPV4.flow -> f

  val flow : f -> S.TCPV4.flow

  val read_tcp : f -> (Cstruct.t, unit) result Lwt.t

  val send_tcp : S.TCPV4.flow -> Cstruct.t -> (unit, unit) result Lwt.t

  val send_udp : S.t -> int -> Ipaddr.V4.t -> int -> Cstruct.t -> unit Lwt.t
end
