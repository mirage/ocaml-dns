(** [Unix] helper module for {!Dns_client}.
    For more information see the {!Dns_client_flow.Make} functor.
*)


(** A flow module based on blocking I/O on top of the Unix socket API. *)
module Uflow : Dns_client_flow.S
  with type flow = Unix.file_descr
   and type io_addr = Unix.inet_addr * int
   and type stack = unit
   and type (+'a,+'b) io = ('a,'b) result

include module type of Dns_client_flow.Make(Uflow)
