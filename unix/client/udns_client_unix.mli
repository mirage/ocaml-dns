(** [Unix] helper module for {!Udns_client}.
    For more information see the {!Udns_client_flow.Make} functor.
*)


(** A flow module based on blocking I/O on top of the Unix socket API. *)
module Uflow : Udns_client_flow.S
  with type flow = Unix.file_descr
   and type io_addr = string * int
   and type stack = unit
   and type (+'a,+'b) io = ('a,'b) result

include module type of Udns_client_flow.Make(Uflow)
