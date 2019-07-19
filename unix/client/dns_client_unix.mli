(** [Unix] helper module for {!Dns_client}.
    For more information see the {!Dns_client_flow.Make} functor.
*)


(** A flow module based on blocking I/O on top of the Unix socket API. *)
module Uflow : Dns_client_flow.S
  with type flow = Unix.file_descr

   and type io_addr =
   (** The first element in the [io_addr] tuple is a list of socket options
       to be applied to socket connection to the server.
       They will be applied before [Unix.connect].
       The remaining elements designate the IP and port number of the server.*)
         [ `Bool of Unix.socket_bool_option
         | `Int of Unix.socket_int_option
         | `Intopt of Unix.socket_optint_option
         | `Float of Unix.socket_float_option
         ] list
         * Unix.inet_addr * int

   and type stack = unit
   and type (+'a,+'b) io = ('a,'b) result

include module type of Dns_client_flow.Make(Uflow)
