(** {!Lwt_unix} helper module for {!Udns_client}.
    For more information see the {!Udns_client_flow.Make} functor.
*)


(** A flow module based on non-blocking I/O on top of the
    Lwt_unix socket API. *)
module Uflow : Udns_client_flow.S
  with type flow = Lwt_unix.file_descr
   and type io_addr = Lwt_unix.inet_addr * int
   and type (+'a,+'b) io = ('a,'b) Lwt_result.t
   and type stack = unit

include module type of Udns_client_flow.Make(Uflow)
