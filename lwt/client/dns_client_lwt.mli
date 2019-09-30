(** {!Lwt_unix} helper module for {!Dns_client}.
    For more information see the {!Dns_client.Make} functor.
*)


(** A flow module based on non-blocking I/O on top of the
    Lwt_unix socket API. *)
module Transport : Dns_client.S
  with type flow = Lwt_unix.file_descr
   and type io_addr = Lwt_unix.inet_addr * int
   and type +'a io = 'a Lwt.t
   and type stack = unit

include module type of Dns_client.Make(Transport)
