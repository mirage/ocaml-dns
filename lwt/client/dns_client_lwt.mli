(** {!Lwt_unix} helper module for {!Dns_client}.
    For more information see the {!Dns_client.Make} functor.

    The {!Dns_client} is available as Dns_client_lwt after
    linking to dns-client.lwt in your dune file.
*)


(** A flow module based on non-blocking I/O on top of the
    Lwt_unix socket API. *)
module Transport : Dns_client.S
   with type io_addr = Lwt_unix.inet_addr * int
   and type +'a io = 'a Lwt.t
   and type stack = unit

include module type of Dns_client.Make(Transport)
