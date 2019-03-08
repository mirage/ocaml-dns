(* {!Uflow} provides the implementation of the underlying flow
   that is in turn used by {!Udns_client_flow.Make} to provide the
   Lwt convenience module
*)

module Uflow : Udns_client_flow.S
  with type flow = Lwt_unix.file_descr
 and type io_addr = Lwt_unix.inet_addr * int
 and type (+'a,+'b) io = ('a,'b) Lwt_result.t
 and type implementation = unit
= struct
  type io_addr = Lwt_unix.inet_addr * int
  type flow = Lwt_unix.file_descr
  type ns_addr = [`TCP | `UDP] * io_addr
  type (+'a,+'b) io = ('a,'b) Lwt_result.t
    constraint 'b = [> `Msg of string]
  type implementation = unit

  let default_ns = `TCP, (Unix.inet_addr_of_string "91.239.100.100", 53)

  let implementation = ()

  let send_string socket tx =
    let open Lwt in
    Lwt_unix.send socket (Bytes.of_string tx) 0
      (String.length tx) [] >>= fun res ->
    if res <> String.length tx then
      Lwt_result.fail (`Msg ("oops" ^ (string_of_int res)))
    else
      Lwt_result.return ()

  let recv_string socket =
    let open Lwt in
    let recv_buffer = Bytes.make 2048 '\000' in
    Lwt_unix.recv socket recv_buffer 0 (Bytes.length recv_buffer) []
    >>= fun read_len ->
    let open Lwt_result in
    (if read_len > 0 then Lwt_result.return ()
     else Lwt_result.fail (`Msg "Empty response")) >|= fun () ->
    (Bytes.sub_string recv_buffer 0 read_len)

  let map = Lwt_result.bind
  let resolve = Lwt_result.bind_result

  let connect (():implementation) (proto, (server,port)) =
    let open Lwt in
    begin match proto with
      | `UDP ->
        Lwt_unix.((getprotobyname "udp") >|= fun x -> x.p_proto,
                                                      SOCK_DGRAM)
      | `TCP ->
        Lwt_unix.((getprotobyname "tcp") >|= fun x -> x.p_proto,
                                                      SOCK_STREAM)
    end >>= fun (proto_number, socket_type) ->
    let socket = Lwt_unix.socket PF_INET socket_type proto_number in
    let addr = Lwt_unix.ADDR_INET (server, port) in
    Lwt_unix.connect socket addr >|= fun () ->
    Ok socket
end

(* Now that we have our {!Uflow} implementation we can include the logic
   that goes on top of it: *)
include Udns_client_flow.Make(Uflow)
