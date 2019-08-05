(* {!Uflow} provides the implementation of the underlying flow
   that is in turn used by {!Dns_client_flow.Make} to provide the
   Lwt convenience module
*)

open Lwt.Infix

module Uflow : Dns_client_flow.S
  with type flow = Lwt_unix.file_descr
 and type io_addr = Lwt_unix.inet_addr * int
 and type +'a io = 'a Lwt.t
 and type stack = unit
= struct
  type io_addr = Lwt_unix.inet_addr * int
  type flow = Lwt_unix.file_descr
  type ns_addr = [`TCP | `UDP] * io_addr
  type +'a io = 'a Lwt.t
  type stack = unit
  type t = { nameserver : ns_addr }

  let create ?(nameserver = `TCP, (Unix.inet_addr_of_string "91.239.100.100", 53)) () =
    { nameserver }

  let nameserver { nameserver } = nameserver

  let close socket =
    Lwt.catch (fun () -> Lwt_unix.close socket) (fun _ -> Lwt.return_unit)

  let send socket tx =
    let open Lwt in
    Lwt.catch (fun () ->
      Lwt_unix.send socket (Cstruct.to_bytes tx) 0
        (Cstruct.len tx) [] >>= fun res ->
      if res <> Cstruct.len tx then
        Lwt_result.fail (`Msg ("oops" ^ (string_of_int res)))
      else
        Lwt_result.return ())
     (fun e -> Lwt.return (Error (`Msg (Printexc.to_string e))))

  let recv socket =
    let open Lwt in
    let recv_buffer = Bytes.make 2048 '\000' in
    Lwt.catch (fun () ->
      Lwt_unix.recv socket recv_buffer 0 (Bytes.length recv_buffer) []
      >>= fun read_len ->
      if read_len > 0 then
        Lwt_result.return (Cstruct.of_bytes ~len:read_len recv_buffer)
      else
        Lwt_result.fail (`Msg "Empty response"))
    (fun e -> Lwt_result.fail (`Msg (Printexc.to_string e)))

  let bind = Lwt.bind
  let lift = Lwt.return

  let connect ?nameserver:ns t =
    let (proto, (server, port)) =
      match ns with None -> nameserver t | Some x -> x
    in
    Lwt.catch (fun () ->
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
        Lwt.catch (fun () ->
            Lwt_unix.connect socket addr >|= fun () ->
            Ok socket)
          (fun e ->
             close socket >|= fun () ->
             Error (`Msg (Printexc.to_string e))))
      (fun e ->
         Lwt_result.fail (`Msg (Printexc.to_string e)))
end

(* Now that we have our {!Uflow} implementation we can include the logic
   that goes on top of it: *)
include Dns_client_flow.Make(Uflow)
