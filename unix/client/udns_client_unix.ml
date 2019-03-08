(* {!Uflow} provides the implementation of the underlying flow
   that is in turn used by {!Udns_client_flow.Make} to provide the
   blocking Unix convenience module:
*)

module Uflow : Udns_client_flow.S
  with type flow = Unix.file_descr
   and type io_addr = string * int
   and type implementation = unit
   and type (+'a,+'b) io = ('a,[> `Msg of string]as 'b) result
= struct
  type io_addr = string * int
  type ns_addr = [`TCP | `UDP] * io_addr
  type implementation = unit
  type flow = Unix.file_descr
  type (+'a,+'b) io = ('a,'b) result constraint 'b = [> `Msg of string]

  let default_ns : ns_addr = `TCP, ("91.239.100.100", 53)

  let implementation = ()

  let map = Rresult.R.((>>=))
  let resolve = (Rresult.R.(>>=))

  open Rresult

  let connect () ((proto,(server,port)):ns_addr) =
    begin match proto with
      | `UDP -> Ok Unix.((getprotobyname "udp").p_proto)
      | `TCP -> Ok Unix.((getprotobyname "tcp").p_proto)
    end >>= fun proto_number ->
    let socket = Unix.socket PF_INET SOCK_STREAM proto_number in
    let server = Unix.inet_addr_of_string server in
    let addr = Unix.ADDR_INET (server, port) in
    Unix.connect socket addr ;
    Ok socket

  let send_string (socket:flow) (tx:string) =
    let res = Unix.send_substring socket tx 0 (String.length tx) [] in
    if res <> String.length tx
    then Error (`Msg ("Broken write to upstream NS" ^ (string_of_int res)))
    else Ok ()

  let recv_string (socket:flow) =
    let buffer = Bytes.make 2048 '\000' in
    let x = Unix.recv socket buffer 0 (Bytes.length buffer) [] in
    if x > 0 && x <= Bytes.length buffer then
      Ok (Bytes.sub_string buffer 0 x)
    else
      Error (`Msg "Reading from NS socket failed")
end

(* Now that we have our {!Uflow} implementation we can include the logic
   that goes on top of it: *)
include Udns_client_flow.Make(Uflow)
