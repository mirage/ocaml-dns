(* {!Uflow} provides the implementation of the underlying flow
   that is in turn used by {!Udns_client_flow.Make} to provide the
   blocking Unix convenience module:
*)

module Uflow : Udns_client_flow.S
  with type flow = Unix.file_descr
   and type io_addr = Unix.inet_addr * int
   and type stack = unit
   and type (+'a,+'b) io = ('a,[> `Msg of string]as 'b) result
= struct
  type io_addr = Unix.inet_addr * int
  type ns_addr = [`TCP | `UDP] * io_addr
  type stack = unit
  type flow = Unix.file_descr
  type t = { nameserver : ns_addr }
  type (+'a,+'b) io = ('a,'b) result constraint 'b = [> `Msg of string]

  let create ?(nameserver = `TCP, (Unix.inet_addr_of_string "91.239.100.100", 53)) () =
    { nameserver }

  let nameserver { nameserver } = nameserver

  let map = Rresult.R.((>>=))
  let resolve = (Rresult.R.(>>=))

  open Rresult

  let connect ?nameserver:ns t =
    let proto, (server, port) = match ns with None -> nameserver t | Some x -> x in
    begin match proto with
      | `UDP -> Ok Unix.((getprotobyname "udp").p_proto)
      | `TCP -> Ok Unix.((getprotobyname "tcp").p_proto)
    end >>= fun proto_number ->
    let socket = Unix.socket PF_INET SOCK_STREAM proto_number in
    let addr = Unix.ADDR_INET (server, port) in
    Unix.connect socket addr ;
    Ok socket

  let send (socket:flow) (tx:Cstruct.t) =
    let str = Cstruct.to_string tx in
    let res = Unix.send_substring socket str 0 (String.length str) [] in
    if res <> String.length str
    then Error (`Msg ("Broken write to upstream NS" ^ (string_of_int res)))
    else Ok ()

  let recv (socket:flow) =
    let buffer = Bytes.make 2048 '\000' in
    let x = Unix.recv socket buffer 0 (Bytes.length buffer) [] in
    if x > 0 && x <= Bytes.length buffer then
      Ok (Cstruct.of_bytes buffer ~len:x)
    else
      Error (`Msg "Reading from NS socket failed")
end

(* Now that we have our {!Uflow} implementation we can include the logic
   that goes on top of it: *)
include Udns_client_flow.Make(Uflow)
