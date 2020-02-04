(* {!Transport} provides the implementation of the underlying flow
   that is in turn used by {!Dns_client.Make} to provide the
   blocking Unix convenience module:
*)

module Transport : Dns_client.S
  with type flow = Unix.file_descr
   and type io_addr = Unix.inet_addr * int
   and type stack = unit
   and type +'a io = 'a
= struct
  type io_addr = Unix.inet_addr * int
  type ns_addr = [`TCP | `UDP] * io_addr
  type stack = unit
  type flow = Unix.file_descr
  type t = {
    rng : int -> Cstruct.t ;
    nameserver : ns_addr ;
  }
  type +'a io = 'a

  let create
      ?(rng = Dns_client.stdlib_random)
      ?(nameserver = `TCP, (Unix.inet_addr_of_string Dns_client.default_resolver, 53)) () =
    { rng ; nameserver }

  let nameserver { nameserver ; _ } = nameserver
  let rng { rng ; _ } = rng

  let bind a b = b a
  let lift v = v

  open Rresult

  let close socket = try Unix.close socket with _ -> ()

  let connect ?nameserver:ns t =
    let proto, (server, port) =
      match ns with None -> nameserver t | Some x -> x
    in
    try
      begin match proto with
        | `UDP -> Ok Unix.((getprotobyname "udp").p_proto)
        | `TCP -> Ok Unix.((getprotobyname "tcp").p_proto)
      end >>= fun proto_number ->
      let socket = Unix.socket PF_INET SOCK_STREAM proto_number in
      let addr = Unix.ADDR_INET (server, port) in
      try
        Unix.connect socket addr ;
        Ok socket
      with e ->
        close socket ;
        Error (`Msg (Printexc.to_string e))
    with e ->
      Error (`Msg (Printexc.to_string e))

  let send (socket:flow) (tx:Cstruct.t) =
    let str = Cstruct.to_string tx in
    try
      let res = Unix.send_substring socket str 0 (String.length str) [] in
      if res <> String.length str
      then
        Error (`Msg ("Broken write to upstream NS" ^ (string_of_int res)))
      else Ok ()
   with e ->
     Error (`Msg (Printexc.to_string e))

  let recv (socket:flow) =
    let buffer = Bytes.make 2048 '\000' in
    try
      let x = Unix.recv socket buffer 0 (Bytes.length buffer) [] in
      if x > 0 && x <= Bytes.length buffer then
        Ok (Cstruct.of_bytes buffer ~len:x)
      else
        Error (`Msg "Reading from NS socket failed")
    with e ->
      Error (`Msg (Printexc.to_string e))
end

(* Now that we have our {!Transport} implementation we can include the logic
   that goes on top of it: *)
include Dns_client.Make(Transport)
