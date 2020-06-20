(* {!Transport} provides the implementation of the underlying flow
   that is in turn used by {!Dns_client.Make} to provide the
   blocking Unix convenience module:
*)

module Transport : Dns_client.S
  with type io_addr = Unix.inet_addr * int
   and type stack = unit
   and type +'a io = 'a
= struct
  type io_addr = Unix.inet_addr * int
  type ns_addr = [`TCP | `UDP] * io_addr
  type stack = unit
  type t = {
    nameserver : ns_addr ;
    timeout_ns : int64 ;
  }
  type context = { t : t ; fd : Unix.file_descr ; timeout_ns : int64 ref }
  type +'a io = 'a

  let create
      ?(nameserver = `TCP, (Unix.inet_addr_of_string Dns_client.default_resolver, 53)) ~timeout () =
    { nameserver ; timeout_ns = timeout }

  let nameserver { nameserver ; _ } = nameserver
  let clock = Mtime_clock.elapsed_ns
  let rng = Mirage_crypto_rng.generate ?g:None

  open Rresult

  let bind a b = b a
  let lift v = v

  let close { fd ; _ } = try Unix.close fd with _ -> ()

  let with_timeout ctx f =
    let start = clock () in
    (* TODO cancel execution of f when time_left is 0 *)
    let r = f ctx.fd in
    let stop = clock () in
    ctx.timeout_ns := Int64.sub !(ctx.timeout_ns) (Int64.sub stop start);
    if !(ctx.timeout_ns) <= 0L then
      Error (`Msg "DNS resolution timed out.")
    else
      r

  (* there is no connect timeouts, just a request timeout (unix: receive timeout) *)
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
      let time_left = ref t.timeout_ns in
      let addr = Unix.ADDR_INET (server, port) in
      let ctx = { t ; fd = socket ; timeout_ns = time_left } in
      try
        with_timeout ctx (fun fd ->
          Unix.connect fd addr;
          Ok ctx)
      with e ->
        close ctx;
        Error (`Msg (Printexc.to_string e))
    with e ->
      Error (`Msg (Printexc.to_string e))

  let send ctx (tx : Cstruct.t) =
    let str = Cstruct.to_string tx in
    try
      with_timeout ctx (fun fd ->
        Unix.setsockopt_float fd Unix.SO_SNDTIMEO (Duration.to_f !(ctx.timeout_ns));
        let res = Unix.send_substring fd str 0 (String.length str) [] in
        if res <> String.length str
        then
          Error (`Msg ("Broken write to upstream NS" ^ (string_of_int res)))
        else Ok ())
   with e ->
     Error (`Msg (Printexc.to_string e))

  let recv ctx =
    let buffer = Bytes.make 2048 '\000' in
    try
      with_timeout ctx (fun fd ->
        Unix.setsockopt_float fd Unix.SO_RCVTIMEO (Duration.to_f !(ctx.timeout_ns));
        let x = Unix.recv fd buffer 0 (Bytes.length buffer) [] in
        if x > 0 && x <= Bytes.length buffer then
          Ok (Cstruct.of_bytes buffer ~len:x)
        else
          Error (`Msg "Reading from NS socket failed"))
    with e ->
      Error (`Msg (Printexc.to_string e))
end

(* Now that we have our {!Transport} implementation we can include the logic
   that goes on top of it: *)
include Dns_client.Make(Transport)

(* initialize the RNG *)
let () = Mirage_crypto_rng_unix.initialize ()
