(* {!Transport} provides the implementation of the underlying flow
   that is in turn used by {!Dns_client.Make} to provide the
   blocking Unix convenience module:
*)

module Transport : Dns_client.S
  with type io_addr = Ipaddr.t * int
   and type stack = unit
   and type +'a io = 'a
= struct
  type io_addr = Ipaddr.t * int
  type stack = unit
  type t = {
    protocol : Dns.proto ;
    nameservers : io_addr list ;
    timeout_ns : int64 ;
  }
  type context = {
    t : t ;
    fd : Unix.file_descr ;
    mutable timeout_ns : int64
  }
  type +'a io = 'a

  let read_file file =
    try
      let fh = open_in file in
      try
        let content = really_input_string fh (in_channel_length fh) in
        close_in_noerr fh ;
        Ok content
      with _ ->
        close_in_noerr fh;
        Error (`Msg ("Error reading file: " ^ file))
    with _ -> Error (`Msg ("Error opening file " ^ file))

  let create ?nameservers ~timeout () =
    let protocol, nameservers =
      match nameservers with
      | Some ns -> ns
      | None ->
        let ips =
          match
            Result.bind
              (read_file "/etc/resolv.conf")
              (fun data -> Dns_resolvconf.parse data)
          with
          | Error _ | Ok [] -> List.map (fun ip -> ip, 53) Dns_client.default_resolvers
          | Ok ips -> List.map (function `Nameserver ip -> (ip, 53)) ips
        in
        `Tcp, ips
    in
    { protocol ; nameservers ; timeout_ns = timeout }

  let nameservers { protocol ; nameservers ; _ } = protocol, nameservers
  let clock = Mtime_clock.elapsed_ns
  let rng = Mirage_crypto_rng.generate ?g:None

  let bind a b = b a
  let lift v = v

  let close { fd ; _ } = try Unix.close fd with _ -> ()

  let with_timeout ctx f =
    let start = clock () in
    (* TODO cancel execution of f when time_left is 0 *)
    let r = f ctx.fd in
    let stop = clock () in
    ctx.timeout_ns <- Int64.sub (ctx.timeout_ns) (Int64.sub stop start);
    if ctx.timeout_ns <= 0L then
      Error (`Msg "DNS resolution timed out.")
    else
      r

  (* there is no connect timeouts, just a request timeout (unix: receive timeout) *)
  let connect t =
    match nameservers t with
    | _, [] -> Error (`Msg "empty nameserver list")
    | proto, (server, port) :: _ ->
      try
        Result.bind
          (match proto with
           | `Udp -> Ok Unix.((getprotobyname "udp").p_proto, SOCK_DGRAM)
           | `Tcp -> Ok Unix.((getprotobyname "tcp").p_proto, SOCK_STREAM))
          (fun (proto_number, sock_typ) ->
             let fam = match server with Ipaddr.V4 _ -> Unix.PF_INET | Ipaddr.V6 _ -> Unix.PF_INET6 in
             let socket = Unix.socket fam sock_typ proto_number in
             let addr = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr server, port) in
             let ctx = { t ; fd = socket ; timeout_ns = t.timeout_ns } in
             try
               with_timeout ctx (fun fd ->
                   Unix.connect fd addr;
                   Ok ctx)
             with e ->
               close ctx;
               Error (`Msg (Printexc.to_string e)))
      with e ->
        Error (`Msg (Printexc.to_string e))

  let send ctx (tx : Cstruct.t) =
    let str = Cstruct.to_string tx in
    try
      with_timeout ctx (fun fd ->
        Unix.setsockopt_float fd Unix.SO_SNDTIMEO (Duration.to_f ctx.timeout_ns);
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
        Unix.setsockopt_float fd Unix.SO_RCVTIMEO (Duration.to_f ctx.timeout_ns);
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
