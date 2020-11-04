open Lwt.Infix

module Transport : Dns_client.S
 with type io_addr = Lwt_unix.inet_addr * int
 and type +'a io = 'a Lwt.t
 and type stack = unit
= struct
  type io_addr = Lwt_unix.inet_addr * int
  type ns_addr = [`TCP | `UDP] * io_addr
  type +'a io = 'a Lwt.t
  type stack = unit
  type t = {
    nameserver : ns_addr ;
    timeout_ns : int64 ;
  }
  type context = { t : t ; fd : Lwt_unix.file_descr ; timeout_ns : int64 ref }

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

  let create ?nameserver ~timeout () =
    let nameserver =
      Rresult.R.(get_ok (of_option ~none:(fun () ->
          let ip =
            match
              read_file "/etc/resolv.conf" >>= fun data ->
              Dns_resolvconf.parse data >>= fun nameservers ->
              List.fold_left (fun acc ns ->
                  match acc, ns with
                  | Ok ip, _ -> Ok ip
                  | _, `Nameserver (Ipaddr.V4 ip) -> Ok ip
                  | acc, _ -> acc)
                (Error (`Msg "no nameserver")) nameservers
            with
            | Error _ -> Unix.inet_addr_of_string Dns_client.default_resolver
            | Ok ip -> Ipaddr_unix.V4.to_inet_addr ip
          in
          Ok (`TCP, (ip, 53)))
          nameserver))
    in
    { nameserver ; timeout_ns = timeout }

  let nameserver { nameserver ; _ } = nameserver
  let rng = Mirage_crypto_rng.generate ?g:None
  let clock = Mtime_clock.elapsed_ns

  let with_timeout ctx f =
    let timeout = Lwt_unix.sleep (Duration.to_f !(ctx.timeout_ns)) >|= fun () -> Error (`Msg "DNS request timeout") in
    let start = clock () in
    Lwt.pick [ f ; timeout ] >|= fun result ->
    let stop = clock () in
    ctx.timeout_ns := Int64.sub !(ctx.timeout_ns) (Int64.sub stop start);
    result

  let close { fd ; _ } =
    Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

  let send ctx tx =
    let open Lwt in
    Lwt.catch (fun () ->
      with_timeout ctx
      (Lwt_unix.send ctx.fd (Cstruct.to_bytes tx) 0
        (Cstruct.len tx) [] >>= fun res ->
      if res <> Cstruct.len tx then
        Lwt_result.fail (`Msg ("oops" ^ (string_of_int res)))
      else
        Lwt_result.return ()))
     (fun e -> Lwt.return (Error (`Msg (Printexc.to_string e))))

  let recv ctx =
    let open Lwt in
    let recv_buffer = Bytes.make 2048 '\000' in
    Lwt.catch (fun () ->
      with_timeout ctx
        (Lwt_unix.recv ctx.fd recv_buffer 0 (Bytes.length recv_buffer) []
        >>= fun read_len ->
        if read_len > 0 then
          Lwt_result.return (Cstruct.of_bytes ~len:read_len recv_buffer)
        else
          Lwt_result.fail (`Msg "Empty response")))
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
        let ctx = { t ; fd = socket ; timeout_ns = ref t.timeout_ns } in
        Lwt.catch (fun () ->
            (* SO_RCVTIMEO does not work in Lwt: it results in an EAGAIN, which
               is handled by re-queuing the event *)
            with_timeout ctx
              (Lwt_unix.connect socket addr >|= fun () -> Ok ()) >>= function
              | Ok () -> Lwt_result.return ctx
              | Error e -> close ctx >|= fun () -> Error e)
          (fun e ->
             close ctx >|= fun () ->
             Error (`Msg (Printexc.to_string e))))
      (fun e ->
         Lwt_result.fail (`Msg (Printexc.to_string e)))
end

(* Now that we have our {!Transport} implementation we can include the logic
   that goes on top of it: *)
include Dns_client.Make(Transport)

(* initialize the RNG *)
let () = Mirage_crypto_rng_lwt.initialize ()
