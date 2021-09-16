open Lwt.Infix

module IM = Map.Make(Int)

let src = Logs.Src.create "dns_client_lwt" ~doc:"effectful DNS lwt layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Transport : Dns_client.S
 with type io_addr = Ipaddr.t * int
 and type +'a io = 'a Lwt.t
 and type stack = unit
= struct
  type io_addr = Ipaddr.t * int
  type ns_addr = Dns.proto * io_addr
  type +'a io = 'a Lwt.t
  type stack = unit
  type t = {
    nameserver : ns_addr ;
    timeout_ns : int64 ;
    mutable fd : Lwt_unix.file_descr option ;
    mutable requests : (Cstruct.t * (Cstruct.t, [ `Msg of string ]) result Lwt_condition.t) IM.t ;
  }
  type context = {
    t : t ;
    fd : Lwt_unix.file_descr option ;
    mutable timeout_ns : int64 ;
    mutable data : Cstruct.t ;
  }

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
                  | _, `Nameserver ip -> Ok ip)
                (Error (`Msg "no nameserver")) nameservers
            with
            | Error _ -> Ipaddr.(V4 (V4.of_string_exn (fst Dns_client.default_resolver)))
            | Ok ip -> ip
          in
          Ok (`Tcp, (ip, 53)))
          nameserver))
    in
    { nameserver ; timeout_ns = timeout ; fd = None ; requests = IM.empty }

  let nameserver { nameserver ; _ } = nameserver
  let rng = Mirage_crypto_rng.generate ?g:None
  let clock = Mtime_clock.elapsed_ns

  let with_timeout ctx f =
    let timeout =
      Lwt_unix.sleep (Duration.to_f ctx.timeout_ns) >|= fun () ->
      Error (`Msg "DNS request timeout")
    in
    let start = clock () in
    Lwt.pick [ f ; timeout ] >|= fun result ->
    let stop = clock () in
    ctx.timeout_ns <- Int64.sub ctx.timeout_ns (Int64.sub stop start);
    result

  let close { fd ; _ } =
    match fd with
    | None -> Lwt.return_unit
    | Some fd -> Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

  let send ctx tx =
    Lwt.catch (fun () ->
      match ctx.fd, ctx.t.fd with
      | Some _, Some _
      | None, None -> Lwt.return (Error (`Msg "DNS client not connected to a remote resolver"))
      | Some fd, None
      | None, Some fd ->
        ctx.data <- tx;
        with_timeout ctx
          (Lwt_unix.send fd (Cstruct.to_bytes tx) 0
            (Cstruct.length tx) [] >>= fun res ->
           if res <> Cstruct.length tx then
             Lwt_result.fail (`Msg ("oops" ^ (string_of_int res)))
           else
             Lwt_result.return ()))
     (fun e -> Lwt.return (Error (`Msg (Printexc.to_string e))))

  let recv ctx =
    match ctx.fd, ctx.t.fd with
    | None, None | Some _, Some _ ->
      Lwt.return (Error (`Msg "invalid state of DNS client"))
    | Some fd, None ->
      let recv_buffer = Bytes.make 2048 '\000' in
      Lwt.catch (fun () ->
        with_timeout ctx
          (Lwt_unix.recv fd recv_buffer 0 (Bytes.length recv_buffer) []
          >>= fun read_len ->
          if read_len > 0 then
            Lwt_result.return (Cstruct.of_bytes ~len:read_len recv_buffer)
          else
            Lwt_result.fail (`Msg "Empty response")))
      (fun e -> Lwt_result.fail (`Msg (Printexc.to_string e)))
    | None, Some _ ->
      if Cstruct.length ctx.data > 2 then
        let cond = Lwt_condition.create () in
        let id = Cstruct.BE.get_uint16 ctx.data 2 in
        ctx.t.requests <- IM.add id (ctx.data, cond) ctx.t.requests;
        with_timeout ctx (Lwt_condition.wait cond) >|= fun data ->
        ctx.t.requests <- IM.remove id ctx.t.requests;
        match data with
        | Ok cs -> Ok cs
        | Error `Msg m -> Error (`Msg m)
      else
        Lwt.return (Error (`Msg "invalid context (data length <= 2)"))

  let bind = Lwt.bind
  let lift = Lwt.return

  let rec read_loop ?(linger = Cstruct.empty) (t : t) fd =
    let recv_buffer = Bytes.make 2048 '\000' in
    Lwt.catch (fun () ->
      Lwt_unix.recv fd recv_buffer 0 (Bytes.length recv_buffer) [])
     (fun e ->
      Log.err (fun m -> m "error %s reading from resolver" (Printexc.to_string e));
      Lwt.return 0) >>= function
     | 0 ->
       Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit) >|= fun () ->
       t.fd <- None;
       Log.info (fun m -> m "end of file reading from resolver")
     | read_len ->
       let rec handle_data data =
         let cs_len = Cstruct.length data in
         if cs_len > 2 then
           let len = Cstruct.BE.get_uint16 data 0 in
           if cs_len - 2 >= len then
             let packet, rest =
               if cs_len - 2 = len
               then data, Cstruct.empty
               else Cstruct.split data (len + 2)
             in
             let id = Cstruct.BE.get_uint16 packet 2 in
             (match IM.find_opt id t.requests with
              | None -> Log.warn (fun m -> m "received unsolicited data, ignoring")
              | Some (_, cond) ->
                Lwt_condition.broadcast cond (Ok packet));
             handle_data rest
           else
             read_loop ~linger:data t fd
         else
           read_loop ~linger:data t fd
       in
       let cs = Cstruct.of_bytes ~len:read_len recv_buffer in
       handle_data (if Cstruct.length linger = 0 then cs else Cstruct.append linger cs)

  let query_one fd data =
    Lwt.catch (fun () ->
      Lwt_unix.send fd (Cstruct.to_bytes data) 0
        (Cstruct.length data) [] >>= fun res ->
      if res <> Cstruct.length data then
        Lwt_result.fail (`Msg ("oops" ^ (string_of_int res)))
      else
        Lwt_result.return ())
     (fun e -> Lwt.return (Error (`Msg (Printexc.to_string e))))

  let req_all fd t =
    IM.fold (fun _id (data, _) r ->
        r >>= function
        | Error _ as e -> Lwt.return e
        | Ok () -> query_one fd data)
      t.requests (Lwt.return (Ok ()))

  let rec connect_via_tcp_to_ns ?(timeout = Duration.of_sec 5) (t : t) =
    match t.fd with
    | Some _ -> Lwt.return (Ok ())
    | None ->
      let _, (server, port) = nameserver t in
      Lwt_unix.(getprotobyname "tcp" >|= fun x -> x.p_proto) >>= fun proto_number ->
      let fam =
        Ipaddr.(Lwt_unix.(match server with V4 _ -> PF_INET | V6 _ -> PF_INET6))
      in
      let socket = Lwt_unix.socket fam Lwt_unix.SOCK_STREAM proto_number in
      let addr = Lwt_unix.ADDR_INET (Ipaddr_unix.to_inet_addr server, port) in
      Lwt.catch (fun () ->
           Lwt_unix.connect socket addr >|= fun () ->
           Ok ())
        (fun e ->
           Lwt.catch (fun () -> Lwt_unix.close socket) (fun _ -> Lwt.return_unit) >|= fun () ->
           Error (`Msg (Printexc.to_string e))) >>= function
       | Error _ as e -> Lwt.return e
       | Ok () ->
         t.fd <- Some socket;
         Lwt.async (fun () ->
             read_loop t socket >>= fun () ->
             if IM.is_empty t.requests then
               Lwt.return_unit
             else
               connect_via_tcp_to_ns ~timeout t >|= function
               | Error (`Msg msg) ->
                 Log.err (fun m -> m "error while connecting to %a: %s"
                   Ipaddr.pp server msg)
               | Ok () -> ());
         req_all socket t

  let connect t =
    let (proto, (server, port)) = nameserver t in
    let ctx = { t ; fd = None ; timeout_ns = t.timeout_ns ; data = Cstruct.empty } in
    match proto with
    | `Tcp ->
      begin
        connect_via_tcp_to_ns t >|= function
        | Ok () -> Ok ctx
        | Error `Msg msg -> Error (`Msg msg)
      end
    | `Udp ->
      Lwt.catch (fun () ->
        Lwt_unix.(getprotobyname "udp" >|= fun x -> x.p_proto) >>= fun proto_number ->
        let fam =
          Ipaddr.(Lwt_unix.(match server with V4 _ -> PF_INET | V6 _ -> PF_INET6))
        in
        let socket = Lwt_unix.socket fam Lwt_unix.SOCK_DGRAM proto_number in
        let addr = Lwt_unix.ADDR_INET (Ipaddr_unix.to_inet_addr server, port) in
        let ctx = { ctx with fd = Some socket } in
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
