open Lwt.Infix

module IM = Map.Make(Int)

let src = Logs.Src.create "dns_client_lwt" ~doc:"effectful DNS lwt layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Transport : Dns_client.S
 with type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
 and type +'a io = 'a Lwt.t
 and type stack = unit
= struct
  type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
  type +'a io = 'a Lwt.t
  type stack = unit
  type nameservers =
    | Static of io_addr list
    | Resolv_conf of {
        mutable nameservers : io_addr list;
        mutable digest : Digest.t option
      }
  type t = {
    nameservers : nameservers;
    timeout_ns : int64 ;
    (* TODO: avoid race, use a mvar instead of condition *)
    mutable fd : [ `Plain of Lwt_unix.file_descr | `Tls of Tls_lwt.Unix.t ] option ;
    mutable connected_condition : unit Lwt_condition.t option ;
    mutable requests : (Cstruct.t * (Cstruct.t, [ `Msg of string ]) result Lwt_condition.t) IM.t ;
    mutable he : Happy_eyeballs.t ;
    mutable waiters : ((Ipaddr.t * int) * Lwt_unix.file_descr, [ `Msg of string ]) result Lwt.u Happy_eyeballs.Waiter_map.t ;
    timer_condition : unit Lwt_condition.t ;
  }
  type context = t

  let nameserver_ips = function
    | Static nameservers -> nameservers
    | Resolv_conf { nameservers; _ } -> nameservers

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

  let clock = Mtime_clock.elapsed_ns

  let he_timer_interval = Duration.of_ms 500

  let close_socket fd =
    Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

  let rec handle_action t action =
    (match action with
     | Happy_eyeballs.Connect (host, id, (ip, port)) ->
       Lwt_unix.(getprotobyname "tcp" >|= fun x -> x.p_proto) >>= fun proto_number ->
       let fam =
         Ipaddr.(Lwt_unix.(match ip with V4 _ -> PF_INET | V6 _ -> PF_INET6))
       in
       let socket = Lwt_unix.socket fam Lwt_unix.SOCK_STREAM proto_number in
       let addr = Lwt_unix.ADDR_INET (Ipaddr_unix.to_inet_addr ip, port) in
       Lwt.catch (fun () ->
           Lwt_unix.connect socket addr >>= fun () ->
           let waiters, r = Happy_eyeballs.Waiter_map.find_and_remove id t.waiters in
           t.waiters <- waiters;
           begin match r with
             | Some waiter ->
               Lwt.wakeup_later waiter (Ok ((ip, port), socket));
               Lwt.return_unit
             | None -> close_socket socket
           end >|= fun () ->
           Some (Happy_eyeballs.Connected (host, id, (ip, port))))
         (fun e ->
            let err =
              Fmt.str "error %s connecting to nameserver %a:%d"
                (Printexc.to_string e) Ipaddr.pp ip port
            in
            close_socket socket >|= fun () ->
            Some (Happy_eyeballs.Connection_failed (host, id, (ip, port), err)))
     | Connect_failed (host, id, reason) ->
       let waiters, r = Happy_eyeballs.Waiter_map.find_and_remove id t.waiters in
       t.waiters <- waiters;
       begin match r with
         | Some waiter ->
           let err =
             Fmt.str "connection to %a failed: %s" Domain_name.pp host reason
           in
           Lwt.wakeup_later waiter (Error (`Msg err))
         | None -> ()
       end;
       Lwt.return None
     | a ->
       Log.warn (fun m -> m "ignoring action %a" Happy_eyeballs.pp_action a);
       Lwt.return None) >>= function
    | None -> Lwt.return_unit
    | Some event ->
      let he, actions = Happy_eyeballs.event t.he (clock ()) event in
      t.he <- he;
      Lwt_list.iter_p (handle_action t) actions

  let handle_timer_actions t actions =
    Lwt.async (fun () -> Lwt_list.iter_p (fun a -> handle_action t a) actions)

  let rec he_timer t =
    let open Lwt.Infix in
    let rec loop () =
      let he, cont, actions = Happy_eyeballs.timer t.he (clock ()) in
      t.he <- he ;
      handle_timer_actions t actions ;
      match cont with
      | `Suspend -> he_timer t
      | `Act ->
        Lwt_unix.sleep (Duration.to_f he_timer_interval) >>= fun () ->
        loop ()
    in
    Lwt_condition.wait t.timer_condition >>= fun () ->
    loop ()

  let authenticator =
    let authenticator_ref = ref None in
    fun () ->
      match !authenticator_ref with
      | Some x -> x
      | None -> match Ca_certs.authenticator () with
        | Ok a -> authenticator_ref := Some a ; a
        | Error `Msg m -> invalid_arg ("failed to load trust anchors: " ^ m)

  let decode_resolv_conf data =
    let ( let* ) = Result.bind in
    let authenticator = authenticator () in
    let* ns = Dns_resolvconf.parse data in
    match
      List.flatten
        (List.map
           (fun (`Nameserver ip) ->
              let tls = Tls.Config.client ~authenticator ~ip () in
              [ `Tls (tls, ip, 853) ; `Plaintext (ip, 53) ])
           ns)
    with
    | [] -> Error (`Msg "no nameservers in resolv.conf")
    | ns -> Ok ns

  let resolv_conf () =
    let ( let* ) = Result.bind in
    let* data = read_file "/etc/resolv.conf" in
    let* ns =
      Result.map_error
        (function `Msg msg ->
           Log.warn (fun m -> m "error %s decoding resolv.conf %S" msg data);
           `Msg msg)
        (decode_resolv_conf data)
    in
    Ok (ns, Digest.string data)

  let default_resolver () =
    let authenticator = authenticator () in
    let peer_name = Dns_client.default_resolver_hostname in
    let tls_config = Tls.Config.client ~authenticator ~peer_name () in
    List.map (fun ip -> `Tls (tls_config, ip, 853)) Dns_client.default_resolvers

  let maybe_resolv_conf t =
    match t.nameservers with
    | Static _ -> ()
    | Resolv_conf resolv_conf ->
      let needs_update =
        match read_file "/etc/resolv.conf", resolv_conf.digest with
        | Ok data, Some dgst ->
          let dgst' = Digest.string data in
          if Digest.equal dgst' dgst then
            `No
          else
            `Data (data, dgst')
        | Ok data, None ->
          let digest = Digest.string data in
          `Data (data, digest)
        | Error _, None ->
          `No
        | Error `Msg msg, Some _ ->
          Log.warn (fun m -> m "error reading /etc/resolv.conf: %s" msg);
          `Default
      in
      match needs_update with
      | `No -> ()
      | `Default ->
        resolv_conf.digest <- None;
        resolv_conf.nameservers <- default_resolver ()
      | `Data (data, dgst) ->
        match decode_resolv_conf data with
        | Ok ns ->
          resolv_conf.digest <- Some dgst;
          resolv_conf.nameservers <- ns
        | Error `Msg msg ->
          Log.warn (fun m -> m "error %s decoding resolv.conf: %S" msg data);
          resolv_conf.digest <- None;
          resolv_conf.nameservers <- default_resolver ()

  let create ?nameservers ~timeout () =
    let nameservers =
      match nameservers with
      | Some (`Udp, _) -> invalid_arg "UDP is not supported"
      | Some (`Tcp, ns) -> Static ns
      | None ->
        match resolv_conf () with
        | Error _ -> Resolv_conf { nameservers = default_resolver (); digest = None }
        | Ok (ips, digest) -> Resolv_conf { nameservers = ips; digest = Some digest }
    in
    let t = {
      nameservers ;
      timeout_ns = timeout ;
      fd = None ;
      connected_condition = None ;
      requests = IM.empty ;
      he = Happy_eyeballs.create (clock ()) ;
      waiters = Happy_eyeballs.Waiter_map.empty ;
      timer_condition = Lwt_condition.create () ;
    } in
    Lwt.async (fun () -> he_timer t);
    t

  let nameservers { nameservers; _ } = `Tcp, nameserver_ips nameservers

  let rng = Mirage_crypto_rng.generate ?g:None

  let with_timeout timeout f =
    let timeout =
      Lwt_unix.sleep (Duration.to_f timeout) >|= fun () ->
      Error (`Msg "DNS request timeout")
    in
    Lwt.pick [ f ; timeout ]

  let close _ = Lwt.return_unit

  let send_query fd tx =
    Lwt.catch (fun () ->
      match fd with
      | `Plain fd ->
        Lwt_unix.send fd (Cstruct.to_bytes tx) 0
          (Cstruct.length tx) [] >>= fun res ->
        if res <> Cstruct.length tx then
          Lwt_result.fail (`Msg ("oops" ^ (string_of_int res)))
        else
          Lwt_result.return ()
      | `Tls fd ->
        Lwt_result.ok (Tls_lwt.Unix.write fd tx))
      (fun e -> Lwt.return (Error (`Msg (Printexc.to_string e))))

  let send_recv (t : context) tx =
    if Cstruct.length tx > 4 then
      match t.fd with
      | None -> Lwt.return (Error (`Msg "no connection to the nameserver established"))
      | Some fd ->
        let id = Cstruct.BE.get_uint16 tx 2 in
        with_timeout t.timeout_ns
          (let open Lwt_result.Infix in
           send_query fd tx >>= fun () ->
           let cond = Lwt_condition.create () in
           t.requests <- IM.add id (tx, cond) t.requests;
           let open Lwt.Infix in
           Lwt_condition.wait cond >|= fun data ->
           match data with Ok _ | Error `Msg _ as r -> r) >|= fun r ->
        t.requests <- IM.remove id t.requests;
        r
    else
      Lwt.return (Error (`Msg "invalid DNS packet (data length <= 4)"))

  let bind = Lwt.bind
  let lift = Lwt.return

  let rec read_loop ?(linger = Cstruct.empty) (t : t) fd =
    Lwt.catch (fun () ->
      match fd with
      | `Plain fd ->
        let recv_buffer = Bytes.make 2048 '\000' in
        Lwt_unix.recv fd recv_buffer 0 (Bytes.length recv_buffer) [] >|= fun r ->
        (r, Cstruct.of_bytes recv_buffer)
      | `Tls fd ->
        let recv_buffer = Cstruct.create 2048 in
        Tls_lwt.Unix.read fd recv_buffer >|= fun r ->
        (r, recv_buffer))
     (fun e ->
      Log.err (fun m -> m "error %s reading from resolver" (Printexc.to_string e));
      Lwt.return (0, Cstruct.empty)) >>= function
     | (0, _) ->
       (match fd with
       | `Plain fd -> close_socket fd
       | `Tls fd -> Tls_lwt.Unix.close fd) >|= fun () ->
       t.fd <- None;
       Log.info (fun m -> m "end of file reading from resolver")
     | (read_len, cs) ->
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
       let cs = Cstruct.sub cs 0 read_len in
       handle_data (if Cstruct.length linger = 0 then cs else Cstruct.append linger cs)

  let req_all fd t =
    IM.fold (fun _id (data, _) r ->
        r >>= function
        | Error _ as e -> Lwt.return e
        | Ok () -> send_query fd data)
      t.requests (Lwt.return (Ok ()))

  let to_pairs =
    List.map (function `Plaintext (ip, port) | `Tls (_, ip, port) -> ip, port)

  let find_ns ns (addr, port) =
    List.find (function `Plaintext (ip, p) | `Tls (_, ip, p) ->
        Ipaddr.compare ip addr = 0 && p = port)
      ns

  let rec connect_to_ns_list (t : t) connected_condition nameservers =
    let waiter, notify = Lwt.task () in
    let waiters, id = Happy_eyeballs.Waiter_map.register notify t.waiters in
    t.waiters <- waiters;
    let ns = to_pairs nameservers in
    let he, actions = Happy_eyeballs.connect_ip t.he (clock ()) ~id ns in
    t.he <- he;
    Lwt_condition.signal t.timer_condition ();
    Lwt.async (fun () -> Lwt_list.iter_p (handle_action t) actions);
    waiter >>= function
    | Error `Msg msg ->
      Lwt_condition.broadcast connected_condition ();
      t.connected_condition <- None;
      Lwt.return
        (Error (`Msg (Fmt.str "error %s connecting to resolver %a"
                        msg Fmt.(list ~sep:(any ",") (pair ~sep:(any ":") Ipaddr.pp int))
                        (to_pairs (nameserver_ips t.nameservers)))))
    | Ok (addr, socket) ->
      let continue socket =
        t.fd <- Some socket;
        Lwt.async (fun () ->
            read_loop t socket >>= fun () ->
            if IM.is_empty t.requests then
              Lwt.return_unit
            else
              connect_via_tcp_to_ns t >|= function
              | Error (`Msg msg) ->
                Log.err (fun m -> m "error while connecting to resolver: %s"  msg)
              | Ok () -> ());
        Lwt_condition.broadcast connected_condition ();
        t.connected_condition <- None;
        req_all socket t
      in
      let config = find_ns (nameserver_ips t.nameservers) addr in
      match config with
      | `Plaintext _ -> continue (`Plain socket)
      | `Tls (tls_cfg, _, _) ->
        Lwt.catch (fun () ->
            Tls_lwt.Unix.client_of_fd tls_cfg socket >>= fun f ->
            continue (`Tls f))
          (fun e ->
             Log.warn (fun m -> m "TLS handshake with %a:%d failed: %s"
                          Ipaddr.pp (fst addr) (snd addr) (Printexc.to_string e));
             let ns' =
               List.filter
                 (function
                   | `Tls (_, ip, port) ->
                     not (Ipaddr.compare ip (fst addr) = 0 && port = snd addr)
                   | _ -> true)
                 nameservers
             in
             if ns' = [] then begin
               Lwt_condition.broadcast connected_condition ();
               t.connected_condition <- None;
               Lwt.return (Error (`Msg "no further nameservers configured"))
             end else
               connect_to_ns_list t connected_condition ns')

  and connect_via_tcp_to_ns (t : t) =
    match t.fd, t.connected_condition with
    | Some _, _ -> Lwt.return (Ok ())
    | None, Some w ->
      Lwt_condition.wait w >>= fun () ->
      connect_via_tcp_to_ns t
    | None, None ->
      let connected_condition = Lwt_condition.create () in
      t.connected_condition <- Some connected_condition ;
      maybe_resolv_conf t;
      connect_to_ns_list t connected_condition (nameserver_ips t.nameservers)

  let connect t =
    connect_via_tcp_to_ns t >|= function
    | Ok () -> Ok (`Tcp, t)
    | Error `Msg msg -> Error (`Msg msg)
end

(* Now that we have our {!Transport} implementation we can include the logic
   that goes on top of it: *)
include Dns_client.Make(Transport)

(* initialize the RNG *)
let () = Mirage_crypto_rng_lwt.initialize ()
