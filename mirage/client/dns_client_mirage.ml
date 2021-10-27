open Lwt.Infix

let src = Logs.Src.create "dns_client_mirage" ~doc:"effectful DNS client layer"
module Log = (val Logs.src_log src : Logs.LOG)

module IM = Map.Make(Int)

module Make (R : Mirage_random.S) (T : Mirage_time.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (S : Mirage_stack.V4V6) = struct

  module TLS = Tls_mirage.Make(S.TCP)
  module CA = Ca_certs_nss.Make(P)

  module Transport : Dns_client.S
    with type stack = S.t
     and type +'a io = 'a Lwt.t
     and type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ] = struct
    type stack = S.t
    type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
    type +'a io = 'a Lwt.t
    type t = {
      nameservers : io_addr list ;
      timeout_ns : int64 ;
      stack : stack ;
      mutable flow : [`Plain of S.TCP.flow | `Tls of TLS.flow ] option ;
      mutable requests : (Cstruct.t * (Cstruct.t, [ `Msg of string ]) result Lwt_condition.t) IM.t ;
      mutable he : Happy_eyeballs.t ;
      mutable waiters : ((Ipaddr.t * int) * S.TCP.flow, [ `Msg of string ]) result Lwt.u Happy_eyeballs.Waiter_map.t ;
      timer_condition : unit Lwt_condition.t ;
    }
    type context = {
      t : t ;
      mutable timeout_ns : int64 ;
      mutable data : Cstruct.t ;
    }

    let clock = M.elapsed_ns
    let he_timer_interval = Duration.of_ms 500

    let rec handle_action t action =
      (match action with
       | Happy_eyeballs.Connect (host, id, addr) ->
         begin
           S.TCP.create_connection (S.tcp t.stack) addr >>= function
           | Error e ->
             Log.err (fun m -> m "error connecting to nameserver %a: %a"
                         Ipaddr.pp (fst addr) S.TCP.pp_error e) ;
             Lwt.return (Some (Happy_eyeballs.Connection_failed (host, id, addr)))
           | Ok flow ->
             let waiters, r = Happy_eyeballs.Waiter_map.find_and_remove id t.waiters in
             t.waiters <- waiters;
             begin match r with
               | Some waiter -> Lwt.wakeup_later waiter (Ok (addr, flow)); Lwt.return_unit
               | None -> S.TCP.close flow
             end >|= fun () ->
             Some (Happy_eyeballs.Connected (host, id, addr))
         end
       | Connect_failed (_host, id) ->
         let waiters, r = Happy_eyeballs.Waiter_map.find_and_remove id t.waiters in
         t.waiters <- waiters;
         begin match r with
           | Some waiter -> Lwt.wakeup_later waiter (Error (`Msg "connection failed"))
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
          T.sleep_ns he_timer_interval >>= fun () ->
          loop ()
      in
      Lwt_condition.wait t.timer_condition >>= fun () ->
      loop ()

    let create ?nameservers ~timeout stack =
      let nameservers = match nameservers with
        | None | Some (`Tcp, []) ->
          let authenticator = match CA.authenticator () with
            | Ok a -> a
            | Error `Msg m -> invalid_arg ("bad CA certificates " ^ m)
          in
          let tls_cfg =
            let peer_name = Dns_client.default_resolver_hostname in
            Tls.Config.client ~authenticator ~peer_name ()
          in
          List.flatten
            (List.map
               (fun ip -> [ `Tls (tls_cfg, ip, 853) ; `Plaintext (ip, 53) ])
               Dns_client.default_resolvers)
        | Some (`Udp, _) -> invalid_arg "UDP is not supported"
        | Some (`Tcp, ns) -> ns
      in
      let t = {
        nameservers ;
        timeout_ns = timeout ;
        stack ;
        flow = None ;
        requests = IM.empty ;
        he = Happy_eyeballs.create (clock ()) ;
        waiters = Happy_eyeballs.Waiter_map.empty ;
        timer_condition = Lwt_condition.create () ;
      } in
      Lwt.async (fun () -> he_timer t);
      t

    let nameservers { nameservers ; _ } = `Tcp, nameservers
    let rng = R.generate ?g:None

    let with_timeout time_left f =
      let timeout =
        T.sleep_ns time_left >|= fun () ->
        Error (`Msg "DNS request timeout")
      in
      let start = clock () in
      Lwt.pick [ f ; timeout ] >|= fun result ->
      let stop = clock () in
      result, Int64.sub time_left (Int64.sub stop start)

    let bind = Lwt.bind
    let lift = Lwt.return

    let rec read_loop ?(linger = Cstruct.empty) t flow =
      let process cs =
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
               | Some (_, cond) -> Lwt_condition.broadcast cond (Ok packet));
              handle_data rest
            else
              read_loop ~linger:data t flow
          else
            read_loop ~linger:data t flow
        in
        handle_data (if Cstruct.length linger = 0 then cs else Cstruct.append linger cs)
      in
      match flow with
      | `Plain flow ->
        begin
          S.TCP.read flow >>= function
          | Error e ->
            t.flow <- None;
            Log.err (fun m -> m "error %a reading from resolver" S.TCP.pp_error e);
            Lwt.return_unit
          | Ok `Eof ->
            t.flow <- None;
            Log.info (fun m -> m "end of file reading from resolver");
            Lwt.return_unit
          | Ok (`Data cs) ->
            process cs
        end
      | `Tls flow ->
        begin
          TLS.read flow >>= function
          | Error e ->
            t.flow <- None;
            Log.err (fun m -> m "error %a reading from resolver" TLS.pp_error e);
            Lwt.return_unit
          | Ok `Eof ->
            t.flow <- None;
            Log.info (fun m -> m "end of file reading from resolver");
            Lwt.return_unit
          | Ok (`Data cs) ->
            process cs
        end

    let query_one flow data =
      match flow with
      | `Plain flow ->
        begin
          S.TCP.write flow data >>= function
          | Error e ->
            Lwt.return (Error (`Msg (Fmt.to_to_string S.TCP.pp_write_error e)))
          | Ok () -> Lwt.return (Ok ())
        end
      | `Tls flow ->
        begin
          TLS.write flow data >>= function
          | Error e ->
            Lwt.return (Error (`Msg (Fmt.to_to_string TLS.pp_write_error e)))
          | Ok () -> Lwt.return (Ok ())
        end

    let req_all flow t =
      IM.fold (fun _id (data, _) r ->
          r >>= function
          | Error _ as e -> Lwt.return e
          | Ok () -> query_one flow data)
        t.requests (Lwt.return (Ok ()))

    let to_pairs =
      List.map (function `Plaintext (ip, port) | `Tls (_, ip, port) -> ip, port)

    let find_ns ns (addr, port) =
      List.find (function `Plaintext (ip, p) | `Tls (_, ip, p) ->
          Ipaddr.compare ip addr = 0 && p = port)
        ns

    let rec connect_ns t =
      let waiter, notify = Lwt.task () in
      let waiters, id = Happy_eyeballs.Waiter_map.register notify t.waiters in
      t.waiters <- waiters;
      let ns = to_pairs t.nameservers in
      let he, actions = Happy_eyeballs.connect_ip t.he (clock ()) ~id ns in
      t.he <- he;
      Lwt_condition.signal t.timer_condition ();
      Lwt.async (fun () -> Lwt_list.iter_p (handle_action t) actions);
      waiter >>= function
      | Error `Msg msg ->
        Log.err (fun m -> m "error connecting to resolver %s" msg);
        Lwt.return (Error (`Msg "connect failure"))
      | Ok (addr, flow) ->
        let config = find_ns t.nameservers addr in
        (match config with
         | `Plaintext _ -> Lwt.return (`Plain flow)
         | `Tls (tls_cfg, _ip, _port) ->
           TLS.client_of_flow tls_cfg flow >>= function
           | Error e ->
             Log.err (fun m -> m "error %a establishing TLS connection to %a:%d"
                         TLS.pp_write_error e Ipaddr.pp (fst addr) (snd addr));
             Lwt.fail_with "TLS handshake error"
           | Ok tls -> Lwt.return (`Tls tls)) >>= fun flow ->
        t.flow <- Some flow;
        Lwt.async (fun () ->
           read_loop t flow >>= fun () ->
           if not (IM.is_empty t.requests) then
             connect_ns t >|= function
             | Error `Msg msg ->
               Log.err (fun m -> m "error while connecting to resolver: %s" msg)
             | Ok () -> ()
           else
             Lwt.return_unit);
        req_all flow t

    let connect t =
      let ctx = { t ; timeout_ns = t.timeout_ns ; data = Cstruct.empty } in
      match t.flow with
      | Some _ -> Lwt.return (Ok ctx)
      | None ->
        connect_ns t >|= function
        | Ok () -> Ok ctx
        | Error `Msg msg -> Error (`Msg msg)

    let close _f =
      (* ignoring this here *)
      Lwt.return_unit

    let recv { t ; timeout_ns ; data } =
      if Cstruct.length data > 2 then
        let cond = Lwt_condition.create () in
        let id = Cstruct.BE.get_uint16 data 2 in
        t.requests <- IM.add id (data, cond) t.requests;
        with_timeout timeout_ns (Lwt_condition.wait cond) >|= fun (data, _) ->
        t.requests <- IM.remove id t.requests;
        match data with
        | Ok cs -> Ok cs
        | Error `Msg m -> Error (`Msg m)
      else
        Lwt.return (Error (`Msg "invalid context (data length <= 2)"))

    let send ({ t ; timeout_ns ; _ } as ctx) s =
      match t.flow with
      | None -> Lwt.return (Error (`Msg "no connection to resolver"))
      | Some flow ->
        ctx.data <- s;
        with_timeout timeout_ns (query_one flow s) >|= function
        | Ok (), timeout_ns -> ctx.timeout_ns <- timeout_ns; Ok ()
        | Error _ as e, _ -> e
  end

  include Dns_client.Make(Transport)
end
