(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

open Lwt.Infix

let src = Logs.Src.create "dns_mirage" ~doc:"effectful DNS layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (TIME : TIME) (S : STACKV4) = struct

  module IM = Map.Make(Ipaddr.V4)

  module U = S.UDPV4
  module T = S.TCPV4

  type f = {
    flow : T.flow ;
    mutable linger : Cstruct.t ;
  }

  let of_flow flow = { flow ; linger = Cstruct.empty }

  let flow { flow ; _ } = flow

  let rec read_exactly f length =
    let dst_ip, dst_port = T.dst f.flow in
    if Cstruct.len f.linger >= length then
      let a, b = Cstruct.split f.linger length in
      f.linger <- b ;
      Lwt.return (Ok a)
    else
      T.read f.flow >>= function
      | Ok `Eof ->
        Log.warn (fun m -> m "end of file on flow %a:%d" Ipaddr.V4.pp_hum dst_ip dst_port) ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Error e ->
        Log.err (fun m -> m "error %a reading flow %a:%d" T.pp_error e Ipaddr.V4.pp_hum dst_ip dst_port) ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Ok (`Data b) ->
        f.linger <- Cstruct.append f.linger b ;
        read_exactly f length

  let send_udp stack src_port dst dst_port data =
    Log.info (fun m -> m "udp: sending %d bytes from %d to %a:%d"
                 (Cstruct.len data) src_port Ipaddr.V4.pp_hum dst dst_port) ;
    U.write ~src_port ~dst ~dst_port (S.udpv4 stack) data >|= function
    | Error e -> Log.warn (fun m -> m "udp: failure %a while sending from %d to %a:%d"
                              U.pp_error e src_port Ipaddr.V4.pp_hum dst dst_port)
    | Ok () -> ()

  let send_tcp flow answer =
    let dst_ip, dst_port = T.dst flow in
    Log.info (fun m -> m "tcp: sending %d bytes to %a:%d" (Cstruct.len answer) Ipaddr.V4.pp_hum dst_ip dst_port) ;
    let len = Cstruct.create 2 in
    Cstruct.BE.set_uint16 len 0 (Cstruct.len answer) ;
    T.write flow (Cstruct.append len answer) >>= function
    | Ok () -> Lwt.return (Ok ())
    | Error e ->
      Log.err (fun m -> m "tcp: error %a while writing to %a:%d" T.pp_write_error e Ipaddr.V4.pp_hum dst_ip dst_port) ;
      T.close flow >|= fun () ->
      Error ()

  let read_tcp flow =
    read_exactly flow 2 >>= function
    | Error () -> Lwt.return (Error ())
    | Ok l ->
      let len = Cstruct.BE.get_uint16 l 0 in
      read_exactly flow len

  let primary stack pclock mclock ?(timer = 2) ?(port = 53) t =
    let state = ref t in
    let send_notify (ip, data) = send_udp stack port ip port data in
    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp_hum src src_port) ;
      let now = Ptime.v (P.now_d_ps pclock) in
      let elapsed = M.elapsed_ns mclock in
      let t, answer, notify = UDns_server.Primary.handle !state now elapsed `Udp src buf in
      state := t ;
      (match answer with
       | None -> Log.warn (fun m -> m "empty answer") ; Lwt.return_unit
       | Some answer -> send_udp stack port src src_port answer) >>= fun () ->
      Lwt_list.iter_p send_notify notify
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "DNS server listening on UDP port %d" port) ;
    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp_hum dst_ip dst_port) ;
      let f = of_flow flow in
      let rec loop () =
        read_tcp f >>= function
        | Error () -> Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps pclock) in
          let elapsed = M.elapsed_ns mclock in
          let t, answer, notify = UDns_server.Primary.handle !state now elapsed `Tcp dst_ip data in
          state := t ;
          Lwt_list.iter_p send_notify notify >>= fun () ->
          match answer with
          | None -> Log.warn (fun m -> m "empty answer") ; loop ()
          | Some answer ->
            send_tcp flow answer >>= function
            | Ok () -> loop ()
            | Error () -> Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "DNS server listening on TCP port %d" port) ;
    let rec time () =
      let t, notifies = UDns_server.Primary.timer !state (M.elapsed_ns mclock) in
      state := t ;
      Lwt_list.iter_p send_notify notifies >>= fun () ->
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time

  let secondary stack pclock mclock ?(timer = 5) ?(port = 53) t =
    let state = ref t in
    let tcp_out = ref IM.empty in

    let rec read_and_handle ip f =
      read_tcp f >>= function
      | Error () ->
        Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp_hum ip) ;
        tcp_out := IM.remove ip !tcp_out ;
        T.close f.flow
      | Ok data ->
        let now = Ptime.v (P.now_d_ps pclock) in
        let elapsed = M.elapsed_ns mclock in
        let t, answer, out =
          UDns_server.Secondary.handle !state now elapsed `Tcp ip data
        in
        state := t ;
        (* assume that answer is empty *)
        (match answer with Some _ -> Log.warn (fun m -> m "got unexpected answer") | None -> ()) ;
        Lwt_list.iter_s request out >>= fun () ->
        read_and_handle ip f
    and request (proto, ip, data) =
      match IM.find ip !tcp_out with
      | exception Not_found ->
        begin
          T.create_connection (S.tcpv4 stack) (ip, port) >>= function
          | Error e ->
            Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                        T.pp_error e Ipaddr.V4.pp_hum ip port) ;
            Lwt.return_unit
          | Ok flow ->
            send_tcp flow data >>= function
            | Error () -> T.close flow
            | Ok () ->
              tcp_out := IM.add ip flow !tcp_out ;
              Lwt.async (fun () -> read_and_handle ip (of_flow flow)) ;
              Lwt.return_unit
        end
      | flow ->
        send_tcp flow data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          Log.warn (fun m -> m "closing tcp flow to %a:%d, retrying request"
                       Ipaddr.V4.pp_hum ip port) ;
          tcp_out := IM.remove ip !tcp_out ;
          T.close flow >>= fun () ->
          request (proto, ip, data)
    in

    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp_hum src src_port) ;
      let now = Ptime.v (P.now_d_ps pclock) in
      let elapsed = M.elapsed_ns mclock in
      let t, answer, out = UDns_server.Secondary.handle !state now elapsed `Udp src buf in
      state := t ;
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      match answer with
      | None -> Lwt.return_unit
      | Some out -> send_udp stack port src src_port out
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "secondary DNS listening on UDP port %d" port) ;

    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp_hum dst_ip dst_port) ;
      let f = of_flow flow in
      let rec loop () =
        read_tcp f >>= function
        | Error () -> Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps pclock) in
          let elapsed = M.elapsed_ns mclock in
          let t, answer, out =
            UDns_server.Secondary.handle !state now elapsed `Tcp dst_ip data
          in
          state := t ;
          List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
          match answer with
          | None ->
            Log.warn (fun m -> m "no TCP output") ;
            loop ()
          | Some data ->
            send_tcp flow data >>= function
            | Ok () -> loop ()
            | Error () -> Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "secondary DNS listening on TCP port %d" port) ;

    let rec time () =
      let now = Ptime.v (P.now_d_ps pclock) in
      let elapsed = M.elapsed_ns mclock in
      let t, out = UDns_server.Secondary.timer !state now elapsed in
      state := t ;
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time

  module FM = Map.Make(struct
      type t = Ipaddr.V4.t * int
      let compare (ip, p) (ip', p') =
        match Ipaddr.V4.compare ip ip' with
        | 0 -> compare p p'
        | x -> x
    end)

  let resolver stack pclock mclock ?(root = false) ?(timer = 500) ?(port = 53) t =
    (* according to RFC5452 4.5, we can chose source port between 1024-49152 *)
    let sport () = 1024 + Randomconv.int ~bound:48128 R.generate in
    let state = ref t in
    let tcp_in = ref FM.empty in
    let tcp_out = ref IM.empty in

    let rec client_out dst port =
      T.create_connection (S.tcpv4 stack) (dst, port) >|= function
      | Error e ->
        (* do i need to report this back into the resolver? what are their options then? *)
        Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                    T.pp_error e Ipaddr.V4.pp_hum dst port) ;
        Error ()
      | Ok flow ->
        Log.debug (fun m -> m "established new outgoing TCP connection to %a:%d"
                      Ipaddr.V4.pp_hum dst port);
        tcp_out := IM.add dst flow !tcp_out ;
        Lwt.async (fun () ->
            let f = of_flow flow in
            let rec loop () =
              read_tcp f >>= function
              | Error () ->
                Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp_hum dst) ;
                tcp_out := IM.remove dst !tcp_out ;
                Lwt.return_unit
              | Ok data ->
                let now = Ptime.v (P.now_d_ps pclock) in
                let ts = M.elapsed_ns mclock in
                let new_state, answers, queries =
                  UDns_resolver.handle !state now ts false `Tcp dst port data
                in
                state := new_state ;
                Lwt_list.iter_p handle_answer answers >>= fun () ->
                Lwt_list.iter_p handle_query queries >>= fun () ->
                loop ()
            in
            loop ()) ;
        Ok ()
    and client_tcp dst port data =
      match try Some (IM.find dst !tcp_out) with Not_found -> None with
      | None ->
        begin
          client_out dst port >>= function
          | Error () ->
            let sport = sport () in
            S.listen_udpv4 stack ~port:sport (udp_cb false) ;
            send_udp stack sport dst port data
          | Ok () -> client_tcp dst port data
        end
      | Some x ->
        send_tcp x data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          tcp_out := IM.remove dst !tcp_out ;
          client_tcp dst port data
    and maybe_tcp dst port data =
      (try
         let flow = IM.find dst !tcp_out in
         send_tcp flow data
       with Not_found -> Lwt.return (Error ())) >>= function
      | Ok () -> Lwt.return_unit
      | Error () ->
        let sport = sport () in
        S.listen_udpv4 stack ~port:sport (udp_cb false) ;
        send_udp stack sport dst port data
    and handle_query (proto, dst, data) = match proto with
      | `Udp -> maybe_tcp dst port data
      | `Tcp -> client_tcp dst port data
    and handle_answer (proto, dst, dst_port, data) = match proto with
      | `Udp -> send_udp stack port dst dst_port data
      | `Tcp -> match try Some (FM.find (dst, dst_port) !tcp_in) with Not_found -> None with
        | None ->
          Log.err (fun m -> m "wanted to answer %a:%d via TCP, but couldn't find a flow"
                       Ipaddr.V4.pp_hum dst dst_port) ;
          Lwt.return_unit
        | Some flow -> send_tcp flow data >|= function
          | Ok () -> ()
          | Error () -> tcp_in := FM.remove (dst, dst_port) !tcp_in
    and udp_cb req ~src ~dst:_ ~src_port buf =
      let now = Ptime.v (P.now_d_ps pclock)
      and ts = M.elapsed_ns mclock
      in
      let new_state, answers, queries =
        UDns_resolver.handle !state now ts req `Udp src src_port buf
      in
      state := new_state ;
      Lwt_list.iter_p handle_answer answers >>= fun () ->
      Lwt_list.iter_p handle_query queries
    in
    S.listen_udpv4 stack ~port (udp_cb true) ;
    Log.app (fun f -> f "DNS resolver listening on UDP port %d" port);

    let tcp_cb query flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp_hum dst_ip dst_port) ;
      tcp_in := FM.add (dst_ip, dst_port) flow !tcp_in ;
      let f = of_flow flow in
      let rec loop () =
        read_tcp f >>= function
        | Error () ->
          tcp_in := FM.remove (dst_ip, dst_port) !tcp_in ;
          Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps pclock) in
          let ts = M.elapsed_ns mclock in
          let new_state, answers, queries =
            UDns_resolver.handle !state now ts query `Tcp dst_ip dst_port data
          in
          state := new_state ;
          Lwt_list.iter_p handle_answer answers >>= fun () ->
          Lwt_list.iter_p handle_query queries >>= fun () ->
          loop ()
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port (tcp_cb true) ;
    Log.info (fun m -> m "DNS resolver listening on TCP port %d" port) ;

    let rec stats_reporter () =
      UDns_resolver.stats !state ;
      TIME.sleep_ns (Duration.of_min 5) >>= fun () ->
      stats_reporter ()
    in
    Lwt.async stats_reporter ;

    let rec time () =
      let new_state, answers, queries =
        UDns_resolver.timer !state (M.elapsed_ns mclock)
      in
      state := new_state ;
      Lwt_list.iter_p handle_answer answers >>= fun () ->
      Lwt_list.iter_p handle_query queries >>= fun () ->
      TIME.sleep_ns (Duration.of_ms timer) >>= fun () ->
      time ()
    in
    Lwt.async time ;

    if root then
      let rec root () =
        let new_state, q = UDns_resolver.query_root !state R.generate (M.elapsed_ns mclock) `Tcp in
        state := new_state ;
        handle_query q >>= fun () ->
        TIME.sleep_ns (Duration.of_day 6) >>= fun () ->
        root ()
      in
      Lwt.async root
end
