(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_mirage_server" ~doc:"effectful DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (P : Mirage_clock_lwt.PCLOCK) (M : Mirage_clock_lwt.MCLOCK) (TIME : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) = struct

  module Dns = Dns_mirage.Make(S)

  module T = S.TCPV4

  let primary ?(on_update = fun ~old:_ _ -> Lwt.return_unit) ?(on_notify = fun _ _ -> Lwt.return None) ?(timer = 2) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Dns.IM.empty in

    let drop ip =
      tcp_out := Dns.IM.remove ip !tcp_out ;
      state := Dns_server.Primary.closed !state ip
    in

    let connect recv_task ip =
      let dport = 53 in
      Log.info (fun m -> m "creating connection to %a:%d" Ipaddr.V4.pp ip dport) ;
      T.create_connection (S.tcpv4 stack) (ip, dport) >>= function
      | Error e ->
        Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                    T.pp_error e Ipaddr.V4.pp ip port) ;
        Lwt.return (Error ())
      | Ok flow ->
        tcp_out := Dns.IM.add ip flow !tcp_out ;
        Lwt.async (recv_task ip dport flow);
        Lwt.return (Ok flow)
    in

    let send_notify recv_task (ip, data) =
      let connect_and_send ip =
        connect recv_task ip >>= function
        | Ok flow -> Dns.send_tcp_multiple flow data
        | Error () -> Lwt.return (Error ())
      in
      (match Dns.IM.find ip !tcp_out with
       | None -> connect_and_send ip
       | Some f -> Dns.send_tcp_multiple f data >>= function
         | Ok () -> Lwt.return (Ok ())
         | Error () -> drop ip ; connect_and_send ip) >>= function
      | Ok () -> Lwt.return_unit
      | Error () ->
        drop ip;
        Lwt_list.iter_p (Dns.send_udp stack port ip 53) data
    in

    let maybe_update_state t =
      let old = !state in
      let trie server = Dns_server.Primary.data server in
      state := t;
      if Dns_trie.equal (trie t) (trie old) then
        Lwt.return_unit
      else
        on_update ~old:(trie old) t
    and maybe_notify recv_task t now ts = function
      | None -> Lwt.return_unit
      | Some n -> on_notify n t >>= function
        | None -> Lwt.return_unit
        | Some (trie, keys) ->
          let state', outs = Dns_server.Primary.with_keys t now ts keys in
          let state'', outs' = Dns_server.Primary.with_data state' now ts trie in
          state := state'';
          Lwt_list.iter_p (send_notify recv_task) (outs @ outs')
    in

    let rec recv_task ip port flow () =
      let f = Dns.of_flow flow in
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () -> drop ip ; Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps ()) in
          let elapsed = M.elapsed_ns () in
          let t, answer, notify, n = Dns_server.Primary.handle_buf !state now elapsed `Tcp ip port data in
          let n' = match n with
            | Some `Keep -> tcp_out := Dns.IM.add ip flow !tcp_out ; None
            | Some `Notify soa -> Some (`Notify soa)
            | Some `Signed_notify soa -> Some (`Signed_notify soa)
            | None -> None
          in
          maybe_update_state t >>= fun () ->
          maybe_notify recv_task t now elapsed n' >>= fun () ->
          (match answer with
           | None -> Log.warn (fun m -> m "empty answer") ; Lwt.return_unit
           | Some answer ->
             Dns.send_tcp flow answer >|= function
             | Ok () -> ()
             | Error () -> drop ip) >>= fun () ->
          Lwt_list.iter_p (send_notify recv_task) notify >>= fun () ->
          loop ()
      in
      loop ()
    in

    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp dst_ip dst_port) ;
      recv_task dst_ip dst_port flow ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "DNS server listening on TCP port %d" port) ;

    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp src src_port) ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, answer, notify, n = Dns_server.Primary.handle_buf !state now elapsed `Udp src src_port buf in
      let n' = match n with
        | None | Some `Keep -> None
        | Some `Notify soa -> Some (`Notify soa)
        | Some `Signed_notify soa -> Some (`Signed_notify soa)
      in
      maybe_update_state t >>= fun () ->
      maybe_notify recv_task t now elapsed n' >>= fun () ->
      (match answer with
       | None -> Log.warn (fun m -> m "empty answer") ; Lwt.return_unit
       | Some answer -> Dns.send_udp stack port src src_port answer) >>= fun () ->
      Lwt_list.iter_p (send_notify recv_task) notify
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "DNS server listening on UDP port %d" port) ;
    let rec time () =
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, notifies = Dns_server.Primary.timer !state now elapsed in
      maybe_update_state t >>= fun () ->
      Lwt_list.iter_p (send_notify recv_task) notifies >>= fun () ->
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time

  let secondary ?(on_update = fun ~old:_ _trie -> Lwt.return_unit) ?(timer = 5) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Dns.IM.empty in
    let tcp_packet_transit = ref Dns.IM.empty in

    let maybe_update_state t =
      let old = !state in
      let trie server = Dns_server.Secondary.data server in
      state := t ;
      if Dns_trie.equal (trie t) (trie old) then
        Lwt.return_unit
      else
        on_update ~old:(trie old) t
    in

    let rec close ip =
      (match Dns.IM.find ip !tcp_out with
       | None -> Lwt.return_unit
       | Some f -> T.close f) >>= fun () ->
      tcp_out := Dns.IM.remove ip !tcp_out ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let state', out = Dns_server.Secondary.closed !state now elapsed ip in
      state := state' ;
      Lwt_list.iter_s request out
    and read_and_handle ip f =
      Dns.read_tcp f >>= function
      | Error () ->
        Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp ip) ;
        close ip >>= fun () ->
        (* re-send once *)
        begin match Dns.IM.find ip !tcp_packet_transit with
          | None -> Lwt.return_unit
          | Some data -> request ~record:false data
        end
      | Ok data ->
        let now = Ptime.v (P.now_d_ps ()) in
        let elapsed = M.elapsed_ns () in
        let t, answer, out =
          Dns_server.Secondary.handle_buf !state now elapsed `Tcp ip data
        in
        maybe_update_state t >>= fun () ->
        (match answer with
         | None -> Lwt.return (Ok ())
         | Some x ->
           Dns.send_tcp (Dns.flow f) x >>= function
           | Error () ->
             Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp ip) ;
             close ip >|= fun () -> Error ()
           | Ok () -> Lwt.return (Ok ())) >>= fun r ->
        Lwt_list.iter_s request out >>= fun () ->
        match r with
        | Ok () -> read_and_handle ip f
        | Error () -> Lwt.return_unit
    and request ?(record = true) (proto, ip, data) =
      let dport = 53 in
      if record then
        tcp_packet_transit := Dns.IM.add ip (proto, ip, data) !tcp_packet_transit;
      match Dns.IM.find ip !tcp_out with
      | None ->
        begin
          Log.info (fun m -> m "creating connection to %a:%d" Ipaddr.V4.pp ip dport) ;
          T.create_connection (S.tcpv4 stack) (ip, dport) >>= function
          | Error e ->
            Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                        T.pp_error e Ipaddr.V4.pp ip dport) ;
            Lwt.async (fun () ->
                TIME.sleep_ns (Duration.of_sec 5) >>= fun () ->
                close ip) ;
            Lwt.return_unit
          | Ok flow ->
            tcp_out := Dns.IM.add ip flow !tcp_out ;
            Dns.send_tcp flow data >>= function
            | Error () -> close ip
            | Ok () ->
              Lwt.async (fun () -> read_and_handle ip (Dns.of_flow flow)) ;
              Lwt.return_unit
        end
      | Some flow ->
        Dns.send_tcp flow data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          Log.warn (fun m -> m "closing tcp flow to %a:%d, retrying request"
                       Ipaddr.V4.pp ip dport) ;
          T.close flow >>= fun () ->
          tcp_out := Dns.IM.remove ip !tcp_out ;
          request (proto, ip, data)
    in

    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp src src_port) ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, answer, out = Dns_server.Secondary.handle_buf !state now elapsed `Udp src buf in
      maybe_update_state t >>= fun () ->
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      match answer with
      | None -> Lwt.return_unit
      | Some out -> Dns.send_udp stack port src src_port out
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "secondary DNS listening on UDP port %d" port) ;

    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      tcp_out := Dns.IM.add dst_ip flow !tcp_out ;
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp dst_ip dst_port) ;
      let f = Dns.of_flow flow in
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () -> tcp_out := Dns.IM.remove dst_ip !tcp_out ; Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps ()) in
          let elapsed = M.elapsed_ns () in
          let t, answer, out =
            Dns_server.Secondary.handle_buf !state now elapsed `Tcp dst_ip data
          in
          maybe_update_state t >>= fun () ->
          List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
          match answer with
          | None ->
            Log.warn (fun m -> m "no TCP output") ;
            loop ()
          | Some data ->
            Dns.send_tcp flow data >>= function
            | Ok () -> loop ()
            | Error () -> tcp_out := Dns.IM.remove dst_ip !tcp_out ; Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "secondary DNS listening on TCP port %d" port) ;

    let rec time () =
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, out = Dns_server.Secondary.timer !state now elapsed in
      maybe_update_state t >>= fun () ->
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time
end
