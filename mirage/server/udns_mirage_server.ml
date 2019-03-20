(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_mirage_server" ~doc:"effectful DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (P : Mirage_clock_lwt.PCLOCK) (M : Mirage_clock_lwt.MCLOCK) (TIME : Mirage_time_lwt.S) (S : Mirage_stack_lwt.V4) = struct

  module Dns = Udns_mirage.Make(S)

  module T = S.TCPV4

  let primary ?(on_update = fun _trie -> Lwt.return_unit) ?(timer = 2) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Dns.IPM.empty in

    let maybe_update_state t t' =
      let trie server = Udns_server.((Primary.server server).data) in
      state := t ;
      if Udns_trie.equal (trie t) (trie t') then
        Lwt.return_unit
      else
        on_update t
    in

    let drop ip port =
      tcp_out := Dns.IPM.remove (ip, port) !tcp_out ;
      state := Udns_server.Primary.closed !state ip port
    in
    let send_notify (ip, dport, data) =
      match Dns.IPM.find (ip, dport) !tcp_out with
      | None -> Dns.send_udp stack port ip dport data
      | Some f -> Dns.send_tcp f data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          drop ip dport ;
          Dns.send_udp stack port ip dport data
    in
    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp src src_port) ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, answer, notify = Udns_server.Primary.handle !state now elapsed `Udp src src_port buf in
      maybe_update_state t !state >>= fun () ->
      (match answer with
       | None -> Log.warn (fun m -> m "empty answer") ; Lwt.return_unit
       | Some answer -> Dns.send_udp stack port src src_port answer) >>= fun () ->
      Lwt_list.iter_p send_notify notify
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "DNS server listening on UDP port %d" port) ;
    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp dst_ip dst_port) ;
      let f = Dns.of_flow flow in
      tcp_out := Dns.IPM.add (dst_ip, dst_port) flow !tcp_out ;
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () -> drop dst_ip dst_port ; Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps ()) in
          let elapsed = M.elapsed_ns () in
          let t, answer, notify = Udns_server.Primary.handle !state now elapsed `Tcp dst_ip dst_port data in
          maybe_update_state t !state >>= fun () ->
          Lwt_list.iter_p send_notify notify >>= fun () ->
          match answer with
          | None -> Log.warn (fun m -> m "empty answer") ; loop ()
          | Some answer ->
            Dns.send_tcp flow answer >>= function
            | Ok () -> loop ()
            | Error () -> drop dst_ip dst_port ; Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "DNS server listening on TCP port %d" port) ;
    let rec time () =
      let t, notifies = Udns_server.Primary.timer !state (M.elapsed_ns ()) in
      maybe_update_state t !state >>= fun () ->
      Lwt_list.iter_p send_notify notifies >>= fun () ->
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time

  let secondary ?(on_update = fun _trie -> Lwt.return_unit) ?(timer = 5) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Dns.IM.empty in
    let in_flight = ref Dns.IS.empty in

    let maybe_update_state t t' =
      let trie server = Udns_server.((Secondary.server server).data) in
      state := t ;
      if Udns_trie.equal (trie t) (trie t') then
        Lwt.return_unit
      else
        on_update t
    in

    let rec close ip port =
      (match Dns.IM.find ip !tcp_out with
       | None -> Lwt.return_unit
       | Some f -> T.close f) >>= fun () ->
      tcp_out := Dns.IM.remove ip !tcp_out ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let state', out = Udns_server.Secondary.closed !state now elapsed ip port in
      state := state' ;
      Lwt_list.iter_s request out
    and read_and_handle ip port f =
      Dns.read_tcp f >>= function
      | Error () ->
        Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp ip) ;
        close ip port
      | Ok data ->
        let now = Ptime.v (P.now_d_ps ()) in
        let elapsed = M.elapsed_ns () in
        let t, answer, out =
          Udns_server.Secondary.handle !state now elapsed `Tcp ip data
        in
        maybe_update_state t !state >>= fun () ->
        Lwt_list.iter_s request out >>= fun () ->
        match answer with
        | None -> read_and_handle ip port f
        | Some x ->
          Dns.send_tcp (Dns.flow f) x >>= function
          | Error () ->
            Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.V4.pp ip) ;
            close ip port
          | Ok () -> read_and_handle ip port f
    and request (proto, ip, port, data) =
      match Dns.IM.find ip !tcp_out with
      | None ->
        begin
          if Dns.IS.mem ip !in_flight then
            Lwt.return_unit
          else begin
            Logs.info (fun m -> m "creating connection to %a:%d" Ipaddr.V4.pp ip port) ;
            in_flight := Dns.IS.add ip !in_flight ;
            T.create_connection (S.tcpv4 stack) (ip, port) >>= function
            | Error e ->
              Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                          T.pp_error e Ipaddr.V4.pp ip port) ;
              in_flight := Dns.IS.remove ip !in_flight ;
              Lwt.async (fun () ->
                  TIME.sleep_ns (Duration.of_sec 5) >>= fun () ->
                  close ip port) ;
              Lwt.return_unit
            | Ok flow ->
              Dns.send_tcp flow data >>= function
              | Error () -> close ip port
              | Ok () ->
                tcp_out := Dns.IM.add ip flow !tcp_out ;
                in_flight := Dns.IS.remove ip !in_flight ;
                Lwt.async (fun () -> read_and_handle ip port (Dns.of_flow flow)) ;
                Lwt.return_unit
          end
        end
      | Some flow ->
        Dns.send_tcp flow data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          Log.warn (fun m -> m "closing tcp flow to %a:%d, retrying request"
                       Ipaddr.V4.pp ip port) ;
          T.close flow >>= fun () ->
          tcp_out := Dns.IM.remove ip !tcp_out ;
          request (proto, ip, port, data)
    in

    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp src src_port) ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, answer, out = Udns_server.Secondary.handle !state now elapsed `Udp src buf in
      maybe_update_state t !state >>= fun () ->
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      match answer with
      | None -> Lwt.return_unit
      | Some out -> Dns.send_udp stack port src src_port out
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "secondary DNS listening on UDP port %d" port) ;

    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp dst_ip dst_port) ;
      let f = Dns.of_flow flow in
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () -> Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps ()) in
          let elapsed = M.elapsed_ns () in
          let t, answer, out =
            Udns_server.Secondary.handle !state now elapsed `Tcp dst_ip data
          in
          maybe_update_state t !state >>= fun () ->
          List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
          match answer with
          | None ->
            Log.warn (fun m -> m "no TCP output") ;
            loop ()
          | Some data ->
            Dns.send_tcp flow data >>= function
            | Ok () -> loop ()
            | Error () -> Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "secondary DNS listening on TCP port %d" port) ;

    let rec time () =
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, out = Udns_server.Secondary.timer !state now elapsed in
      maybe_update_state t !state >>= fun () ->
      List.iter (fun x -> Lwt.async (fun () -> request x)) out ;
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time
end
