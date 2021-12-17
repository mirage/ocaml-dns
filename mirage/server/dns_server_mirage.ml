(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_server_mirage" ~doc:"effectful DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (P : Mirage_clock.PCLOCK) (M : Mirage_clock.MCLOCK) (TIME : Mirage_time.S) (S : Tcpip.Stack.V4V6) = struct

  let inc =
    let f = function
      | `Udp_query -> "udp queries"
      | `Udp_answer -> "udp answers"
      | `Tcp_query -> "tcp queries"
      | `Tcp_answer -> "tcp answers"
      | `Tcp -> "tcp-server"
      | `Tcp_client -> "tcp-client"
      | `Tcp_keep -> "keep tcp flow"
      | `Notify -> "request"
      | `On_update -> "on update"
      | `On_notify -> "on notify"
      | `Tcp_cache_add -> "tcp cache add"
      | `Tcp_cache_drop -> "tcp cache drop"
    in
    let src = Dns.counter_metrics ~f "dns-server-mirage" in
    (fun x -> Metrics.add src (fun x -> x) (fun d -> d x))

  module Dns = Dns_mirage.Make(S)
  module T = S.TCP

  let primary ?(on_update = fun ~old:_ ~authenticated_key:_ ~update_source:_ _ -> Lwt.return_unit) ?(on_notify = fun _ _ -> Lwt.return None) ?(timer = 2) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Ipaddr.Map.empty in

    let drop ip =
      if Ipaddr.Map.mem ip !tcp_out then begin
        inc `Tcp_cache_drop;
        tcp_out := Ipaddr.Map.remove ip !tcp_out ;
        state := Dns_server.Primary.closed !state ip
      end
    in

    let connect recv_task ip =
      inc `Tcp_client;
      let dport = 53 in
      Log.debug (fun m -> m "creating connection to %a:%d" Ipaddr.pp ip dport) ;
      T.create_connection (S.tcp stack) (ip, dport) >>= function
      | Error e ->
        Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                    T.pp_error e Ipaddr.pp ip port) ;
        Lwt.return (Error ())
      | Ok flow ->
        inc `Tcp_cache_add;
        tcp_out := Ipaddr.Map.add ip flow !tcp_out ;
        Lwt.async (recv_task ip dport flow);
        Lwt.return (Ok flow)
    in

    let send_notify recv_task (ip, data) =
      inc `Notify;
      let connect_and_send ip =
        connect recv_task ip >>= function
        | Ok flow -> Dns.send_tcp_multiple flow data
        | Error () -> Lwt.return (Error ())
      in
      (match Ipaddr.Map.find_opt ip !tcp_out with
       | None -> connect_and_send ip
       | Some f -> Dns.send_tcp_multiple f data >>= function
         | Ok () -> Lwt.return (Ok ())
         | Error () -> drop ip ; connect_and_send ip) >>= function
      | Ok () -> Lwt.return_unit
      | Error () ->
        drop ip;
        Lwt_list.iter_p (Dns.send_udp stack port ip 53) data
    in

    let maybe_update_state key ip t =
      let old = !state in
      let trie server = Dns_server.Primary.data server in
      state := t;
      if Dns_trie.equal (trie t) (trie old) then
        Lwt.return_unit
      else begin
        inc `On_update ; on_update ~old:(trie old) ~authenticated_key:key ~update_source:ip t
      end
    and maybe_notify recv_task t now ts = function
      | None -> Lwt.return_unit
      | Some n -> inc `On_notify ; on_notify n t >>= function
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
          inc `Tcp_query;
          let now = Ptime.v (P.now_d_ps ()) in
          let ts = M.elapsed_ns () in
          let t, answers, notify, n, key =
            Dns_server.Primary.handle_buf !state now ts `Tcp ip port data
          in
          let n' = match n with
            | Some `Keep -> inc `Tcp_cache_add ; inc `Tcp_keep ; tcp_out := Ipaddr.Map.add ip flow !tcp_out ; None
            | Some `Notify soa -> Some (`Notify soa)
            | Some `Signed_notify soa -> Some (`Signed_notify soa)
            | None -> None
          in
          maybe_update_state key ip t >>= fun () ->
          maybe_notify recv_task t now ts n' >>= fun () ->
          if answers <> [] then inc `Tcp_answer;
          (Dns.send_tcp_multiple flow answers >|= function
            | Ok () -> ()
            | Error () -> drop ip) >>= fun () ->
          Lwt_list.iter_p (send_notify recv_task) notify >>= fun () ->
          loop ()
      in
      loop ()
    in

    let tcp_cb flow =
      inc `Tcp;
      let dst_ip, dst_port = T.dst flow in
      recv_task dst_ip dst_port flow ()
    in
    S.TCP.listen (S.tcp stack) ~port tcp_cb ;
    Log.info (fun m -> m "DNS server listening on TCP port %d" port) ;

    let udp_cb ~src ~dst:_ ~src_port buf =
      inc `Udp_query;
      let now = Ptime.v (P.now_d_ps ()) in
      let ts = M.elapsed_ns () in
      let t, answers, notify, n, key =
        Dns_server.Primary.handle_buf !state now ts `Udp src src_port buf
      in
      let n' = match n with
        | None | Some `Keep -> None
        | Some `Notify soa -> Some (`Notify soa)
        | Some `Signed_notify soa -> Some (`Signed_notify soa)
      in
      maybe_update_state key src t >>= fun () ->
      maybe_notify recv_task t now ts n' >>= fun () ->
      if answers <> [] then inc `Udp_answer;
      (Lwt_list.iter_s (Dns.send_udp stack port src src_port) answers) >>= fun () ->
      Lwt_list.iter_p (send_notify recv_task) notify
    in
    S.UDP.listen (S.udp stack) ~port udp_cb ;
    Log.info (fun m -> m "DNS server listening on UDP port %d" port) ;
    let rec time () =
      let now = Ptime.v (P.now_d_ps ()) in
      let ts = M.elapsed_ns () in
      let t, notifies = Dns_server.Primary.timer !state now ts in
      maybe_update_state None Ipaddr.(V4 V4.localhost) t >>= fun () ->
      Lwt_list.iter_p (send_notify recv_task) notifies >>= fun () ->
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time

  let secondary ?(on_update = fun ~old:_ _trie -> Lwt.return_unit) ?(timer = 5) ?(port = 53) stack t =
    let state = ref t in
    let tcp_out = ref Ipaddr.Map.empty in

    let maybe_update_state t =
      let old = !state in
      let trie server = Dns_server.Secondary.data server in
      state := t ;
      if Dns_trie.equal (trie t) (trie old) then
        Lwt.return_unit
      else begin
        inc `On_update ; on_update ~old:(trie old) t
      end
    in

    let rec close ip =
      (match Ipaddr.Map.find_opt ip !tcp_out with
       | None -> Lwt.return_unit
       | Some f -> T.close f) >>= fun () ->
      tcp_out := Ipaddr.Map.remove ip !tcp_out ;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let state', out = Dns_server.Secondary.closed !state now elapsed ip in
      state := state' ;
      request (ip, out)
    and read_and_handle ip f =
      Dns.read_tcp f >>= function
      | Error () ->
        Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.pp ip) ;
        close ip
      | Ok data ->
        inc `Tcp_query;
        let now = Ptime.v (P.now_d_ps ()) in
        let elapsed = M.elapsed_ns () in
        let t, answer, out =
          Dns_server.Secondary.handle_buf !state now elapsed `Tcp ip data
        in
        maybe_update_state t >>= fun () ->
        (match answer with
         | None -> Lwt.return (Ok ())
         | Some x ->
           inc `Tcp_answer;
           Dns.send_tcp (Dns.flow f) x >>= function
           | Error () ->
             Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.pp ip) ;
             close ip >|= fun () -> Error ()
           | Ok () -> Lwt.return (Ok ())) >>= fun r ->
        (match out with
         | None -> Lwt.return_unit
         | Some (ip, data) -> request_one (ip, data)) >>= fun () ->
        match r with
        | Ok () -> read_and_handle ip f
        | Error () -> Lwt.return_unit
    and request (ip, data) =
      inc `Notify;
      let dport = 53 in
      match Ipaddr.Map.find_opt ip !tcp_out with
      | None ->
        begin
          Log.debug (fun m -> m "creating connection to %a:%d" Ipaddr.pp ip dport) ;
          inc `Tcp_client;
          T.create_connection (S.tcp stack) (ip, dport) >>= function
          | Error e ->
            Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                        T.pp_error e Ipaddr.pp ip dport) ;
            close ip
          | Ok flow ->
            tcp_out := Ipaddr.Map.add ip flow !tcp_out ;
            Dns.send_tcp_multiple flow data >>= function
            | Error () -> close ip
            | Ok () ->
              Lwt.async (fun () -> read_and_handle ip (Dns.of_flow flow)) ;
              Lwt.return_unit
        end
      | Some flow ->
        Dns.send_tcp_multiple flow data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          Log.warn (fun m -> m "closing tcp flow to %a:%d, retrying request"
                       Ipaddr.pp ip dport) ;
          T.close flow >>= fun () ->
          tcp_out := Ipaddr.Map.remove ip !tcp_out ;
          request (ip, data)
    and request_one (ip, d) = request (ip, [ d ])
    in

    let udp_cb ~src ~dst:_ ~src_port buf =
      Log.debug (fun m -> m "udp frame from %a:%d" Ipaddr.pp src src_port) ;
      inc `Udp_query;
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, answer, out =
        Dns_server.Secondary.handle_buf !state now elapsed `Udp src buf
      in
      maybe_update_state t >>= fun () ->
      (match out with
       | None -> ()
       | Some (ip, cs) -> Lwt.async (fun () -> request_one (ip, cs))) ;
      match answer with
      | None -> Lwt.return_unit
      | Some out -> inc `Udp_answer; Dns.send_udp stack port src src_port out
    in
    S.UDP.listen (S.udp stack) ~port udp_cb ;
    Log.info (fun m -> m "secondary DNS listening on UDP port %d" port) ;

    let tcp_cb flow =
      inc `Tcp;
      let dst_ip, dst_port = T.dst flow in
      tcp_out := Ipaddr.Map.add dst_ip flow !tcp_out ;
      Log.debug (fun m -> m "tcp connection from %a:%d" Ipaddr.pp dst_ip dst_port) ;
      let f = Dns.of_flow flow in
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () -> tcp_out := Ipaddr.Map.remove dst_ip !tcp_out ; Lwt.return_unit
        | Ok data ->
          inc `Tcp_query;
          let now = Ptime.v (P.now_d_ps ()) in
          let elapsed = M.elapsed_ns () in
          let t, answer, out =
            Dns_server.Secondary.handle_buf !state now elapsed `Tcp dst_ip data
          in
          maybe_update_state t >>= fun () ->
          (match out with
           | None -> ()
           | Some (ip, cs) -> Lwt.async (fun () -> request_one (ip, cs)));
          match answer with
          | None ->
            Log.warn (fun m -> m "no TCP output") ;
            loop ()
          | Some data ->
            inc `Tcp_answer;
            Dns.send_tcp flow data >>= function
            | Ok () -> loop ()
            | Error () -> tcp_out := Ipaddr.Map.remove dst_ip !tcp_out ; Lwt.return_unit
      in
      loop ()
    in
    S.TCP.listen (S.tcp stack) ~port tcp_cb ;
    Log.info (fun m -> m "secondary DNS listening on TCP port %d" port) ;

    let rec time () =
      let now = Ptime.v (P.now_d_ps ()) in
      let elapsed = M.elapsed_ns () in
      let t, out = Dns_server.Secondary.timer !state now elapsed in
      maybe_update_state t >>= fun () ->
      List.iter (fun (ip, cs) ->
          Lwt.async (fun () -> request (ip, cs))) out ;
      TIME.sleep_ns (Duration.of_sec timer) >>= fun () ->
      time ()
    in
    Lwt.async time
end
