(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Mirage_types_lwt

open Lwt.Infix

let src = Logs.Src.create "dns_mirage" ~doc:"effectful DNS layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (TIME : TIME) (S : STACKV4) = struct
  module U = S.UDPV4
  module T = S.TCPV4

  type f = {
    flow : T.flow ;
    mutable linger : Cstruct.t ;
  }

  let rec read_exactly f length =
    if Cstruct.len f.linger >= length then
      let a, b = Cstruct.split f.linger length in
      f.linger <- b ;
      Lwt.return (Ok a)
    else
      T.read f.flow >>= function
      | Ok `Eof ->
        Log.warn (fun m -> m "end of file on flow") ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Error e ->
        Log.err (fun m -> m "error reading flow %a" T.pp_error e) ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Ok (`Data b) ->
        f.linger <- Cstruct.append f.linger b ;
        read_exactly f length

  let send_udp udp port (dst, data) =
    Log.info (fun m -> m "sending %d bytes udp to %a%d"
                 (Cstruct.len data) Ipaddr.V4.pp_hum dst port) ;
    U.write ~src_port:port ~dst ~dst_port:port udp data >|= function
    | Error e -> Log.warn (fun m -> m "failure sending notify to %a:%d: %a"
                              Ipaddr.V4.pp_hum dst port U.pp_error e)
    | Ok () -> ()

  let primary stack pclock mclock ?(timer = 2) ?(port = 53) t =
    let state = ref t in
    let send_notify = send_udp (S.udpv4 stack) port in
    let udp_cb ~src ~dst ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp_hum src src_port) ;
      Log.debug (fun m -> m "received:@.%a" Cstruct.hexdump_pp buf) ;
      let now = Ptime.v (P.now_d_ps pclock) in
      let elapsed = M.elapsed_ns mclock in
      let t, answer, notify = Dns_server.Primary.handle !state now elapsed `Udp src buf in
      state := t ;
      (match answer with
       | None -> Log.warn (fun m -> m "empty answer") ; Lwt.return_unit
       | Some answer ->
         Log.info (fun m -> m "udp sending %d bytes to %a:%d" (Cstruct.len answer) Ipaddr.V4.pp_hum src src_port) ;
         (U.write ~src_port:port ~dst:src ~dst_port:src_port (S.udpv4 stack) answer >|= function
           | Error e -> Log.warn (fun m -> m "failure sending reply: %a" U.pp_error e)
           | Ok () -> ())) >>= fun () ->
      Lwt_list.iter_p send_notify notify
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "DNS server listening on UDP port %d" port) ;
    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp_hum dst_ip dst_port) ;
      let f = { flow ; linger = Cstruct.create 0 } in
      let rec loop () =
        read_exactly f 2 >>= function
        | Error _ -> Lwt.return_unit
        | Ok l ->
          let len = Cstruct.BE.get_uint16 l 0 in
          read_exactly f len >>= function
          | Error _ -> Lwt.return_unit
          | Ok data ->
            let now = Ptime.v (P.now_d_ps pclock) in
            let elapsed = M.elapsed_ns mclock in
            let t, answer, notify = Dns_server.Primary.handle !state now elapsed `Tcp dst_ip data in
            state := t ;
            Lwt_list.iter_p send_notify notify >>= fun () ->
            match answer with
            | None -> Log.warn (fun m -> m "empty answer") ; loop ()
            | Some answer ->
              Log.info (fun m -> m "tcp: sending %d bytes to %a:%d" (Cstruct.len answer) Ipaddr.V4.pp_hum dst_ip dst_port) ;
              let len = Cstruct.create 2 in
              Cstruct.BE.set_uint16 len 0 (Cstruct.len answer) ;
              T.write flow (Cstruct.append len answer) >>= function
              | Ok () -> loop ()
              | Error e ->
                Log.err (fun m -> m "error while writing %a" T.pp_write_error e) ;
                T.close flow
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "DNS server listening on TCP port %d" port) ;
    let zzz = Duration.of_sec timer in
    let rec timer () =
      let t, notifies = Dns_server.Primary.timer !state (M.elapsed_ns mclock) in
      state := t ;
      Lwt_list.iter_p send_notify notifies >>= fun () ->
      TIME.sleep_ns zzz >>= fun () ->
      timer ()
    in
    Lwt.async timer

  let secondary stack pclock mclock ?(timer = 300) ?(port = 53) t =
    let state = ref t in
    let send (proto, ip, data) =
      match proto with
      | `Udp -> send_udp (S.udpv4 stack) port (ip, data)
      | `Tcp ->
        Lwt.async (fun () ->
            Log.info (fun m -> m "tcp sending %d bytes to %a@.%a" (Cstruct.len data) Ipaddr.V4.pp_hum ip Cstruct.hexdump_pp data) ;
            T.create_connection (S.tcpv4 stack) (ip, port) >>= function
            | Error e -> Log.err (fun m -> m "error %a while establishing connection" T.pp_error e) ; Lwt.return_unit
            | Ok flow ->
              let len = Cstruct.create 2 in
              Cstruct.BE.set_uint16 len 0 (Cstruct.len data) ;
              T.write flow (Cstruct.append len data) >>= function
              | Error e -> Log.err (fun m -> m "error while writing %a" T.pp_write_error e) ; Lwt.return_unit
              | Ok () ->
                let f = { flow ; linger = Cstruct.create 0 } in
                read_exactly f 2 >>= function
                | Error _ -> Lwt.return_unit
                | Ok l ->
                  let len = Cstruct.BE.get_uint16 l 0 in
                  read_exactly f len >>= function
                  | Error _ -> Lwt.return_unit
                  | Ok data ->
                    let now = Ptime.v (P.now_d_ps pclock) in
                    let elapsed = M.elapsed_ns mclock in
                    let t, answer, out = Dns_server.Secondary.handle !state now elapsed `Tcp ip data in
                    state := t ;
                    (* assume that answer and out are empty *)
                    (match answer with Some _ -> Log.err (fun m -> m "expected no answer") | None -> ()) ;
                    (match out with [] -> () | _ -> Log.err (fun m -> m "expected no out")) ;
                    T.close flow) ;
        Lwt.return_unit
    in
    let udp_cb ~src ~dst ~src_port buf =
      Log.info (fun m -> m "udp frame from %a:%d" Ipaddr.V4.pp_hum src src_port) ;
      Log.debug (fun m -> m "received:@.%a" Cstruct.hexdump_pp buf) ;
      let now = Ptime.v (P.now_d_ps pclock) in
      let elapsed = M.elapsed_ns mclock in
      let t, answer, out = Dns_server.Secondary.handle !state now elapsed `Udp src buf in
      state := t ;
      Lwt_list.iter_p send out >>= fun () ->
      match answer with
      | None -> Lwt.return_unit
      | Some out ->
        Log.info (fun m -> m "udp sending %d bytes to %a:%d" (Cstruct.len out) Ipaddr.V4.pp_hum src src_port) ;
        U.write ~src_port:port ~dst:src ~dst_port:src_port (S.udpv4 stack) out >|= function
        | Error e -> Log.warn (fun m -> m "failure sending reply: %a" U.pp_error e)
        | Ok () -> ()
    in
    S.listen_udpv4 stack ~port udp_cb ;
    Log.info (fun m -> m "secondary DNS listening on UDP port %d" port) ;
    let tcp_cb flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.V4.pp_hum dst_ip dst_port) ;
      let f = { flow ; linger = Cstruct.create 0 } in
      let rec loop () =
        read_exactly f 2 >>= function
        | Error _ -> Lwt.return_unit
        | Ok l ->
          let len = Cstruct.BE.get_uint16 l 0 in
          read_exactly f len >>= function
          | Error _ -> Lwt.return_unit
          | Ok data ->
            let now = Ptime.v (P.now_d_ps pclock) in
            let elapsed = M.elapsed_ns mclock in
            let t, answer, out = Dns_server.Secondary.handle !state now elapsed `Tcp dst_ip data in
            state := t ;
            Lwt_list.iter_p send out >>= fun () ->
            match answer with
            | None ->
              Log.warn (fun m -> m "no TCP output") ;
              loop ()
            | Some data ->
              Log.info (fun m -> m "sending answer %d bytes via tcp to %a:%d" (Cstruct.len data) Ipaddr.V4.pp_hum dst_ip dst_port) ;
              let len = Cstruct.create 2 in
              Cstruct.BE.set_uint16 len 0 (Cstruct.len data) ;
              T.write flow (Cstruct.append len data) >>= function
              | Ok () -> loop ()
              | Error e ->
                Log.err (fun m -> m "error while writing %a" T.pp_write_error e) ;
                T.close flow
      in
      loop ()
    in
    S.listen_tcpv4 stack ~port tcp_cb ;
    Log.info (fun m -> m "secondary DNS listening on TCP port %d" port) ;
    let zzz = Duration.of_sec timer in
    let rec timer () =
      let now = Ptime.v (P.now_d_ps pclock) in
      let elapsed = M.elapsed_ns mclock in
      let t, out = Dns_server.Secondary.timer !state now elapsed in
      state := t ;
      Lwt_list.iter_p send out >>= fun () ->
      TIME.sleep_ns zzz >>= fun () ->
      timer ()
    in
    Lwt.async timer
end
