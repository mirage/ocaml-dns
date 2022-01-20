(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_resolver_mirage" ~doc:"effectful DNS resolver"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (P : Mirage_clock.PCLOCK) (M : Mirage_clock.MCLOCK) (TIME : Mirage_time.S) (S : Tcpip.Stack.V4V6) = struct

  module Dns = Dns_mirage.Make(S)

  module T = S.TCP

  module TLS = Tls_mirage.Make(T)

  type tls_flow = { tls_flow : TLS.flow ; mutable linger : Cstruct.t }

  module FM = Map.Make(struct
      type t = Ipaddr.t * int
      let compare (ip, p) (ip', p') =
        match Ipaddr.compare ip ip' with
        | 0 -> compare p p'
        | x -> x
    end)

  let resolver stack ?(root = false) ?(timer = 500) ?(udp = true) ?(tcp = true) ?tls ?(port = 53) ?(tls_port = 853) t =
    (* according to RFC5452 4.5, we can chose source port between 1024-49152 *)
    let sport () = 1024 + Randomconv.int ~bound:48128 R.generate in
    let state = ref t in
    let tcp_in = ref FM.empty in
    let tcp_out = ref Ipaddr.Map.empty in

    let send_tls flow data =
      let len = Cstruct.create 2 in
      Cstruct.BE.set_uint16 len 0 (Cstruct.length data);
      TLS.writev flow [len; data] >>= function
      | Ok () -> Lwt.return (Ok ())
      | Error e ->
        Log.err (fun m -> m "tls error %a while writing" TLS.pp_write_error e);
        TLS.close flow >|= fun () ->
        Error ()
    in

    let rec client_out dst port =
      T.create_connection (S.tcp stack) (dst, port) >|= function
      | Error e ->
        (* do i need to report this back into the resolver? what are their options then? *)
        Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                    T.pp_error e Ipaddr.pp dst port) ;
        Error ()
      | Ok flow ->
        Log.debug (fun m -> m "established new outgoing TCP connection to %a:%d"
                      Ipaddr.pp dst port);
        tcp_out := Ipaddr.Map.add dst flow !tcp_out ;
        Lwt.async (fun () ->
            let f = Dns.of_flow flow in
            let rec loop () =
              Dns.read_tcp f >>= function
              | Error () ->
                Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.pp dst) ;
                tcp_out := Ipaddr.Map.remove dst !tcp_out ;
                Lwt.return_unit
              | Ok data ->
                let now = Ptime.v (P.now_d_ps ()) in
                let ts = M.elapsed_ns () in
                let new_state, answers, queries =
                  Dns_resolver.handle_buf !state now ts false `Tcp dst port data
                in
                state := new_state ;
                Lwt_list.iter_p handle_answer answers >>= fun () ->
                Lwt_list.iter_p handle_query queries >>= fun () ->
                loop ()
            in
            loop ()) ;
        Ok ()
    and client_tcp dst port data =
      match Ipaddr.Map.find_opt dst !tcp_out with
      | None ->
        begin
          client_out dst port >>= function
          | Error () ->
            let sport = sport () in
            S.UDP.listen (S.udp stack) ~port:sport (udp_cb sport false) ;
            Dns.send_udp stack sport dst port data
          | Ok () -> client_tcp dst port data
        end
      | Some x ->
        Dns.send_tcp x data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          tcp_out := Ipaddr.Map.remove dst !tcp_out ;
          client_tcp dst port data
    and maybe_tcp dst port data =
      (match Ipaddr.Map.find_opt dst !tcp_out with
       | Some flow -> Dns.send_tcp flow data
       | None -> Lwt.return (Error ())) >>= function
      | Ok () -> Lwt.return_unit
      | Error () ->
        let sport = sport () in
        S.UDP.listen (S.udp stack) ~port:sport (udp_cb sport false) ;
        Dns.send_udp stack sport dst port data
    and handle_query (proto, dst, data) = match proto with
      | `Udp -> maybe_tcp dst port data
      | `Tcp -> client_tcp dst port data
    and handle_answer (proto, dst, dst_port, data) = match proto with
      | `Udp -> Dns.send_udp stack port dst dst_port data
      | `Tcp -> match try Some (FM.find (dst, dst_port) !tcp_in) with Not_found -> None with
        | None ->
          Log.err (fun m -> m "wanted to answer %a:%d via TCP, but couldn't find a flow"
                       Ipaddr.pp dst dst_port) ;
          Lwt.return_unit
        | Some `Tcp flow ->
          (Dns.send_tcp flow data >|= function
           | Ok () -> ()
           | Error () -> tcp_in := FM.remove (dst, dst_port) !tcp_in)
        | Some `Tls flow ->
          (send_tls flow data >|= function
           | Ok () -> ()
           | Error () -> tcp_in := FM.remove (dst, dst_port) !tcp_in)
    and udp_cb lport req ~src ~dst:_ ~src_port buf =
      let now = Ptime.v (P.now_d_ps ())
      and ts = M.elapsed_ns ()
      in
      let new_state, answers, queries =
        Dns_resolver.handle_buf !state now ts req `Udp src src_port buf
      in
      if not req then
        (Log.app (fun m -> m "unlisten on UDP %d" src_port);
         S.UDP.unlisten (S.udp stack) ~port:lport);
      state := new_state ;
      Lwt_list.iter_p handle_answer answers >>= fun () ->
      Lwt_list.iter_p handle_query queries
    in
    if udp then begin
      S.UDP.listen (S.udp stack) ~port (udp_cb port true);
      Log.app (fun f -> f "DNS resolver listening on UDP port %d" port);
    end;

    let tcp_cb query flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.pp dst_ip dst_port) ;
      tcp_in := FM.add (dst_ip, dst_port) (`Tcp flow) !tcp_in ;
      let f = Dns.of_flow flow in
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () ->
          tcp_in := FM.remove (dst_ip, dst_port) !tcp_in ;
          Lwt.return_unit
        | Ok data ->
          let now = Ptime.v (P.now_d_ps ()) in
          let ts = M.elapsed_ns () in
          let new_state, answers, queries =
            Dns_resolver.handle_buf !state now ts query `Tcp dst_ip dst_port data
          in
          state := new_state ;
          Lwt_list.iter_p handle_answer answers >>= fun () ->
          Lwt_list.iter_p handle_query queries >>= fun () ->
          loop ()
      in
      loop ()
    in
    if tcp then begin
      S.TCP.listen (S.tcp stack) ~port (tcp_cb true);
      Log.info (fun m -> m "DNS resolver listening on TCP port %d" port);
    end;

    let rec read_tls ({ tls_flow ; linger } as f) length =
      if Cstruct.length linger >= length then
        let a, b = Cstruct.split linger length in
        f.linger <- b;
        Lwt.return (Ok a)
      else
        TLS.read tls_flow >>= function
        | Ok `Eof -> Log.debug (fun m -> m "end of file while reading"); TLS.close tls_flow >|= fun () -> Error ()
        | Error e -> Log.warn (fun m -> m "error reading TLS: %a" TLS.pp_error e); TLS.close tls_flow >|= fun () -> Error ()
        | Ok (`Data d) ->
          f.linger <- Cstruct.append linger d;
          read_tls f length
    in
    let read_tls_packet f =
      read_tls f 2 >>= function
      | Error () -> Lwt.return (Error ())
      | Ok k ->
        let len = Cstruct.BE.get_uint16 k 0 in
        read_tls f len
    in

    let tls_cb cfg flow =
      let dst_ip, dst_port = T.dst flow in
      TLS.server_of_flow cfg flow >>= function
      | Error e ->
        Log.warn (fun m -> m "TLS error (from %a:%d): %a" Ipaddr.pp dst_ip dst_port
          TLS.pp_write_error e);
        Lwt.return_unit
      | Ok tls ->
        Log.info (fun m -> m "tls connection from %a:%d" Ipaddr.pp dst_ip dst_port);
        tcp_in := FM.add (dst_ip, dst_port) (`Tls tls) !tcp_in ;
        let tls_and_linger = { tls_flow = tls ; linger = Cstruct.empty } in
        let rec loop () =
          read_tls_packet tls_and_linger >>= function
          | Error () ->
            tcp_in := FM.remove (dst_ip, dst_port) !tcp_in ;
            Lwt.return_unit
          | Ok data ->
            let now = Ptime.v (P.now_d_ps ()) in
            let ts = M.elapsed_ns () in
            let new_state, answers, queries =
              Dns_resolver.handle_buf !state now ts true `Tcp dst_ip dst_port data
            in
            state := new_state ;
            Lwt_list.iter_p handle_answer answers >>= fun () ->
            Lwt_list.iter_p handle_query queries >>= fun () ->
            loop ()
        in
        loop ()
    in
    (match tls with
     | None -> ()
     | Some cfg ->
       S.TCP.listen (S.tcp stack) ~port:tls_port (tls_cb cfg);
       Log.info (fun m -> m "DNS resolver listening on TLS port %d" tls_port));

    let rec time () =
      let new_state, answers, queries =
        Dns_resolver.timer !state (M.elapsed_ns ())
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
        let new_state, q = Dns_resolver.query_root !state (M.elapsed_ns ()) `Tcp in
        state := new_state ;
        handle_query q >>= fun () ->
        TIME.sleep_ns (Duration.of_day 6) >>= fun () ->
        root ()
      in
      Lwt.async root
end
