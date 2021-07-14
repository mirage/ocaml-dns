(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_resolver_mirage" ~doc:"effectful DNS resolver"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (P : Mirage_clock.PCLOCK) (M : Mirage_clock.MCLOCK) (TIME : Mirage_time.S) (S : Mirage_stack.V4V6) = struct

  module Dns = Dns_mirage.Make(S)

  module T = S.TCP

  module FM = Map.Make(struct
      type t = Ipaddr.t * int
      let compare (ip, p) (ip', p') =
        match Ipaddr.compare ip ip' with
        | 0 -> compare p p'
        | x -> x
    end)

  let resolver stack ?(root = false) ?(timer = 500) ?(port = 53) t =
    (* according to RFC5452 4.5, we can chose source port between 1024-49152 *)
    let sport () = 1024 + Randomconv.int ~bound:48128 R.generate in
    let state = ref t in
    let tcp_in = ref FM.empty in
    let tcp_out = ref Dns.IM.empty in

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
        tcp_out := Dns.IM.add dst flow !tcp_out ;
        Lwt.async (fun () ->
            let f = Dns.of_flow flow in
            let rec loop () =
              Dns.read_tcp f >>= function
              | Error () ->
                Log.debug (fun m -> m "removing %a from tcp_out" Ipaddr.pp dst) ;
                tcp_out := Dns.IM.remove dst !tcp_out ;
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
      match Dns.IM.find dst !tcp_out with
      | None ->
        begin
          client_out dst port >>= function
          | Error () ->
            let sport = sport () in
            S.listen_udp stack ~port:sport (udp_cb false) ;
            Dns.send_udp stack sport dst port data
          | Ok () -> client_tcp dst port data
        end
      | Some x ->
        Dns.send_tcp x data >>= function
        | Ok () -> Lwt.return_unit
        | Error () ->
          tcp_out := Dns.IM.remove dst !tcp_out ;
          client_tcp dst port data
    and maybe_tcp dst port data =
      (match Dns.IM.find dst !tcp_out with
       | Some flow -> Dns.send_tcp flow data
       | None -> Lwt.return (Error ())) >>= function
      | Ok () -> Lwt.return_unit
      | Error () ->
        let sport = sport () in
        S.listen_udp stack ~port:sport (udp_cb false) ;
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
        | Some flow -> Dns.send_tcp flow data >|= function
          | Ok () -> ()
          | Error () -> tcp_in := FM.remove (dst, dst_port) !tcp_in
    and udp_cb req ~src ~dst:_ ~src_port buf =
      let now = Ptime.v (P.now_d_ps ())
      and ts = M.elapsed_ns ()
      in
      let new_state, answers, queries =
        Dns_resolver.handle_buf !state now ts req `Udp src src_port buf
      in
      state := new_state ;
      Lwt_list.iter_p handle_answer answers >>= fun () ->
      Lwt_list.iter_p handle_query queries
    in
    S.listen_udp stack ~port (udp_cb true) ;
    Log.app (fun f -> f "DNS resolver listening on UDP port %d" port);

    let tcp_cb query flow =
      let dst_ip, dst_port = T.dst flow in
      Log.info (fun m -> m "tcp connection from %a:%d" Ipaddr.pp dst_ip dst_port) ;
      tcp_in := FM.add (dst_ip, dst_port) flow !tcp_in ;
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
    S.listen_tcp stack ~port (tcp_cb true) ;
    Log.info (fun m -> m "DNS resolver listening on TCP port %d" port) ;

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
