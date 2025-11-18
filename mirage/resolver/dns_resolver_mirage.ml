(* (c) 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_resolver_mirage" ~doc:"effectful DNS resolver"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (S : Tcpip.Stack.V4V6) = struct

  module Dns = Dns_mirage.Make(S)

  module T = S.TCP

  module TLS = Tls_mirage.Make(T)

  type t = {
    push : (Ipaddr.t * int * string * (int32 * string) Lwt.u) option -> unit ;
    primary_data : unit -> Dns_trie.t ;
    with_primary_data : Dns_trie.t -> unit ;
    update_tls : Tls.Config.server -> unit ;
  }

  type tls_flow = { tls_flow : TLS.flow ; mutable linger : Cstruct.t }

  module FM = Map.Make(struct
      type t = Ipaddr.t * int
      let compare (ip, p) (ip', p') =
        match Ipaddr.compare ip ip' with
        | 0 -> compare p p'
        | x -> x
    end)

  let resolver stack ?(root = false) ?(timer = 500) ?(udp = true) ?(tcp = true) ?tls ?(port = 53) ?(tls_port = 853) t =
    let server_port = 53 in
    let server_tls_port = 853 in
    let state = ref t in
    (* according to RFC5452 4.5, we can chose source port between 1024-49152 *)
    let sport () = 1024 + Randomconv.int ~bound:48128 Mirage_crypto_rng.generate in
    (* TODO limit these maps so we don't use too much memory *)
    let tcp_in = ref FM.empty in
    let ocaml_in = ref FM.empty in
    let auth = ref Ipaddr.Map.empty in
    let tls_auth = ref Ipaddr.Map.empty in
    let stream, push = Lwt_stream.create () in
    let opportunistic = List.mem `Opportunistic_tls_authoritative (Dns_resolver.features t) in

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

    let retry_tls = Duration.of_day 1 in (* from RFC 9539, 4.3 "damping" *)
    let tls_timeout = Duration.of_sec 2 in (* RFC 9539, 4.3 "timeout" (4s), we use 2s *)
    let rec client_tls_out cfg dst port =
      tls_auth := Ipaddr.Map.add dst (`Tls_tried (Mirage_mtime.elapsed_ns ())) !tls_auth;
      T.create_connection (S.tcp stack) (dst, port) >>= function
      | Error e ->
        (* do i need to report this back into the resolver? what are their options then? *)
        Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                    T.pp_error e Ipaddr.pp dst port) ;
        Lwt.return (Error ())
      | Ok flow ->
        Log.debug (fun m -> m "established new outgoing TCP connection to %a:%d"
                      Ipaddr.pp dst port);
        TLS.client_of_flow cfg flow >|= function
        | Error e ->
          Log.warn (fun m -> m "TLS error (to %a:%d): %a" Ipaddr.pp dst port
                       TLS.pp_write_error e);
          Error ()
        | Ok tls ->
          let cfg =
            match TLS.epoch tls with
            | Error () -> cfg
            | Ok ed ->
              let anchors = Result.get_ok Ca_certs_nss.trust_anchors in
              let authenticator =
                let time () = Some (Mirage_ptime.now ()) in
                match X509.Validation.verify_chain_of_trust ~host:None ~ip:dst
                        ~time ~anchors ed.Tls.Core.peer_certificate_chain
                with
                | Ok _ ->
                  Log.info (fun m -> m "NS %a using ca-certs-nss authenticator"
                               Ipaddr.pp dst);
                  Result.get_ok (Ca_certs_nss.authenticator ())
                | Error _ ->
                  match ed.peer_certificate with
                  | None ->
                    Log.info (fun m -> m "NS %a no certificate provided"
                                 Ipaddr.pp dst);
                    fun ?ip:_ ~host:_ _certs -> Ok None
                  | Some cert ->
                    let fingerprint =
                      X509.(Public_key.fingerprint (Certificate.public_key cert))
                    in
                    Log.info (fun m -> m "NS %a using key-fingerprint %a authenticator"
                                 Ohex.pp fingerprint Ipaddr.pp dst);
                    X509.Authenticator.key_fingerprint ~time ~hash:`SHA256 ~fingerprint
              in
              Result.get_ok (Tls.Config.client ~authenticator ())
          in
          tls_auth := Ipaddr.Map.add dst (`Tls_succeeded cfg) !tls_auth;
          Log.debug (fun m -> m "tls connection to %a:%d" Ipaddr.pp dst port);
          auth := Ipaddr.Map.add dst (`Tls tls) !auth ;
          Lwt.async (fun () ->
              let tls_and_linger = { tls_flow = tls ; linger = Cstruct.empty } in
              let rec loop () =
                read_tls_packet tls_and_linger >>= function
                | Error () ->
                  Log.debug (fun m -> m "removing %a from auth" Ipaddr.pp dst) ;
                  auth := Ipaddr.Map.remove dst !auth ;
                  Lwt.return_unit
                | Ok data ->
                  let now = Mirage_ptime.now () in
                  let ts = Mirage_mtime.elapsed_ns () in
                  let new_state, answers, queries =
                    let data = Cstruct.to_string data in
                    Dns_resolver.handle_buf !state now ts false `Tcp dst port data
                  in
                  state := new_state ;
                  Lwt_list.iter_p handle_answer answers >>= fun () ->
                  Lwt_list.iter_p handle_query queries >>= fun () ->
                  loop ()
              in
              loop ()) ;
          Ok ()
    and client_tcp_out dst port =
      T.create_connection (S.tcp stack) (dst, port) >|= function
      | Error e ->
        (* do i need to report this back into the resolver? what are their options then? *)
        Log.err (fun m -> m "error %a while establishing tcp connection to %a:%d"
                    T.pp_error e Ipaddr.pp dst port) ;
        Error ()
      | Ok flow ->
        Log.debug (fun m -> m "established new outgoing TCP connection to %a:%d"
                      Ipaddr.pp dst port);
        auth := Ipaddr.Map.add dst (`Tcp flow) !auth ;
        Lwt.async (fun () ->
            let f = Dns.of_flow flow in
            let rec loop () =
              Dns.read_tcp f >>= function
              | Error () ->
                Log.debug (fun m -> m "removing %a from auth" Ipaddr.pp dst) ;
                auth := Ipaddr.Map.remove dst !auth ;
                Lwt.return_unit
              | Ok data ->
                let now = Mirage_ptime.now () in
                let ts = Mirage_mtime.elapsed_ns () in
                let new_state, answers, queries =
                  let data = Cstruct.to_string data in
                  Dns_resolver.handle_buf !state now ts false `Tcp dst port data
                in
                state := new_state ;
                Lwt_list.iter_p handle_answer answers >>= fun () ->
                Lwt_list.iter_p handle_query queries >>= fun () ->
                loop ()
            in
            loop ()) ;
        Ok ()
    and client_tcp dst port ~tls_port data =
      match Ipaddr.Map.find_opt dst !auth with
      | None ->
        begin
          let try_it = match Ipaddr.Map.find_opt dst !tls_auth with
            | None -> Some None
            | Some `Tls_succeeded cfg -> Some (Some cfg)
            | Some `Tls_tried ts ->
              if Int64.(ts >= sub (Mirage_mtime.elapsed_ns ()) retry_tls) then
                Some None
              else
                None
          in
          (match try_it with
           | Some cfg when opportunistic ->
             let cfg =
               match cfg with
               | None ->
                 let authenticator ?ip:_ ~host:_ _certs = Ok None in
                 Result.get_ok (Tls.Config.client ~authenticator ())
               | Some cfg -> cfg
             in
             client_tls_out cfg dst tls_port
           | _ ->
             client_tcp_out dst port) >>= function
          | Error () ->
            let sport = sport () in
            S.UDP.listen (S.udp stack) ~port:sport (udp_cb sport false) ;
            Dns.send_udp stack sport dst port (Cstruct.of_string data)
          | Ok () -> client_tcp dst port ~tls_port data
        end
      | Some `Tcp x ->
        begin
          Dns.send_tcp x (Cstruct.of_string data) >>= function
          | Ok () -> Lwt.return_unit
          | Error () ->
            auth := Ipaddr.Map.remove dst !auth ;
            client_tcp dst port ~tls_port data
        end
      | Some `Tls tls ->
        begin
          send_tls tls (Cstruct.of_string data) >>= function
          | Ok () -> Lwt.return_unit
          | Error () ->
            auth := Ipaddr.Map.remove dst !auth ;
            client_tcp dst port ~tls_port data
        end
    and maybe_tcp dst port data =
      (match Ipaddr.Map.find_opt dst !auth with
       | Some `Tcp flow -> Dns.send_tcp flow (Cstruct.of_string data)
       | Some `Tls tls -> send_tls tls (Cstruct.of_string data)
       | None -> Lwt.return (Error ())) >>= function
      | Ok () -> Lwt.return_unit
      | Error () ->
        let try_tls =
          match Ipaddr.Map.find_opt dst !tls_auth with
          | None -> true
          | Some `Tls_succeeded _ -> true
          | Some `Tls_tried ts ->
            Int64.(ts >= sub (Mirage_mtime.elapsed_ns ()) retry_tls)
        in
        (if try_tls then
           Lwt.pick [
             (Mirage_sleep.ns tls_timeout >|= fun () -> `Timeout);
             (client_tcp dst port ~tls_port:server_tls_port data >|= fun () -> `Used_tls)
           ]
         else
           Lwt.return `Timeout) >>= function
        | `Timeout ->
          let sport = sport () in
          S.UDP.listen (S.udp stack) ~port:sport (udp_cb sport false) ;
          Dns.send_udp stack sport dst port (Cstruct.of_string data)
        | `Used_tls -> Lwt.return_unit
    and handle_query (proto, dst, data) = match proto with
      | `Udp -> maybe_tcp dst server_port data
      | `Tcp -> client_tcp dst server_port ~tls_port:server_tls_port data
    and handle_answer (proto, dst, dst_port, ttl, data) = match proto with
      | `Udp -> Dns.send_udp stack port dst dst_port (Cstruct.of_string data)
      | `Tcp ->
        let from_tcp = FM.find_opt (dst, dst_port) !tcp_in in
        let from_ocaml = FM.find_opt (dst, dst_port) !ocaml_in in
        match from_tcp, from_ocaml with
        | None, None ->
          Log.err (fun m -> m "wanted to answer %a:%d via TCP, but couldn't find a flow"
                       Ipaddr.pp dst dst_port) ;
          Lwt.return_unit
        | Some (`Tcp flow), None ->
          (Dns.send_tcp flow (Cstruct.of_string data) >|= function
           | Ok () -> ()
           | Error () -> tcp_in := FM.remove (dst, dst_port) !tcp_in)
        | Some (`Tls flow), None ->
          (send_tls flow (Cstruct.of_string data) >|= function
           | Ok () -> ()
           | Error () -> tcp_in := FM.remove (dst, dst_port) !tcp_in)
        | None, Some wk -> begin
            ocaml_in := FM.remove (dst, dst_port) !ocaml_in;
            Lwt.wakeup wk (ttl, data);
            Lwt.return_unit end
        | Some _, Some _ -> assert false
    and udp_cb lport req ~src ~dst:_ ~src_port buf =
      let buf = Cstruct.to_string buf in
      let now = Mirage_ptime.now ()
      and ts = Mirage_mtime.elapsed_ns ()
      in
      let new_state, answers, queries =
        Dns_resolver.handle_buf !state now ts req `Udp src src_port buf
      in
      if not req then
        S.UDP.unlisten (S.udp stack) ~port:lport;
      state := new_state ;
      Lwt_list.iter_p handle_answer answers >>= fun () ->
      Lwt_list.iter_p handle_query queries
    in
    if udp then begin
      S.UDP.listen (S.udp stack) ~port (udp_cb port true);
      Log.info (fun f -> f "DNS resolver listening on UDP port %d" port);
    end;

    let rec ocaml_cb () =
      Lwt_stream.get stream >>= function
      | Some (dst_ip, dst_port, data, wk) ->
          ocaml_in := FM.add (dst_ip, dst_port) wk !ocaml_in;
          let now = Mirage_ptime.now () in
          let ts = Mirage_mtime.elapsed_ns () in
          let new_state, answers, queries =
            Dns_resolver.handle_buf !state now ts true `Tcp dst_ip dst_port data in
          state := new_state ;
          Lwt_list.iter_p handle_answer answers >>= fun () ->
          Lwt_list.iter_p handle_query queries >>= fun () ->
          ocaml_cb ()
      | None -> Lwt.return_unit in
    Lwt.async ocaml_cb;

    let tcp_cb query flow =
      let dst_ip, dst_port = T.dst flow in
      Log.debug (fun m -> m "tcp connection from %a:%d" Ipaddr.pp dst_ip dst_port) ;
      tcp_in := FM.add (dst_ip, dst_port) (`Tcp flow) !tcp_in ;
      let f = Dns.of_flow flow in
      let rec loop () =
        Dns.read_tcp f >>= function
        | Error () ->
          tcp_in := FM.remove (dst_ip, dst_port) !tcp_in ;
          Lwt.return_unit
        | Ok data ->
          let data = Cstruct.to_string data in
          let now = Mirage_ptime.now () in
          let ts = Mirage_mtime.elapsed_ns () in
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

    let tls_cb cfg flow =
      let dst_ip, dst_port = T.dst flow in
      TLS.server_of_flow cfg flow >>= function
      | Error e ->
        Log.warn (fun m -> m "TLS error (from %a:%d): %a" Ipaddr.pp dst_ip dst_port
          TLS.pp_write_error e);
        Lwt.return_unit
      | Ok tls ->
        Log.debug (fun m -> m "tls connection from %a:%d" Ipaddr.pp dst_ip dst_port);
        tcp_in := FM.add (dst_ip, dst_port) (`Tls tls) !tcp_in ;
        let tls_and_linger = { tls_flow = tls ; linger = Cstruct.empty } in
        let rec loop () =
          read_tls_packet tls_and_linger >>= function
          | Error () ->
            tcp_in := FM.remove (dst_ip, dst_port) !tcp_in ;
            Lwt.return_unit
          | Ok data ->
            let data = Cstruct.to_string data in
            let now = Mirage_ptime.now () in
            let ts = Mirage_mtime.elapsed_ns () in
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
    let update_tls tls_cfg =
       S.TCP.listen (S.tcp stack) ~port:tls_port (tls_cb tls_cfg);
    in
    (match tls with
     | None -> ()
     | Some cfg ->
       update_tls cfg;
       Log.info (fun m -> m "DNS resolver listening on TLS port %d" tls_port));

    let rec time () =
      let new_state, answers, queries =
        Dns_resolver.timer !state (Mirage_mtime.elapsed_ns ())
      in
      state := new_state ;
      Lwt_list.iter_p handle_answer answers >>= fun () ->
      Lwt_list.iter_p handle_query queries >>= fun () ->
      Mirage_sleep.ns (Duration.of_ms timer) >>= fun () ->
      time ()
    in
    Lwt.async time ;

    let primary_data () =
      Dns_resolver.primary_data !state
    in
    let with_primary_data data =
      let (t, outs) =
        Dns_resolver.with_primary_data !state
          (Mirage_ptime.now ())
          (Mirage_mtime.elapsed_ns ())
          data
      in
      state := t;
      if outs <> [] then
        Log.warn (fun m -> m "Updating resolver's primary name server resulted
        in 'notify's. Secondaries in the resolver's primary DNS is *not*
        supported. The 'notify's are discarded.")
    in

    if root then begin
      let rec root () =
        let new_state, q = Dns_resolver.query_root !state (Mirage_mtime.elapsed_ns ()) `Tcp in
        state := new_state ;
        handle_query q >>= fun () ->
        Mirage_sleep.ns (Duration.of_day 6) >>= fun () ->
        root ()
      in
      Lwt.async root end ;
    { push; primary_data; with_primary_data; update_tls }

  let resolve_external { push; _ } (dst_ip, dst_port) data =
      let th, wk = Lwt.wait () in
      push (Some (dst_ip, dst_port, data, wk));
      th

  let primary_data { primary_data; _ } = primary_data ()

  let update_primary_data { with_primary_data; _ } data = with_primary_data data

  let update_tls { update_tls; _ } tls_config = update_tls tls_config
end
