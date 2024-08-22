open Lwt.Infix

module IM = Map.Make(Int)

let src = Logs.Src.create "dns_client_lwt" ~doc:"effectful DNS lwt layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Transport : Dns_client.S
 with type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
 and type +'a io = 'a Lwt.t
 and type stack = Happy_eyeballs_lwt.t
= struct
  type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
  type +'a io = 'a Lwt.t
  type stack = Happy_eyeballs_lwt.t
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
    mutable connected_condition : (unit, [ `Msg of string ]) result Lwt_condition.t option ;
    mutable requests : (string * (string, [ `Msg of string ]) result Lwt_condition.t) IM.t ;
    he : Happy_eyeballs_lwt.t ;
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

  let close_socket fd =
    Lwt.catch (fun () -> Lwt_unix.close fd) (fun _ -> Lwt.return_unit)

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
              match Tls.Config.client ~authenticator ~ip () with
              | Ok tls -> [ `Tls (tls, ip, 853) ; `Plaintext (ip, 53) ]
              | Error `Msg msg ->
                Log.err (fun m -> m "creating TLS configuratio for %a: %s"
                            Ipaddr.pp ip msg);
                [ `Plaintext (ip, 53) ])
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
    let tls_config =
      match Tls.Config.client ~authenticator ~peer_name () with
      | Ok cfg -> cfg
      | Error `Msg msg -> invalid_arg msg
    in
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

  let create ?nameservers ~timeout happy_eyeballs =
    let nameservers =
      match nameservers with
      | Some (`Udp, _) -> invalid_arg "UDP is not supported"
      | Some (`Tcp, ns) -> Static ns
      | None ->
        match resolv_conf () with
        | Error _ -> Resolv_conf { nameservers = default_resolver (); digest = None }
        | Ok (ips, digest) -> Resolv_conf { nameservers = ips; digest = Some digest }
    in
    {
      nameservers ;
      timeout_ns = timeout ;
      fd = None ;
      connected_condition = None ;
      requests = IM.empty ;
      he = happy_eyeballs ;
    }

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
        Lwt_unix.send fd (Bytes.unsafe_of_string tx) 0
          (String.length tx) [] >>= fun res ->
        if res <> String.length tx then
          Lwt_result.fail (`Msg ("oops" ^ (string_of_int res)))
        else
          Lwt_result.return ()
      | `Tls fd ->
        Lwt_result.ok (Tls_lwt.Unix.write fd tx))
      (fun e -> Lwt.return (Error (`Msg (Printexc.to_string e))))

  let send_recv (t : context) tx =
    if String.length tx > 4 then
      match t.fd with
      | None -> Lwt.return (Error (`Msg "no connection to the nameserver established"))
      | Some fd ->
        let id = String.get_uint16_be tx 2 in
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

  let rec read_loop ?(linger = "") (t : t) fd =
    Lwt.catch (fun () ->
      match fd with
      | `Plain fd ->
        let recv_buffer = Bytes.create 2048 in
        Lwt_unix.recv fd recv_buffer 0 (Bytes.length recv_buffer) [] >|= fun r ->
        (r, recv_buffer)
      | `Tls fd ->
        let recv_buffer = Bytes.create 2048 in
        Tls_lwt.Unix.read fd recv_buffer >|= fun r ->
        (r, recv_buffer))
     (fun e ->
      Log.err (fun m -> m "error %s reading from resolver" (Printexc.to_string e));
      Lwt.return (0, Bytes.empty)) >>= function
     | (0, _) ->
       (match fd with
       | `Plain fd -> close_socket fd
       | `Tls fd -> Tls_lwt.Unix.close fd) >|= fun () ->
       t.fd <- None;
       if not (IM.is_empty t.requests) then
         Log.info (fun m -> m "end of file reading from resolver")
     | (read_len, cs) ->
       let rec handle_data data =
         let cs_len = String.length data in
         if cs_len > 2 then
           let len = String.get_uint16_be data 0 in
           if cs_len - 2 >= len then
             let packet, rest =
               if cs_len - 2 = len
               then data, ""
               else String.sub data 0 (len + 2), String.sub data (len + 2) (String.length data - len - 2)
             in
             let id = String.get_uint16_be packet 2 in
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
       let cs = String.sub (Bytes.unsafe_to_string cs) 0 read_len in
       handle_data (if String.length linger = 0 then cs else linger ^ cs)

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
    let ns = to_pairs nameservers in
    (* The connect_timeout given here is a bit too much, since it should
       be (a) connect to the remote NS (b) send query, receive answer.

       At the moment, how this is done, is that we use the connect_timeout
       for (a) and another separate one for (b). Since we do connection
       pooling, it is slightly tricky to use only a single connect_timeout. *)
    Happy_eyeballs_lwt.connect_ip ~connect_timeout:t.timeout_ns t.he ns >>= function
    | Error `Msg msg ->
      let err =
        Error (`Msg (Fmt.str "error %s connecting to resolver %a"
                       msg
                       Fmt.(list ~sep:(any ", ") (pair ~sep:(any ":") Ipaddr.pp int))
                       (to_pairs (nameserver_ips t.nameservers))))
      in
      Lwt_condition.broadcast connected_condition err;
      t.connected_condition <- None;
      Lwt.return err
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
        Lwt_condition.broadcast connected_condition (Ok ());
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
               let err = Error (`Msg "no further nameservers configured") in
               Lwt_condition.broadcast connected_condition err;
               t.connected_condition <- None;
               Lwt.return err
             end else
               connect_to_ns_list t connected_condition ns')

  and connect_via_tcp_to_ns (t : t) =
    match t.fd, t.connected_condition with
    | Some _, _ -> Lwt.return (Ok ())
    | None, Some w -> Lwt_condition.wait w
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

let create ?cache_size ?edns ?nameservers ?timeout happy_eyeballs =
  let dns = create ?cache_size ?edns ?nameservers ?timeout happy_eyeballs in
  let getaddrinfo record domain_name =
    let open Lwt_result.Infix in
    match record with
    | `A ->
      getaddrinfo dns Dns.Rr_map.A domain_name >|= fun (_ttl, set) ->
      Ipaddr.V4.Set.fold (fun ipv4 -> Ipaddr.Set.add (Ipaddr.V4 ipv4))
        set Ipaddr.Set.empty
    | `AAAA ->
      getaddrinfo dns Dns.Rr_map.Aaaa domain_name >|= fun (_ttl, set) ->
      Ipaddr.V6.Set.fold (fun ipv6 -> Ipaddr.Set.add (Ipaddr.V6 ipv6))
        set Ipaddr.Set.empty
  in
  Happy_eyeballs_lwt.inject happy_eyeballs getaddrinfo;
  dns

(* initialize the RNG *)
let () = Mirage_crypto_rng_lwt.initialize (module Mirage_crypto_rng.Fortuna)
