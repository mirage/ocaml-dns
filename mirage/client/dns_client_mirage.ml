open Lwt.Infix

let src = Logs.Src.create "dns_client_mirage" ~doc:"effectful DNS client layer"
module Log = (val Logs.src_log src : Logs.LOG)

module IM = Map.Make(Int)

module type S = sig
  type happy_eyeballs

  module Transport : Dns_client.S
    with type io_addr = [
        | `Plaintext of Ipaddr.t * int
        | `Tls of Tls.Config.client * Ipaddr.t * int
      ]
     and type +'a io = 'a Lwt.t

  include module type of Dns_client.Make(Transport)

  val nameserver_of_string : string ->
    (Dns.proto * Transport.io_addr, [> `Msg of string ]) result

  val connect :
    ?cache_size:int ->
    ?edns:[ `None | `Auto | `Manual of Dns.Edns.t ] ->
    ?nameservers:string list ->
    ?timeout:int64 ->
    Transport.stack -> t Lwt.t

  val with_happy_eyeballs : ?cache_size:int ->
    ?edns:[ `None | `Auto | `Manual of Dns.Edns.t ] ->
    ?nameservers:string list ->
    ?timeout:int64 ->
    Transport.stack -> happy_eyeballs -> t Lwt.t
end

module Make
  (R : Mirage_random.S)
  (T : Mirage_time.S)
  (M : Mirage_clock.MCLOCK)
  (P : Mirage_clock.PCLOCK)
  (S : Tcpip.Stack.V4V6)
  (H : Happy_eyeballs_mirage.S with type stack = S.t
                                and type flow = S.TCP.flow) = struct
  type happy_eyeballs = H.t

  module TLS = Tls_mirage.Make(S.TCP)
  module CA = Ca_certs_nss.Make(P)

  let auth_err = match X509.Authenticator.of_string "" with
    | Ok _ -> "should not happen"
    | Error `Msg m -> m

  let format = {|
The format of an IP address and optional port is:
- '[::1]:port' for an IPv6 address, or
- '127.0.0.1:port' for an IPv4 address.

The format of a nameserver is:
- 'udp:IP' where the first element is the string "udp" and the [IP] as described
  above (port defaults to 53): UDP packets to the provided IP address will be
  sent from a random source port;
- 'tcp:IP' where the first element is the string "tcp" and the [IP] as described
  above (port defaults to 53): a TCP connection to the provided IP address will
  be established;
- 'tls:IP' where the first element is the string "tls", the [IP] as described
  above (port defaults to 853): a TCP connection will be established, on top of
  which a TLS handshake with the authenticator
  (https://github.com/mirage/ca-certs-nss) will be done (which checks for the
  IP address being in the certificate as SubjectAlternativeName);
- 'tls:IP!hostname' where the first element is the string "tls",
  the [IP] as described above (port defaults to 853), the [hostname] a host name
  used for the TLS authentication: a TCP connection will be established, on top
  of which a TLS handshake with the authenticator
  (https://github.com/mirage/ca-certs-nss) will be done;
- 'tls:IP!hostname!authenticator' where the first element is the string "tls",
  the [IP] as described above (port defaults to 853), the [hostname] a host name
  used for the TLS authentication, and the [authenticator] an X509
  authenticator: a TCP connection will be established, on top of which a TLS
  handshake with the authenticator will be done.
|} ^ auth_err

  let nameserver_of_string str =
    let ( let* ) = Result.bind in
    begin match String.split_on_char ':' str with
      | "tls" :: rest ->
        let str = String.concat ":" rest in
        ( match String.split_on_char '!' str with
          | [ nameserver ] ->
            let* ipaddr, port = Ipaddr.with_port_of_string ~default:853 nameserver in
            let* authenticator = CA.authenticator () in
            let tls = Tls.Config.client ~authenticator () in
            Ok (`Tcp, `Tls (tls, ipaddr, port))
          | nameserver :: opt_hostname :: authenticator ->
            let* ipaddr, port = Ipaddr.with_port_of_string ~default:853 nameserver in
            let peer_name, data =
              match
                let* dn = Domain_name.of_string opt_hostname in
                Domain_name.host dn
              with
              | Ok hostname -> Some hostname, String.concat "!" authenticator
              | Error _ -> None, String.concat "!" (opt_hostname :: authenticator)
            in
            let* authenticator =
              if data = "" then
                CA.authenticator ()
              else
                let* a = X509.Authenticator.of_string data in
                Ok (a (fun () -> Some (Ptime.v (P.now_d_ps ()))))
            in
            let tls = Tls.Config.client ~authenticator ?peer_name () in
            Ok (`Tcp, `Tls (tls, ipaddr, port))
          | [] -> assert false )
      | "tcp" :: nameserver ->
        let str = String.concat ":" nameserver in
        let* ipaddr, port = Ipaddr.with_port_of_string ~default:53 str in
        Ok (`Tcp, `Plaintext (ipaddr, port))
      | "udp" :: nameserver ->
        let str = String.concat ":" nameserver in
        let* ipaddr, port = Ipaddr.with_port_of_string ~default:53 str in
        Ok (`Udp, `Plaintext (ipaddr, port))
      | _ ->
        Error (`Msg ("Unable to decode nameserver " ^ str))
    end |> Result.map_error (function `Msg e -> `Msg (e ^ format))

  module Transport : Dns_client.S
    with type stack = S.t
     and type +'a io = 'a Lwt.t
     and type io_addr = [
         | `Plaintext of Ipaddr.t * int
         | `Tls of Tls.Config.client * Ipaddr.t * int
       ] = struct
    type stack = S.t
    type io_addr = [
      | `Plaintext of Ipaddr.t * int
      | `Tls of Tls.Config.client * Ipaddr.t * int
    ]
    type +'a io = 'a Lwt.t
    module IS = Set.Make(Int)
    type t = {
      nameservers : io_addr list ;
      proto : Dns.proto ;
      timeout_ns : int64 ;
      stack : stack ;
      mutable udp_ports : IS.t ;
      mutable flow : [`Plain of S.TCP.flow | `Tls of TLS.flow ] option ;
      mutable connected_condition : (unit, [ `Msg of string ]) result Lwt_condition.t option ;
      mutable requests : (Cstruct.t * (Cstruct.t, [ `Msg of string ]) result Lwt_condition.t) IM.t ;
      he : H.t ;
    }
    type context = t

    let clock = M.elapsed_ns

    let read_udp t ip ip_us ~src ~dst ~src_port:_ data =
      if Ipaddr.compare ip_us dst = 0 && Ipaddr.compare ip src = 0 &&
         Cstruct.length data > 12 (* minimum DNS length (header length) *)
      then
        (let id = Cstruct.BE.get_uint16 data 0 in
         (match IM.find_opt id t.requests with
          | None -> Log.warn (fun m -> m "received unsolicited data, ignoring")
          | Some (_, cond) -> Lwt_condition.broadcast cond (Ok data)));
      Lwt.return_unit

    let generate_udp_port t =
      let rec go retries =
        if retries = 0 then
          Error (`Msg "couldn't find a free UDP port")
        else
          let port = 1024 + ((Cstruct.BE.get_uint16 (R.generate 2) 0) mod (65536 - 1024)) in
          if IS.mem port t.udp_ports then
            go (retries - 1)
          else
            (t.udp_ports <- IS.add port t.udp_ports;
             Ok port)
      in
      go 32

    let create ?nameservers ~timeout stack =
      let proto, nameservers = match nameservers with
        | None ->
          let authenticator = match CA.authenticator () with
            | Ok a -> a
            | Error `Msg m -> invalid_arg ("bad CA certificates " ^ m)
          in
          let tls_cfg =
            let peer_name = Dns_client.default_resolver_hostname in
            Tls.Config.client ~authenticator ~peer_name ()
          in
          let ns =
            List.map (fun ip -> `Tls (tls_cfg, ip, 853))
              Dns_client.default_resolvers
          in
          `Tcp, ns
        | Some (a, ns) -> a, ns
      in
      let he =
        let happy_eyeballs = Happy_eyeballs.create ~connect_timeout:timeout (clock ()) in
        H.create ~happy_eyeballs stack
      in
      {
        nameservers ;
        proto ;
        timeout_ns = timeout ;
        stack ;
        udp_ports = IS.empty ;
        flow = None ;
        connected_condition = None ;
        requests = IM.empty ;
        he ;
      }

    let nameservers { proto ; nameservers ; _ } = proto, nameservers
    let rng = R.generate ?g:None

    let with_timeout time_left f =
      let timeout =
        T.sleep_ns time_left >|= fun () ->
        Error (`Msg "DNS request timeout")
      in
      Lwt.pick [ f ; timeout ]

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
            if not (IM.is_empty t.requests) then
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
            if not (IM.is_empty t.requests) then
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
      List.map (function `Plaintext (ip, port)
                       | `Tls (_, ip, port) -> (ip, port))

    let find_ns ns (addr, port) =
      List.find (function `Plaintext (ip, p) | `Tls (_, ip, p) ->
          Ipaddr.compare ip addr = 0 && p = port)
        ns

    let rec connect_ns t nameservers =
      let connected_condition = Lwt_condition.create () in
      t.connected_condition <- Some connected_condition ;
      let ns = to_pairs nameservers in
      H.connect_ip t.he ns >>= function
      | Error `Msg msg ->
        let err = Error (`Msg (Fmt.str "error %s connecting to resolver %a"
                                 msg
                                 Fmt.(list ~sep:(any ", ") (pair ~sep:(any ":") Ipaddr.pp int))
                                 (to_pairs t.nameservers)))
        in
        Lwt_condition.broadcast connected_condition err;
        t.connected_condition <- None;
        Log.err (fun m -> m "error connecting to resolver %s" msg);
        Lwt.return err
      | Ok (addr, flow) ->
        let continue flow =
          t.flow <- Some flow;
          Lwt.async (fun () ->
              read_loop t flow >>= fun () ->
              if not (IM.is_empty t.requests) then
                connect_ns t t.nameservers >|= function
                | Error `Msg msg ->
                  Log.err (fun m -> m "error while connecting to resolver: %s" msg)
                | Ok () -> ()
              else
                Lwt.return_unit);
          Lwt_condition.broadcast connected_condition (Ok ());
          t.connected_condition <- None;
          req_all flow t
        in
        let config = find_ns t.nameservers addr in
        match config with
        | `Plaintext _ -> continue (`Plain flow)
        | `Tls (tls_cfg, _ip, _port) ->
          TLS.client_of_flow tls_cfg flow >>= function
          | Ok tls -> continue (`Tls tls)
          | Error e ->
            Log.warn (fun m -> m "error establishing TLS connection to %a:%d: %a"
                         Ipaddr.pp (fst addr) (snd addr) TLS.pp_write_error e);
            let ns' =
              List.filter (function
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
              connect_ns t ns'

    let connect t =
      let to_tcp = function
        | Ok () -> Ok (`Tcp, t)
        | Error `Msg msg -> Error (`Msg msg)
      in
      match t.proto with
      | `Udp -> Lwt.return (Ok (`Udp, t))
      | `Tcp -> match t.flow, t.connected_condition with
        | Some _, _ -> Lwt.return (Ok (`Tcp, t))
        | None, Some w -> Lwt_condition.wait w >|= to_tcp
        | None, None -> connect_ns t t.nameservers >|= to_tcp

    let close _f =
      (* ignoring this here *)
      Lwt.return_unit

    let send_recv t tx =
      let ( >>>= ) = Lwt_result.bind in
      if Cstruct.length tx > 4 then
        match t.proto, t.flow with
        | `Udp, _ ->
          let dst, dst_port = match t.nameservers with
            | `Plaintext (ip, port) :: _ -> ip, port
            | _ -> assert false
          in
          let src = S.IP.src (S.ip t.stack) ~dst in
          let id = Cstruct.BE.get_uint16 tx 0 in
          Lwt.return (generate_udp_port t) >>>= fun udp_port ->
          with_timeout t.timeout_ns
            (S.UDP.listen (S.udp t.stack) ~port:udp_port (read_udp t dst src);
             (S.UDP.write ~src_port:udp_port ~dst ~dst_port (S.udp t.stack) tx >|= function
               | Error e -> Error (`Msg (Fmt.to_to_string S.UDP.pp_error e))
               | Ok () -> Ok ()) >>>= fun () ->
             let cond = Lwt_condition.create () in
             t.requests <- IM.add id (tx, cond) t.requests;
             let open Lwt.Infix in
             Lwt_condition.wait cond >|= fun data ->
             match data with Ok _ | Error `Msg _ as r -> r) >|= fun r ->
          S.UDP.unlisten (S.udp t.stack) ~port:udp_port;
          t.udp_ports <- IS.remove udp_port t.udp_ports;
          t.requests <- IM.remove id t.requests;
          r
        | `Tcp, None -> Lwt.return (Error (`Msg "no connection to resolver"))
        | `Tcp, Some flow ->
          let id = Cstruct.BE.get_uint16 tx 2 in
          with_timeout t.timeout_ns
            (let open Lwt_result.Infix in
             query_one flow tx >>= fun () ->
             let cond = Lwt_condition.create () in
             t.requests <- IM.add id (tx, cond) t.requests;
             let open Lwt.Infix in
             Lwt_condition.wait cond >|= fun data ->
             match data with Ok _ | Error `Msg _ as r -> r) >|= fun r ->
          t.requests <- IM.remove id t.requests;
          r
      else
        Lwt.return (Error (`Msg "invalid context (data length <= 4)"))

  end

  include Dns_client.Make(Transport)

  let connect ?cache_size ?edns ?(nameservers= []) ?timeout stack =
    let nameservers =
      List.map
        (fun nameserver -> match nameserver_of_string nameserver with
           | Ok nameserver -> nameserver
           | Error (`Msg err) -> invalid_arg err)
        nameservers
    in
    let tcp, udp =
      List.fold_left (fun (tcp, udp) -> function
          | `Tcp, a -> a :: tcp, udp
          | `Udp, a -> tcp, a :: udp)
        ([], []) nameservers
    in
    let nameservers =
      match tcp, udp with
      | [], [] -> None
      | [], _::_ -> Some (`Udp, udp)
      | _::_, _ -> Some (`Tcp, tcp)
    in
    Lwt.return (create ?cache_size ?edns ?nameservers ?timeout stack)

  let with_happy_eyeballs ?cache_size ?edns ?nameservers ?timeout stack happy_eyeballs =
    connect ?cache_size ?edns ?nameservers ?timeout stack >>= fun t ->
    let getaddrinfo record domain_name =
      let open Lwt_result.Infix in
      match record with
      | `A ->
        getaddrinfo t Dns.Rr_map.A domain_name >|= fun (_ttl, set) ->
        Ipaddr.V4.Set.fold (fun ipv4 -> Ipaddr.Set.add (Ipaddr.V4 ipv4))
          set Ipaddr.Set.empty
      | `AAAA ->
        getaddrinfo t Dns.Rr_map.Aaaa domain_name >|= fun (_ttl, set) ->
        Ipaddr.V6.Set.fold (fun ipv6 -> Ipaddr.Set.add (Ipaddr.V6 ipv6))
          set Ipaddr.Set.empty
    in
    H.inject happy_eyeballs getaddrinfo;
    Lwt.return t
end
