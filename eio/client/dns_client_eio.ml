type 'a env = <
  clock         : Eio.Time.clock ;
  mono_clock    : Eio.Time.Mono.t ;
  net           : Eio.Net.t ;
  fs            : Eio.Fs.dir Eio.Path.t ;
  secure_random : Eio.Flow.source;
  ..
> as 'a

type io_addr = [`Plaintext of Ipaddr.t * int | `Tls of Ipaddr.t * int]
type stack = {
  fs          : Eio.Fs.dir Eio.Path.t;
  sw          : Eio.Switch.t;
  mono_clock  : Eio.Time.Mono.t;
  net         : Eio.Net.t;
  resolv_conf : string;
}

module IM = Map.Make(Int)

let src = Logs.Src.create "dns_client_eio" ~doc:"eio backend for DNS client"
module Log = (val Logs.src_log src: Logs.LOG)

module Transport : Dns_client.S
  with type io_addr = io_addr
   and type stack   = stack
   and type +'a io  = 'a
= struct
  type nonrec io_addr = io_addr
  type nonrec stack = stack
  type +'a io = 'a

  type t = {
    nameservers : Dns.proto * nameservers ;
    stack : stack ;
    timeout : Eio.Time.Timeout.t ;
    mutable ns_connection_condition : Eio.Condition.t option ;
    mutable ctx : (Dns.proto * context) option ;
  }

  and context = {
    t : t ;
    mutable requests : Cstruct.t Eio.Promise.u IM.t ;
    mutable ns_connection: <Eio.Flow.two_way> ;
    mutable recv_buf : Cstruct.t ;
    mutable closed : bool ;
  }

  (* DNS nameservers. *)
  and nameservers =
    | Static of io_addr list
    | Resolv_conf of resolv_conf

  (* /etc/resolv.conf *)
  and resolv_conf = {
    mutable ips    : io_addr list ;
    mutable digest : Digest.t option ;
  }

  let read_resolv_conf stack =
    match Eio.Path.(stack.fs / stack.resolv_conf) |> Eio.Path.load with
    | content -> Ok content
    | exception e ->
      Fmt.error_msg "Error while reading file %s: %a" stack.resolv_conf Fmt.exn e

  let ( let* ) = Result.bind
  let ( let+ ) r f = Result.map f r

  let decode_resolv_conf data =
    let* ips = Dns_resolvconf.parse data in
    match ips with
    | [] -> Error (`Msg "empty nameservers from resolv.conf")
    | ips ->
      List.map (function `Nameserver ip -> [`Plaintext (ip, 53); `Tls (ip, 853)]) ips
      |> List.flatten
      |> Result.ok

  let default_resolvers () =
    List.map (fun ip -> `Tls (ip, 853)) Dns_client.default_resolvers

  let rng = Mirage_crypto_rng.generate ?g:None
  let clock = Mtime_clock.elapsed_ns

  let create ?nameservers ~timeout stack =
    { nameservers =
        (match nameservers with
         | Some (`Udp,_) -> invalid_arg "UDP is not supported"
         | Some (proto, []) -> proto, Static (default_resolvers ())
         | Some (`Tcp, ns) -> `Tcp, Static ns
         | None ->
           (let* data = read_resolv_conf stack in
            let+ ips = decode_resolv_conf data in
            (ips, Some (Digest.string data)))
           |> function
           | Error (`Msg e) ->
             Log.warn (fun m -> m "failed to decode %s - %s" stack.resolv_conf e);
             (`Tcp, Resolv_conf { ips = default_resolvers (); digest = None})
           | Ok(ips, digest) -> `Tcp, Resolv_conf {ips; digest})
    ; stack
    ; timeout = Eio.Time.Timeout.v stack.mono_clock @@ Mtime.Span.of_uint64_ns timeout
    ; ns_connection_condition = None
    ; ctx = None
    }

  let nameserver_ips t =
    match t.nameservers with
    | _, Static ips -> ips
    | _, Resolv_conf{ ips;_ } -> ips

  let nameservers t = (`Tcp, nameserver_ips t)

  let maybe_update_nameservers t =
    let update_resolv_conf resolv_conf data dgst =
      match decode_resolv_conf data with
      | Ok ips ->
        resolv_conf.digest <- Some dgst;
        resolv_conf.ips <- ips;
      | Error _ ->
        resolv_conf.digest <- None;
        resolv_conf.ips <- default_resolvers ()
    in
    match t.nameservers with
    | _, Static _ -> ()
    | _, Resolv_conf resolv_conf ->
      (match read_resolv_conf t.stack, resolv_conf.digest with
       | Ok data, Some d ->
         let digest = Digest.string data in
         if Digest.equal digest d then () else update_resolv_conf resolv_conf data digest
       | Ok data, None -> update_resolv_conf resolv_conf data (Digest.string data)
       | Error _, None -> ()
       | Error _, Some _ ->
         resolv_conf.digest <- None;
         resolv_conf.ips <- default_resolvers ())

  let find_ns t (ip, port) =
    List.find
      (function `Plaintext (ip', p) | `Tls (ip', p) -> Ipaddr.compare ip ip' = 0 && p = port)
      (nameserver_ips t)

  let rec he_handle_actions t he actions =
    let fiber_of_action = function
      | Happy_eyeballs.Connect (host, id, (ip, port)) ->
        fun () ->
          let ip' =
            (match ip with
             | Ipaddr.V4 ip -> Ipaddr.V4.to_octets ip
             | Ipaddr.V6 ip -> Ipaddr.V6.to_octets ip)
            |> Eio.Net.Ipaddr.of_raw
          in
          let stream = `Tcp (ip', port) in
          begin try
              Eio.Time.Timeout.run_exn t.timeout (fun () ->
                  let flow = Eio.Net.connect ~sw:t.stack.sw t.stack.net stream in
                  Log.debug (fun m -> m "[he_handle_actions] connected to nameserver (%a)"
                                Fmt.(pair ~sep:comma Ipaddr.pp int) (ip, port));
                  Some (ip, port, flow))
            with Eio.Time.Timeout as ex ->
              Log.debug (fun m -> m "[he_handle_actions] connection to nameserver (%a) timed out"
                            Fmt.(pair ~sep:comma Ipaddr.pp int) (ip, port));
              let err = Printexc.to_string ex in
              let event = Happy_eyeballs.Connection_failed (host, id, (ip, port), err) in
              let he, actions = Happy_eyeballs.event he (clock ()) event in
              he_handle_actions t he actions
          end
      | Connect_failed _ -> fun () -> None
      | Connect_cancelled _ | Resolve_a _ | Resolve_aaaa _ as a ->
        fun () ->
          Log.warn (fun m -> m "[he_handle_actions] ignoring action %a" Happy_eyeballs.pp_action a);
          None
    in
    Eio.Fiber.any (List.map fiber_of_action actions)

  let to_ip_port =
    List.map (function `Plaintext (ip, port) -> (ip, port) | `Tls (ip, port) -> (ip, port))

  let authenticator =
    let authenticator_ref = ref None in
    fun () ->
      match !authenticator_ref with
      | Some x -> x
      | None -> match Ca_certs.authenticator () with
        | Ok a -> authenticator_ref := Some a ; a
        | Error `Msg m -> invalid_arg ("failed to load trust anchors: " ^ m)

  let rec connect t =
    match t.ctx, t.ns_connection_condition with
    | Some ctx, _ -> Ok ctx
    | None, Some condition ->
      Eio.Condition.await_no_mutex condition;
      connect t
    | None, None ->
      let ns_connection_condition = Eio.Condition.create () in
      t.ns_connection_condition <- Some ns_connection_condition;
      maybe_update_nameservers t;
      let ns = to_ip_port @@ nameserver_ips t in
      let _waiters, id = Happy_eyeballs.Waiter_map.(register () empty) in
      let he = Happy_eyeballs.create (clock ()) in
      let he, actions = Happy_eyeballs.connect_ip he (clock ()) ~id ns in
      begin match he_handle_actions t he actions with
        | Some (ip, port, conn) ->
          let conn =
            match find_ns t (ip, port) with
            | `Plaintext _ -> (conn :> Eio.Flow.two_way)
            | `Tls (_,_) ->
              let authenticator = authenticator () in
              let config = Tls.Config.(client ~authenticator ()) in
              (Tls_eio.client_of_flow config conn :> Eio.Flow.two_way)
          in
          let ctx =
            { t = t
            ; requests = IM.empty
            ; ns_connection = conn
            ; recv_buf = Cstruct.create 2048
            ; closed = false
            }
          in
          t.ctx <- Some (`Tcp, ctx);
          Eio.Fiber.fork ~sw:t.stack.sw ( fun () -> recv_dns_packets ctx );
          Eio.Condition.broadcast ns_connection_condition;
          Ok (`Tcp, ctx)
        | None ->
          t.ns_connection_condition <- None;
          Eio.Condition.broadcast ns_connection_condition;
          let error_msg =
            Fmt.str "unable to connect to nameservers %a"
              Fmt.(list ~sep:(any ", ") (pair ~sep:(any ":") Ipaddr.pp int))
              (to_ip_port @@ nameserver_ips t)
          in
          Log.debug (fun m -> m "connect : %s" error_msg);
          Error (`Msg error_msg)
      end

  and recv_dns_packets ?(recv_data = Cstruct.empty) (ctx : context) =

    let append_recv_buf ctx got recv_data =
      let buf = Cstruct.sub ctx.recv_buf 0 got in
      if Cstruct.is_empty recv_data
      then buf
      else Cstruct.append recv_data buf
    in

    let rec handle_data recv_data =
      let recv_data_len = Cstruct.length recv_data in
      if recv_data_len < 2
      then recv_dns_packets ~recv_data ctx
      else
        match Cstruct.BE.get_uint16 recv_data 0 with
        | packet_len when recv_data_len - 2 >= packet_len ->
          let packet, recv_data = Cstruct.split recv_data @@ packet_len + 2 in
          let response_id = Cstruct.BE.get_uint16 packet 2 in
          (match IM.find response_id ctx.requests with
           | r ->
             ctx.requests <- IM.remove response_id ctx.requests ;
             Eio.Promise.resolve r packet
           | exception Not_found -> () (* spurious data, ignore *)
          );
          if not @@ IM.is_empty ctx.requests then handle_data recv_data else ()
        | _ -> recv_dns_packets ~recv_data ctx
    in

    match Eio.Flow.single_read ctx.ns_connection ctx.recv_buf with
    | got ->
      let recv_data = append_recv_buf ctx got recv_data in
      handle_data recv_data
    | exception End_of_file ->
      ctx.t.ns_connection_condition <- None ;
      ctx.t.ctx <- None ;
      ctx.closed <- true ;
      if not @@ IM.is_empty ctx.requests then
        (match connect ctx.t with
         | Ok _ -> recv_dns_packets ~recv_data ctx
         | Error _ -> Log.warn (fun m -> m "[recv_dns_packets] connection closed while processing dns requests") )
      else ()

  let validate_query_packet tx =
    if Cstruct.length tx > 4 then Ok () else
      Error (`Msg "Invalid DNS query packet (data length <= 4)")

  let send_recv ctx packet =
    if not ctx.closed then
      let* () = validate_query_packet packet in
      try
        let request_id = Cstruct.BE.get_uint16 packet 2 in
        let response_p, response_r = Eio.Promise.create () in
        ctx.requests <- IM.add request_id response_r ctx.requests;
        Eio.Time.Timeout.run_exn ctx.t.timeout (fun () ->
            Eio.Flow.write ctx.ns_connection [packet];
            let response = Eio.Promise.await response_p in
            Ok response
          )
      with Eio.Time.Timeout -> Error (`Msg "DNS request timeout")
    else 
      Error (`Msg "Nameserver closed connection")

  let close _ = ()
  let bind a f = f a
  let lift v = v
end

include Dns_client.Make(Transport)

let run ?(resolv_conf = "/etc/resolv.conf") (env: _ env) f =
  Mirage_crypto_rng_eio.run (module Mirage_crypto_rng.Fortuna) env (fun () ->
      Eio.Switch.run (fun sw ->
          let stack =
            { sw
            ; mono_clock = env#mono_clock
            ; net = env#net
            ; resolv_conf
            ; fs = env#fs
            }
          in
          f stack
        )
    )
