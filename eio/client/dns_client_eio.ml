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
    mutable buf : Cstruct.t ;
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
      | Connect_failed _ ->
        fun () ->
          Log.debug (fun m -> m "[he_handle_actions] connection failed");
          None
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
    Log.debug (fun m -> m "connect : establishing connection to nameservers");
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
          let context =
            { t = t
            ; requests = IM.empty
            ; ns_connection = conn
            ; buf = Cstruct.empty
            }
          in
          t.ctx <- Some (`Tcp, context);
          Eio.Condition.broadcast ns_connection_condition;
          Ok (`Tcp, context)
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

  let recv_data t flow id : unit =
    let buf = Cstruct.create 512 in
    Log.debug (fun m -> m "recv_data (%X): t.buf.len %d" id (Cstruct.length t.buf));
    let got = Eio.Flow.single_read flow buf in
    Log.debug (fun m -> m "recv_data (%X): got %d" id got);
    let buf = Cstruct.sub buf 0 got in
    t.buf <- if Cstruct.length t.buf = 0 then buf else Cstruct.append t.buf buf;
    Log.debug (fun m -> m "recv_data (%X): t.buf.len %d" id (Cstruct.length t.buf))

  let rec recv_packet t ns_connection request_id =
    Log.debug (fun m -> m "recv_packet (%X)" request_id);
    let buf_len = Cstruct.length t.buf in
    if buf_len > 2 then (
      let packet_len = Cstruct.BE.get_uint16 t.buf 0 in
      Log.debug (fun m -> m "recv_packet (%X): packet_len %d" request_id (Cstruct.length t.buf));
      if buf_len - 2 >= packet_len then
        let packet, rest =
          if buf_len - 2 = packet_len
          then t.buf, Cstruct.empty
          else Cstruct.split t.buf (packet_len + 2)
        in
        t.buf <- rest;
        let response_id = Cstruct.BE.get_uint16 packet 2 in
        Log.debug (fun m -> m "recv_packet (%X): got response %X" request_id response_id);
        if response_id = request_id
        then packet
        else begin
          (match IM.find response_id t.requests with
           | r -> Eio.Promise.resolve r packet
           | exception Not_found -> ());
          recv_packet t ns_connection request_id
        end
      else begin
        recv_data t ns_connection request_id;
        recv_packet t ns_connection request_id
      end
    )
    else begin
      recv_data t ns_connection request_id;
      recv_packet t ns_connection request_id
    end

  let validate_query_packet tx =
    if Cstruct.length tx > 4 then Ok () else
      Error (`Msg "Invalid DNS query packet (data length <= 4)")

  let send_recv ctx packet =
    let* () = validate_query_packet packet in
    try
      let request_id = Cstruct.BE.get_uint16 packet 2 in
      Eio.Time.Timeout.run_exn ctx.t.timeout (fun () ->
          Eio.Flow.write ctx.ns_connection [packet];
          Log.debug (fun m -> m "send_recv (%X): wrote request" request_id);
          let response_p, response_r = Eio.Promise.create () in
          ctx.requests <- IM.add request_id response_r ctx.requests;
          let response =
            Eio.Fiber.first
              (fun () -> recv_packet ctx ctx.ns_connection request_id)
              (fun () -> Eio.Promise.await response_p)
          in
          Log.debug (fun m -> m "send_recv (%X): got response" request_id);
          Ok response
        )
    with
    | Eio.Time.Timeout -> Error (`Msg "DNS request timeout")
  (*     | exn -> Error (`Msg (Printexc.to_string exn)) *)

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
