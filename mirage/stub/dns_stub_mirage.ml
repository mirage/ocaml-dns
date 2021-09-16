(* mirage stub resolver *)
open Lwt.Infix

open Dns

let src = Logs.Src.create "dns_stub_mirage" ~doc:"effectful DNS stub layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (T : Mirage_time.S) (P : Mirage_clock.PCLOCK) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4V6) = struct

  (* data in the wild:
     - a request comes in hdr, q
       - q to be found in cache
       - q not found in cache (to be forwarded to the recursive resolver)
         - unless q in transit (this to-be-done if it is worth it (is it?))
         - a fresh hdr, q is generated and sent to the recursive resolver
         - now hdr, q is registered to be awaited for
         -- we can either signal the request task once we found something,
            or preserve the original hdr, q together with ip and port
     - a reply goes out hdr, q, answer

     the "Client" is only concerned about the connection to the resolver, with
     multiplexing.

     the current API is:
      dns_client calls connect .. -> flow
                       send flow data
                       recv flow (* potentially multiple times *)

     i.e. our flow being (int * _):
       connect <nothing>
       send (id, _) data <- id <- data[2..3]
       recv (id, _) <- registers condition in N[id] ; waits ; removes condition

     or phrased differently:
       a recv_loop reads continously, whenever a full packet is received,
        N[id] is woken up with the packet
  *)

  let metrics =
    let f = function
      | `Udp_queries -> "udp-queries"
      | `Tcp_queries -> "tcp-queries"
      | `Queries -> "queries"
      | `Decoding_errors -> "decoding-errors"
      | `Tcp_connections -> "tcp-connections"
      | `Recursive_queries -> "recursive-questions"
      | `Recursive_answers -> "recursive-answers"
      | `Recursive_connections -> "recursive-connections"
      | `Authoritative_answers -> "authoritative-answers"
      | `Authoritative_errors -> "authoritative-errors"
      | `Reserved_answers -> "reserved-answers"
      | `On_update -> "on-update"
      | `Resolver_queries -> "resolver-queries"
      | `Resolver_answers -> "resolver-answers"
      | `Resolver_nodata -> "resolver-nodata"
      | `Resolver_nodomain -> "resolver-nodomain"
      | `Resolver_servfail -> "resolver-servfail"
      | `Resolver_notimp -> "resolver-notimplemented"
    in
    let metrics = Dns.counter_metrics ~f "stub-resolver" in
    (fun x -> Metrics.add metrics (fun x -> x) (fun d -> d x))

  module IM = Map.Make(struct
      type t = int
      let compare : int -> int -> int = fun a b -> compare a b
    end)

  module Client = struct
    module Transport : Dns_client.S
      with type stack = S.t
       and type +'a io = 'a Lwt.t
       and type io_addr = Ipaddr.t * int = struct
      type stack = S.t
      type io_addr = Ipaddr.t * int
      type ns_addr = Dns.proto * io_addr
      type +'a io = 'a Lwt.t

      type t = {
        nameserver : ns_addr ;
        timeout_ns : int64 ;
        stack : stack ;
        mutable flow : S.TCP.flow option ;
        mutable requests : (Cstruct.t * (Cstruct.t, [ `Msg of string ]) result Lwt_condition.t) IM.t ;
      }
      type context = {
        t : t ;
        mutable timeout_ns : int64 ;
        mutable data : Cstruct.t ;
      }

      let create
          ?(nameserver = `Tcp, (Ipaddr.V4 (Ipaddr.V4.of_string_exn (fst Dns_client.default_resolver)), 53))
          ~timeout
          stack =
        { nameserver ; timeout_ns = timeout ; stack ; flow = None ; requests = IM.empty }

      let nameserver { nameserver ; _ } = nameserver
      let rng = R.generate ?g:None
      let clock = C.elapsed_ns

      let with_timeout timeout_ns f =
        let timeout =
          T.sleep_ns timeout_ns >|= fun () ->
          Error (`Msg "DNS request timeout")
        in
        let start = clock () in
        Lwt.pick [ f ; timeout ] >|= fun result ->
        let stop = clock () in
        result, Int64.sub timeout_ns (Int64.sub stop start)

      let bind = Lwt.bind
      let lift = Lwt.return

      let rec read_loop ?(linger = Cstruct.empty) t flow =
        S.TCP.read flow >>= function
        | Error e ->
          t.flow <- None;
          Log.err (fun m -> m "error %a reading from resolver" S.TCP.pp_error e);
          Lwt.return_unit
        | Ok `Eof ->
          t.flow <- None;
          Log.info (fun m -> m "end of file reading from resolver");
          Lwt.return_unit
        | Ok (`Data cs) ->
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
                 | Some (_, cond) ->
                   metrics `Recursive_answers;
                   Lwt_condition.broadcast cond (Ok packet));
                handle_data rest
              else
                read_loop ~linger:data t flow
            else
              read_loop ~linger:data t flow
          in
          handle_data (if Cstruct.length linger = 0 then cs else Cstruct.append linger cs)

      let query_one flow data =
        S.TCP.write flow data >>= function
        | Error e ->
          Lwt.return (Error (`Msg (Fmt.to_to_string S.TCP.pp_write_error e)))
        | Ok () -> Lwt.return (Ok ())

      let req_all flow t =
        IM.fold (fun _id (data, _) r ->
            r >>= function
            | Error _ as e -> Lwt.return e
            | Ok () -> query_one flow data)
          t.requests (Lwt.return (Ok ()))

      let rec connect_ns ?(timeout = Duration.of_sec 5) t =
        let _proto, addr = nameserver t in
        with_timeout timeout
          (S.TCP.create_connection (S.tcp t.stack) addr >>= function
            | Error e ->
              Log.err (fun m -> m "error connecting to nameserver %a: %a"
                          Ipaddr.pp (fst addr) S.TCP.pp_error e) ;
              Lwt.return (Error (`Msg "connect failure"))
            | Ok flow ->
              metrics `Recursive_connections;
              t.flow <- Some flow;
              Lwt.async (fun () ->
                  read_loop t flow >>= fun () ->
                  if not (IM.is_empty t.requests) then
                    connect_ns ~timeout t >|= function
                    | Error (`Msg msg), _ ->
                      Log.err (fun m -> m "error while connecting to %a: %s"
                                  Ipaddr.pp (fst addr) msg);
                      ()
                    | Ok (), _ -> ()
                  else
                    Lwt.return_unit);
              req_all flow t)

      let connect t =
        match t.flow with
        | Some _ -> Lwt.return (Ok ({ t ; timeout_ns = t.timeout_ns ; data = Cstruct.empty }))
        | None ->
          connect_ns ~timeout:t.timeout_ns t >|= function
          | Ok (), timeout_ns -> Ok { t ; timeout_ns ; data = Cstruct.empty }
          | Error `Msg msg, _ -> Error (`Msg msg)

      let close _f =
        (* ignoring this here *)
        Lwt.return_unit

      let recv { t ; timeout_ns ; data } =
        if Cstruct.length data > 2 then
          let cond = Lwt_condition.create () in
          let id = Cstruct.BE.get_uint16 data 2 in
          t.requests <- IM.add id (data, cond) t.requests;
          with_timeout timeout_ns (Lwt_condition.wait cond) >|= fun (data, _) ->
          t.requests <- IM.remove id t.requests;
          match data with
          | Ok cs -> Ok cs
          | Error `Msg m -> Error (`Msg m)
        else
          Lwt.return (Error (`Msg "invalid context (data length <= 2)"))

      let send ({ t ; timeout_ns ; _ } as ctx) s =
        match t.flow with
        | None -> Lwt.return (Error (`Msg "no connection to resolver"))
        | Some flow ->
          ctx.data <- s;
          with_timeout timeout_ns (S.TCP.write flow s >>= function
            | Error e ->
              t.flow <- None;
              Lwt.return (Error (`Msg (Fmt.to_to_string S.TCP.pp_write_error e)))
            | Ok () ->
              metrics `Recursive_queries;
              Lwt.return (Ok ())) >|= function
          | Ok (), timeout_ns -> ctx.timeout_ns <- timeout_ns; Ok ()
          | Error _ as e, _ -> e
    end

    include Dns_client.Make(Transport)
  end

  (* likely this should contain:
     - a primary server (handling updates)
     - a client on steroids: multiplexing on connections
     - listening for DNS requests from clients:
        first find them in primary server
        if not authoritative, use the client
  *)

  (* task management
     - multiple requests for the same name, type can be done at the same "time"
     -> need to remember outstanding requests and signal to clients
  *)

  (* take multiple resolver IPs and round-robin / ask both (take first answer,
     ignoring ServFail etc.) *)

  (* timeout of resolver, retransmission (to another resolver / another flow) *)

  module Dns_flow = Dns_mirage.Make(S)

  type t = {
    client : Client.t ;
    reserved : Dns_server.t ;
    mutable server : Dns_server.t ;
    on_update : old:Dns_trie.t -> ?authenticated_key:[`raw] Domain_name.t -> update_source:Ipaddr.t -> Dns_trie.t -> unit Lwt.t ;
  }

  let query_server trie question data build_reply =
    match Dns_server.handle_question trie question with
    | Ok (_flags, answer, additional) ->
      (* TODO do sth with flags *)
      metrics `Authoritative_answers;
      Some (build_reply ?additional (`Answer answer))
    | Error (Rcode.NotAuth, _) -> None
    | Error (rcode, answer) ->
      metrics `Authoritative_errors;
      let data = `Rcode_error (rcode, Packet.opcode_data data, answer) in
      Some (build_reply ?additional:None data)

  let tsig_decode_sign server proto packet buf build_reply =
    let now = Ptime.v (P.now_d_ps ()) in
    match Dns_server.handle_tsig server now packet buf with
    | Error _ ->
      let data =
        `Rcode_error (Rcode.Refused, Packet.opcode_data packet.Packet.data, None)
      in
      Error (build_reply data)
    | Ok k ->
      let key =
        match k with None -> None | Some (keyname, _, _, _) -> Some keyname
      in
      let sign data =
        let packet =
          Packet.create packet.Packet.header packet.Packet.question data
        in
        match k with
        | None -> Some (fst (Packet.encode proto packet))
        | Some (keyname, _tsig, mac, dnskey) ->
          match Dns_tsig.encode_and_sign ~proto ~mac packet now dnskey keyname with
          | Error s -> Log.err (fun m -> m "error %a while signing answer" Dns_tsig.pp_s s); None
          | Ok (cs, _) -> Some cs
      in
      Ok (key, sign)

  let axfr_server server proto packet question buf build_reply =
    match tsig_decode_sign server proto packet buf build_reply with
    | Error e -> Some e
    | Ok (key, sign) ->
      match Dns_server.handle_axfr_request server proto key question with
      | Error rcode ->
        let err = `Rcode_error (rcode, Packet.opcode_data packet.Packet.data, None) in
        Some (build_reply err)
      | Ok axfr ->
        sign (`Axfr_reply axfr)

  let update_server t proto ip packet question u buf build_reply =
    let server = t.server in
    match tsig_decode_sign server proto packet buf build_reply with
    | Error e -> Lwt.return (Some e)
    | Ok (key, sign) ->
      match Dns_server.handle_update server proto key question u with
      | Ok (trie, _) ->
        let old = server.data in
        let server' = Dns_server.with_data server trie in
        t.server <- server';
        metrics `On_update;
        t.on_update ~old ?authenticated_key:key ~update_source:ip trie >|= fun () ->
        sign `Update_ack
      | Error rcode ->
        Lwt.return (sign (`Rcode_error (rcode, Opcode.Update, None)))

  let server t proto ip packet buf build_reply =
    let question, data = packet.Packet.question, packet.Packet.data in
    match data with
    | `Query -> Lwt.return (query_server t.server question data build_reply)
    | `Axfr_request ->
      Lwt.return (axfr_server t.server proto packet question buf (build_reply ?additional:None))
    | `Update u ->
      update_server t proto ip packet question u buf (build_reply ?additional:None)
    | _ ->
      let data =
        `Rcode_error (Rcode.NotImp, Packet.opcode_data packet.Packet.data, None)
      in
      Lwt.return (Some (build_reply ?additional:None data))

  let resolve t question data build_reply =
    metrics `Resolver_queries;
    let name = fst question in
    match data, snd question with
    | `Query, `K Rr_map.K key ->
      begin Client.get_resource_record t.client key name >|= function
        | Error `Msg msg ->
          Logs.err (fun m -> m "couldn't resolve %s" msg);
          let data = `Rcode_error (Rcode.ServFail, Opcode.Query, None) in
          metrics `Resolver_servfail;
          Some (build_reply data)
        | Error `No_data (domain, soa) ->
          let answer = (Name_rr_map.empty, Name_rr_map.singleton domain Soa soa) in
          let data = `Answer answer in
          metrics `Resolver_nodata;
          Some (build_reply data)
        | Error `No_domain (domain, soa) ->
          let answer = (Name_rr_map.empty, Name_rr_map.singleton domain Soa soa) in
          let data = `Rcode_error (Rcode.NXDomain, Opcode.Query, Some answer) in
          metrics `Resolver_nodomain;
          Some (build_reply data)
        | Ok reply ->
          let answer = (Name_rr_map.singleton name key reply, Name_rr_map.empty) in
          let data = `Answer answer in
          metrics `Resolver_answers;
          Some (build_reply data)
      end
    | _ ->
      Logs.err (fun m -> m "not implemented %a, data %a"
                   Dns.Packet.Question.pp question
                   Dns.Packet.pp_data data);
      let data = `Rcode_error (Rcode.NotImp, Packet.opcode_data data, None) in
      metrics `Resolver_notimp;
      Lwt.return (Some (build_reply data))

  (* we're now doing up to three lookups for each request:
    - in authoritative server (Dns_trie)
    - in reserved trie (Dns_trie)
    - in resolver cache (Dns_cache)
    - asking a remote resolver

     instead, on startup authoritative (from external) could be merged with
     reserved (but that makes data store very big and not easy to understand
     (lots of files for the reserved zones)) *)
  let handle t proto ip data =
    match Packet.decode data with
    | Error err ->
      metrics `Decoding_errors;
      (* TODO send FormErr back *)
      Logs.err (fun m -> m "couldn't decode %a" Packet.pp_err err);
      Lwt.return None
    | Ok packet ->
      metrics `Queries;
      (* check header flags: recursion desired (and send recursion available) *)
      let build_reply ?additional data =
        let packet = Packet.create ?additional packet.header packet.question data in
        fst (Packet.encode proto packet)
      in
      server t proto ip packet data build_reply >>= function
      | Some data -> Lwt.return (Some data)
      | None ->
        (* next look in reserved trie! *)
        let question, data = packet.Packet.question, packet.Packet.data in
        match query_server t.reserved question data build_reply with
        | Some data -> metrics `Reserved_answers ; Lwt.return (Some data)
        | None -> resolve t packet.Packet.question packet.Packet.data build_reply

  let create ?nameserver ?(size = 10000) ?(on_update = fun ~old:_ ?authenticated_key:_ ~update_source:_ _trie -> Lwt.return_unit) primary stack =
    let nameserver = match nameserver with None -> None | Some ns -> Some (`Tcp, (ns, 53)) in
    let client = Client.create ~size ?nameserver stack in
    let server = Dns_server.Primary.server primary in
    let reserved = Dns_server.create Dns_resolver_root.reserved R.generate in
    let t = { client ; reserved ; server ; on_update } in
    let udp_cb ~src ~dst:_ ~src_port buf =
      metrics `Udp_queries;
      handle t `Udp src buf >>= function
      | None -> Lwt.return_unit
      | Some data ->
        S.UDP.write ~src_port:53 ~dst:src ~dst_port:src_port (S.udp stack) data >|= function
        | Error e -> Logs.warn (fun m -> m "udp: failure %a while sending to %a:%d"
                                  S.UDP.pp_error e Ipaddr.pp src src_port)
        | Ok () -> ()
    in
    S.listen_udp stack ~port:53 udp_cb ;
    let tcp_cb flow =
      metrics `Tcp_connections;
      let dst_ip, dst_port = S.TCP.dst flow in
      Log.debug (fun m -> m "tcp connection from %a:%d" Ipaddr.pp dst_ip dst_port) ;
      let f = Dns_flow.of_flow flow in
      let rec loop () =
        Dns_flow.read_tcp f >>= function
        | Error () -> Lwt.return_unit
        | Ok data ->
          metrics `Tcp_queries;
          handle t `Tcp dst_ip data >>= function
          | None ->
            Log.warn (fun m -> m "no TCP output") ;
            loop ()
          | Some data ->
            Dns_flow.send_tcp flow data >>= function
            | Ok () -> loop ()
            | Error () -> Lwt.return_unit
      in
      loop ()
    in
    S.listen_tcp stack ~port:53 tcp_cb;
    t
end
