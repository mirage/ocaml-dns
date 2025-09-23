(* mirage stub resolver *)
open Lwt.Infix

open Dns

let src = Logs.Src.create "dns_stub_mirage" ~doc:"effectful DNS stub layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (S : Tcpip.Stack.V4V6) = struct

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
      | `Ocaml_queries -> "ocaml-queries"
      | `Tcp_connections -> "tcp-connections"
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

  module H = Happy_eyeballs_mirage.Make(S)
  module Client = Dns_client_mirage.Make(S)(H)

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
    push : (Ipaddr.t * int * string * (int32 * string) Lwt.u) option -> unit ;
  }

  let primary_data { server ; _ } =
    server.Dns_server.data

  let update_primary_data t trie =
    let server = Dns_server.with_data t.server trie in
    t.server <- server

  let resolve_external { push ; _ } (ip, port) data =
    let th, wk = Lwt.wait () in
    push (Some (ip, port, data, wk));
    th

  let update_tls _t _tls = ()

  let build_reply header question proto ?additional data =
    let ttl = Packet.minimum_ttl data in
    let packet = Packet.create ?additional header question data in
    ttl, fst (Packet.encode proto packet)

  let query_server trie question data header proto =
    match Dns_server.handle_question trie question with
    | Ok (_flags, answer, additional) ->
      (* TODO do sth with flags *)
      metrics `Authoritative_answers;
      let data = `Answer answer in
      let ttl = Packet.minimum_ttl data in
      let packet = Packet.create ?additional header question data in
      let packet =
        match Dns_block.edns packet with
        | None -> packet
        | Some edns ->
          Dns_resolver_metrics.resolver_stats `Blocked;
          Dns.Packet.with_edns packet (Some edns)
      in
      let reply = ttl, fst (Packet.encode proto packet) in
      Some reply
    | Error (Rcode.NotAuth, _) -> None
    | Error (rcode, answer) ->
      metrics `Authoritative_errors;
      let data = `Rcode_error (rcode, Packet.opcode_data data, answer) in
      let reply = build_reply header question proto data in
      Some reply

  let tsig_decode_sign server proto packet buf header question =
    let now = Mirage_ptime.now () in
    match Dns_server.handle_tsig server now packet buf with
    | Error _ ->
      let data =
        `Rcode_error (Rcode.Refused, Packet.opcode_data packet.Packet.data, None)
      in
      let reply = build_reply header question proto data in
      Error reply
    | Ok k ->
      let key =
        match k with None -> None | Some (keyname, _, _, _) -> Some keyname
      in
      let sign data =
        let ttl = Packet.minimum_ttl data in
        let packet = Packet.create header question data in
        match k with
        | None -> Some (ttl, fst (Packet.encode proto packet))
        | Some (keyname, _tsig, mac, dnskey) ->
          match Dns_tsig.encode_and_sign ~proto ~mac packet now dnskey keyname with
          | Error s -> Log.err (fun m -> m "error %a while signing answer" Dns_tsig.pp_s s); None
          | Ok (cs, _) -> Some (ttl, cs)
      in
      Ok (key, sign)

  let axfr_server server proto packet question buf header =
    match tsig_decode_sign server proto packet buf header question with
    | Error e -> Some e
    | Ok (key, sign) ->
      match Dns_server.handle_axfr_request server proto key question with
      | Error rcode ->
        let err = `Rcode_error (rcode, Packet.opcode_data packet.Packet.data, None) in
        let reply = build_reply header question proto err in
        Some reply
      | Ok axfr ->
        sign (`Axfr_reply axfr)

  let update_server t proto ip packet question u buf header =
    let server = t.server in
    match tsig_decode_sign server proto packet buf header question with
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

  let server t proto ip packet header question data buf =
    match data with
    | `Query -> Lwt.return (query_server t.server question data header proto)
    | `Axfr_request ->
      Lwt.return (axfr_server t.server proto packet question buf header)
    | `Update u ->
      update_server t proto ip packet question u buf header
    | _ ->
      let data =
        `Rcode_error (Rcode.NotImp, Packet.opcode_data packet.Packet.data, None)
      in
      let pkt = build_reply header question proto data in
      Lwt.return (Some pkt)

  let resolve t question data header proto =
    metrics `Resolver_queries;
    let name = fst question in
    match data, snd question with
    | `Query, `K Rr_map.K key ->
      begin Client.get_resource_record t.client key name >|= function
        | Error `Msg msg ->
          Log.err (fun m -> m "couldn't resolve %s" msg);
          let data = `Rcode_error (Rcode.ServFail, Opcode.Query, None) in
          metrics `Resolver_servfail;
          let reply = build_reply header question proto data in
          Some reply
        | Error `No_data (domain, soa) ->
          let answer = (Name_rr_map.empty, Name_rr_map.singleton domain Soa soa) in
          let data = `Answer answer in
          metrics `Resolver_nodata;
          let reply = build_reply header question proto data in
          Some reply
        | Error `No_domain (domain, soa) ->
          let answer = (Name_rr_map.empty, Name_rr_map.singleton domain Soa soa) in
          let data = `Rcode_error (Rcode.NXDomain, Opcode.Query, Some answer) in
          metrics `Resolver_nodomain;
          let reply = build_reply header question proto data in
          Some reply
        | Ok reply ->
          let answer = (Name_rr_map.singleton name key reply, Name_rr_map.empty) in
          let data = `Answer answer in
          metrics `Resolver_answers;
          let reply = build_reply header question proto data in
          Some reply
      end
    | _ ->
      Log.err (fun m -> m "not implemented %a, data %a"
                   Dns.Packet.Question.pp question
                   Dns.Packet.pp_data data);
      let data = `Rcode_error (Rcode.NotImp, Packet.opcode_data data, None) in
      metrics `Resolver_notimp;
      let reply = build_reply header question proto data in
      Lwt.return (Some reply)

  (* we're now doing up to three lookups for each request:
    - in authoritative server (Dns_trie)
    - in reserved trie (Dns_trie)
    - in resolver cache (Dns_cache)
    - asking a remote resolver

     instead, on startup authoritative (from external) could be merged with
     reserved (but that makes data store very big and not easy to understand
     (lots of files for the reserved zones)) *)
  let handle t proto ip buf =
    match Packet.decode buf with
    | Error err ->
      (* TODO send FormErr back *)
      Log.err (fun m -> m "couldn't decode %a" Packet.pp_err err);
      Dns_resolver_metrics.response_metric 0L;
      Dns_resolver_metrics.resolver_stats `Error;
      Lwt.return None
    | Ok packet ->
      Dns_resolver_metrics.resolver_stats `Queries;
      let start = Mirage_mtime.elapsed_ns () in
      let header, question, data = packet.Packet.header, packet.question, packet.data in
      (* check header flags: recursion desired (and send recursion available) *)
      (server t proto ip packet header question data buf >>= function
        | Some data -> Lwt.return (Some data)
        | None ->
          (* next look in reserved trie! *)
          match query_server t.reserved question data header proto with
          | Some data -> metrics `Reserved_answers ; Lwt.return (Some data)
          | None -> resolve t question data header proto) >|= fun reply ->
      let stop = Mirage_mtime.elapsed_ns () in
      Dns_resolver_metrics.response_metric (Int64.sub stop start);
      reply

  let create ?(cache_size = 10000) ?edns ?nameservers ?timeout ?(on_update = fun ~old:_ ?authenticated_key:_ ~update_source:_ _trie -> Lwt.return_unit) primary ~happy_eyeballs stack =
    Client.connect ~cache_size ?edns ?nameservers ?timeout (stack, happy_eyeballs) >|= fun client ->
    let server = Dns_server.Primary.server primary in
    let stream, push = Lwt_stream.create () in
    let reserved = Dns_server.create Dns_resolver_root.reserved Mirage_crypto_rng.generate in
    let t = { client ; reserved ; server ; on_update ; push } in
    let udp_cb ~src ~dst:_ ~src_port buf =
      let buf = Cstruct.to_string buf in
      metrics `Udp_queries;
      handle t `Udp src buf >>= function
      | None -> Lwt.return_unit
      | Some (_ttl, data) ->
        let data = Cstruct.of_string data in
        S.UDP.write ~src_port:53 ~dst:src ~dst_port:src_port (S.udp stack) data >|= function
        | Error e -> Log.warn (fun m -> m "udp: failure %a while sending to %a:%d"
                                  S.UDP.pp_error e Ipaddr.pp src src_port)
        | Ok () -> ()
    in
    S.UDP.listen (S.udp stack) ~port:53 udp_cb ;
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
          let data = Cstruct.to_string data in
          handle t `Tcp dst_ip data >>= function
          | None ->
            Log.warn (fun m -> m "no TCP output") ;
            loop ()
          | Some (_ttl, data) ->
            let data = Cstruct.of_string data in
            Dns_flow.send_tcp flow data >>= function
            | Ok () -> loop ()
            | Error () -> Lwt.return_unit
      in
      loop ()
    in
    let rec ocaml_cb () =
      Lwt_stream.get stream >>= function
      | Some (dst_ip, _dst_port, data, wk) ->
        metrics `Ocaml_queries;
        begin
          handle t `Tcp dst_ip data >|= function
          | None ->
            Log.warn (fun m -> m "no TCP output")
          | Some (ttl, data) ->
            Lwt.wakeup wk (ttl, data);
        end >>= fun () ->
        ocaml_cb ()
      | None -> Lwt.return_unit in
    Lwt.async ocaml_cb;
    S.TCP.listen (S.tcp stack) ~port:53 tcp_cb;
    t
end
