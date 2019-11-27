(* mirage stub resolver *)
open Lwt.Infix

open Dns

let src = Logs.Src.create "dns_stub_mirage" ~doc:"effectful DNS stub layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4) = struct

  (* data in the wild:
     - a request comes in hdr, q
       - q to be found in cache
       - q not found in cache (to be forwarded to the recursive resolver)
         - unless q in transit:
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
       connect creates a unique identifier
       send (id, _) data <- registers in map M M[id] := DNS_id
       recv (id, _) <- registers M[id] (=DNS_id) in N[DNS_id] := this task

     or phrased differently:
       a recv_loop reads continously, whenever a full packet is received,
        N[DNS_id] is woken up with the packet
  *)
  module IM = Map.Make(struct
      type t = int
      let compare : int -> int -> int = fun a b -> compare a b
    end)

  module Client = struct
    module Transport : Dns_client.S
      with type stack = S.t
       and type +'a io = 'a Lwt.t
       and type io_addr = Ipaddr.V4.t * int = struct
      type stack = S.t
      type io_addr = Ipaddr.V4.t * int
      type ns_addr = [`TCP | `UDP] * io_addr
      type +'a io = 'a Lwt.t

      type t = {
        rng : (int -> Cstruct.t) ;
        nameserver : ns_addr ;
        stack : stack ;
        mutable flow : S.TCPV4.flow option ;
        mutable requests : (Cstruct.t, [ `Msg of string ]) result Lwt_condition.t IM.t ;
      }
      type flow = { t : t ; mutable id : int }

      let create
          ?rng
          ?(nameserver = `TCP, (Ipaddr.V4.of_string_exn "91.239.100.100", 53))
          stack =
        let rng = match rng with None -> R.generate ?g:None | Some x -> x in
        { rng ; nameserver ; stack ; flow = None ; requests = IM.empty }

      let nameserver { nameserver ; _ } = nameserver
      let rng { rng ; _ } = rng

      let bind = Lwt.bind
      let lift = Lwt.return

      let cancel_all t =
        IM.iter (fun _id cond ->
            Lwt_condition.broadcast cond (Error (`Msg "disconnected")))
          t.requests

      let rec read_loop ?(linger = Cstruct.empty) t flow =
        S.TCPV4.read flow >>= function
        | Error e ->
          t.flow <- None;
          Log.err (fun m -> m "error %a reading from resolver" S.TCPV4.pp_error e);
          cancel_all t;
          Lwt.return_unit
        | Ok `Eof ->
          t.flow <- None;
          Log.warn (fun m -> m "end of file reading from resolver");
          cancel_all t;
          Lwt.return_unit
        | Ok (`Data cs) ->
          let rec handle_data data =
            let cs_len = Cstruct.len data in
            if cs_len > 2 then
              let len = Cstruct.BE.get_uint16 data 0 in
              if cs_len - 2 >= len then
                let packet, rest = Cstruct.split data (len + 2) in
                let id = Cstruct.BE.get_uint16 packet 2 in
                (match IM.find_opt id t.requests with
                 | None -> Log.warn (fun m -> m "received unsolicited data, ignoring")
                 | Some cond -> Lwt_condition.broadcast cond (Ok packet));
                handle_data rest
              else
                read_loop ~linger:data t flow
            else
              read_loop ~linger:data t flow
          in
          handle_data (if Cstruct.len linger = 0 then cs else Cstruct.append linger cs)

      let connect ?nameserver:ns t =
        match t.flow with
        | Some _ -> Lwt.return (Ok ({ t ; id = 0 }))
        | None ->
          let _proto, addr = match ns with None -> nameserver t | Some x -> x in
          S.TCPV4.create_connection (S.tcpv4 t.stack) addr >|= function
          | Error e ->
            Log.err (fun m -> m "error connecting to nameserver %a"
                        S.TCPV4.pp_error e) ;
            Error (`Msg "connect failure")
          | Ok flow ->
            Lwt.async (fun () -> read_loop t flow);
            t.flow <- Some flow;
            Ok ({ t ; id = 0 })

      let close _f =
        (* ignoring this here *)
        Lwt.return_unit

      let recv { t ; id } =
        let cond = Lwt_condition.create () in
        t.requests <- IM.add id cond t.requests;
        Lwt_condition.wait cond >|= fun data ->
        t.requests <- IM.remove id t.requests;
        match data with
        | Ok cs -> Ok cs
        | Error `Msg m -> Error (`Msg m)

      let send f s =
        match f.t.flow with
        | None -> Lwt.return (Error (`Msg "no connection to resolver"))
        | Some flow ->
          let id = Cstruct.BE.get_uint16 s 2 in
          f.id <- id;
          S.TCPV4.write flow s >>= function
          | Error e ->
            f.t.flow <- None;
            Lwt.return (Error (`Msg (Fmt.to_to_string S.TCPV4.pp_write_error e)))
          | Ok () -> Lwt.return (Ok ())
    end

    include Dns_client.Make(Transport)

    let create ?size ?nameserver stack =
      create ?size ~rng:R.generate ?nameserver ~clock:C.elapsed_ns stack
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

  (* multiplex TCP connection to resolver *)

  (* take multiple resolver IPs and round-robin / ask both (take first answer,
     ignoring ServFail etc.) *)

  type t = {
    client : Client.t ;
  }

  let handle t proto data =
    match Packet.decode data with
    | Error err ->
      (* TODO send FormErr back *)
      Logs.err (fun m -> m "couldn't decode %a" Packet.pp_err err);
      Lwt.return None
    | Ok packet ->
      (* check header flags: recursion desired (and send recursion available) *)
      let name = fst packet.Packet.question in
      match packet.Packet.data, snd packet.Packet.question with
      | `Query, `K K key ->
        begin Client.getaddrinfo t.client key name >|= function
            (* TODO reply based on error type, nodomain, nodata *)
          | Error `Msg msg ->
            (* TODO send error to user *)
            Logs.err (fun m -> m "couldn't resolve %s" msg);
            None
          | Ok reply ->
            let my_reply = (* data with response content *)
              let answer = (Name_rr_map.singleton name key reply, Name_rr_map.empty) in
              let data = `Answer answer in
              Packet.create packet.header packet.question data
            in
            Some (fst (Packet.encode proto my_reply))
        end
      | _ ->
        Logs.err (fun m -> m "not handling packet %a"
                     Dns.Packet.pp packet);
        Lwt.return None

  let create ?size stack =
    let nameserver = `TCP, (Ipaddr.V4.of_string_exn "141.1.1.1", 53) in
    let client = Client.create ?size ~nameserver stack in
    let t = { client } in
    let udp_cb ~src ~dst:_ ~src_port buf =
      handle t `Udp buf >>= function
      | None -> Lwt.return_unit
      | Some data ->
        S.UDPV4.write ~src_port:53 ~dst:src ~dst_port:src_port (S.udpv4 stack) data >|= function
        | Error e -> Logs.warn (fun m -> m "udp: failure %a while sending to %a:%d"
                                  S.UDPV4.pp_error e Ipaddr.V4.pp src src_port)
        | Ok () -> ()
    in
    S.listen_udpv4 stack ~port:53 udp_cb ;
    t

end
