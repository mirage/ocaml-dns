(* mirage stub resolver *)
open Lwt.Infix

open Dns

let src = Logs.Src.create "dns_stub_mirage" ~doc:"effectful DNS stub layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4) = struct

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
      }
      type flow = t

      let create
          ?rng
          ?(nameserver = `TCP, (Ipaddr.V4.of_string_exn "91.239.100.100", 53))
          stack =
        let rng = match rng with None -> R.generate ?g:None | Some x -> x in
        { rng ; nameserver ; stack ; flow = None }

      let nameserver { nameserver ; _ } = nameserver
      let rng { rng ; _ } = rng

      let bind = Lwt.bind
      let lift = Lwt.return

      let connect ?nameserver:ns t =
        match t.flow with
        | Some _ -> Lwt.return (Ok t)
        | None ->
          let _proto, addr = match ns with None -> nameserver t | Some x -> x in
          S.TCPV4.create_connection (S.tcpv4 t.stack) addr >|= function
          | Error e ->
            Log.err (fun m -> m "error connecting to nameserver %a"
                        S.TCPV4.pp_error e) ;
            Error (`Msg "connect failure")
          | Ok flow ->
            t.flow <- Some flow;
            Ok t

      let close _f =
        (* ignoring this here *)
        Lwt.return_unit

      let recv t =
        match t.flow with
        | None -> Lwt.return (Error (`Msg "no connected flow"))
        | Some flow ->
          S.TCPV4.read flow >|= function
          | Error e -> t.flow <- None; Error (`Msg (Fmt.to_to_string S.TCPV4.pp_error e))
          | Ok (`Data cs) -> Ok cs
          | Ok `Eof -> Ok Cstruct.empty

      let send t s =
        let rec connected ?(first = true) () =
          match t.flow with
          | Some flow -> Lwt.return (Ok flow)
          | None when first -> connect t >>= fun _ -> connected ~first:false ()
          | None -> Lwt.return (Error (`Msg "couldn't establish connection to resolver"))
        in
        let rec resolve ?(first = true) () =
          connected () >>= function
          | Error e -> Lwt.return (Error e)
          | Ok flow ->
            S.TCPV4.write flow s >>= function
            | Error e ->
              t.flow <- None;
              if first then
                resolve ~first:false ()
              else
                Lwt.return (Error (`Msg (Fmt.to_to_string S.TCPV4.pp_write_error e)))
            | Ok () -> Lwt.return (Ok ())
        in
        resolve ()
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
