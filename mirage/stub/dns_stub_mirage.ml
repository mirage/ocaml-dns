(* mirage stub resolver *)
open Lwt.Infix

open Dns

module Make (R : Mirage_random.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4) = struct
  module Client = Dns_client_mirage.Make(R)(C)(S)

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
    let client = Client.create ?size stack in
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
