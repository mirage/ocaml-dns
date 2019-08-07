(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

let src = Logs.Src.create "dns_mirage" ~doc:"effectful DNS layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (S : Mirage_stack_lwt.V4) = struct

  module IS = Set.Make(Ipaddr.V4)

  module IM = struct
    include Map.Make(Ipaddr.V4)
    let find k t = try Some (find k t) with Not_found -> None
  end

  module IPM = struct
    include Map.Make(struct
        type t = Ipaddr.V4.t * int
        let compare (ip, p) (ip', p') = match Ipaddr.V4.compare ip ip' with
          | 0 -> compare p p'
          | x -> x
      end)
    let find k t = try Some (find k t) with Not_found -> None
  end

  module U = S.UDPV4
  module T = S.TCPV4

  type f = {
    flow : T.flow ;
    mutable linger : Cstruct.t ;
  }

  let of_flow flow = { flow ; linger = Cstruct.empty }

  let flow { flow ; _ } = flow

  let rec read_exactly f length =
    let dst_ip, dst_port = T.dst f.flow in
    if Cstruct.len f.linger >= length then
      let a, b = Cstruct.split f.linger length in
      f.linger <- b ;
      Lwt.return (Ok a)
    else
      T.read f.flow >>= function
      | Ok `Eof ->
        Log.warn (fun m -> m "end of file on flow %a:%d" Ipaddr.V4.pp dst_ip dst_port) ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Error e ->
        Log.err (fun m -> m "error %a reading flow %a:%d" T.pp_error e Ipaddr.V4.pp dst_ip dst_port) ;
        T.close f.flow >>= fun () ->
        Lwt.return (Error ())
      | Ok (`Data b) ->
        f.linger <- Cstruct.append f.linger b ;
        read_exactly f length

  let send_udp stack src_port dst dst_port data =
    Log.info (fun m -> m "udp: sending %d bytes from %d to %a:%d"
                 (Cstruct.len data) src_port Ipaddr.V4.pp dst dst_port) ;
    U.write ~src_port ~dst ~dst_port (S.udpv4 stack) data >|= function
    | Error e -> Log.warn (fun m -> m "udp: failure %a while sending from %d to %a:%d"
                              U.pp_error e src_port Ipaddr.V4.pp dst dst_port)
    | Ok () -> ()

  let send_tcp flow answer =
    let dst_ip, dst_port = T.dst flow in
    Log.info (fun m -> m "tcp: sending %d bytes to %a:%d" (Cstruct.len answer) Ipaddr.V4.pp dst_ip dst_port) ;
    let len = Cstruct.create 2 in
    Cstruct.BE.set_uint16 len 0 (Cstruct.len answer) ;
    T.write flow (Cstruct.append len answer) >>= function
    | Ok () -> Lwt.return (Ok ())
    | Error e ->
      Log.err (fun m -> m "tcp: error %a while writing to %a:%d" T.pp_write_error e Ipaddr.V4.pp dst_ip dst_port) ;
      T.close flow >|= fun () ->
      Error ()

  let send_tcp_multiple flow datas =
    Lwt_list.fold_left_s (fun acc d ->
        match acc with
        | Error () -> Lwt.return (Error ())
        | Ok () -> send_tcp flow d)
      (Ok ()) datas

  let read_tcp flow =
    read_exactly flow 2 >>= function
    | Error () -> Lwt.return (Error ())
    | Ok l ->
      let len = Cstruct.BE.get_uint16 l 0 in
      read_exactly flow len
end
