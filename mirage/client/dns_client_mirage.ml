open Lwt.Infix

let src = Logs.Src.create "dns_client_mirage" ~doc:"effectful DNS client layer"
module Log = (val Logs.src_log src : Logs.LOG)

module IM = Map.Make(Int)

module Make (R : Mirage_random.S) (T : Mirage_time.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4V6) = struct

  module Transport : Dns_client.S
    with type stack = S.t
     and type +'a io = 'a Lwt.t
     and type io_addr = Ipaddr.t * int = struct
    type stack = S.t
    type io_addr = Ipaddr.t * int
    type +'a io = 'a Lwt.t
    type t = {
      protocol : Dns.proto ;
      nameservers : io_addr list ;
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

    let create ?nameservers ~timeout stack =
      let protocol, nameservers = match nameservers with
        | None | Some (_, []) -> `Tcp, Dns_client.default_resolvers
        | Some ns -> ns
      in
      { protocol ; nameservers ; timeout_ns = timeout ; stack ; flow = None ; requests = IM.empty }

    let nameservers { protocol ; nameservers ; _ } = protocol, nameservers
    let rng = R.generate ?g:None
    let clock = C.elapsed_ns

    let with_timeout time_left f =
      let timeout =
        T.sleep_ns time_left >|= fun () ->
        Error (`Msg "DNS request timeout")
      in
      let start = clock () in
      Lwt.pick [ f ; timeout ] >|= fun result ->
      let stop = clock () in
      result, Int64.sub time_left (Int64.sub stop start)

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
               | Some (_, cond) -> Lwt_condition.broadcast cond (Ok packet));
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
      match t.nameservers with
      | [] -> Lwt.return (Error (`Msg "empty list of nameservers"), timeout)
      | addr :: _ ->
        with_timeout timeout
          (S.TCP.create_connection (S.tcp t.stack) addr >>= function
            | Error e ->
              Log.err (fun m -> m "error connecting to nameserver %a: %a"
                          Ipaddr.pp (fst addr) S.TCP.pp_error e) ;
              Lwt.return (Error (`Msg "connect failure"))
            | Ok flow ->
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
          | Ok () -> Lwt.return (Ok ())) >|= function
        | Ok (), timeout_ns -> ctx.timeout_ns <- timeout_ns; Ok ()
        | Error _ as e, _ -> e
  end

  include Dns_client.Make(Transport)
end
