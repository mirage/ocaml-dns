open Lwt.Infix

let src = Logs.Src.create "dns_client_mirage" ~doc:"effectful DNS client layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (T : Mirage_time.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4V6) = struct

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
    }
    type context = {
      t : t ;
      flow : S.TCP.flow ;
      mutable timeout_ns : int64
    }

    let create
        ?(nameserver = `Tcp, (Ipaddr.V4 (Ipaddr.V4.of_string_exn (fst Dns_client.default_resolver)), 53))
        ~timeout
        stack =
      { nameserver ; timeout_ns = timeout ; stack }

    let nameserver { nameserver ; _ } = nameserver
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

    let connect ?nameserver:ns t =
      let _proto, addr = match ns with None -> nameserver t | Some x -> x in
      with_timeout t.timeout_ns
        (S.TCP.create_connection (S.tcp t.stack) addr >|= function
          | Error e ->
            Log.err (fun m -> m "error connecting to nameserver %a"
                        S.TCP.pp_error e) ;
            Error (`Msg "connect failure")
          | Ok flow -> Ok flow) >|= function
      | Ok flow, timeout_ns -> Ok { t ; flow ; timeout_ns }
      | Error _ as e, _ -> e

    let close { flow ; _ } = S.TCP.close flow

    let recv ctx =
      with_timeout ctx.timeout_ns (S.TCP.read ctx.flow >|= function
        | Error e -> Error (`Msg (Fmt.to_to_string S.TCP.pp_error e))
        | Ok (`Data cs) -> Ok cs
        | Ok `Eof -> Ok Cstruct.empty) >|= function
      | Ok x, timeout_ns -> ctx.timeout_ns <- timeout_ns; Ok x
      | Error _ as e, _ -> e

    let send ctx s =
      with_timeout ctx.timeout_ns (S.TCP.write ctx.flow s >|= function
        | Error e -> Error (`Msg (Fmt.to_to_string S.TCP.pp_write_error e))
        | Ok () -> Ok ()) >|= function
      | Ok (), timeout_ns -> ctx.timeout_ns <- timeout_ns; Ok ()
      | Error _ as e, _ -> e
  end

  include Dns_client.Make(Transport)
end
