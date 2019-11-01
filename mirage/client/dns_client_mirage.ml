open Lwt.Infix

let src = Logs.Src.create "dns_client_mirage" ~doc:"effectful DNS client layer"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (R : Mirage_random.S) (C : Mirage_clock.MCLOCK) (S : Mirage_stack.V4) = struct

  module Transport : Dns_client.S
    with type flow = S.TCPV4.flow
     and type stack = S.t
     and type +'a io = 'a Lwt.t
     and type io_addr = Ipaddr.V4.t * int = struct
    type flow = S.TCPV4.flow
    type stack = S.t
    type io_addr = Ipaddr.V4.t * int
    type ns_addr = [`TCP | `UDP] * io_addr
    type +'a io = 'a Lwt.t
    type t = {
      rng : (int -> Cstruct.t) ;
      nameserver : ns_addr ;
      stack : stack ;
    }

    let create
        ?rng
        ?(nameserver = `TCP, (Ipaddr.V4.of_string_exn "91.239.100.100", 53))
        stack =
      let rng = match rng with None -> R.generate ?g:None | Some x -> x in
      { rng ; nameserver ; stack }

    let nameserver { nameserver ; _ } = nameserver
    let rng { rng ; _ } = rng

    let bind = Lwt.bind
    let lift = Lwt.return

    let connect ?nameserver:ns t =
      let _proto, addr = match ns with None -> nameserver t | Some x -> x in
      S.TCPV4.create_connection (S.tcpv4 t.stack) addr >|= function
      | Error e ->
        Log.err (fun m -> m "error connecting to nameserver %a"
                    S.TCPV4.pp_error e) ;
        Error (`Msg "connect failure")
      | Ok flow -> Ok flow

    let close f = S.TCPV4.close f

    let recv flow =
      S.TCPV4.read flow >|= function
      | Error e -> Error (`Msg (Fmt.to_to_string S.TCPV4.pp_error e))
      | Ok (`Data cs) -> Ok cs
      | Ok `Eof -> Ok Cstruct.empty

    let send flow s =
      S.TCPV4.write flow s >|= function
      | Error e -> Error (`Msg (Fmt.to_to_string S.TCPV4.pp_write_error e))
      | Ok () -> Ok ()
  end

  include Dns_client.Make(Transport)

  let create ?size ?nameserver stack =
    create ?size ~rng:R.generate ?nameserver ~clock:C.elapsed_ns stack
end

(*
type dns_ty = Dns_client

let config : 'a Mirage.impl =
  let open Mirage in
  impl @@ object inherit Mirage.base_configurable
    method module_name = "Dns_client"
    method name = "Dns_client"
    method ty : 'a typ = Type Dns_client
    method! packages : package list value =
      (Key.match_ Key.(value target) @@ begin function
          | `Unix -> [package "dns-client.unix"]
          | _ -> []
        end
      )
    method! deps = []
  end
*)
