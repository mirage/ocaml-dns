open Lwt.Infix

module Make (Time : Mirage_time_lwt.S) (IPv4 : Mirage_stack_lwt.V4) = struct

  module S : Udns_client_flow.S = struct
    type flow = IPv4.TCPV4.flow
    type implementation = IPv4.t
    type io_addr = IPv4.ipv4addr * int
    type ns_addr = [`TCP | `UDP] * io_addr
    type (+'a,+'b) io = 'a Mirage_flow_lwt.io
      constraint 'b = [> `Msg of string]

    let default_ns =
      `TCP, (Ipaddr.V4.of_string_exn "91.239.100.100", 53)

    let implementation = IPv4.tcpv4 (IPv4.IPV4.t)

    let map = Lwt_result.bind
    let resolve = Lwt_result.bind_result

    let connect stack ((_proto, (ip, port)):ns_addr) =
      IPv4.TCPV4.create_connection stack (ip, port)

    let recv flow =
        let open Lwt_result.Infix in
        IPv4.TCPV4.read flow >|= function
        | `Data cs -> cs
        | `Eof -> Cstruct.empty

      let send flow s =
        IPv4.TCPV4.write flow s
          >|= fun always_works -> Ok always_works
    end

  
end

(*
type udns_ty = Udns_client

let config : 'a Mirage.impl =
  let open Mirage in
  impl @@ object inherit Mirage.base_configurable
    method module_name = "Udns_client"
    method name = "Udns_client"
    method ty : 'a typ = Type Udns_client
    method! packages : package list value =
      (Key.match_ Key.(value target) @@ begin function
          | `Unix -> [package "udns-client-unix"]
          | _ -> []
        end
      )
    method! deps = []
  end
*)
