module type S = sig
  type t
  type stack

  val create : stack -> t

  val getaddrinfo : Domain_name.t -> unit Lwt.t
end

module S = struct
  type t = int
  type stack = int

  let create i = i

  let getaddrinfo _domain_name = Lwt.return_unit
end

module Make =
  functor (Time : Mirage_time_lwt.S) ->
  functor (IPv4 : Mirage_stack_lwt.V4) ->
  struct
    module Uflow : Udns_client_flow.S
      with type flow = IPv4.TCPV4.flow
       and type implementation = IPv4.tcpv4
       and type io_addr = IPv4.ipv4addr * int
       and type (+'a,+'b) io = 'a Mirage_flow_lwt.io = struct
      open Lwt.Infix
      type flow = IPv4.TCPV4.flow
      type implementation = IPv4.tcpv4
      type io_addr = IPv4.ipv4addr * int
      type ns_addr = [`TCP | `UDP] * io_addr
      type (+'a,+'b) io = 'a Mirage_flow_lwt.io
        constraint 'b = [> `Msg of string]
      let default_ns = `TCP,
                       ((Ipaddr.(
                            (V4.of_string_exn "TODO")), 53):io_addr)

      let implementation = IPv4.tcpv4 (IPv4.IPV4.t)

      let map = Lwt_result.bind
      let resolve = Lwt_result.bind_result

      let connect stack ((_proto, (ip, port)):ns_addr) =
        IPv4.TCPV4.create_connection stack (ip, port)

      let recv_string flow =
        let open Lwt_result.Infix in
        IPv4.TCPV4.read flow >|= function
        | `Data cs -> Cstruct.to_string cs
        | `Eof -> ""

      let send_string flow s =
        IPv4.TCPV4.write flow (Cstruct.of_string s)
          >|= fun always_works -> Ok always_works

    end
    include S
end

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
