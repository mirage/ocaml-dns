module type S = sig
  type flow
  type (+'a,+'b) io constraint 'b = [> `Msg of string]
  type io_addr
  type ns_addr = ([`TCP | `UDP]) * io_addr
  type stack

  val default_ns : ns_addr

  val connect : stack -> ns_addr -> (flow,'err) io
  val send : flow -> Cstruct.t -> (unit,'b) io
  val recv : flow -> (Cstruct.t, 'b) io

  val resolve : ('a,'b) io -> ('a -> ('c,'b) result) -> ('c,'b) io
  val map : ('a,'b) io -> ('a -> ('c,'b) io) -> ('c,'b) io
end

module Make = functor (Uflow:S) ->
struct

  let default_ns = Uflow.default_ns

  let getaddrinfo (type requested) stack ?nameserver (query_type:requested Dns_map.k) name
    : (requested, [> `Msg of string]) Uflow.io =
    let (proto, _) as ns_addr = match nameserver with None -> Uflow.default_ns | Some x -> x in
    let tx, state =
      let cs, state = Udns_client.make_query
          (match proto with `UDP -> `Udp
                          | `TCP -> `Tcp) name query_type in
      cs, state
    in
    let (>>=), (>>|) = Uflow.(resolve, map) in
    Uflow.connect stack ns_addr >>| fun socket ->
    Logs.debug (fun m -> m "Connected to NS.");
    Uflow.send socket tx >>| fun () ->
    (* TODO steal loop logic from lwt *)
    Logs.debug (fun m -> m "Receiving from NS");
    Uflow.recv socket >>= fun recv_buffer ->
    Logs.debug (fun m -> m "Read %d bytes" (Cstruct.len recv_buffer));
    match Udns_client.parse_response state recv_buffer with
    | Ok x -> Ok x
    | Error (`Msg xxx) -> Error (`Msg( "err: " ^ xxx))
    | Error `Partial -> Error (`Msg "got something else, partial")

  let gethostbyname stack ?nameserver domain =
    let (>>=) = Uflow.resolve in
    getaddrinfo stack ?nameserver Dns_map.A domain >>= fun (_ttl, resp) ->
    match Dns_map.Ipv4Set.choose_opt resp with
    | None -> Error (`Msg "No A record found")
    | Some ip -> Ok ip
end
