module type S = sig
  type flow
  type (+'a,+'b) io constraint 'b = [> `Msg of string]
  type io_addr
  type ns_addr = ([`TCP | `UDP]) * io_addr
  type implementation

  val implementation : implementation

  val default_ns : ns_addr

  val connect : implementation -> ns_addr -> (flow,'err) io
  val send : flow -> Cstruct.t -> (unit,'b) io
  val recv : flow -> (Cstruct.t, 'b) io

  val resolve : ('a,'b) io -> ('a -> ('c,'b) result) -> ('c,'b) io
  val map : ('a,'b) io -> ('a -> ('c,'b) io) -> ('c,'b) io
end

module Make = functor (Uflow:S) ->
struct
  type io_addr = Uflow.io_addr
  type ('a,'b) io = ('a,'b) Uflow.io
  type flow = Uflow.flow

  let default_ns = Uflow.default_ns

  let getaddrinfo (type requested) ((proto,_) as ns_addr)
      (query_type:requested Dns_map.k) name
    : (requested, [> `Msg of string]) Uflow.io =
  let tx, state =
    let cs, state = Udns_client.make_query
        (match proto with `UDP -> `Udp
                        | `TCP -> `Tcp) name query_type in
    cs, state
  in
  let (>>=), (>>|) = Uflow.(resolve, map) in
  Uflow.connect Uflow.implementation ns_addr >>| fun socket ->
  Logs.debug (fun m -> m "Connected to NS.");
  Uflow.send socket tx >>| fun () ->
  (* TODO steal loop logic from lwt *)
  Logs.debug (fun m -> m "Receiving from NS");
  Uflow.recv socket >>= fun recv_buffer ->
  Logs.debug (fun m -> m "Read %d bytes" (Cstruct.len recv_buffer));
  match Udns_client.parse_response state recv_buffer with
  | Ok x -> Ok x
  | Error (`Msg xxx) ->
    Error (`Msg( "err: " ^ xxx))
  | Error `Partial ->
    Error (`Msg "got something else, partial")

  let gethostbyname ns_addr domain =
    let (>>=) = Uflow.resolve in
    getaddrinfo ns_addr Dns_map.A domain >>= fun (_ttl, resp) ->
    match Dns_map.Ipv4Set.choose_opt resp with
    | None -> Error (`Msg "No A record found")
    | Some ip -> Ok ip

end
