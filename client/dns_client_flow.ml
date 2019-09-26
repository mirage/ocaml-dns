
let stdlib_random n =
  let b = Cstruct.create n in
  for i = 0 to pred n do
    Cstruct.set_uint8 b i (Random.int 256)
  done;
  b

module type S = sig
  type flow
  type +'a io
  type io_addr
  type ns_addr = ([`TCP | `UDP]) * io_addr
  type stack
  type t

  val create : ?rng:(int -> Cstruct.t) -> ?nameserver:ns_addr -> stack -> t

  val nameserver : t -> ns_addr
  val rng : t -> (int -> Cstruct.t)

  val connect : ?nameserver:ns_addr -> t -> (flow, [> `Msg of string ]) result io
  val send : flow -> Cstruct.t -> (unit, [> `Msg of string ]) result io
  val recv : flow -> (Cstruct.t, [> `Msg of string ]) result io
  val close : flow -> unit io

  val bind : 'a io -> ('a -> 'b io) -> 'b io
  val lift : 'a -> 'a io
end

module Make = functor (Uflow:S) ->
struct

  let create ?rng ?nameserver stack = Uflow.create ?rng ?nameserver stack

  let nameserver t = Uflow.nameserver t

  let (>>=) = Uflow.bind

  (* result-bind *)
  let (>>|) a b =
    a >>= function
    | Ok a' -> b a'
    | Error e -> Uflow.lift (Error e)

  (* result-bind-and-lift *)
  let (>>|=) a f = a >>| fun b -> Uflow.lift (f b)

  let getaddrinfo (type requested) t ?nameserver (query_type:requested Dns.Rr_map.key) name
    : (requested, [> `Msg of string]) result Uflow.io =
    let proto, _ = match nameserver with None -> Uflow.nameserver t | Some x -> x in
    let tx, state =
      Dns_client.make_query (Uflow.rng t)
        (match proto with `UDP -> `Udp | `TCP -> `Tcp) name query_type
    in
    Uflow.connect ?nameserver t >>| fun socket ->
    Logs.debug (fun m -> m "Connected to NS.");
    (Uflow.send socket tx >>| fun () ->
     Logs.debug (fun m -> m "Receiving from NS");
     let rec recv_loop acc =
       Uflow.recv socket >>| fun recv_buffer ->
       Logs.debug (fun m -> m "Read @[<v>%d bytes@]"
                      (Cstruct.len recv_buffer)) ;
       let buf = Cstruct.append acc recv_buffer in
       match Dns_client.parse_response state buf with
       | `Ok x -> Uflow.lift (Ok x)
       | `Msg xxx -> Uflow.lift (Error (`Msg( "err: " ^ xxx)))
       | `Partial when proto = `TCP -> recv_loop buf
       | `Partial -> Uflow.lift (Error (`Msg "Truncated UDP response"))
    in recv_loop Cstruct.empty) >>= fun r ->
    Uflow.close socket >>= fun () ->
    Uflow.lift r

  let gethostbyname stack ?nameserver domain =
    getaddrinfo stack ?nameserver Dns.Rr_map.A domain >>|= fun (_ttl, resp) ->
    match Dns.Rr_map.Ipv4_set.choose_opt resp with
    | None -> Error (`Msg "No A record found")
    | Some ip -> Ok ip

  let gethostbyname6 stack ?nameserver domain =
    getaddrinfo stack ?nameserver Dns.Rr_map.Aaaa domain >>|= fun (_ttl, res) ->
    match Dns.Rr_map.Ipv6_set.choose_opt res with
    | None -> Error (`Msg "No AAAA record found")
    | Some ip -> Ok ip
end
