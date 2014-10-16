open Core.Std
open Async.Std
open Dns.Name
open Dns.Operators
open Dns.Protocol
open Async_dns_resolver

module DP = Dns.Packet

let buflen = 4096
let ns = "8.8.8.8"
let port = 53

let stderr_writer () = Lazy.force Writer.stderr
let log_warn s = 
  Writer.write (stderr_writer ()) (Printf.sprintf "WARN: %s\n%!" s)

(** Ipaddr.t -> int -> Async.Std.Socket.Address.Inet.t *)
let sockaddr addr port =
  Socket.Address.Inet.create (Unix.Inet_addr.of_string addr) ~port

(**  [< Async.Std.Socket.Address.t ] -> string *)
let sockaddr_to_string sadr =
  Socket.Address.to_string sadr


let active_sock_exn addr port =
  let sock = Socket.create (Socket.Type.udp)
  and addr = sockaddr addr port
  and timeout = after (sec 10.) in
  Socket.connect_interruptible sock addr ~interrupt:timeout

let timerfn () = after (sec 5.0)

let cleanfn sock () =
  ((try Socket.shutdown sock `Both with | _ -> ());
   (try_with (fun () -> Unix.close (Socket.fd sock))) >>| fun _ -> ())
;;

let connect_to_resolver server_addr port =
  let sock = Socket.create (Socket.Type.udp)
  and addr = sockaddr server_addr port
  and timeout = after (sec 10.0) in
  try_with (fun () ->
    Socket.connect_interruptible sock addr ~interrupt:timeout)
  >>= (function 
    | Ok `Interrupted -> 
        cleanfn sock () >>= fun () -> failwith "connection to DNS server timed out"
    | Error e -> cleanfn sock () >>= fun () -> raise (Monitor.extract_exn e)
    | Ok (`Ok ac_sock) -> begin
        let txfn buf =
          let w = Writer.create (Socket.fd ac_sock) in
          Writer.write_bigstring ~pos:0 ~len:(Dns.Buf.length buf) w buf;
          Writer.flushed w in
        let rec rxfn f =
          let buf = String.create buflen in
          let r = Reader.create ~buf_len:buflen (Socket.fd ac_sock) in
          Reader.read r ~pos:0 ~len:buflen buf >>=
          (function
            | `Eof -> failwith "unexpected EOF"
            | `Ok n ->
                match f (Bigstring.of_string (String.slice buf 0 n)) with
                | None -> rxfn f
                | Some r -> return r
          )
        in return {txfn; rxfn; timerfn; cleanfn=(cleanfn ac_sock)} end)


let resolve client
    ?(dnssec=false)
    server dns_port
    (q_class:DP.q_class) (q_type:DP.q_type)
    (q_name:domain_name) =
   connect_to_resolver server dns_port >>= (fun commfn ->
   resolve client ~dnssec commfn q_class q_type q_name)


let gethostbyname
    ?(server = ns) ?(dns_port = port)
    ?(q_class:DP.q_class = DP.Q_IN) ?(q_type:DP.q_type = DP.Q_A)
    name =
   connect_to_resolver server dns_port >>= (fun commfn ->
   gethostbyname ~q_class ~q_type commfn name)