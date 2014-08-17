open Lwt
open V1_LWT
open Printf

let listening_port = 5354

let red fmt    = sprintf ("\027[31m"^^fmt^^"\027[m")
let green fmt  = sprintf ("\027[32m"^^fmt^^"\027[m")
let yellow fmt = sprintf ("\027[33m"^^fmt^^"\027[m")
let blue fmt   = sprintf ("\027[36m"^^fmt^^"\027[m")

let domain = "google.com"
let server = Ipaddr.V4.of_string_exn "127.0.0.1"

module Client (C:CONSOLE) (S:STACKV4) (E:ENTROPY) = struct

  module U = S.UDPV4
  module DNS = Dns_resolver_mirage.Make(OS.Time)(S)

  let start c s e =
    Console.log_s c "Started, will begin resolving shortly..." >>= fun () ->
    OS.Time.sleep 2.0 >>= fun () ->
    while_lwt true do
      Console.log_s c (green "Resolving %s" domain)
      >>= fun () ->
      DNS.gethostbyname s ~server "google.com"
      >>= fun rl ->
      Lwt_list.iter_s
        (fun r ->
           Console.log_s c (yellow "  => %s" (Ipaddr.to_string r))
        ) rl
      >>= fun () ->
      OS.Time.sleep 1.0
    done
end
