open Core.Std
open Async.Std
open Async_dns_resolver_unix

let () =
  don't_wait_for ((gethostbyname "www.google.com" >>| (fun l ->
    List.iter ~f:(fun addr -> print_endline (Ipaddr.to_string addr)) l)) >>|
    (fun () -> shutdown 0))

let () =
  never_returns (Scheduler.go())

