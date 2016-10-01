open Core.Std
open Async.Std
open Log.Global
open Async_dns_resolver_unix

let print_resolve server port url =
  begin gethostbyname ~log:(Lazy.force log) ~server ~port  url >>| function
    | Error err ->
      begin match Error.to_exn err |> Monitor.extract_exn with
        | Dns.Protocol.Dns_resolve_error exns ->
          List.iter exns ~f:(fun exn -> error "%s" @@ Exn.to_string exn);
        | _ -> ()
      end
    | Ok hosts -> List.iter hosts ~f:(fun addr -> printf "%s" @@ Ipaddr.to_string addr)
  end >>| fun () ->
  shutdown 0

let main ll ip port url () =
  set_level @@ (match ll with 2 -> `Info | 3 -> `Debug | _ -> `Error);
  don't_wait_for @@ print_resolve ip port url;
  never_returns @@ Scheduler.go ()

let command =
  let spec =
    let open Command.Spec in
    empty
    +> flag "-loglevel" (optional_with_default 1 int) ~doc:"1-3 loglevel"
    +> flag "-host" (optional_with_default "127.0.0.1" string) ~doc:"ip ip of the DNS resolver"
    +> flag "-port" (optional_with_default 53 int) ~doc:"int port of the DNS resolver"
    +> anon ("url" %: string)
  in
  Command.basic ~summary:"DNS Resolver" spec main

let () = Command.run command

