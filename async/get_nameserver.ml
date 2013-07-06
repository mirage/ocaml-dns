open Core.Std
open Async.Std
open Async_unix
open Printf
open Dns.Resolvconf


  let default_configuration_file = "/etc/resolv.conf"

  let get_resolvers ?(file=default_configuration_file) () =
    Unix_syscalls.with_file ~mode:[`Rdonly]  file ~f:(fun fd ->
      let warn x = prerr_endline (Printf.sprintf "resolvconf in file %s: %s" file x) in
      let reader = Reader.create fd in
      let rec input_lines (res : string list ) : string list Deferred.t = 
        Reader.read_line reader
	>>= function 
	  | `Ok x -> input_lines (x::res)
	  | `Eof ->  return res  in
      input_lines []
        >>| List.filter_map ~f:map_line
        >>| List.filter_map ~f:(fun line ->
        try Some (KeywordValue.of_string line)
        with
        | KeywordValue.Unknown x -> warn ("unknown keyword: " ^ x); None
        | OptionsValue.Unknown x -> warn ("unknown option: " ^ x); None
        | LookupValue.Unknown x  -> warn ("unknown lookup option: " ^ x); None
      ))
    

 let run ()  =  
  upon (get_resolvers())  (fun (res:KeywordValue.t list) -> 
	let servers = all_servers res in
         match servers with
           | (server,_)::_ ->
               (printf "Your nameserver is %S" server; Caml.exit 0)
	   | [] -> (printf "o no :("; Caml.exit 1)
  )

 let _ =
  let _ = run (); in
   Printf.printf "starting...\n%!";
   Scheduler.go ()
