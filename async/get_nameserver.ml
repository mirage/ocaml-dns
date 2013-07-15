open Core.Std
open Async.Std
open Dns.Resolvconf

let default_configuration_file = "/etc/resolv.conf"

let get_resolvers ?(file=default_configuration_file) () =
  let warn x = prerr_endline (Printf.sprintf "resolvconf in file %s: %s" file x) in
  Reader.open_file file
  >>= fun rd -> Reader.lines rd
  |> Pipe.filter_map ~f:(fun l -> prerr_endline l; map_line l)
  |> Pipe.filter_map ~f:(fun line ->
      try Some (KeywordValue.of_string line)
      with
      | KeywordValue.Unknown x -> warn ("unknown keyword: " ^ x); None
      | OptionsValue.Unknown x -> warn ("unknown option: " ^ x); None
      | LookupValue.Unknown x  -> warn ("unknown lookup option: " ^ x); None
    )
  |> Pipe.to_list

let show_resolvers ()  =  
  get_resolvers ()
  >>| fun res ->
  match all_servers res with
  | (server,_)::_ -> (printf "Your nameserver is %S\n" server)
  | [] -> (printf "oh noes! :(\n")

let () =
  Command.async_basic ~summary:"Show nameservers"
    Command.Spec.empty
    show_resolvers
  |> Command.run
