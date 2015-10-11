(* Forwarding DNS server example. Looks up query locally first then forwards to another resolver. *)
open Lwt
open Dns

(* check db first, then fall back to resolver on error *)
let process db resolver ~src ~dst packet =
      let open Packet in
      match packet.questions with
      | [] -> return None; (* no questions in packet *)
      | [q] -> begin
          let answer = Query.(answer q.q_name q.q_type db.Loader.trie) in (* query local db *)
          match answer.Query.rcode with
          | Packet.NoError ->  (* local match *)
            Lwt_io.printf "Local match for %s\n" (Name.to_string q.q_name)
            >>= fun() ->
            return (Some answer)
          | _ -> (* no match, forward *)
            Lwt_io.printf "No local match, forwarding...\n" 
            >>= fun() -> 
            Dns_resolver_unix.resolve resolver q.q_class q.q_type q.q_name 
            >>= fun result ->
            (return (Some (Dns.Query.answer_of_response result))) 
      end
      | _::_::_ -> return None

let () =
    Lwt_main.run (  
        let address = "127.0.0.1" in (* listen on localhost *)
        let port = 53 in
        let db = Loader.new_db() in (* create new empty db *)
        Dns_resolver_unix.create () (* create resolver using /etc/resolv.conf *)
        >>= fun resolver ->
        let processor = ((Dns_server.processor_of_process (process db resolver)) :> (module Dns_server.PROCESSOR)) in 
        Dns_server_unix.serve_with_processor ~address ~port ~processor)
