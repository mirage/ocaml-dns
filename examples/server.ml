
(* A minimal DNS server *)
open Lwt
open Dns

(* Note: a server with lots of records should use the Trie structure instead. *)
let addresses = [
  Dns.Name.of_string "foo.my.domain", Ipaddr.V4.of_string_exn "1.2.3.4";
  Dns.Name.of_string "bar.my.domain", Ipaddr.V4.of_string_exn "1.2.3.5";
]

let nxdomain = Dns.Query.({ rcode = Dns.Packet.NXDomain; aa = true; answer = []; authority = []; additional = [] })

let lookup ~src ~dst packet =
  let open Dns.Packet in
  match packet.questions with
  | [ { q_class = Q_IN; q_type = Q_A; q_name; _ } ] ->
    if List.mem_assoc q_name addresses then begin
      let ip = List.assoc q_name addresses in
      Lwt_io.printf "DNS: %s is a builtin: %s\n" (to_string packet) Ipaddr.V4.(to_string ip)
      >>= fun () ->
      let rrs = [ { name = q_name; cls = RR_IN; flush = false; ttl = 0l; rdata = A ip } ] in
      Lwt.return (Some (Dns.Query.({ rcode = NoError; aa = true; answer = rrs; authority = []; additional = [] })))
    end else begin
      Lwt_io.printf "DNS: %s returning NXDOMAIN\n" (to_string packet)
      >>= fun () ->
      Lwt.return (Some nxdomain)
    end
  | _ ->
    Lwt_io.printf "DNS: %s returning NXDOMAIN\n" (to_string packet)
    >>= fun () ->
    Lwt.return (Some nxdomain)

let () =
    Lwt_main.run (
        let address = "127.0.0.1" in (* listen on localhost *)
        let port = 53 in
        let processor = ((Dns_server.processor_of_process lookup) :> (module Dns_server.PROCESSOR)) in
        Dns_server_unix.serve_with_processor ~address ~port ~processor)
