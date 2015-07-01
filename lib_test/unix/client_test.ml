(* From https://github.com/mirage/ocaml-dns/issues/15 *)

open Lwt

let rec loop k m resolver =
  if k <= m
  then (Dns_resolver_unix.gethostbyname resolver "www.example.com"
        >>= fun _packet ->
        loop (k + 1) m resolver)
  else return ()

;;

(* sequential resolution of 1025 names to test for fd leaks *)
Lwt_main.run (Dns_resolver_unix.create () >>= loop 0 (1 lsl 10 + 1));
prerr_endline "fd leak test: success\n";
(* Failed resolution of one name to test for correct error *)
let config = `Static ([Ipaddr.of_string_exn "127.0.0.2", 53],[]) in
Lwt_main.run begin
  Dns_resolver_unix.create ~config ()
  >>= fun resolver ->
  catch (fun () ->
    let open Dns.Packet in
    let name = Dns.Name.of_string "www.example.com" in
    Dns_resolver_unix.resolve resolver Q_IN Q_MX name
    >|= fun _ -> None
  ) (fun exn -> return (Some exn))
  >>= Dns.(function
  | None ->
    prerr_endline "resolution error test: failed with no error\n";
    return ()
  | Some (Protocol.Dns_resolve_error [Protocol.Dns_resolve_timeout]) ->
    prerr_endline "resolution error test: success\n";
    return ()
  | Some (Protocol.Dns_resolve_error exns) ->
    prerr_endline "resolution error test: failed with bad errors:";
    List.iter (fun exn -> prerr_endline (Printexc.to_string exn)) exns;
    prerr_endline "";
    return ()
  | Some exn ->
    prerr_endline "resolution error test: failed with unexpected error:";
    prerr_endline (Printexc.to_string exn);
    prerr_endline "";
    return ()
  )
end
