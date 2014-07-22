(* From https://github.com/mirage/ocaml-dns/issues/15 *)

open Lwt

let rec loop k m resolver =
  if k <= m
  then (Lwt_io.eprintf "sequential resolution %d\n%!" k
        >>= fun () ->
        Dns_resolver_unix.gethostbyname resolver "www.example.com"
        >>= fun _packet ->
        loop (k + 1) m resolver)
  else return ()

;;

Lwt_main.run (Dns_resolver_unix.create () >>= loop 0 (1 lsl 10 + 1))
