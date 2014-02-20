open Lwt
open Dns_server_core

let bind_fd ~address ~port =
  lwt src =
    try_lwt
      (* should this be lwt hent = Lwt_lib.gethostbyname addr ? *)
      let hent = Unix.gethostbyname address in
      return (Unix.ADDR_INET (hent.Unix.h_addr_list.(0), port))
    with _ ->
      raise_lwt (Failure ("cannot resolve " ^ address))
  in
  let fd = Lwt_unix.(socket PF_INET SOCK_DGRAM 0) in
  let () = Lwt_unix.bind fd src in
  return (fd,src)

let eventual_process_of_zonefile zonefile =
  let lines = Lwt_io.lines_of_file zonefile in
  let buf = Buffer.create 1024 in
  Lwt_stream.iter (fun l ->
      Buffer.add_string buf l;
      Buffer.add_char buf '\n') lines
  >>= fun () ->
  return (process_of_zonebuf (Buffer.contents buf))

let bufsz = 4096

let ipaddr_of_sockaddr =
  function
  | Unix.ADDR_UNIX _ -> fail (Failure "Unix domain sockets not supported")
  | Unix.ADDR_INET (ip,port) -> return (Ipaddr_unix.of_inet_addr ip, port)

let listen ~fd ~src ~processor =
  let cont = ref true in
  let bufs = Lwt_pool.create 64 
      (fun () -> return (Dns.Buf.create bufsz)) in
  lwt src = ipaddr_of_sockaddr src in
  let _ =
    while_lwt !cont do
      Lwt_pool.use bufs
        (fun buf ->
           lwt len, dst = Lwt_bytes.recvfrom fd buf 0 bufsz [] in
           (* TODO Process in a background thread; should be a bounded queue *)
           let _ = ignore_result (
               lwt dst' = ipaddr_of_sockaddr dst in
               process_query buf len src dst' processor
               >>= function
               | None -> return ()
               | Some buf -> 
                   Lwt_bytes.sendto fd buf 0 (Dns.Buf.length buf) [] dst
                   >>= fun _ -> return ()
             ) in
           return ()
        )
    done
  in
  let t,u = Lwt.task () in
  Lwt.on_cancel t
    (fun () -> Printf.eprintf "listen: cancelled\n%!"; cont := false);
  Printf.eprintf "listen: done\n%!";
  t

let serve_with_processor ~address ~port ~processor =
  bind_fd ~address ~port
  >>= fun (fd, src) -> listen ~fd ~src ~processor

let serve_with_zonebuf ~address ~port ~zonebuf =
  let process = process_of_zonebuf zonebuf in
  let processor = (processor_of_process process :> (module PROCESSOR)) in
  serve_with_processor ~address ~port ~processor

let serve_with_zonefile ~address ~port ~zonefile =
  eventual_process_of_zonefile zonefile
  >>= fun process ->
  let processor = (processor_of_process process :> (module PROCESSOR)) in
  serve_with_processor ~address ~port ~processor

