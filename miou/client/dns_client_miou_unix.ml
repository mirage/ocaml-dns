let error_msgf fmt = Fmt.kstr (fun msg -> Error (`Msg msg)) fmt

let src = Logs.Src.create "dns-client-miou-unix"

module Log = (val Logs.src_log src : Logs.LOG)

module Transport = struct
  open Happy_eyeballs_miou_unix

  type +'a io = 'a

  type io_addr =
    [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
  
  type t = {
      nameservers: io_addr list
    ; proto: Dns.proto
    ; timeout: float
    ; happy: stack
  }
  and stack = Happy_eyeballs_miou_unix.t
  
  type context =
    { fd : [ `Udp of Miou_unix.file_descr
           | `Tcp of Miou_unix.file_descr
           | `Tls of Tls_miou_unix.t ]
    ; timeout : float }

  let clock = Mtime_clock.elapsed_ns

  let same_address ipaddr' port' = function
    | `Plaintext (ipaddr, port) -> Ipaddr.compare ipaddr ipaddr' = 0 && port = port'
    | `Tls (_, ipaddr, port) -> Ipaddr.compare ipaddr ipaddr' = 0 && port = port'

  exception Timeout

  let with_timeout ~timeout:ts fn =
    let timeout () = Miou_unix.sleep ts; raise Timeout in
    let prm1 = Miou.async timeout in
    let prm0 = Miou.async fn in
    Miou.await_first [ prm0; prm1 ]

  let connect_to_nameservers t =
    let ( let* ) = Result.bind in
    match t.proto with
    | `Tcp ->
      let ip_of_nameserver = function
        | `Plaintext (ipaddr, port) -> (ipaddr, port)
        | `Tls (_, ipaddr, port) -> (ipaddr, port) in
      let ips = List.map ip_of_nameserver t.nameservers in
      let* ((ipaddr, port) as addr), fd = connect_ip t.happy ips in
      begin match List.find (same_address ipaddr port) t.nameservers with
      | `Plaintext _ -> Ok (addr, `Tcp fd)
      | `Tls (config, _, _) ->
        try let fd = Tls_miou_unix.client_of_fd config fd in
            Ok (addr, `Tls fd)
        with End_of_file ->
            Miou_unix.close fd;
            error_msgf "Connection to nameservers (via TLS) impossible" end
    | `Udp ->
      let is_plaintext = function `Plaintext v -> Either.Left v | _ -> Either.Right () in
      let[@warning "-8"] (ipaddr, port) :: _, _ = List.partition_map is_plaintext t.nameservers in
      let proto_number, socket_type = Unix.((getprotobyname "udp").p_proto, SOCK_DGRAM) in
      let domain = match ipaddr with
        | Ipaddr.V4 _ -> Unix.PF_INET
        | Ipaddr.V6 _ -> Unix.PF_INET6 in
      let fd = Unix.socket domain socket_type proto_number in
      let addr = Unix.ADDR_INET (Ipaddr_unix.to_inet_addr ipaddr, port) in
      let connect () =
        Unix.connect fd addr;
        ((ipaddr, port), `Udp (Miou_unix.of_file_descr fd)) in
      match with_timeout ~timeout:t.timeout connect with
      | Ok value -> Ok value
      | Error Timeout ->
          Unix.close fd;
          error_msgf "Connection to nameservers (via UDP) timeout"
      | Error exn ->
          Unix.close fd;
          error_msgf "Unexpected error: %S" (Printexc.to_string exn)
  
  let nameservers { nameservers; proto; _ } = (proto, nameservers)
  let bind x f = f x
  let lift = Fun.id
  let rng = Mirage_crypto_rng.generate ?g:None
  
  let connect t =
    let ( let* ) = Result.bind in
    let* ((addr, port), fd) = connect_to_nameservers t in
    Log.debug (fun m -> m "Connected to a nameserver %a:%d" Ipaddr.pp addr port);
    match fd with
    | `Tcp _ | `Tls _ -> Ok (`Tcp, { fd; timeout= t.timeout })
    | `Udp _ -> Ok (`Udp, { fd; timeout= t.timeout })
  
  let send_recv_tls ~timeout ~id fd str =
    let send () = Tls_miou_unix.write fd str in
    let recv () =
      let rec go buf rx_len =
        let expected_len =
          if rx_len >= 2 then Some (Bytes.get_uint16_be buf 0) else None in
        match expected_len with
        | None ->
          let len = Tls_miou_unix.read fd buf ~off:rx_len in
          if rx_len + len >= 2 && len > 0 then go buf (rx_len + len)
          else failwith "TLS connection closed by nameserver"
        | Some expected_len when rx_len >= expected_len + 2 ->
          let id' = Bytes.get_uint16_be buf 2 in
          if id = id'
          then Bytes.sub_string buf 0 (expected_len + 2)
          else
            let buf' = Bytes.make 2048 '\000' in
            let rx_len' = rx_len - (expected_len + 2) in
            Bytes.blit buf (expected_len + 2) buf' 0 rx_len';
            go buf' rx_len'
        | Some expected_len when Bytes.length buf >= expected_len + 2 ->
          let len = (expected_len + 2) - rx_len in
          Tls_miou_unix.really_read fd buf ~off:rx_len ~len;
          go buf (rx_len + len)
        | Some expected_len ->
          (* NOTE(dinosaure): in this branch, [buf] is not large enough to store
             the DNS packet. We allocate a new buffer which can store the actual
             DNS packet and use it for the next [go] iteration. *)
          let buf' = Bytes.make (expected_len + 2) '\000' in
          Bytes.blit buf 0 buf' 0 rx_len;
          go buf' rx_len in
      go (Bytes.make 2048 '\000') 0 in
    let ( >>= ) = Result.bind in
    match with_timeout ~timeout send >>= fun () ->
          with_timeout ~timeout recv with
    | Ok _ as rx -> rx
    | Error Timeout -> error_msgf "DNS request timeout"
    | Error (Failure msg) -> Error (`Msg msg)
    | Error (End_of_file | Tls_miou_unix.Closed_by_peer) ->
      error_msgf "End of file reading from nameserver"
    | Error exn ->
      error_msgf "Got an unexpected exception: %s"
        (Printexc.to_string exn)
  
  let send_recv { fd; timeout } str =
    if String.length str > 4 then begin
      match fd with
      | `Tls fd ->
        let id = String.get_int16_be str 2 in
        send_recv_tls ~timeout ~id fd str 
      | `Udp fd | `Tcp fd ->
          let fd = Miou_unix.to_file_descr fd in
          Unix.clear_nonblock fd;
          let send () =
            Log.debug (fun m -> m "sending a dns packet to resolver");
            Unix.setsockopt_float fd Unix.SO_SNDTIMEO timeout;
            let len = Unix.send_substring fd str 0 (String.length str) [] in
            if len <> String.length str
            then failwith "Broken write to upstream nameserver" in
          let recv () =
            let buffer = Bytes.make 2048 '\000' in
            Unix.setsockopt_float fd Unix.SO_RCVTIMEO timeout;
            let len = Unix.recv fd buffer 0 (Bytes.length buffer) [] in
            (* TODO(dinosaure): should we check rx_len and continue until we got
               the full packet (only for tcp/ip)? *)
            if len > 0 && len <= Bytes.length buffer
            then Bytes.sub_string buffer 0 len
            else failwith "Reading from nameserver socket failed" in
          let ( >>= ) = Result.bind in
          match with_timeout ~timeout send >>= fun () ->
                with_timeout ~timeout recv with
          | Ok _ as rx -> rx
          | Error Timeout -> error_msgf "DNS request timeout"
          | Error (Failure msg) -> Error (`Msg msg)
          | Error exn ->
              error_msgf "Got an unexpected exception: %s"
                (Printexc.to_string exn)
    end
    else error_msgf "Invalid context (data length <= 4)"
  
  let close { fd; _ } = match fd with
    | `Tcp fd | `Udp fd -> Miou_unix.close fd
    | `Tls fd -> Tls_miou_unix.close fd
  
  let of_ns ns = Int64.to_float ns /. 1_000_000_000.
  
  let create ?nameservers ~timeout happy =
    let proto, nameservers =
      match nameservers with
      | None -> (`Udp, [ `Plaintext (Ipaddr.of_string_exn "8.8.8.8", 53) ])
      | Some (a, nss) -> (a, nss)
    in
    { nameservers; proto; timeout= of_ns timeout; happy }
end

include Dns_client.Make (Transport)
