(*
 * Copyright (c) 2014 marklrh <marklrh@gmail.com>
 * Copyright (c) 2016 Vincent Bernardoff <vb@luminar.eu.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

open Core.Std
open Async.Std

open Dns
open Async_dns_resolver

let sockaddr addr ~port =
  Socket.Address.Inet.create (Unix.Inet_addr.of_string addr) ~port

let sockaddr_to_string sadr =
  Socket.Address.to_string sadr

let cleanfn ?log sock () =
  begin
    try Socket.shutdown sock `Both
    with exn -> Option.iter log ~f:(fun log -> Log.error log "%s" @@ Exn.to_string exn)
  end;
  Monitor.try_with_or_error (fun () -> Unix.close @@ Socket.fd sock) >>| function
  | Error err -> Option.iter log ~f:(fun log -> Log.error log "%s" @@ Error.to_string_hum err)
  | Ok () -> ()

let connect_to_resolver ?log ?(timeout=Time_ns.Span.of_int_sec 1) ?(port=53) addr =
  let sock = Socket.create (Socket.Type.udp) in
  let addr = sockaddr addr port in
  Monitor.try_with_or_error
    (fun () -> Socket.connect_interruptible sock addr ~interrupt:(Clock_ns.after timeout)) >>= begin function
    | Error e ->
      cleanfn sock () >>| fun () -> Error e
    | Ok `Interrupted ->
      cleanfn sock () >>= fun () -> Deferred.Or_error.error_string "connection to DNS server timed out"
    | Ok (`Ok ac_sock) ->
      let txfn buf =
        let w = Writer.create (Socket.fd ac_sock) in
        Writer.write_bigstring ~pos:0 ~len:(Buf.length buf) w buf;
        Writer.flushed w
      in
      let rec rxfn f =
        let r = Reader.create (Socket.fd ac_sock) in
        let handle_chunk (iobuf : ([ `Read | `Who_can_write of Core_kernel.Perms.me ], Iobuf.seek) Iobuf.t) =
          match f @@ Iobuf.Consume.To_bigstring.subo (iobuf :> ([ `Read ], Iobuf.seek) Iobuf.t) with
          | None ->
            Option.iter log ~f:(fun log -> Log.error log "Received wrong data, retrying");
            return `Continue
          | Some res -> return @@ `Stop res
        in
        Reader.read_one_iobuf_at_a_time r ~handle_chunk >>| function
        | `Eof -> failwith "unexpected EOF"
        | `Eof_with_unconsumed_data _ -> failwith "unexpected EOF with unconsumed data"
        | `Stopped res -> res
      in
      let timerfn () = Clock_ns.after timeout in
      Deferred.Or_error.return { log; txfn; rxfn; timerfn; cleanfn=(cleanfn ac_sock) }
  end

let resolve ?log ?(dnssec=false) ?port client server q_class q_type q_name =
  connect_to_resolver ?log ?port server >>| fun commfn ->
  Or_error.map commfn ~f:(fun commfn -> resolve client ~dnssec commfn q_class q_type q_name)

let gethostbyname ?log ?(server="127.0.0.1") ?port ?(q_class=Dns.Packet.Q_IN) ?(q_type=Dns.Packet.Q_A) name =
  Deferred.Or_error.bind
    (connect_to_resolver ?log ?port server)
    ~f:(fun commfn -> gethostbyname ~q_class ~q_type commfn name)
