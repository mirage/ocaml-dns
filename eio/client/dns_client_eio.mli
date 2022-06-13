type 'a env = <
  clock         : Eio.Time.clock ;
  mono_clock    : Eio.Time.Mono.t ;
  net           : Eio.Net.t ;
  fs            : Eio.Fs.dir Eio.Path.t ;
  secure_random : Eio.Flow.source ;
  ..
> as 'a

module Transport : Dns_client.S
  with type io_addr = Ipaddr.t * int
   and type +'a io  = 'a

include module type of Dns_client.Make(Transport)

val run :
  ?resolv_conf:string
  -> _ env
  -> (Transport.stack -> 'a)
  -> 'a
(** [run env f] executes [f] which can call various dns client functions defined in
    [Dns_client.S].

    @param resolv_conf is the local path to [resolv_conf] file. It is by default set to
                        [/etc/resolv.conf]. 
    
    Example:
    {[
      let () =
        Eio_main.run @@ fun env ->
        Dns_client_eio.run @@ fun stack ->
        let t = Dns_client_eio.create stack in
        let dn = Domain_name.(host_exn (of_string_exn "tarides.com")) in
        match Dns_client_eio.gethostbyname t dn with
        | OK addr -> Fmt.pr "%a has IPv4 address %a\n" Domain_name.pp Ipaddr.V4.pp addr
        | Error (`Msg e) -> Fmt.pr "Error %s" e
    ]} *)
