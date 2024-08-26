module Transport : Dns_client.S
  with type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
   and type +'a io = 'a
   and type stack = Happy_eyeballs_miou_unix.t

include module type of Dns_client.Make (Transport)
