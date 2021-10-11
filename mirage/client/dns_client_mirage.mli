
module Make (R : Mirage_random.S) (T : Mirage_time.S) (M : Mirage_clock.MCLOCK) (P : Mirage_clock.PCLOCK) (S : Mirage_stack.V4V6) : sig
  module Transport : Dns_client.S
    with type io_addr = [ `Plaintext of Ipaddr.t * int | `Tls of Tls.Config.client * Ipaddr.t * int ]
     and type +'a io = 'a Lwt.t
     and type stack = S.t

  include module type of Dns_client.Make(Transport)
end
