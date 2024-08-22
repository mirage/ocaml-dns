module type S = sig
  type happy_eyeballs

  module Transport :
    sig
      include Dns_client.S
        with type +'a io = 'a Lwt.t
         and type io_addr = [
             | `Plaintext of Ipaddr.t * int
             | `Tls of Tls.Config.client * Ipaddr.t * int
           ]
      val happy_eyeballs : t -> happy_eyeballs
    end

  include module type of Dns_client.Make(Transport)

  val nameserver_of_string : string ->
    (Dns.proto * Transport.io_addr, [> `Msg of string ]) result
  (** [nameserver_of_string authenticators str] returns a {!Transport.io_addr}
      from the given string. The format is:
      - [udp:<ipaddr>(:port)?] for a plain nameserver and we will communicate
        with it {i via} the UDP protocol
      - [tcp:<ipaddr>(:port)?] for a plain nameserver and we will communicate
        with it {i via} the TCP protocol
      - [tls:<ipaddr>(:port)?((!hostname)?!authenticator)?] for a nameserver and
        we will communicate with it {i via} the TCP protocol plus the TLS
        encrypted layer. The user can verify the nameserver {i via} an
        {i authenticator} (see {!X509.Authenticator.of_string} for the format
        of it). The {i hostname} can be provided to be used as peer name by the
        authenticator. By default, {!Ca_certs_nss.authenticator} is used.
    *)

  val connect :
    ?cache_size:int ->
    ?edns:[ `None | `Auto | `Manual of Dns.Edns.t ] ->
    ?nameservers:string list ->
    ?timeout:int64 ->
    Transport.stack -> t Lwt.t
  (** [connect ?cache_size ?edns ?nameservers ?timeout (stack, happy_eyeballs)]
      creates a DNS entity which is able to resolve domain-name. It expects
      few optional arguments:
      - [cache_size] the size of the LRU cache,
      - [edns] the behaviour of whether or not to send edns in queries,
      - [nameservers] a list of {i nameservers} used to resolve domain-names,
      - [timeout] (in nanoseconds), passed to {create}.

      The provided [happy_eyeballs] will use [t] for resolving hostnames.

      @raise [Invalid_argument] if given strings don't respect formats explained
      by {!nameserver_of_string}.
  *)
end

module Make
  (R : Mirage_crypto_rng_mirage.S)
  (T : Mirage_time.S)
  (M : Mirage_clock.MCLOCK)
  (P : Mirage_clock.PCLOCK)
  (S : Tcpip.Stack.V4V6)
  (H : Happy_eyeballs_mirage.S with type stack = S.t
                                and type flow = S.TCP.flow)
  : S with type Transport.stack = S.t * H.t
       and type happy_eyeballs = H.t
