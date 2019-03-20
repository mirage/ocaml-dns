
val nsupdate : (int -> Cstruct.t) -> (unit -> Ptime.t) -> host:Domain_name.t ->
  keyname:Domain_name.t -> zone:Domain_name.t -> Udns.Dnskey.t ->
  X509.CA.signing_request ->
  (Cstruct.t * (Cstruct.t -> (unit, string) result), string) result

val query :
  (int -> Cstruct.t) -> X509.public_key -> Domain_name.t ->
  Cstruct.t * (Cstruct.t -> (X509.t, string) result)
