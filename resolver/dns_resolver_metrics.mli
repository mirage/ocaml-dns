val ip_to_hll : Ipaddr.t -> int64

val resolver_stats : [ `Blocked | `Clients | `Error | `Queries ] -> unit

val response_metric : int64 -> unit
