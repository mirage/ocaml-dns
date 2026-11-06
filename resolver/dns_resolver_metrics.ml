let ip_to_hll ip =
  (* from murmurhash3 *)
  let fmix64 k =
    let open Int64 in
    let k = logxor k (shift_right_logical k 33) in
    let k = mul k 0xff51afd7ed558ccdL in
    let k = logxor k (shift_right_logical k 33) in
    let k = mul k 0xc4ceb9fe1a85ec53L in
    logxor k (shift_right_logical k 33)
  in
  let h, l = Ipaddr.V6.to_int64 (Ipaddr.to_v6 ip) in
  fmix64 (Int64.logxor h l)

let resolver_stats =
  let f = function
    | `Error -> "error"
    | `Queries -> "queries"
    | `Blocked -> "blocked"
    | `Clients -> "clients"
  in
  let src = Dns.counter_metrics ~f "dns-resolver" in
  (fun r -> Metrics.add src (fun x -> x) (fun d -> d r))

let response_metric =
  let store = ref (0L, 0L) in
  let data dp =
    store := (Int64.succ (fst !store), Int64.add dp (snd !store));
    Metrics.Data.v [ Metrics.uint "mean response" (Duration.to_ms (Int64.div (snd !store) (fst !store))) ]
  in
  let src = Metrics.Src.v ~tags:Metrics.Tags.[] ~data "dns-resolver-timings" in
  (fun dp -> Metrics.add src (fun x -> x) (fun d -> d dp))
