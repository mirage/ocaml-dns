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
