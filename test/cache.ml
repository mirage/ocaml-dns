open Dns

let ip = Ipaddr.V4.of_string_exn
let name = Domain_name.of_string_exn

let invalid_soa name =
  let p pre =
    Domain_name.(prepend_label_exn name "invalid" |> fun n -> prepend_label_exn n pre)
  in
  {
    Soa.nameserver = p "ns" ; hostmaster = p "hostmaster" ;
    serial = 1l ; refresh = 16384l ; retry = 2048l ;
    expiry = 1048576l ; minimum = 300l
  }

let cached_err =
  let module M = struct
    type t = [ `Cache_miss | `Cache_drop ]
    let pp ppf = function
      | `Cache_miss -> Fmt.string ppf "cache miss"
      | `Cache_drop -> Fmt.string ppf "cache drop"
    let equal a b = match a, b with
      | `Cache_miss, `Cache_miss -> true
      | `Cache_drop, `Cache_drop -> true
      | _ -> false
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let entry_eq t a b =
  match a, b with
  | `Entry b, `Entry b' -> Rr_map.equal_rr t b b'
  | `No_data (name, soa), `No_data (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | `No_domain (name, soa), `No_domain (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | `Serv_fail (name, soa), `Serv_fail (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | _, _ -> false

let cached_ok (t : 'a Rr_map.key) =
  let pp ppf res = Dns_cache.pp_entry t ppf res
  and equal r r' = entry_eq t r r'
  in
  Alcotest.testable pp equal

let cached_r t = Alcotest.(result (cached_ok t) cached_err)

let empty_cache () =
  let cache = Dns_cache.empty 100 in
  Alcotest.check (cached_r Rr_map.A) "empty cache results in Cache_miss"
    (Error `Cache_miss)
    (snd (Dns_cache.get cache 0L (name "an-actual-website.com") A))

let cache_a () =
  let cache = Dns_cache.empty 100 in
  let name = name "an-actual-website.com" in
  let a = 250l, Ipaddr.V4.Set.singleton (ip "1.2.3.4") in
  let cache = Dns_cache.set cache 0L name A AuthoritativeAnswer (`Entry a) in
  Alcotest.check (cached_r Rr_map.A) "cache with A results in res"
    (Ok (`Entry a)) (snd (Dns_cache.get cache 0L name A)) ;
  Alcotest.check (cached_r Rr_map.Cname) "cache with A results in CacheMiss"
    (Error `Cache_miss) (snd (Dns_cache.get cache 0L name Cname))

let cache_nodata () =
  let cache = Dns_cache.empty 100 in
  let name = name "an-alias.com"
  and subname = name "another-domain.an-alias.com"
  in
  let soa = invalid_soa name in
  let nodata = `No_data (subname, soa) in
  let a = 250l, Ipaddr.V4.Set.singleton (ip "1.2.3.4") in
  let cache = Dns_cache.set cache 0L name A AuthoritativeAnswer (`Entry a) in
  let cache = Dns_cache.set cache 0L subname A AuthoritativeAnswer nodata in
  Alcotest.check (cached_r Rr_map.A) "cache with A nodata results in nodata"
    (Ok nodata) (snd (Dns_cache.get cache 0L subname A)) ;
  Alcotest.check (cached_r Rr_map.Ns) "cache with A nodata results in cache miss for NS"
    (Error `Cache_miss) (snd (Dns_cache.get cache 0L subname Ns)) ;
  Alcotest.check (cached_r Rr_map.A) "cache with A nodata results in a record"
    (Ok (`Entry a)) (snd (Dns_cache.get cache 0L name A)) ;
  Alcotest.check (cached_r Rr_map.Ns) "cache with A nodata results in cache miss for NS'"
    (Error `Cache_miss) (snd (Dns_cache.get cache 0L name Ns)) ;
  let cache = Dns_cache.set cache 0L subname A AuthoritativeAnswer (`Entry a) in
  Alcotest.check (cached_r Rr_map.A) "cache with A nodata results in nodata"
    (Ok (`Entry a)) (snd (Dns_cache.get cache 0L subname A))

let cache_tests = [
  "empty cache", `Quick, empty_cache ;
  "cache with A", `Quick, cache_a ;
  "cache nodata", `Quick, cache_nodata ;
]

let entry_or_cname t a b = match a, b with
 | `Alias (ttl, name), `Alias (ttl', name') -> ttl = ttl' && Domain_name.equal name name'
 | (#Dns_cache.entry as e1), (#Dns_cache.entry as e2) -> entry_eq t e1 e2
 | _ -> false

let pp_or_cname t ppf = function
 | `Alias (ttl, name) -> Fmt.pf ppf "alias %lu %a" ttl Domain_name.pp name
 | #Dns_cache.entry as e -> Dns_cache.pp_entry t ppf e

let cname_or_cached t =
  Alcotest.testable (pp_or_cname t) (entry_or_cname t)

let cached_cname_r t = Alcotest.result (cname_or_cached t) cached_err

let empty = Dns_cache.empty 100

let cname_empty_cache () =
  Alcotest.check (cached_cname_r Rr_map.A) "empty cache results in Cache_miss"
    (Error `Cache_miss)
    (snd (Dns_cache.get_or_cname empty 0L (name "foo.com") A))

let cname_cache_a () =
  let name = name "foo.com" in
  let a = 250l, Ipaddr.V4.Set.singleton (ip "1.2.3.4") in
  let cache = Dns_cache.set empty 0L name A AuthoritativeAnswer (`Entry a) in
  Alcotest.check (cached_cname_r Rr_map.A) "cache with A results in res"
    (Ok (`Entry a))
    (snd (Dns_cache.get_or_cname cache 0L name A)) ;
  Alcotest.check (cached_cname_r Rr_map.Cname) "cache with A results in CacheMiss"
    (Error `Cache_miss)
    (snd (Dns_cache.get_or_cname cache 0L name Cname))

let cname_cache_cname () =
  let rel = name "bar.com" in
  let name = name "foo.com" in
  let cname = 250l, rel in
  let cache = Dns_cache.set empty 0L name Cname AuthoritativeAnswer (`Entry cname) in
  Alcotest.check (cached_cname_r Rr_map.Cname) "cache with CNAME results in res"
    (Ok (`Alias cname))
    (snd (Dns_cache.get_or_cname cache 0L name Cname)) ;
  Alcotest.check (cached_cname_r Rr_map.A) "cache with CNAME results in res for A"
    (Ok (`Alias cname))
    (snd (Dns_cache.get_or_cname cache 0L name A)) ;
  Alcotest.check (cached_cname_r Rr_map.Ns) "cache with CNAME results in res for NS"
    (Ok (`Alias cname))
    (snd (Dns_cache.get_or_cname cache 0L name Ns))

let cname_cache_cname_nodata () =
  let rel = name "bar.com" in
  let name = name "foo.com" in
  let cname = 250l, rel in
  let bad_soa = invalid_soa name in
  let cache =
    Dns_cache.set
      (Dns_cache.set empty 0L name Cname AuthoritativeAnswer (`Entry cname))
      0L name Ns AuthoritativeAnswer (`No_data (name, bad_soa))
  in
  Alcotest.check (cached_cname_r Rr_map.Cname) "cache with CNAME results in res"
    (Ok (`Alias cname))
    (snd (Dns_cache.get_or_cname cache 0L name Cname)) ;
  Alcotest.check (cached_cname_r Rr_map.Ns) "cache with CNAME results in res for NS"
    (Ok (`Alias cname))
    (snd (Dns_cache.get_or_cname cache 0L name Ns)) ;
  Alcotest.check (cached_cname_r Rr_map.A) "cache with CNAME results in res for A"
    (Ok (`Alias cname))
    (snd (Dns_cache.get_or_cname cache 0L name A))

let cname_cache_tests = [
  "empty cache", `Quick, cname_empty_cache ;
  "cache with A", `Quick, cname_cache_a ;
  "cache with CNAME", `Quick, cname_cache_cname ;
  "cache with another cname", `Quick, cname_cache_cname_nodata ;
]

let tests = [
  "cache tests", cache_tests;
  "cname cache tests", cname_cache_tests;
]

let () = Alcotest.run "DNS cache tests" tests
