open Dns

let empty = Dns_cache.empty 100
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

let res_eq a b =
  match a, b with
  | `Entry b, `Entry b' -> Rr_map.equalb b b'
  | `No_data (name, soa), `No_data (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | `No_domain (name, soa), `No_domain (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | `Serv_fail (name, soa), `Serv_fail (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | _, _ -> false

let cached_ok =
  let module M = struct
    type t = Dns_cache.entry * Dns_cache.t
    let pp ppf (res, _) = Dns_cache.pp_entry ppf res
    let equal (r, _) (r', _) = res_eq r r'
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)


let cached_r = Alcotest.(result cached_ok cached_err)

let empty_cache () =
  Alcotest.check cached_r "empty cache results in Cache_miss"
    (Error `Cache_miss)
    (Dns_cache.get empty 0L (name "an-actual-website.com") A)

let cache_a () =
  let name = name "an-actual-website.com" in
  let a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4")))) in
  let cache = Dns_cache.set empty 0L name A AuthoritativeAnswer (`Entry a) in
  Alcotest.check cached_r "cache with A results in res"
    (Ok (`Entry a, cache))
    (Dns_cache.get cache 0L name A) ;
  Alcotest.check cached_r "cache with A results in CacheMiss"
    (Error `Cache_miss)
    (Dns_cache.get cache 0L name Cname)

let cache_nodata () =
  let name = name "an-alias.com"
  and subname = name "another-domain.an-alias.com"
  in
  let soa = invalid_soa name in
  let nodata = `No_data (subname, soa) in
  let a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4")))) in
  let cache =
    let cache = Dns_cache.set empty 0L name A AuthoritativeAnswer (`Entry a) in
    Dns_cache.set cache 0L subname A AuthoritativeAnswer nodata
  in
  Alcotest.check cached_r "cache with A nodata results in nodata"
    (Ok (nodata, cache))
    (Dns_cache.get cache 0L subname A) ;
  Alcotest.check cached_r "cache with A nodata results in cache miss for NS"
    (Error `Cache_miss)
    (Dns_cache.get cache 0L subname Ns) ;
  Alcotest.check cached_r "cache with A nodata results in a record"
    (Ok (`Entry a, cache))
    (Dns_cache.get cache 0L name A) ;
  Alcotest.check cached_r "cache with A nodata results in cache miss for NS'"
    (Error `Cache_miss)
    (Dns_cache.get cache 0L name Ns) ;
  let updated_cache =
    Dns_cache.set empty 0L subname A AuthoritativeAnswer (`Entry a)
  in
  Alcotest.check cached_r "cache with A nodata results in nodata"
    (Ok (`Entry a, updated_cache))
    (Dns_cache.get updated_cache 0L subname A)

let cache_tests = [
  "empty cache", `Quick, empty_cache ;
  "cache with A", `Quick, cache_a ;
  "cache nodata", `Quick, cache_nodata ;
]

let tests = [
    "cache tests", cache_tests;
]

let () = Alcotest.run "DNS cache tests" tests
