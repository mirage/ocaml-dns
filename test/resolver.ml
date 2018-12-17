(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns_resolver_entry
open Dns_resolver_cache
open Dns_packet

let empty = empty 100

let ip = Ipaddr.V4.of_string_exn
let ip6 = Ipaddr.V6.of_string_exn
let name = Domain_name.of_string_exn
let sec = Duration.of_sec

let invalid_soa = Dns_resolver_utils.invalid_soa

let root_servers = snd (List.split Dns_resolver_root.root_servers)
let a_root = List.hd root_servers

let rng i = Cstruct.create i

let rr_equal a b =
  Domain_name.equal a.name b.name &&
  a.ttl = b.ttl &&
  compare_rdata a.rdata b.rdata = 0

let follow_res =
  let module M = struct
    type t =
      [ `Cycle of rr list * Dns_resolver_cache.t
      | `NoData of (rr list * rr) * Dns_resolver_cache.t
      | `NoDom of (rr list * rr) * Dns_resolver_cache.t
      | `NoError of rr list * Dns_resolver_cache.t
      | `Query of Domain_name.t * Dns_resolver_cache.t
      | `ServFail of rr * Dns_resolver_cache.t
      ]
      let pp ppf = function
        | `Cycle (rrs, _) -> Fmt.pf ppf "cycle %a" pp_rrs rrs
        | `NoData ((rrs, soa), _) -> Fmt.pf ppf "nodata %a, soa %a" pp_rrs rrs pp_rr soa
        | `NoDom ((rrs, soa), _) -> Fmt.pf ppf "nodom %a, soa %a" pp_rrs rrs pp_rr soa
        | `NoError (rrs, _) -> Fmt.pf ppf "noerror %a" pp_rrs rrs
        | `Query (name, _) -> Fmt.pf ppf "query %a" Domain_name.pp name
        | `ServFail (soa, _) -> Fmt.pf ppf "servfail %a" pp_rr soa
      let equal a b = match a, b with
        | `Cycle (rrs, _), `Cycle (rrs', _) -> List.for_all2 rr_equal rrs rrs'
        | `NoData ((rrs, soa), _), `NoData ((rrs', soa'), _) -> List.for_all2 rr_equal rrs rrs' && rr_equal soa soa'
        | `NoDom ((rrs, soa), _), `NoDom ((rrs', soa'), _) -> List.for_all2 rr_equal rrs rrs' && rr_equal soa soa'
        | `NoError (rrs, _), `NoError (rrs', _) -> List.for_all2 rr_equal rrs rrs'
        | `Query (name, _), `Query (name', _) -> Domain_name.equal name name'
        | `ServFail (soa, _), `ServFail (soa', _) -> rr_equal soa soa'
        | _, _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

let follow_cname_cycle () =
  let circ = {
    name = name "foo.com" ;
    ttl = 250l ;
    rdata = CNAME (name "foo.com")
  } in
  let cache = maybe_insert Dns_enum.A (name "foo.com") 0L AuthoritativeAnswer (NoErr [circ]) empty in
  Alcotest.check follow_res "CNAME single cycle is detected"
    (`Cycle ([ circ ], cache))
    (follow_cname cache 0L Dns_enum.A (name "foo.com") [circ]) ;
  Alcotest.check follow_res "CNAME single cycle after timeout is still a cycle (how did you get the rr in the first place?)"
    (`Cycle ([ circ ], cache))
    (follow_cname cache (sec 251) Dns_enum.A (name "foo.com") [circ]) ;
  let a = { name = name "foo.com" ; ttl = 250l ; rdata = CNAME (name "bar.com") }
  and b = { name = name "bar.com" ; ttl = 500l ; rdata = CNAME (name "foo.com") }
  in
  let cache =
    maybe_insert Dns_enum.A (name "bar.com") 0L AuthoritativeAnswer (NoErr [b])
      (maybe_insert Dns_enum.A (name "foo.com") 0L AuthoritativeAnswer (NoErr [a])
         empty)
  in
  Alcotest.check follow_res "CNAME cycle is detected"
    (`Cycle ([ b ; a ], cache))
    (follow_cname cache 0L Dns_enum.A (name "bar.com") [b]) ;
  Alcotest.check follow_res "Query foo.com (since it timed out)"
    (`Query (name "foo.com", cache))
    (follow_cname cache (sec 251) Dns_enum.A (name "bar.com") [b])

let follow_cname_tests = [
  "follow_cname cycles", `Quick, follow_cname_cycle ;
]

let resolve_ns_ret =
  let module M = struct
    type t = [ `NeedA of Domain_name.t | `NeedCname of Domain_name.t | `HaveIPS of Ipaddr.V4.t list | `No | `NoDom ] * Dns_resolver_cache.t
    let pp ppf = function
      | `NeedA nam, _ -> Fmt.pf ppf "need A of %a" Domain_name.pp nam
      | `NeedCname nam, _ -> Fmt.pf ppf "need cname of %a" Domain_name.pp nam
      | `HaveIPS ips, _ -> Fmt.pf ppf "have IPs %a" Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp) ips
      | `No, _ -> Fmt.string ppf "no"
      | `NoDom, _ -> Fmt.string ppf "nodom"
    let equal a b = match a, b with
      | (`NeedA n, _), (`NeedA n', _) -> Domain_name.equal n n'
      | (`NeedCname n, _), (`NeedCname n', _) -> Domain_name.equal n n'
      | (`HaveIPS ips, _), (`HaveIPS ips', _) -> List.for_all2 (fun a b -> Ipaddr.V4.compare a b = 0) ips ips'
      | (`No, _), (`No, _) -> true
      | (`NoDom, _), (`NoDom, _) -> true
      | _, _ -> false
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let resolve_ns_empty () =
  Alcotest.(check resolve_ns_ret
              "looking for NS in empty cache needA"
              (`NeedA (name "foo.com"), empty)
              (resolve_ns empty 0L (name "foo.com")))

let resolve_ns_cname () =
  let cname_rr =
    { name = name "foo.com" ; ttl = 250l ; rdata = CNAME (name "bar.com") }
  in
  let cache = maybe_insert Dns_enum.A (name "foo.com") 0L AuthoritativeAnswer (NoErr [cname_rr]) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with CNAME returns needA"
              (`NeedCname (name "bar.com"), cache)
              (resolve_ns cache 0L (name "foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired CNAME returns needA"
              (`NeedA (name "foo.com"), cache)
              (resolve_ns cache (sec 251) (name "foo.com")))

let resolve_ns_empty_noerr () =
  let cache = maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr []) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with A (NoErr []) returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired A returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache (sec 251) (name "ns1.foo.com")))

let resolve_ns_noerr_aaaa () =
  let aaaa =
    { name = name "ns1.foo.com" ; ttl = 250l ; rdata = AAAA (ip6 "::1") }
  in
  let cache = maybe_insert Dns_enum.AAAA (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [aaaa]) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with AAAA returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired AAAA returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache (sec 251) (name "ns1.foo.com")))

let resolve_ns_a () =
  let a_rr =
    { name = name "ns1.foo.com" ; ttl = 250l ; rdata = A (ip "1.2.3.4") }
  in
  let cache = maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [a_rr]) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with A returns haveIP"
              (`HaveIPS [ip "1.2.3.4"], cache)
              (resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with A returns NeedA after timeout"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache (sec 251) (name "ns1.foo.com")))

let resolve_ns_as () =
  let a_rrs = [
    { name = name "ns1.foo.com" ; ttl = 250l ; rdata = A (ip "1.2.3.4") } ;
    { name = name "ns1.foo.com" ; ttl = 2500l ; rdata = A (ip "1.2.3.5") }
  ] in
  let cache = maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a_rrs) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with multiple A returns all IPs"
              (`HaveIPS [ip "1.2.3.4" ; ip "1.2.3.5"], cache)
              (resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with multiple A after TTL expired for one returns other"
              (`HaveIPS [ip "1.2.3.5"], cache)
              (resolve_ns cache (sec 251) (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with multiple A after TTL expired for all returns NeedA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache (sec 2501) (name "ns1.foo.com")))

(* TODO: not sure whether the semantics is correct... now no more any errors
   from resolve_ns, no more result type *)
let resolve_ns_bad () =
  let bad_rr = invalid_soa (name "ns1.foo.com") in
  let cache = maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoData bad_rr) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodata returns needa"
              (`No, cache)
              (resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired nodata returns NeedA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache (sec 301) (name "ns1.foo.com"))) ;
  let cache = maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoDom bad_rr) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodom returns error"
              (`NoDom, cache)
              (resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodom returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache (sec 301) (name "ns1.foo.com"))) ;
  let cache = maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail bad_rr) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with servfail returns error"
              (`No, cache)
              (resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired servfail returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (resolve_ns cache (sec 301) (name "ns1.foo.com")))

let resolve_ns_tests = [
  "empty", `Quick, resolve_ns_empty ;
  "cname", `Quick, resolve_ns_cname ;
  "empty noerr", `Quick, resolve_ns_empty_noerr ;
  "aaaa", `Quick, resolve_ns_noerr_aaaa ;
  "a", `Quick, resolve_ns_a ;
  "as", `Quick, resolve_ns_as ;
  "nodom nodata servfail", `Quick, resolve_ns_bad ;
]

let find_ns_ret =
  let module M = struct
    type t = [ `Loop | `NeedNS | `No | `NoDom | `Cname of Domain_name.t | `NeedA of Domain_name.t | `HaveIP of Ipaddr.V4.t | `NeedGlue of Domain_name.t ] * Dns_resolver_cache.t
    let pp ppf = function
      | `NeedA name, _ -> Fmt.pf ppf "need A of %a" Domain_name.pp name
      | `NeedGlue name, _ -> Fmt.pf ppf "need glue for %a" Domain_name.pp name
      | `HaveIP ip, _ -> Fmt.pf ppf "have IP %a" Ipaddr.V4.pp ip
      | `NeedNS, _ -> Fmt.string ppf "need NS"
      | `Cname nam, _ -> Fmt.pf ppf "cname %a" Domain_name.pp nam
      | `No, _ -> Fmt.string ppf "no"
      | `NoDom, _ -> Fmt.string ppf "nodom"
      | `Loop, _ -> Fmt.string ppf "loop"
    let equal a b = match a, b with
      | (`NeedA n, _), (`NeedA n', _) -> Domain_name.equal n n'
      | (`NeedGlue n, _), (`NeedGlue n', _) -> Domain_name.equal n n'
      | (`HaveIP ip, _), (`HaveIP ip', _) -> Ipaddr.V4.compare ip ip' = 0
      | (`NeedNS, _), (`NeedNS, _) -> true
      | (`Cname n, _), (`Cname n', _) -> Domain_name.equal n n'
      | (`No, _), (`No, _) -> true
      | (`NoDom, _), (`NoDom, _) -> true
      | (`Loop, _), (`Loop, _) -> true
      | _, _ -> false
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let eds = Domain_name.Set.empty

let find_ns_empty () =
  Alcotest.check find_ns_ret "looking for NS in empty cache `NeedNS"
    (`NeedNS, empty) (find_ns empty rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in empty cache for root `NeedNS"
    (`NeedNS, empty) (find_ns empty rng 0L eds Domain_name.root)

let with_root =
  let cache =
    List.fold_left (fun cache (name, rr) ->
        Dns_resolver_cache.maybe_insert
          Dns_enum.A name 0L Dns_resolver_entry.Additional
          (Dns_resolver_entry.NoErr [ rr ]) cache)
      empty Dns_resolver_root.a_records
  in
  Dns_resolver_cache.maybe_insert
    Dns_enum.NS Domain_name.root 0L Dns_resolver_entry.Additional
    (Dns_resolver_entry.NoErr Dns_resolver_root.ns_records) cache

let find_ns_prefilled () =
  Alcotest.check find_ns_ret "looking for NS in empty cache `NeedNS"
    (`NeedNS, empty) (find_ns with_root rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in empty cache for root `HaveIP"
    (`HaveIP a_root, empty)
    (find_ns with_root rng 0L eds Domain_name.root)

let find_ns_cname () =
  let cname_rr =
    { name = name "foo.com" ; ttl = 250l ; rdata = CNAME (name "bar.com") }
  in
  let cache = maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr [cname_rr]) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with CNAME returns cname"
    (`Cname (name "bar.com"), cache) (find_ns cache rng 0L eds (name "foo.com"))

let find_ns_bad () =
  let bad_rr = invalid_soa (name "foo.com") in
  let cache = maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoData bad_rr) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with nodata returns No"
    (`No, cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired nodata returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 301) eds (name "foo.com")) ;
  let cache = maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoDom bad_rr) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with nodom returns No"
    (`No, cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired nodom returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 301) eds (name "foo.com")) ;
  let cache = maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (ServFail bad_rr) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with servfail returns no"
    (`No, cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired servfail returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 301) eds (name "foo.com"))

let find_ns_empty_noerr () =
  let cache = maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr []) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with NoErr returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NoErr returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns () =
  let ns =
    { name = name "foo.com" ; ttl = 250l ; rdata = NS (name "ns1.foo.com") }
  in
  let cache = maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr [ns]) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with NS returns NeedA"
    (`NeedGlue (name "foo.com"), cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a () =
  let ns =
    { name = name "foo.com" ; ttl = 250l ; rdata = NS (name "ns1.foo.com") }
  and a =
    { name = name "ns1.foo.com" ; ttl = 2500l ; rdata = A (ip "1.2.3.4") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [a]) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A and NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS and A returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a_exp () =
  let ns =
    { name = name "foo.com" ; ttl = 2500l ; rdata = NS (name "ns1.foo.com") }
  and a =
    { name = name "ns1.foo.com" ; ttl = 250l ; rdata = A (ip "1.2.3.4") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [a]) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A and NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A and NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a_a_exp () =
  let ns = [
    { name = name "foo.com" ; ttl = 2000l ; rdata = NS (name "ns1.foo.com") } ;
    { name = name "foo.com" ; ttl = 2500l ; rdata = NS (name "ns2.foo.com") }
  ]
  and a1 = [
    { name = name "ns1.foo.com" ; ttl = 200l ; rdata = A (ip "1.2.3.4") } ;
    { name = name "ns1.foo.com" ; ttl = 150l ; rdata = A (ip "1.2.3.2") }
  ]
  and a2 =
    { name = name "ns2.foo.com" ; ttl = 250l ; rdata = A (ip "1.2.3.5") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a1)
         (maybe_insert Dns_enum.A (name "ns2.foo.com") 0L AuthoritativeAnswer (NoErr [a2])
            empty))
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A, A and NS, NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A and A, NS, NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (find_ns cache rng (sec 151) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns Needglue foo.com"
    (`NeedGlue (name "foo.com"), cache) (find_ns cache rng (sec 201) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (find_ns cache rng (sec 251) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (find_ns cache rng (sec 2001) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 2501) eds (name "foo.com"))

let find_ns_ns_and_cname () =
  let ns =
    { name = name "foo.com" ; ttl = 250l ; rdata = NS (name "ns1.foo.com") }
  and cname =
    { name = name "ns1.foo.com" ; ttl = 2500l ; rdata = CNAME (name "ns1.bar.com") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [cname]) empty)
  in
  (* TODO this is a bad cache entry, not sure whether this behaviour is good (following cnames) *)
  Alcotest.check find_ns_ret "looking for NS in cache with CNAME and NS returns NeedGlue"
    (`NeedA (name "ns1.bar.com"), cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired CNAME and NS returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_aaaa () =
  let ns =
    { name = name "foo.com" ; ttl = 250l ; rdata = NS (name "ns1.foo.com") }
  and aaaa =
    { name = name "ns1.foo.com" ; ttl = 2500l ; rdata = AAAA (ip6 "::1") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.AAAA (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [aaaa]) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with AAAA and NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS and AAAA returns NeedNS"
    (`NeedNS, cache) (find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_tests = [
  "empty", `Quick, find_ns_empty ;
  "with_root", `Quick, find_ns_prefilled ;
  "cname", `Quick, find_ns_cname ;
  "nodata nodom servfail", `Quick, find_ns_bad ;
  "empty noerr", `Quick, find_ns_empty_noerr ;
  "ns", `Quick, find_ns_ns ;
  "ns a", `Quick, find_ns_ns_and_a ;
  "ns a exp", `Quick, find_ns_ns_and_a_exp ;
  "ns a a exp", `Quick, find_ns_ns_and_a_a_exp ;
  "ns cname", `Quick, find_ns_ns_and_cname ;
  "ns aaaa", `Quick, find_ns_ns_and_aaaa ;
]

let resolve_ret =
  let module M = struct
    type t = Domain_name.t * Dns_enum.rr_typ * Ipaddr.V4.t * Dns_resolver_cache.t
    let pp ppf (name, typ, ip, _) =
      Fmt.pf ppf "requesting %a for %a (asking %a)"
        Dns_enum.pp_rr_typ typ Domain_name.pp name
        Ipaddr.V4.pp ip
    let equal (n, t, i, _) (n', t', i', _) =
      Domain_name.equal n n' && t = t' && Ipaddr.V4.compare i i' = 0
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let str_err =
  let module M = struct
    type t = string
    let pp = Fmt.string
    let equal _ _ = true
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let resolve_res = Alcotest.result resolve_ret str_err

let resolve ~rng a b c d = match resolve ~rng a b c d with
  | Error e -> Error e
  | Ok (_, a, b, c, d) -> Ok (a, b, c, d)

let resolve_empty () =
  Alcotest.check resolve_res "looking for NS in empty cache for root -> look for NS . @a_root"
    (Ok (Domain_name.root, Dns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L Domain_name.root Dns_enum.NS) ;
  Alcotest.check resolve_res  "resolving A foo.com in empty cache -> look for NS . @a_root"
    (Ok (Domain_name.root, Dns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L (name "foo.com") Dns_enum.A) ;
  Alcotest.check resolve_res  "resolving NS foo.com in empty cache -> look for NS . @a_root"
    (Ok (Domain_name.root, Dns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L (name "foo.com") Dns_enum.NS) ;
  Alcotest.check resolve_res  "resolving PTR 1.2.3.4.in-addr.arpa in empty cache -> look for NS . @a_root"
    (Ok (Domain_name.root, Dns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L (name "1.2.3.4.in-addr.arpa") Dns_enum.PTR)

let resolve_with_root () =
  Alcotest.check resolve_res "looking for NS in with_root -> look for NS . @a_root"
    (Ok (Domain_name.root, Dns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L Domain_name.root Dns_enum.NS) ;
  Alcotest.check resolve_res  "resolving A foo.com in with_root -> look for NS .com @a_root "
    (Ok (name "com", Dns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L (name "foo.com") Dns_enum.A) ;
  Alcotest.check resolve_res  "resolving NS foo.com in with_root -> look for NS .com @a_root"
    (Ok (name "com", Dns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L (name "foo.com") Dns_enum.NS) ;
  Alcotest.check resolve_res  "resolving PTR 1.2.3.4.in-addr.arpa in with_root -> look for NS .arpa @a_root"
    (Ok (name "arpa", Dns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L (name "1.2.3.4.in-addr.arpa") Dns_enum.PTR)

let resolve_with_ns () =
  let ns =
    { name = name "com" ; ttl = 250l ; rdata = NS (name "ns1.foo.org") }
  in
  let cache = maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns]) with_root in
  Alcotest.check resolve_res "looking for A for foo.com asks for NS org"
    (Ok (name "org", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A)

let resolve_with_ns_err () =
  let ns =
    { name = name "com" ; ttl = 250l ; rdata = NS (name "ns1.foo.com") }
  and bad_rr = invalid_soa (name "ns1.foo.com")
  in
  let cache =
    maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoData bad_rr)
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com NoData requests NS foo.com"
    (Ok (name "foo.com", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  let cache =
    maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoDom bad_rr)
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com NoDom errors"
    (Error "")
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  let cache =
    maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail bad_rr)
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com ServFail requests NS foo.com"
    (Ok (name "foo.com", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  let cache =
    maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail bad_rr)
         (maybe_insert Dns_enum.A (name "com") 0L AuthoritativeAnswer (ServFail bad_rr)
            with_root))
  in
  (* TODO: correctness? should request NS for .com! *)
  Alcotest.check resolve_res "looking for A com with com NS ns1.foo.com, ns1.foo.com ServFail, com A ServFail asks for A foo.com"
    (Ok (name "com", Dns_enum.A, a_root, cache))
    (resolve ~rng cache 0L (name "com") Dns_enum.A)

let resolve_with_ns_a () =
  let ns =
    { name = name "com" ; ttl = 250l ; rdata = NS (name "ns1.foo.com") }
  and a =
    { name = name "ns1.foo.com" ; ttl = 250l ; rdata = A (ip "1.2.3.4") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [a])
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com asks for NS foo.com @ns1.foo.com"
    (Ok (name "foo.com", Dns_enum.NS, ip "1.2.3.4", cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A)

let resolve_with_ns_a_ns () =
  let ns =
    { name = name "com" ; ttl = 2500l ; rdata = NS (name "ns1.foo.com") }
  and a =
    { name = name "ns1.foo.com" ; ttl = 250l ; rdata = A (ip "1.2.3.4") }
  and ns2 =
    { name = name "foo.com" ; ttl = 250l ; rdata = NS (name "ns2.foo.com") }
  and a2 =
    { name = name "ns2.foo.com" ; ttl = 250l ; rdata = A (ip "1.2.3.5") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr [a])
         (maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr [ns2])
            (maybe_insert Dns_enum.A (name "ns2.foo.com") 0L AuthoritativeAnswer (NoErr [a2])
               with_root)))
  in
  Alcotest.check resolve_res "looking for A for foo.com asks for A foo.com @ns1.foo.com"
    (Ok (name "foo.com", Dns_enum.A, ip "1.2.3.5", cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  Alcotest.check resolve_res "looking for A after TTL for foo.com asks NS .com @a_root"
    (Ok (name "com", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache (sec 251) (name "foo.com") Dns_enum.A)

let resolve_cycle () =
  let ns =
    { name = name "com" ; ttl = 2500l ; rdata = NS (name "ns1.org") }
  and ns2 =
    { name = name "org" ; ttl = 250l ; rdata = NS (name "ns1.com") }
  in
  let cache =
    maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr [ns])
      (maybe_insert Dns_enum.NS (name "org") 0L AuthoritativeAnswer (NoErr [ns2])
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com Errors cycle"
    (Error "cycle detected")
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A)

let resolve_tests = [
  "empty", `Quick, resolve_empty ;
  "with root", `Quick, resolve_with_root ;
  "with ns", `Quick, resolve_with_ns ;
  "with ns err", `Quick, resolve_with_ns_err ;
  "with ns a", `Quick, resolve_with_ns_a ;
  "with ns a ns", `Quick, resolve_with_ns_a_ns ;
  "cycle", `Quick, resolve_cycle ;
]

let res_eq a b = match a, b with
  | NoErr rr, NoErr rr' -> List.length rr = List.length rr' && List.for_all (fun e -> List.exists (rr_equal e) rr') rr
  | NoData soa, NoData soa' -> rr_equal soa soa'
  | NoDom soa, NoDom soa' -> rr_equal soa soa'
  | ServFail rr, ServFail rr' -> rr_equal rr rr'
  | _, _ -> false

let entry =
  let module M = struct
    type t = res
    let pp = pp_res
    let equal = res_eq
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

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

let cached_ok =
  let module M = struct
    type t = res * Dns_resolver_cache.t
    let pp ppf (res, _) = pp_res ppf res
    let equal (r, _) (r', _) = res_eq r r'
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)


let cached_r = Alcotest.(result cached_ok cached_err)

let empty_cache () =
  Alcotest.check cached_r "empty cache results in Cache_miss"
    (Error `Cache_miss)
    (cached empty 0L Dns_enum.A (name "foo.com"))

let cache_a () =
  let name = name "foo.com" in
  let a = { name ; ttl = 250l ; rdata = A (ip "1.2.3.4") } in
  let cache = maybe_insert Dns_enum.A name 0L AuthoritativeAnswer (NoErr [ a ]) empty in
  Alcotest.check cached_r "cache with A results in res"
    (Ok (NoErr [ a ], cache))
    (cached cache 0L Dns_enum.A name) ;
  Alcotest.check cached_r "cache with A results in CacheMiss"
    (Error `Cache_miss)
    (cached cache 0L Dns_enum.CNAME name)

let cache_cname () =
  let rel = name "bar.com" in
  let name = name "foo.com" in
  let cname = { name ; ttl = 250l ; rdata = CNAME rel } in
  let cache = maybe_insert Dns_enum.CNAME name 0L AuthoritativeAnswer (NoErr [ cname ]) empty in
  Alcotest.check cached_r "cache with CNAME results in res"
    (Ok (NoErr [ cname ], cache))
    (cached cache 0L Dns_enum.CNAME name) ;
  Alcotest.check cached_r "cache with CNAME results in res for A"
    (Ok (NoErr [ cname ], cache))
    (cached cache 0L Dns_enum.A name) ;
  Alcotest.check cached_r "cache with CNAME results in res for NS"
    (Ok (NoErr [ cname ], cache))
    (cached cache 0L Dns_enum.NS name)

let cache_cname_nodata () =
  let rel = name "bar.com" in
  let name = name "foo.com" in
  let cname = { name ; ttl = 250l ; rdata = CNAME rel } in
  let cache =
    maybe_insert Dns_enum.CNAME name 0L AuthoritativeAnswer (NoErr [ cname ])
      (maybe_insert Dns_enum.NS name 0L AuthoritativeAnswer (NoData (invalid_soa name))
         empty)
  in
  Alcotest.check cached_r "cache with CNAME results in res"
    (Ok (NoErr [ cname ], cache))
    (cached cache 0L Dns_enum.CNAME name) ;
  Alcotest.check cached_r "cache with CNAME results in res for NS"
    (Ok (NoErr [ cname ], cache))
    (cached cache 0L Dns_enum.NS name) ;
  Alcotest.check cached_r "cache with CNAME results in res for A"
    (Ok (NoErr [ cname ], cache))
    (cached cache 0L Dns_enum.A name)

let cache_tests = [
  "empty cache", `Quick, empty_cache ;
  "cache with A", `Quick, cache_a ;
  "cache with CNAME", `Quick, cache_cname ;
  "cache with another cname", `Quick, cache_cname_nodata ;
]

let typ =
  let module M = struct
    type t = Dns_enum.rr_typ
    let pp = Dns_enum.pp_rr_typ
    let equal a b = a = b
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let nam =
  let module M = struct
    type t = Domain_name.t
    let pp = Domain_name.pp
    let equal a b = Domain_name.equal a b
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

(* once again the complete thingy since I don't care about list ordering (Alcotest.list is order-enforcing) *)
let res =
  let module M = struct
    type t = (Dns_enum.rr_typ * Domain_name.t * rank * res) list
    let pp ppf xs =
      let pp_elem ppf (t, n, r, e) =
        Fmt.pf ppf "%a %a (%a): %a" Domain_name.pp n Dns_enum.pp_rr_typ t pp_rank r pp_res e
      in
      Fmt.pf ppf "%a" Fmt.(list ~sep:(unit ";@,") pp_elem) xs
    let equal a a' =
      let eq (t, n, r, e) (t', n', r', e') =
        Domain_name.equal n n' && t = t' &&
        compare_rank r r' = `Equal &&
        res_eq e e'
      in
      List.length a = List.length a' &&
      List.for_all (fun e -> List.exists (eq e) a') a
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let rcode =
  let module M = struct
    type t = Dns_enum.rcode
    let pp = Dns_enum.pp_rcode
    let equal a b = Dns_enum.rcode_to_int a = Dns_enum.rcode_to_int b
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let res = Alcotest.(result res rcode)

let empty_q () =
  { question = [] ; answer = [] ; authority = [] ; additional = [] }

let header = { id = 0 ; query = false ; operation = Dns_enum.Query ;
               authoritative = false ; truncation = false ;
               recursion_desired = false ; recursion_available = false ;
               authentic_data = false ; checking_disabled = false ;
               rcode = Dns_enum.NoError }

let scrub q hdr dns = Dns_resolver_utils.scrub q.q_name q hdr dns

let scrub_empty () =
  let name = name "foo.com" in
  let q = { q_name = name; q_type = Dns_enum.A }
  and dns = empty_q ()
  in
  Alcotest.check res "empty frame results in empty scrub"
    (Ok [ Dns_enum.A, name, Additional, NoData (invalid_soa name) ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "empty authoritative frame results in empty scrub"
    (Ok [ Dns_enum.A, name, Additional, NoData (invalid_soa name) ])
    (scrub q hdr dns)

let scrub_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer = [ { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } ] in
  let dns = { tdns with answer } in
  Alcotest.check res "A record results in scrubbed A"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative A record results in scrubbed A"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer])
    (scrub q hdr dns)

let scrub_a_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer =
    let entry = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    let entry2 = { entry with rdata = A (ip "1.2.3.5") } in
    [ entry ; entry2 ]
  in
  let dns = { tdns with answer } in
  Alcotest.check res "A records results in scrubbed A with same records"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative A records results in scrubbed A with same records"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ])
    (scrub q hdr dns)

let scrub_cname () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer =
    [ { name = q_name ; ttl = 1l ; rdata = CNAME (name "bar.com") } ]
  in
  let dns = { tdns with answer } in
  Alcotest.check res "CNAME record results in scrubbed CNAME with same record"
    (Ok [ Dns_enum.CNAME, q_name, NonAuthoritativeAnswer, NoErr answer])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative CNAME record results in scrubbed CNAME with same record"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr answer])
    (scrub q hdr dns)

let scrub_soa () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let soa =
    let soa = {
      nameserver = name "a" ; hostmaster = name "b" ;
      serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
    } in
    { name = q_name ; ttl = 1l ; rdata = SOA soa }
  in
  let dns = { tdns with authority = [ soa ] } in
  Alcotest.check res "SOA record results in NoData SOA"
    (Ok [ Dns_enum.A, q_name, Additional, NoData soa ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative SOA record results in NoData SOA"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAuthority, NoData soa ])
    (scrub q hdr dns)

let scrub_bad_soa () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let soa =
    let soa = {
      nameserver = name "a" ; hostmaster = name "b" ;
      serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
    } in
    { name = name "bar.com" ; ttl = 1l ; rdata = SOA soa }
  in
  let dns = { tdns with authority = [ soa ] } in
  Alcotest.check res "bad SOA record results in NoData SOA"
    (Ok [ Dns_enum.A, q_name, Additional, NoData (invalid_soa q_name) ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative bad SOA record results in NoData SOA"
    (Ok [ Dns_enum.A, q_name, Additional, NoData (invalid_soa q_name) ])
    (scrub q hdr dns)

let scrub_soa_super () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let soa =
    let soa = {
      nameserver = name "a" ; hostmaster = name "b" ;
      serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
    } in
    { name = name "com" ; ttl = 1l ; rdata = SOA soa }
  in
  let dns = { tdns with authority = [ soa ] } in
  Alcotest.check res "SOA record results in NoData SOA"
    (Ok [ Dns_enum.A, q_name, Additional, NoData soa ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative SOA record results in NoData SOA"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAuthority, NoData soa ])
    (scrub q hdr dns)

let scrub_cname_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer =
    let one = { name = q_name ; ttl = 1l ; rdata = CNAME (name "bar.com") } in
    let two = { one with rdata = A (ip "1.2.3.4") } in
    [ one ; two ]
  in
  let dns = { tdns with answer } in
  Alcotest.check res "CNAME and A record results in nodata"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoData (invalid_soa q_name) ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative CNAME and A record results in nodata"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoData (invalid_soa q_name) ])
    (scrub q hdr dns)

let scrub_authority_ns () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let authority =
    [ { name = q_name ; ttl = 1l ; rdata = NS (name "ns1.foo.com") } ]
  in
  let dns = { tdns with authority } in
  Alcotest.check res "NS in authority results in NoData foo.com and NoErr NS"
    (Ok [ Dns_enum.NS, q_name, Additional, NoErr authority ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority results in NoData foo.com and NoErr NS"
    (Ok [ Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ])
    (scrub q hdr dns)

let scrub_a_authority_ns () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer, authority =
    let one = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    [ one ], [ { one with rdata = NS (name "ns1.foo.com") } ]
  in
  let dns = { tdns with answer ; authority } in
  Alcotest.check res "NS in authority, and A in answer results in NoErr foo.com and NoErr NS"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, Additional, NoErr authority ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, and A in answer results in NoErr foo.com and NoErr NS"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ])
    (scrub q hdr dns)

let scrub_a_authority_ns_add_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer, authority, additional =
    let one = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    let glue = { one with name = name "ns1.foo.com" } in
    [ one ], [ { one with rdata = NS (name "ns1.foo.com") } ], [ glue ]
  in
  let dns = { tdns with answer ; authority ; additional } in
  Alcotest.check res "NS in authority, A in answer, glue in additional results in NoErr foo.com, NoErr NS, NoErr ns1.foo.com A"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, Additional, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr additional ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, A in answer, glue in additional results in NoErr foo.com, NoErr NS, NoErr ns1.foo.com A"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr additional ])
    (scrub q hdr dns)

let scrub_a_authority_ns_bad_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer, authority, additional =
    let one = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    let glue = { one with name = name "ns2.foo.com" } in
    [ one ], [ { one with rdata = NS (name "ns1.foo.com") } ], [ glue ]
  in
  let dns = { tdns with answer ; authority ; additional } in
  Alcotest.check res "NS in authority, A in answer, crap in additional results in NoErr foo.com and NoErr NS"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, Additional, NoErr authority ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, A in answer, crap in additional results in NoErr foo.com and NoErr NS"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ])
    (scrub q hdr dns)

let scrub_a_authority_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer, authority, additional =
    let one = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    let glue = { one with name = name "ns1.foo.com" } in
    [ one ], [ { one with rdata = NS (name "ns1.foo.com") } ],
    [ glue ; { glue with rdata = A (ip "1.2.3.5") } ]
  in
  let dns = { tdns with answer ; authority ; additional } in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, Additional, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr additional ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr additional ])
    (scrub q hdr dns)

let scrub_a_authority_ns_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer, authority, a1, a2 =
    let one = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    let glue = { one with name = name "ns1.foo.com" } in
    [ one ], [ { one with rdata = NS (name "ns1.foo.com") } ; { one with rdata = NS (name "ns2.foo.com") } ],
    glue, { glue with name = name "ns2.foo.com" ; rdata = A (ip "1.2.3.5") }
  in
  let dns = { tdns with answer ; authority ; additional = [ a1 ; a2 ] } in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, Additional, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ;
          Dns_enum.A, name "ns2.foo.com", Additional, NoErr [ a2 ] ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ;
          Dns_enum.A, name "ns2.foo.com", Additional, NoErr [ a2 ] ])
    (scrub q hdr dns)

let scrub_a_authority_ns_bad_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer, au1, au2, a1, a2 =
    let one = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    let glue = { one with name = name "ns1.foo.com" } in
    [ one ],
    { one with rdata = NS (name "ns1.foo.com") },
    { one with name = name "com" ; rdata = NS (name "ns2.foo.com") },
    glue, { glue with name = name "ns2.foo.com" ; rdata = A (ip "1.2.3.5") }
  in
  let dns = { tdns with answer ; authority = [ au1 ; au2 ] ; additional = [ a1 ; a2 ] } in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, Additional, NoErr [ au1 ] ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr [ au1 ] ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ])
    (scrub q hdr dns)

let scrub_authority_ns_add_a_bad () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let authority, a1, a2 =
    let glue = { name = name "ns1.foo.com" ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    [ { glue with name = q_name ; rdata = NS (name "ns1.foo.com") } ],
    glue, { glue with rdata = NS (name "ns3.foo.com") }
  in
  let dns = { tdns with authority ; additional = [ a1 ; a2 ] } in
  Alcotest.check res "NS in authority, A and NS in additional results in NoErr NS, NoErr As"
    (Ok [ Dns_enum.NS, q_name, Additional, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, A and NS in additional results in NoErr NS, NoErr As"
    (Ok [ Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ])
    (scrub q hdr dns)

let scrub_authority_ns_add_a_aaaa () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let authority, a1, a2 =
    let glue = { name = name "ns1.foo.com" ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    [ { glue with name = q_name ; rdata = NS (name "ns1.foo.com") } ],
    glue, { glue with rdata = AAAA (ip6 "::1") }
  in
  let dns = { tdns with authority ; additional = [ a1 ; a2 ] } in
  Alcotest.check res "NS in authority, A and AAAA in additional results in NoErr NS, NoErr A, NoErr AAAA"
    (Ok [ Dns_enum.NS, q_name, Additional, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ;
          Dns_enum.AAAA, name "ns1.foo.com", Additional, NoErr [ a2 ]])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS in authority, A and AAAA in additional results in NoErr NS, NoErr A, NoErr AAAA"
    (Ok [ Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr authority ;
          Dns_enum.A, name "ns1.foo.com", Additional, NoErr [ a1 ] ;
          Dns_enum.AAAA, name "ns1.foo.com", Additional, NoErr [ a2 ]])
    (scrub q hdr dns)

let scrub_a_authority_ns_a () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let tdns = empty_q () in
  let answer, a1, a2 =
    let one = { name = q_name ; ttl = 1l ; rdata = A (ip "1.2.3.4") } in
    [ one ], { one with rdata = NS (name "ns1.foo.com") }, { one with rdata = A (ip "1.2.3.4") }
  in
  let dns = { tdns with answer ; authority = [ a1 ; a2 ] } in
  Alcotest.check res "NS and crap in authority, A in answer results in NoErr foo.com, NoErr NS"
    (Ok [ Dns_enum.A, q_name, NonAuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, Additional, NoErr [ a1 ] ])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative NS and crap in authority, A in answer results in NoErr foo.com, NoErr NS"
    (Ok [ Dns_enum.A, q_name, AuthoritativeAnswer, NoErr answer ;
          Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr [ a1 ] ])
    (scrub q hdr dns)

let scrub_bad_packets () =
  let q_name = name "foo.com" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let answer = [ { name = name "bar.com" ; ttl = 1l ; rdata = A (ip "1.2.3.4") } ] in
  let dns =
    let dns = empty_q () in
    { dns with answer }
  in
  Alcotest.check res "No results in scrubbed A with bad A"
    (Ok [ Dns_enum.A, q_name, Additional, NoData (invalid_soa q_name)])
    (scrub q header dns) ;
  let hdr = { header with authoritative = true } in
  Alcotest.check res "authoritative no results in scrubbed A with bad A"
    (Ok [ Dns_enum.A, q_name, Additional, NoData (invalid_soa q_name)])
    (scrub q hdr dns)

let scrub_rfc2308_2_1 () =
  let q_name = name "an.example" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let hdr = { header with rcode = Dns_enum.NXDomain } in
  let base =
    let dns = empty_q () in
    { dns with question = [ q ] }
  in
  let soa =
    let soa = {
      nameserver = name "ns1.xx" ; hostmaster = name "hostmaster.ns1.xx" ;
      serial = 1l ; refresh = 1l ; retry = 2l ; expiry = 3l ; minimum = 4l
    } in
    { name = name "xx" ; ttl = 1l ; rdata = SOA soa }
  and ns =
    [ { name = name "xx" ; ttl = 1l ; rdata = NS (name "ns1.xx") } ;
      { name = name "xx" ; ttl = 1l ; rdata = NS (name "ns2.xx") } ]
  in
  let a =
    { name = q_name ; ttl = 1l ; rdata = CNAME (name "tripple.xx") }
  and additional =
    [ { name = name "ns1.xx" ; ttl = 1l ; rdata = A (ip "127.0.0.2") } ;
      { name = name "ns2.xx" ; ttl = 1l ; rdata = A (ip "127.0.0.3") } ]
  in
  let dns =
    let authority = soa :: ns in
    { base with answer = [ a ]; authority ; additional }
  in
  (* considering what is valid in the response, it turns out only the cname is *)
  Alcotest.check res "Sec 2.1 type 1"
    (Ok [ Dns_enum.CNAME, q_name, NonAuthoritativeAnswer, NoErr [ a ] ])
    (scrub q hdr dns) ;
  let dns =
    { base with answer = [ a ] ; authority = [ soa ] }
  in
  Alcotest.check res "Sec 2.1 type 2"
    (Ok [ Dns_enum.CNAME, q_name, NonAuthoritativeAnswer, NoErr [ a ] ])
    (scrub q hdr dns) ;
  let dns =
    { base with answer = [ a ] }
  in
  Alcotest.check res "Sec 2.1 type 3"
    (Ok [ Dns_enum.CNAME, q_name, NonAuthoritativeAnswer, NoErr [ a ] ])
    (scrub q hdr dns) ;
  let dns =
    { base with answer = [ a ] ; authority = ns ; additional }
  in
  Alcotest.check res "Sec 2.1 type 4"
    (Ok [ Dns_enum.CNAME, q_name, NonAuthoritativeAnswer, NoErr [ a ] ])
    (scrub q hdr dns) ;
  let hdr = header in
  let dns =
    { base with answer = [ a ] ; authority = ns ; additional }
  in
  Alcotest.check res "Sec 2.1 type referral response"
    (Ok [ Dns_enum.CNAME, q_name, NonAuthoritativeAnswer, NoErr [ a ] ])
    (scrub q hdr dns)

(* bailiwick thingies (may repeat above tests):
   - q_name is foo, q_type is A!
   - answer contains additional A records [ foo A 1.2.3.4 ; bar A 1.2.3.4 ]
   - answer contains cname and A: [ foo cname bar ; bar A 1.2.3.4 ]
   - authority contains [ foo CNAME bar ] [ bar NS boo ]
   - answer cname and authority NS [ foo cname bar ] [ bar NS boo ]
   - additional contains glue [ foo CNAME bar ] [] [ bar A 1.2.3.4 ]
   - additional contains glue with au [ foo CNAME bar ] [ bar NS boo ] [ boo A 1.2.3.4 ]
*)
let bailiwick_a () =
  let q_name = name "foo" in
  let q = { q_name ; q_type = Dns_enum.A } in
  let base_dns = { question = [ q ] ; answer = [] ; authority = [] ; additional = [] } in
  let hdr = { header with authoritative = true } in
  let a = { name = q_name ; ttl = 300l ; rdata = A (ip "1.2.3.4") } in
  let answer = Dns_enum.A, q_name, AuthoritativeAnswer, NoErr [ a ] in
  let add_a = { base_dns with answer = [ a ; { a with name = name "bar" } ] } in
  Alcotest.check res "additional A records"
    (Ok [ answer ])
    (scrub q hdr add_a) ;
  let cname = { name = name "foo" ; ttl = 300l ; rdata = CNAME (name "bar") } in
  let cname_a = { base_dns with answer = [ cname ; { a with name = name "bar" } ] } in
  Alcotest.check res "A and CNAME record"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr [ cname ] ])
    (scrub q hdr cname_a) ;
  let ns = { name = name "bar" ; ttl = 300l ; rdata = NS (name "boo") } in
  let cname_ns = { base_dns with answer = [ cname ; ns ] } in
  Alcotest.check res "CNAME and NS record in answer"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr [ cname ] ])
    (scrub q hdr cname_ns) ;
  let cname_auth = { base_dns with answer = [ cname ] ; authority = [ ns ] } in
  Alcotest.check res "CNAME and NS record in authority"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr [ cname ] ])
    (scrub q hdr cname_auth) ;
  let ns' = { ns with name = name "foobar" } in
  let cname_ns_unrelated = { base_dns with answer = [ cname ; ns' ] } in
  Alcotest.check res "CNAME and unrelated NS record in answer"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr [ cname ] ])
    (scrub q hdr cname_ns_unrelated) ;
  let cname_auth_unrelated = { base_dns with answer = [ cname ] ; authority = [ ns' ] } in
  Alcotest.check res "CNAME and unrelated NS record in authority"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr [ cname ] ])
    (scrub q hdr cname_auth_unrelated) ;
  let glue = { name = name "bar" ; ttl = 300l ; rdata = A (ip "1.2.3.4") } in
  let cname_glue = { base_dns with answer = [ cname ] ; additional = [ glue ] } in
  Alcotest.check res "CNAME and glue record in additional"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr [ cname ] ])
    (scrub q hdr cname_glue) ;
  let glue' = { glue with name = name "boo" } in
  let cname_au_glue = { base_dns with answer = [ cname ] ; authority = [ ns ] ; additional = [ glue' ] } in
  Alcotest.check res "CNAME and glue record in additional"
    (Ok [ Dns_enum.CNAME, q_name, AuthoritativeAnswer, NoErr [ cname ] ])
    (scrub q hdr cname_au_glue)

(* similar, but with MX records:
   - query is MX, "foo"
   - answer = [ "foo" MX 10 "bar" ; "foo" A 1.2.3.4 ]
   - answer = [ "foo" MX 10 "bar" ; "bar" MX 10 "bar" ]
   - answer = [ "foo" MX 10 "bar" ; "bar" A 1.2.3.4 ]
   - answer = [ "foo" MX 10 "bar" ], additional = [ "bar" A 1.2.3.4 ]
   - answer = [ "foo" MX 10 "bar" ], authority = [ "foo" NS "foobar" ],
       additional = [ "bar" A 1.2.3.4 ; "foobar" A 1.2.3.4 ] <- takes au
   - answer = [ "foo" MX 10 "bar" ], authority = [ "bar" NS "foobar" ],
       additional = [ "bar" A 1.2.3.4 ; "foobar" A 1.2.3.4 ] <- only answer
*)
let bailiwick_mx () =
  let q_name = name "foo" in
  let q = { q_name ; q_type = Dns_enum.MX } in
  let base_dns = { question = [ q ] ; answer = [] ; authority = [] ; additional = [] } in
  let hdr = { header with authoritative = true } in
  let mx = { name = q_name ; ttl = 300l ; rdata = MX (10, name "bar") } in
  let answer = Dns_enum.MX, q_name, AuthoritativeAnswer, NoErr [ mx ] in
  let a = { name = q_name ; ttl = 300l ; rdata = A (ip "1.2.3.4") } in
  let mx_a = { base_dns with answer = [ mx ; a ] } in
  Alcotest.check res "additional A record"
    (Ok [ answer ])
    (scrub q hdr mx_a) ;
  let mx_mx = { base_dns with answer = [ mx ; { mx with name = name "bar" } ] } in
  Alcotest.check res "additional MX records"
    (Ok [ answer ])
    (scrub q hdr mx_mx) ;
  let mx_amx = { base_dns with answer = [ mx ; { a with name = name "bar" } ] } in
  Alcotest.check res "MX record and an A record"
    (Ok [ answer ])
    (scrub q hdr mx_amx) ;
  let mx_add = { base_dns with answer = [ mx ] ; additional = [ { a with name = name "bar" } ] } in
  Alcotest.check res "MX record and additional A record"
    (Ok [ answer ])
    (scrub q hdr mx_add) ;
  let ns = { name = name "foo" ; ttl = 300l ; rdata = NS (name "foobar") } in
  let mx_au_add = { base_dns with answer = [ mx ] ;
                                  authority = [ ns ] ;
                                  additional = [ { a with name = name "bar" } ; { a with name = name "foobar" } ] } in
  let answer' = [
    answer ;
    Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr [ ns ] ]
  in
  Alcotest.check res "MX record and authority and additional A record"
    (Ok answer')
    (scrub q hdr mx_au_add) ;
  let mx_au_add' = { mx_au_add with authority = [ { ns with name = name "bar" } ] } in
  Alcotest.check res "MX record and bad authority and additional A record"
    (Ok [ answer ])
     (scrub q hdr mx_au_add')

(* similar, but with NS records:
   - query is NS, "foo"
   - answer = [ "foo" NS "bar" ; "foo" A 1.2.3.4 ]
   - answer = [ "foo" NS "bar" ; "bar" NS "bar" ]
   - answer = [ "foo" NS "bar" ; "bar" A 1.2.3.4 ]
   - answer = [ "foo" NS "bar" ], additional = [ "foo" A 1.2.3.4 ]
   - answer = [ "foo" NS "bar" ], additional = [ "bar" A 1.2.3.4 ]
   - answer = [ "foo" NS "bar" ], authority = [ "foo" NS "foobar" ],
       additional = [ "bar" A 1.2.3.4 ; "foobar" A 1.2.3.4 ] <- takes au
   - answer = [ "foo" NS "bar" ], authority = [ "bar" NS "foobar" ],
       additional = [ "bar" A 1.2.3.4 ; "foobar" A 1.2.3.4 ] <- only answer
*)
let bailiwick_ns () =
  let q_name = name "foo" in
  let q = { q_name ; q_type = Dns_enum.NS } in
  let base_dns = { question = [ q ] ; answer = [] ; authority = [] ; additional = [] } in
  let hdr = { header with authoritative = true } in
  let ns = { name = q_name ; ttl = 300l ; rdata = NS (name "bar") } in
  let answer = Dns_enum.NS, q_name, AuthoritativeAnswer, NoErr [ ns ] in
  let a = { name = q_name ; ttl = 300l ; rdata = A (ip "1.2.3.4") } in
  let ns_a = { base_dns with answer = [ ns ; a ] } in
  (* fail atm - get NS and A *)
  Alcotest.check res "additional A record"
      (Ok [ answer ])
      (scrub q hdr ns_a) ;
  let ns_ns = { base_dns with answer = [ ns ; { ns with name = name "bar" } ] } in
  Alcotest.check res "additional NS records"
    (Ok [ answer ])
    (scrub q hdr ns_ns) ;
  let ns_ans = { base_dns with answer = [ ns ; { a with name = name "bar" } ] } in
  Alcotest.check res "NS record and an A record"
    (Ok [ answer ])
    (scrub q hdr ns_ans) ;
  let ns_add = { base_dns with answer = [ ns ] ; additional = [ a ] } in
  (* should glue be respected? don't think it's worth it *)
  Alcotest.check res "NS record and additional A record"
    (Ok [ answer ])
    (scrub q hdr ns_add) ;
  let ns_add' = { base_dns with answer = [ ns ] ; additional = [ { a with name = name "bar" } ] } in
  (* fail atm - get NS and A *)
  Alcotest.check res "NS record and additional A record with NS name"
    (Ok [ answer ])
     (scrub q hdr ns_add') ;
  let ns' = { name = name "foo" ; ttl = 300l ; rdata = NS (name "foobar") } in
  let ns_au_add = { base_dns with answer = [ ns ] ;
                                  authority = [ ns' ] ;
                                  additional = [ { a with name = name "bar" } ; { a with name = name "foobar" } ] } in
  let answer' = [
    answer ;
    Dns_enum.NS, q_name, AuthoritativeAuthority, NoErr [ ns' ] ]
  in
  (* fail atm - get NS NS + A A *)
  Alcotest.check res "NS record and authority and additional A record"
    (Ok answer')
    (scrub q hdr ns_au_add) ;
  let ns_au_add' = { ns_au_add with authority = [ { ns with name = name "bar" } ] } in
  (* fail atm - get NS + A *)
  Alcotest.check res "NS record and bad authority and additional A record"
    (Ok [ answer ])
     (scrub q hdr ns_au_add')

let scrub_tests = [
  "empty", `Quick, scrub_empty ;
  "scrub A", `Quick, scrub_a ;
  "scrub A A", `Quick, scrub_a_a ;
  "scrub CNAME", `Quick, scrub_cname ;
  "scrub SOA", `Quick, scrub_soa ;
  "scrub bad SOA", `Quick, scrub_bad_soa ;
  "scrub SOA super", `Quick, scrub_soa_super ;
  "scrub CNAME A", `Quick, scrub_cname_a ;
  "scrub authority NS", `Quick, scrub_authority_ns ;
  "scrub A authority NS", `Quick, scrub_a_authority_ns ;
  "scrub A authority NS add A", `Quick, scrub_a_authority_ns_add_a ;
  "scrub A authority NS bad A", `Quick, scrub_a_authority_ns_bad_a ;
  "scrub A authority NS add A A", `Quick, scrub_a_authority_ns_add_a_a ;
  "scrub A authority NS NS add A A" ,`Quick, scrub_a_authority_ns_ns_add_a_a ;
  "scrub A authority NS badNS add A A", `Quick, scrub_a_authority_ns_bad_ns_add_a_a ;
  "scrub authority NS add A NS", `Quick, scrub_authority_ns_add_a_bad ;
  "scrub authority NS add A AAAA", `Quick, scrub_authority_ns_add_a_aaaa ;
  "scrub A authority NS A", `Quick, scrub_a_authority_ns_a ;
  "bad packets", `Quick, scrub_bad_packets ;
  "rfc2308 2.1", `Quick, scrub_rfc2308_2_1 ;
  "bailiwick a", `Quick, bailiwick_a ;
  "bailiwick mx", `Quick, bailiwick_mx ;
  "bailiwick ns", `Quick, bailiwick_ns ;
]

let tests = [
  "follow_cname cycles", follow_cname_tests ;
  "resolve_ns", resolve_ns_tests ;
  "find_ns", find_ns_tests ;
  (*  "resolve", resolve_tests ;*)
  "cache", cache_tests ;
  "scrub", scrub_tests ;
]

let () = Alcotest.run "DNS resolver tests" tests
