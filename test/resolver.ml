(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Udns

let empty = Udns_resolver_cache.empty 100

let ip = Ipaddr.V4.of_string_exn
let ip6 = Ipaddr.V6.of_string_exn
let name = Domain_name.of_string_exn
let sec = Duration.of_sec

let invalid_soa = Udns_resolver_utils.invalid_soa

let root_servers = snd (List.split Udns_resolver_root.root_servers)
let a_root = List.hd root_servers

let rng i = Cstruct.create i

let follow_res =
  let module M = struct
    type t =
      [ `Out of Rcode.t * Name_rr_map.t * Name_rr_map.t * Udns_resolver_cache.t
      | `Query of Domain_name.t * Udns_resolver_cache.t
      ]
      let pp ppf = function
        | `Out (rcode, answer, authority, _) -> Fmt.pf ppf "out %a answer %a authority %a" Rcode.pp rcode Name_rr_map.pp answer Name_rr_map.pp authority
        | `Query (name, _) -> Fmt.pf ppf "query %a" Domain_name.pp name
      let equal a b = match a, b with
        | `Out (rc, an, au, _), `Out (rc', an', au', _) ->
          Rcode.compare rc rc' = 0 && Name_rr_map.equal an an' && Name_rr_map.equal au au'
        | `Query (name, _), `Query (name', _) -> Domain_name.equal name name'
        | _, _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

let follow_cname_cycle () =
  let circ = Rr_map.(B (Cname, (250l, name "foo.com"))) in
  let circ_map = Domain_name.Map.singleton (name "foo.com") Rr_map.(addb circ empty) in
  let cache =
    Udns_resolver_cache.maybe_insert Rr.A (name "foo.com") 0L AuthoritativeAnswer
      (`Entry circ)
      empty
  in
  Alcotest.check follow_res "CNAME single cycle is detected"
    (`Out (Rcode.NoError, circ_map, Name_rr_map.empty, cache))
    (Udns_resolver_cache.follow_cname cache 0L Rr.A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"));
  Alcotest.check follow_res "CNAME single cycle after timeout errors"
    (`Query (name "foo.com", cache))
    (Udns_resolver_cache.follow_cname cache (sec 251) Rr.A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"));
  let a = Rr_map.(B (Cname, (250l, name "bar.com")))
  and b = Rr_map.(B (Cname, (500l, name "foo.com")))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Rr.A (name "bar.com") 0L AuthoritativeAnswer (`Entry b)
      (Udns_resolver_cache.maybe_insert Rr.A (name "foo.com") 0L AuthoritativeAnswer (`Entry a)
         empty)
  in
  let c_map =
    Domain_name.Map.add (name "bar.com") Rr_map.(addb b empty)
      (Domain_name.Map.singleton (name "foo.com") Rr_map.(addb a empty))
  in
  Alcotest.check follow_res "CNAME cycle is detected"
    (`Out (Rcode.NoError, c_map, Name_rr_map.empty, cache))
    (Udns_resolver_cache.follow_cname cache 0L Rr.A
       ~name:(name "bar.com") 250l ~alias:(name "foo.com"));
  Alcotest.check follow_res "Query foo.com (since it timed out)"
    (`Query (name "foo.com", cache))
    (Udns_resolver_cache.follow_cname cache (sec 251) Rr.A
       ~name:(name "bar.com") 250l ~alias:(name "foo.com"))

let follow_cname_tests = [
  "follow_cname cycles", `Quick, follow_cname_cycle ;
]
(*
let resolve_ns_ret =
  let module M = struct
    type t = [ `NeedA of Domain_name.t | `NeedCname of Domain_name.t | `HaveIPS of Rr_map.Ipv4_set.t | `No | `NoDom ] * Udns_resolver_cache.t
    let pp ppf = function
      | `NeedA nam, _ -> Fmt.pf ppf "need A of %a" Domain_name.pp nam
      | `NeedCname nam, _ -> Fmt.pf ppf "need cname of %a" Domain_name.pp nam
      | `HaveIPS ips, _ -> Fmt.pf ppf "have IPs %a" Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp) (Rr_map.Ipv4_set.elements ips)
      | `No, _ -> Fmt.string ppf "no"
      | `NoDom, _ -> Fmt.string ppf "nodom"
    let equal a b = match a, b with
      | (`NeedA n, _), (`NeedA n', _) -> Domain_name.equal n n'
      | (`NeedCname n, _), (`NeedCname n', _) -> Domain_name.equal n n'
      | (`HaveIPS ips, _), (`HaveIPS ips', _) -> Rr_map.Ipv4_set.equal ips ips'
      | (`No, _), (`No, _) -> true
      | (`NoDom, _), (`NoDom, _) -> true
      | _, _ -> false
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let resolve_ns_empty () =
  Alcotest.(check resolve_ns_ret
              "looking for NS in empty cache needA"
              (`NeedA (name "foo.com"), empty)
              (Udns_resolver_cache.resolve_ns empty 0L (name "foo.com")))

let resolve_ns_cname () =
  let cname = Rr_map.(B (Cname, (250l, name "bar.com"))) in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.A (name "foo.com") 0L AuthoritativeAnswer (NoErr cname) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with CNAME returns needA"
              (`NeedCname (name "bar.com"), cache)
              (Udns_resolver_cache.resolve_ns cache 0L (name "foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired CNAME returns needA"
              (`NeedA (name "foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache (sec 251) (name "foo.com")))

let resolve_ns_noerr_aaaa () =
  let aaaa = Rr_map.(B (Aaaa, (250l, Ipv6_set.singleton (ip6 "::1")))) in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.AAAA (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr aaaa) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with AAAA returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired AAAA returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache (sec 251) (name "ns1.foo.com")))

let resolve_ns_a () =
  let a_rr = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4")))) in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a_rr) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with A returns haveIP"
              (`HaveIPS (Rr_map.Ipv4_set.singleton (ip "1.2.3.4")), cache)
              (Udns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with A returns NeedA after timeout"
              (`NeedA (name "ns1.foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache (sec 251) (name "ns1.foo.com")))

let resolve_ns_as () =
  let a_rrs = Rr_map.(B (A, (250l, Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.5")))))) in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a_rrs) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with multiple A returns all IPs"
              (`HaveIPS Rr_map.Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.5"))), cache)
              (Udns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with multiple A after TTL expired for all returns NeedA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache (sec 251) (name "ns1.foo.com")))

(* TODO: not sure whether the semantics is correct... now no more any errors
   from resolve_ns, no more result type *)
let resolve_ns_bad () =
  let (name_soa, bad_soa) = invalid_soa (name "ns1.foo.com") in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoData (name_soa, bad_soa)) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodata returns needa"
              (`No, cache)
              (Udns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired nodata returns NeedA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache (sec 301) (name "ns1.foo.com"))) ;
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoDom (name_soa, bad_soa)) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodom returns error"
              (`NoDom, cache)
              (Udns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodom returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache (sec 301) (name "ns1.foo.com"))) ;
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail (name_soa, bad_soa)) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with servfail returns error"
              (`No, cache)
              (Udns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired servfail returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Udns_resolver_cache.resolve_ns cache (sec 301) (name "ns1.foo.com")))

let resolve_ns_tests = [
  "empty", `Quick, resolve_ns_empty ;
  "cname", `Quick, resolve_ns_cname ;
  "aaaa", `Quick, resolve_ns_noerr_aaaa ;
  "a", `Quick, resolve_ns_a ;
  "as", `Quick, resolve_ns_as ;
  "nodom nodata servfail", `Quick, resolve_ns_bad ;
]

let find_ns_ret =
  let module M = struct
    type t = [ `Loop | `NeedNS | `No | `NoDom | `Cname of Domain_name.t | `NeedA of Domain_name.t | `HaveIP of Ipaddr.V4.t | `NeedGlue of Domain_name.t ] * Udns_resolver_cache.t
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
    (`NeedNS, empty) (Udns_resolver_cache.find_ns empty rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in empty cache for root `NeedNS"
    (`NeedNS, empty) (Udns_resolver_cache.find_ns empty rng 0L eds Domain_name.root)

let with_root =
  let cache =
    List.fold_left (fun cache (name, b) ->
        Udns_resolver_cache.maybe_insert
          Udns_enum.A name 0L Udns_resolver_entry.Additional
          (Udns_resolver_entry.NoErr b) cache)
      empty Udns_resolver_root.a_records
  in
  Udns_resolver_cache.maybe_insert
    Udns_enum.NS Domain_name.root 0L Udns_resolver_entry.Additional
    (Udns_resolver_entry.NoErr Udns_resolver_root.ns_records) cache

let find_ns_prefilled () =
  Alcotest.check find_ns_ret "looking for NS in empty cache `NeedNS"
    (`NeedNS, empty) (Udns_resolver_cache.find_ns with_root rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in empty cache for root `HaveIP"
    (`HaveIP a_root, empty)
    (Udns_resolver_cache.find_ns with_root rng 0L eds Domain_name.root)

let find_ns_cname () =
  let cname = Rr_map.(B (Cname, (250l, name "bar.com"))) in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr cname) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with CNAME returns cname"
    (`Cname (name "bar.com"), cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com"))

let find_ns_bad () =
  let (bad_name, bad_rr) = invalid_soa (name "foo.com") in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoData (bad_name, bad_rr)) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with nodata returns No"
    (`No, cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired nodata returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 301) eds (name "foo.com")) ;
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoDom (bad_name, bad_rr)) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with nodom returns No"
    (`No, cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired nodom returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 301) eds (name "foo.com")) ;
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_rr)) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with servfail returns no"
    (`No, cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired servfail returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 301) eds (name "foo.com"))

let find_ns_ns () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com")))) in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with NS returns NeedA"
    (`NeedGlue (name "foo.com"), cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (2500l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A and NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS and A returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a_exp () =
  let ns = Rr_map.(B (Ns, (2500l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A and NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A and NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Udns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a_a_exp () =
  let ns =
    Rr_map.(B (Ns, (250l, Domain_name.Set.(add (name "ns1.foo.com") (singleton (name "ns2.foo.com"))))))
  and a1 =
    Rr_map.(B (A, (150l, Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.2"))))))
  and a2 =
    Rr_map.(B (A, (200l, Ipv4_set.singleton (ip "1.2.3.5"))))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a1)
         (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns2.foo.com") 0L AuthoritativeAnswer (NoErr a2)
            empty))
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A, A and NS, NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A and A, NS, NS returns HaveIP"
    (`HaveIP (ip "1.2.3.5"), cache) (Udns_resolver_cache.find_ns cache rng (sec 151) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns Needglue foo.com"
    (`NeedGlue (name "foo.com"), cache) (Udns_resolver_cache.find_ns cache rng (sec 201) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Udns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Udns_resolver_cache.find_ns cache rng (sec 2001) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 2501) eds (name "foo.com"))

let find_ns_ns_and_cname () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and cname = Rr_map.(B (Cname, (2500l, name "ns1.bar.com")))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr cname) empty)
  in
  (* TODO this is a bad cache entry, not sure whether this behaviour is good (following cnames) *)
  Alcotest.check find_ns_ret "looking for NS in cache with CNAME and NS returns NeedGlue"
    (`NeedA (name "ns1.bar.com"), cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired CNAME and NS returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_aaaa () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and aaaa = Rr_map.(B (Aaaa, (2500l, Ipv6_set.singleton (ip6 "::1"))))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.AAAA (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr aaaa) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with AAAA and NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Udns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS and AAAA returns NeedNS"
    (`NeedNS, cache) (Udns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_tests = [
  "empty", `Quick, find_ns_empty ;
  "with_root", `Quick, find_ns_prefilled ;
  "cname", `Quick, find_ns_cname ;
  "nodata nodom servfail", `Quick, find_ns_bad ;
  "ns", `Quick, find_ns_ns ;
  "ns a", `Quick, find_ns_ns_and_a ;
  "ns a exp", `Quick, find_ns_ns_and_a_exp ;
  "ns a a exp", `Quick, find_ns_ns_and_a_a_exp ;
  "ns cname", `Quick, find_ns_ns_and_cname ;
  "ns aaaa", `Quick, find_ns_ns_and_aaaa ;
]

let resolve_ret =
  let module M = struct
    type t = Domain_name.t * Udns_enum.rr_typ * Ipaddr.V4.t * Udns_resolver_cache.t
    let pp ppf (name, typ, ip, _) =
      Fmt.pf ppf "requesting %a for %a (asking %a)"
        Udns_enum.pp_rr_typ typ Domain_name.pp name
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

let resolve ~rng a b c d = match Udns_resolver_cache.resolve ~rng a b c d with
  | Error e -> Error e
  | Ok (_, a, b, c, d) -> Ok (a, b, c, d)

let resolve_empty () =
  Alcotest.check resolve_res "looking for NS in empty cache for root -> look for NS . @a_root"
    (Ok (Domain_name.root, Udns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L Domain_name.root Udns_enum.NS) ;
  Alcotest.check resolve_res  "resolving A foo.com in empty cache -> look for NS . @a_root"
    (Ok (Domain_name.root, Udns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L (name "foo.com") Udns_enum.A) ;
  Alcotest.check resolve_res  "resolving NS foo.com in empty cache -> look for NS . @a_root"
    (Ok (Domain_name.root, Udns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L (name "foo.com") Udns_enum.NS) ;
  Alcotest.check resolve_res  "resolving PTR 1.2.3.4.in-addr.arpa in empty cache -> look for NS . @a_root"
    (Ok (Domain_name.root, Udns_enum.NS, List.hd root_servers, empty))
    (resolve ~rng empty 0L (name "1.2.3.4.in-addr.arpa") Udns_enum.PTR)

let resolve_with_root () =
  Alcotest.check resolve_res "looking for NS in with_root -> look for NS . @a_root"
    (Ok (Domain_name.root, Udns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L Domain_name.root Udns_enum.NS) ;
  Alcotest.check resolve_res  "resolving A foo.com in with_root -> look for NS .com @a_root "
    (Ok (name "com", Udns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L (name "foo.com") Udns_enum.A) ;
  Alcotest.check resolve_res  "resolving NS foo.com in with_root -> look for NS .com @a_root"
    (Ok (name "com", Udns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L (name "foo.com") Udns_enum.NS) ;
  Alcotest.check resolve_res  "resolving PTR 1.2.3.4.in-addr.arpa in with_root -> look for NS .arpa @a_root"
    (Ok (name "arpa", Udns_enum.NS, a_root, empty))
    (resolve ~rng with_root 0L (name "1.2.3.4.in-addr.arpa") Udns_enum.PTR)

let resolve_with_ns () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.org"))))
  in
  let cache = Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns) with_root in
  Alcotest.check resolve_res "looking for A for foo.com asks for NS org"
    (Ok (name "org", Udns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Udns_enum.A)

let resolve_with_ns_err () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and (bad_name, bad_soa) = invalid_soa (name "ns1.foo.com")
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoData (bad_name, bad_soa))
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com NoData requests NS foo.com"
    (Ok (name "foo.com", Udns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Udns_enum.A) ;
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoDom (bad_name, bad_soa))
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com NoDom errors"
    (Error "")
    (resolve ~rng cache 0L (name "foo.com") Udns_enum.A) ;
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_soa))
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com ServFail requests NS foo.com"
    (Ok (name "foo.com", Udns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Udns_enum.A) ;
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_soa))
         (Udns_resolver_cache.maybe_insert Udns_enum.A (name "com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_soa))
            with_root))
  in
  (* TODO: correctness? should request NS for .com! *)
  Alcotest.check resolve_res "looking for A com with com NS ns1.foo.com, ns1.foo.com ServFail, com A ServFail asks for A foo.com"
    (Ok (name "com", Udns_enum.A, a_root, cache))
    (resolve ~rng cache 0L (name "com") Udns_enum.A)

let resolve_with_ns_a () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a)
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com asks for NS foo.com @ns1.foo.com"
    (Ok (name "foo.com", Udns_enum.NS, ip "1.2.3.4", cache))
    (resolve ~rng cache 0L (name "foo.com") Udns_enum.A)

let resolve_with_ns_a_ns () =
  let ns = Rr_map.(B (Ns, (2500l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and ns2 = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns2.foo.com"))))
  and a2 = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.5"))))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a)
         (Udns_resolver_cache.maybe_insert Udns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns2)
            (Udns_resolver_cache.maybe_insert Udns_enum.A (name "ns2.foo.com") 0L AuthoritativeAnswer (NoErr a2)
               with_root)))
  in
  Alcotest.check resolve_res "looking for A for foo.com asks for A foo.com @ns1.foo.com"
    (Ok (name "foo.com", Udns_enum.A, ip "1.2.3.5", cache))
    (resolve ~rng cache 0L (name "foo.com") Udns_enum.A) ;
  Alcotest.check resolve_res "looking for A after TTL for foo.com asks NS .com @a_root"
    (Ok (name "com", Udns_enum.NS, a_root, cache))
    (resolve ~rng cache (sec 251) (name "foo.com") Udns_enum.A)

let resolve_cycle () =
  let ns = Rr_map.(B (Ns, (2500l, Domain_name.Set.singleton (name "ns1.org"))))
  and ns2 = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.com"))))
  in
  let cache =
    Udns_resolver_cache.maybe_insert Udns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Udns_resolver_cache.maybe_insert Udns_enum.NS (name "org") 0L AuthoritativeAnswer (NoErr ns2)
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com Errors cycle"
    (Error "cycle detected")
    (resolve ~rng cache 0L (name "foo.com") Udns_enum.A)

let resolve_tests = [
  "empty", `Quick, resolve_empty ;
  "with root", `Quick, resolve_with_root ;
  "with ns", `Quick, resolve_with_ns ;
  "with ns err", `Quick, resolve_with_ns_err ;
  "with ns a", `Quick, resolve_with_ns_a ;
  "with ns a ns", `Quick, resolve_with_ns_a_ns ;
  "cycle", `Quick, resolve_cycle ;
]
*)

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
  | `Alias (ttl, alias), `Alias (ttl', alias') -> ttl = ttl' && Domain_name.equal alias alias'
  | `Entry b, `Entry b' -> Rr_map.equal_b b b'
  | `No_data (name, soa), `No_data (name', soa') -> Domain_name.equal name name' && Udns.Soa.compare soa soa' = 0
  | `No_domain (name, soa), `No_domain (name', soa') -> Domain_name.equal name name' && Udns.Soa.compare soa soa' = 0
  | `Serv_fail (name, soa), `Serv_fail (name', soa') -> Domain_name.equal name name' && Udns.Soa.compare soa soa' = 0
  | _, _ -> false

let res_entries_eq a b =
  match a with
  | #Udns_resolver_cache.res as r1 -> begin match b with
      | #Udns_resolver_cache.res as r2 -> res_eq r1 r2
      | _ -> false
    end
  | `Entries a -> match b with
    | `Entries b -> Rr_map.equal Rr_map.equal_b a b
    | _ -> false

let res_pp ppf = function
  | #Udns_resolver_cache.res as r -> Udns_resolver_cache.pp_res ppf r
  | `Entries all -> Rr_map.pp ppf all

let cached_ok =
  let module M = struct
    type t = [ Udns_resolver_cache.res | `Entries of Rr_map.t ] * Udns_resolver_cache.t
    let pp ppf (res, _) = res_pp ppf res
    let equal (r, _) (r', _) = res_entries_eq r r'
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)


let cached_r = Alcotest.(result cached_ok cached_err)

let empty_cache () =
  Alcotest.check cached_r "empty cache results in Cache_miss"
    (Error `Cache_miss)
    (Udns_resolver_cache.cached empty 0L Rr.A (name "foo.com"))

let cache_a () =
  let name = name "foo.com" in
  let a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4")))) in
  let cache = Udns_resolver_cache.maybe_insert Rr.A name 0L AuthoritativeAnswer (`Entry a) empty in
  Alcotest.check cached_r "cache with A results in res"
    (Ok (`Entry a, cache))
    (Udns_resolver_cache.cached cache 0L Rr.A name) ;
  Alcotest.check cached_r "cache with A results in CacheMiss"
    (Error `Cache_miss)
    (Udns_resolver_cache.cached cache 0L Rr.CNAME name)

let cache_cname () =
  let rel = name "bar.com" in
  let name = name "foo.com" in
  let cname = 250l, rel in
  let cache = Udns_resolver_cache.maybe_insert Rr.CNAME name 0L AuthoritativeAnswer (`Alias cname) empty in
  Alcotest.check cached_r "cache with CNAME results in res"
    (Ok (`Alias cname, cache))
    (Udns_resolver_cache.cached cache 0L Rr.CNAME name) ;
  Alcotest.check cached_r "cache with CNAME results in res for A"
    (Ok (`Alias cname, cache))
    (Udns_resolver_cache.cached cache 0L Rr.A name) ;
  Alcotest.check cached_r "cache with CNAME results in res for NS"
    (Ok (`Alias cname, cache))
    (Udns_resolver_cache.cached cache 0L Rr.NS name)

let cache_cname_nodata () =
  let rel = name "bar.com" in
  let name = name "foo.com" in
  let cname = 250l, rel in
  let bad_soa = invalid_soa name in
  let cache =
    Udns_resolver_cache.maybe_insert Rr.CNAME name 0L AuthoritativeAnswer (`Alias cname)
      (Udns_resolver_cache.maybe_insert Rr.NS name 0L AuthoritativeAnswer (`No_data (name, bad_soa))
         empty)
  in
  Alcotest.check cached_r "cache with CNAME results in res"
    (Ok (`Alias cname, cache))
    (Udns_resolver_cache.cached cache 0L Rr.CNAME name) ;
  Alcotest.check cached_r "cache with CNAME results in res for NS"
    (Ok (`Alias cname, cache))
    (Udns_resolver_cache.cached cache 0L Rr.NS name) ;
  Alcotest.check cached_r "cache with CNAME results in res for A"
    (Ok (`Alias cname, cache))
    (Udns_resolver_cache.cached cache 0L Rr.A name)

let cache_tests = [
  "empty cache", `Quick, empty_cache ;
  "cache with A", `Quick, cache_a ;
  "cache with CNAME", `Quick, cache_cname ;
  "cache with another cname", `Quick, cache_cname_nodata ;
]

let typ =
  let module M = struct
    type t = Rr.t
    let pp = Rr.pp
    let equal a b = Rr.compare a b = 0
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
    type t = (Rr.t * Domain_name.t * Udns_resolver_cache.rank * Udns_resolver_cache.res) list
    let pp ppf xs =
      let pp_elem ppf (t, n, r, e) =
        Fmt.pf ppf "%a %a (%a): %a" Domain_name.pp n Rr.pp t Udns_resolver_cache.pp_rank r Udns_resolver_cache.pp_res e
      in
      Fmt.pf ppf "%a" Fmt.(list ~sep:(unit ";@,") pp_elem) xs
    let equal a a' =
      let eq (t, n, r, e) (t', n', r', e') =
        Domain_name.equal n n' && t = t' &&
        Udns_resolver_cache.compare_rank r r' = 0 &&
        res_eq e e'
      in
      List.length a = List.length a' &&
      List.for_all (fun e -> List.exists (eq e) a') a
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let rcode =
  let module M = struct
    type t = Rcode.t
    let pp = Rcode.pp
    let equal a b = Rcode.compare a b = 0
  end in
  (module M: Alcotest.TESTABLE with type t = M.t)

let res = Alcotest.(result res rcode)

let header = (0, Packet.Flags.empty)

let scrub_empty () =
  let name = name "foo.com" in
  let q = (name, Rr.A) in
  let dns = Packet.create header q (`Answer Packet.Query.empty) in
  let bad_soa = invalid_soa name in
  Alcotest.check res "empty frame results in empty scrub"
    (Ok [ Rr.A, name, Additional, `No_data (name, bad_soa) ])
    (Udns_resolver_utils.scrub name dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer Packet.Query.empty) in
  Alcotest.check res "empty authoritative frame results in empty scrub"
    (Ok [ Rr.A, name, Additional, `No_data (name, bad_soa) ])
    (Udns_resolver_utils.scrub name dns')

let scrub_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let b = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4")))) in
  let answer = Domain_name.Map.singleton q_name Rr_map.(addb b empty) in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "A record results in scrubbed A"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry b])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative A record results in scrubbed A"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry b])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let b = Rr_map.(B (A, (1l, Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.5")))))) in
  let answer = Domain_name.Map.singleton q_name Rr_map.(addb b empty) in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "A records results in scrubbed A with same records"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry b ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative A records results in scrubbed A with same records"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry b ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_cname () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let cname = (1l, name "bar.com") in
  let b = Rr_map.(B (Cname, cname)) in
  let answer = Domain_name.Map.singleton q_name Rr_map.(addb b empty) in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "CNAME record results in scrubbed CNAME with same record"
    (Ok [ Rr.CNAME, q_name, NonAuthoritativeAnswer, `Alias cname])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative CNAME record results in scrubbed CNAME with same record"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias cname])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_soa () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let soa = {
    Soa.nameserver = name "a" ; hostmaster = name "b" ;
    serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
  } in
  let b = Rr_map.(B (Soa, soa)) in
  let authority = Domain_name.Map.singleton q_name Rr_map.(addb b empty) in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "SOA record results in NoData SOA"
    (Ok [ Rr.A, q_name, Additional, `No_data (q_name, soa) ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative SOA record results in NoData SOA"
    (Ok [ Rr.A, q_name, AuthoritativeAuthority, `No_data (q_name, soa) ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_bad_soa () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let soa = {
    Soa.nameserver = name "a" ; hostmaster = name "b" ;
    serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
  } in
  let b = Rr_map.(B (Soa, soa)) in
  let authority = Domain_name.Map.singleton (name "bar.com") Rr_map.(addb b empty) in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  let bad_soa = invalid_soa q_name in
  Alcotest.check res "bad SOA record results in NoData SOA"
    (Ok [ Rr.A, q_name, Additional, `No_data (q_name, bad_soa) ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative bad SOA record results in NoData SOA"
    (Ok [ Rr.A, q_name, Additional, `No_data (q_name, bad_soa) ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_soa_super () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let soa = {
    Soa.nameserver = name "a" ; hostmaster = name "b" ;
    serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
  } in
  let b = Rr_map.(B (Soa, soa)) in
  let authority = Domain_name.Map.singleton (name "com") Rr_map.(addb b empty) in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "SOA record results in NoData SOA"
    (Ok [ Rr.A, q_name, Additional, `No_data (name "com", soa) ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative SOA record results in NoData SOA"
    (Ok [ Rr.A, q_name, AuthoritativeAuthority, `No_data (name "com", soa) ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_cname_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let alias = (1l, name "bar.com")
  and a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let answer =
    let an = Domain_name.Map.singleton q_name
        Rr_map.(addb Rr_map.(B (Cname, alias)) (addb a empty)) in
    `Answer (an, Name_rr_map.empty)
  in
  let dns = Packet.create header q answer in
  Alcotest.check res "CNAME and A record results in the A record :"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let dns' = Packet.create header (q_name, Rr.CNAME) answer in
  Alcotest.check res "CNAME and A record, asking for CNAME results in the cname record :"
    (Ok [ Rr.CNAME, q_name, NonAuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns') ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create hdr q answer in
  Alcotest.check res "authoritative CNAME and A record results in the A record"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns');
  let dns' = Packet.create hdr (q_name, Rr.CNAME) answer in
  Alcotest.check res "authoritative CNAME and A record, asking for CNAME, results in the CNAME record"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_authority_ns () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let ns = Rr_map.B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))) in
  let authority =
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty)
  in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "NS in authority results in NoData foo.com and NoErr NS"
    (Ok [ Rr.NS, q_name, Additional, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative NS in authority results in NoData foo.com and NoErr NS"
    (Ok [ Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_authority_ns () =
  let q_name = name "foo.com" in
  let q = q_name, Rr.A in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  in
  let answer, authority =
    Domain_name.Map.singleton q_name Rr_map.(addb a empty),
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty)
  in
  let dns = Packet.create header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, and A in answer results in NoErr foo.com and NoErr NS"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, Additional, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, and A in answer results in NoErr foo.com and NoErr NS"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_authority_ns_add_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  in
  let answer, authority, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb a empty),
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.singleton (name "ns1.foo.com") Rr_map.(addb a empty)
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, glue in additional results in NoErr foo.com, NoErr NS, NoErr ns1.foo.com A"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, Additional, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, glue in additional results in NoErr foo.com, NoErr NS, NoErr ns1.foo.com A"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_authority_ns_bad_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  in
  let answer, authority, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb a empty),
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.singleton (name "ns2.foo.com") Rr_map.(addb a empty)
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, crap in additional results in NoErr foo.com and NoErr NS"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, Additional, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, crap in additional results in NoErr foo.com and NoErr NS"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_authority_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and a' = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.5"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  in
  let answer, authority, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb a empty),
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.singleton (name "ns1.foo.com") Rr_map.(addb a' (addb a empty))
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, Additional, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a' ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a' ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_authority_ns_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and a' = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.5"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.(add (name "ns2.foo.com") (singleton (name "ns1.foo.com"))))))
  in
  let answer, authority, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb a empty),
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.add (name "ns1.foo.com") Rr_map.(addb a empty)
      (Domain_name.Map.singleton (name "ns2.foo.com") Rr_map.(addb a' empty))
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, Additional, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ;
          Rr.A, name "ns2.foo.com", Additional, `Entry a' ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ;
          Rr.A, name "ns2.foo.com", Additional, `Entry a' ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_authority_ns_bad_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and a' = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.5"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and ns' = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns2.foo.com"))))
  in
  let answer, additional =
    `Answer (Domain_name.Map.singleton q_name Rr_map.(addb a empty),
             Domain_name.Map.add q_name Rr_map.(addb ns empty)
               (Domain_name.Map.singleton (name "com") Rr_map.(addb ns' empty))),
    Domain_name.Map.add (name "ns1.foo.com") Rr_map.(addb a empty)
      (Domain_name.Map.singleton (name "ns2.foo.com") Rr_map.(addb a' empty))
  in
  let dns = Packet.create ~additional header q answer in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, Additional, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q answer in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_authority_ns_add_a_bad () =
  let q_name = name "foo.com" in
  let q = (q_name, Rr.A) in
  let ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and ns' = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns3.foo.com"))))
  and a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let authority, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.add (name "ns1.foo.com") Rr_map.(addb a empty)
      (Domain_name.Map.singleton (name "ns1.foo.com") Rr_map.(addb ns' empty))
  in
  let dns = Packet.create ~additional header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "NS in authority, A and NS in additional results in NoErr NS, NoErr As"
    (Ok [ Rr.NS, q_name, Additional, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative NS in authority, A and NS in additional results in NoErr NS, NoErr As"
    (Ok [ Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_authority_ns_add_a_aaaa () =
  let q_name = name "foo.com" in
  let q = q_name, Rr.A in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and aaaa = Rr_map.(B (Aaaa, (1l, Ipv6_set.singleton (ip6 "::1"))))
  in
  let authority, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.singleton (name "ns1.foo.com") Rr_map.(addb a (addb aaaa empty))
  in
  let dns = Packet.create ~additional header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "NS in authority, A and AAAA in additional results in NoErr NS, NoErr A, NoErr AAAA"
    (Ok [ Rr.NS, q_name, Additional, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ;
          Rr.AAAA, name "ns1.foo.com", Additional, `Entry aaaa ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative NS in authority, A and AAAA in additional results in NoErr NS, NoErr A, NoErr AAAA"
    (Ok [ Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ;
          Rr.A, name "ns1.foo.com", Additional, `Entry a ;
          Rr.AAAA, name "ns1.foo.com", Additional, `Entry aaaa ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_a_authority_ns_a () =
  let q_name = name "foo.com" in
  let q = q_name, Rr.A in
  let a = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and a' = Rr_map.(B (A, (1l, Ipv4_set.singleton (ip "1.2.3.5"))))
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  in
  let answer =
    `Answer (Domain_name.Map.singleton q_name Rr_map.(addb a empty),
             Domain_name.Map.singleton q_name Rr_map.(addb ns (addb a' empty)))
  in
  let dns = Packet.create header q answer in
  Alcotest.check res "NS and crap in authority, A in answer results in NoErr foo.com, NoErr NS"
    (Ok [ Rr.A, q_name, NonAuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, Additional, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create hdr q answer in
  Alcotest.check res "authoritative NS and crap in authority, A in answer results in NoErr foo.com, NoErr NS"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_bad_packets () =
  let q_name = name "foo.com" in
  let q = q_name, Rr.A in
  let answer =
    Domain_name.Map.singleton (name "bar.com")
      Rr_map.(singleton A (1l, (Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "No results in scrubbed A with bad A"
    (Ok [ Rr.A, q_name, Additional, `No_data (q_name, invalid_soa q_name)])
    (Udns_resolver_utils.scrub q_name dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative no results in scrubbed A with bad A"
    (Ok [ Rr.A, q_name, Additional, `No_data (q_name, invalid_soa q_name)])
    (Udns_resolver_utils.scrub q_name dns')

let scrub_rfc2308_2_1 () =
  let q_name = name "an.example" in
  let q = q_name, Rr.A in
  let soa = {
    Soa.nameserver = name "ns1.xx" ; hostmaster = name "hostmaster.ns1.xx" ;
    serial = 1l ; refresh = 1l ; retry = 2l ; expiry = 3l ; minimum = 4l
  }
  and ns = Rr_map.(B (Ns, (1l, Domain_name.Set.(add (name "ns1.xx") (singleton (name "ns2.xx"))))))
  and alias = 1l, name "tripple.xx"
  and additional =
    Domain_name.Map.add (name "ns1.xx") Rr_map.(singleton A (1l, Ipv4_set.singleton (ip "127.0.0.2")))
      (Domain_name.Map.singleton (name "ns2.xx") Rr_map.(singleton A (1l, Ipv4_set.singleton (ip "127.0.0.3"))))
  in
  let answer = Domain_name.Map.singleton q_name Rr_map.(singleton Cname alias)
  and authority =
    Domain_name.Map.singleton (name "xx") Rr_map.(addb (B (Soa, soa)) (addb ns empty))
  in
  let dns = Packet.create ~additional header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, authority))) in
  (* considering what is valid in the response, it turns out only the cname is *)
  Alcotest.check res "Sec 2.1 type 1"
    (Ok [ Rr.CNAME, q_name, NonAuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let authority = Domain_name.Map.singleton (name "xx") Rr_map.(addb (B (Soa, soa)) empty) in
  let dns = Packet.create header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, authority))) in
  Alcotest.check res "Sec 2.1 type 2"
    (Ok [ Rr.CNAME, q_name, NonAuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let dns = Packet.create header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, Name_rr_map.empty))) in
  Alcotest.check res "Sec 2.1 type 3"
    (Ok [ Rr.CNAME, q_name, NonAuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let authority = Domain_name.Map.singleton (name "xx") Rr_map.(addb ns empty) in
  let dns = Packet.create ~additional header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, authority))) in
  Alcotest.check res "Sec 2.1 type 4"
    (Ok [ Rr.CNAME, q_name, NonAuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "Sec 2.1 type referral response"
    (Ok [ Rr.CNAME, q_name, NonAuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns)


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
  let q = (q_name, Rr.A) in
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let a = Rr_map.(B (A, (300l, Ipv4_set.singleton (ip "1.2.3.4")))) in
  let answer = `Answer (Domain_name.Map.add q_name Rr_map.(addb a empty)
                          (Domain_name.Map.singleton (name "bar") Rr_map.(addb a empty)),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "additional A records"
    (Ok [ Rr.A, q_name, AuthoritativeAnswer, `Entry a ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let alias = 300l, name "bar" in
  let answer = `Answer (Domain_name.Map.add q_name Rr_map.(singleton Cname alias)
                          (Domain_name.Map.singleton (name "bar") Rr_map.(addb a empty)),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "A and CNAME record"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let ns = Rr_map.(B (Ns, (300l, Domain_name.Set.singleton (name "boo")))) in
  let answer = `Answer (Domain_name.Map.add q_name Rr_map.(singleton Cname alias)
                          (Domain_name.Map.singleton (name "bar") Rr_map.(addb ns empty)),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and NS record in answer"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let answer = `Answer (Domain_name.Map.singleton q_name Rr_map.(singleton Cname alias),
                        Domain_name.Map.singleton q_name Rr_map.(addb ns empty))
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and NS record in authority"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let answer = `Answer (Domain_name.Map.add q_name Rr_map.(singleton Cname alias)
                          (Domain_name.Map.singleton (name "foobar") Rr_map.(addb ns empty)),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and unrelated NS record in answer"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let answer = `Answer (Domain_name.Map.singleton q_name Rr_map.(singleton Cname alias),
                        Domain_name.Map.singleton (name "foobar") Rr_map.(addb ns empty))
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and unrelated NS record in authority"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let answer = `Answer (Domain_name.Map.singleton q_name Rr_map.(singleton Cname alias),
                        Name_rr_map.empty)
  in
  let additional = Domain_name.Map.singleton (name "bar") Rr_map.(addb a empty) in
  let dns = Packet.create ~additional hdr q answer in
  Alcotest.check res "CNAME and glue record in additional"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let answer = `Answer (Domain_name.Map.singleton q_name Rr_map.(singleton Cname alias),
                        Domain_name.Map.singleton q_name Rr_map.(addb ns empty))
  in
  let additional = Domain_name.Map.singleton (name "boo") Rr_map.(addb a empty) in
  let dns = Packet.create ~additional hdr q answer in
  Alcotest.check res "CNAME and glue record in additional"
    (Ok [ Rr.CNAME, q_name, AuthoritativeAnswer, `Alias alias ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns)


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
  let q = (q_name, Rr.MX) in
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let mx = Rr_map.(B (Mx, (300l, Mx_set.singleton { Mx.preference = 10 ; mail_exchange = name "bar" } )))
  and a = Rr_map.(B (A, (300l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let mx_a = Domain_name.Map.singleton q_name Rr_map.(addb a (addb mx empty)) in
  let dns = Packet.create hdr q (`Answer (mx_a, Name_rr_map.empty)) in
  Alcotest.check res "additional A record"
    (Ok [ Rr.MX, q_name, AuthoritativeAnswer, `Entry mx ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let mx_mx =
    Domain_name.Map.add q_name Rr_map.(addb a (addb mx empty))
      (Domain_name.Map.singleton (name "bar") Rr_map.(addb mx empty))
  in
  let dns = Packet.create hdr q (`Answer (mx_mx, Name_rr_map.empty)) in
  Alcotest.check res "additional MX records"
    (Ok [ Rr.MX, q_name, AuthoritativeAnswer, `Entry mx ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let mx_amx =
    Domain_name.Map.add q_name Rr_map.(addb a (addb mx empty))
      (Domain_name.Map.singleton (name "bar") Rr_map.(addb a empty))
  in
  let dns = Packet.create hdr q (`Answer (mx_amx, Name_rr_map.empty)) in
  Alcotest.check res "MX record and an A record"
    (Ok [ Rr.MX, q_name, AuthoritativeAnswer, `Entry mx ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let mx', additional =
    Domain_name.Map.singleton q_name Rr_map.(addb a (addb mx empty)),
    Domain_name.Map.singleton (name "bar") Rr_map.(addb a empty)
  in
  let dns = Packet.create ~additional hdr q (`Answer (mx', Name_rr_map.empty)) in
  Alcotest.check res "MX record and additional A record"
    (Ok [ Rr.MX, q_name, AuthoritativeAnswer, `Entry mx ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let ns = Rr_map.(B (Ns, (300l, Domain_name.Set.singleton (name "foobar")))) in
  let mx_au, additional =
    (Domain_name.Map.singleton q_name Rr_map.(addb mx empty),
     Domain_name.Map.singleton q_name Rr_map.(addb ns empty)),
    Domain_name.Map.add (name "bar") Rr_map.(addb a empty)
      (Domain_name.Map.singleton (name "foobar") Rr_map.(addb a empty))
  in
  let dns = Packet.create ~additional hdr q (`Answer mx_au) in
  Alcotest.check res "MX record and authority and additional A record"
    (Ok [ Rr.MX, q_name, AuthoritativeAnswer, `Entry mx ;
          Rr.NS, q_name, AuthoritativeAuthority, `Entry ns ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let mx_au' =
    (Domain_name.Map.singleton q_name Rr_map.(addb mx empty),
     Domain_name.Map.singleton (name "bar") Rr_map.(addb ns empty))
  in
  let dns = Packet.create ~additional hdr q (`Answer mx_au') in
  Alcotest.check res "MX record and bad authority and additional A record"
    (Ok [ Rr.MX, q_name, AuthoritativeAnswer, `Entry mx ])
     (Udns_resolver_utils.scrub q_name dns)

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
  let q = q_name, Rr.NS in
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let ns = Rr_map.(B (Ns, (300l, Domain_name.Set.singleton (name "bar"))))
  and a = Rr_map.(B (A, (300l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let answer = Rr.NS, q_name, Udns_resolver_cache.AuthoritativeAnswer, `Entry ns in
  let data = Domain_name.Map.singleton q_name Rr_map.(addb ns (addb a empty)) in
  let dns = Packet.create hdr q (`Answer (data, Name_rr_map.empty)) in
  (* fail atm - get NS and A *)
  Alcotest.check res "additional A record"
    (Ok [ answer ]) (Udns_resolver_utils.scrub q_name dns) ;
  let data =
    Domain_name.Map.add q_name Rr_map.(addb ns empty)
      (Domain_name.Map.singleton (name "bar") Rr_map.(addb ns empty))
  in
  let dns = Packet.create hdr q (`Answer (data, Name_rr_map.empty)) in
  Alcotest.check res "additional NS records"
    (Ok [ answer ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let data =
    Domain_name.Map.add q_name Rr_map.(addb ns empty)
      (Domain_name.Map.singleton (name "bar") Rr_map.(addb a empty))
  in
  let dns = Packet.create hdr q (`Answer (data, Name_rr_map.empty)) in
  Alcotest.check res "NS record and an A record"
    (Ok [ answer ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let data, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.singleton q_name Rr_map.(addb a empty)
  in
  let dns = Packet.create ~additional hdr q (`Answer (data, Name_rr_map.empty)) in
  (* should glue be respected? don't think it's worth it *)
  Alcotest.check res "NS record and additional A record"
    (Ok [ answer ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let data, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.singleton (name "bar") Rr_map.(addb a empty)
  in
  let dns = Packet.create ~additional hdr q (`Answer (data, Name_rr_map.empty)) in
  Alcotest.check res "NS record and additional A record with NS name"
    (Ok [ answer ])
    (Udns_resolver_utils.scrub q_name dns) ;
  let ns' = Rr_map.(B (Ns, (300l, Domain_name.Set.singleton (name "foobar")))) in
  let data, au, additional =
    Domain_name.Map.singleton q_name Rr_map.(addb ns empty),
    Domain_name.Map.singleton q_name Rr_map.(addb ns' empty),
    Domain_name.Map.add (name "bar") Rr_map.(addb a empty)
      (Domain_name.Map.singleton (name "foobar") Rr_map.(addb a empty))
  in
  let dns = Packet.create ~additional hdr q (`Answer (data, au)) in
  let answer' = [
    answer ;
    Rr.NS, q_name, AuthoritativeAuthority, `Entry ns' ]
  in
  Alcotest.check res "NS record and authority and additional A record"
    (Ok answer')
    (Udns_resolver_utils.scrub q_name dns) ;
  let au' =
    Domain_name.Map.singleton (name "bar") Rr_map.(addb ns' empty)
  in
  let dns = Packet.create ~additional hdr q (`Answer (data, au')) in
  Alcotest.check res "NS record and bad authority and additional A record"
    (Ok [ answer ])
     (Udns_resolver_utils.scrub q_name dns)

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
(*  "resolve_ns", resolve_ns_tests ;
    "find_ns", find_ns_tests ; *)
  (*  "resolve", resolve_tests ;*)
  "cache", cache_tests ;
  "scrub", scrub_tests ;
]

let () = Alcotest.run "DNS resolver tests" tests
