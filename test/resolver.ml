(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

let empty = Dns_resolver_cache.empty 100

let ip = Ipaddr.V4.of_string_exn
let ip6 = Ipaddr.V6.of_string_exn
let name = Domain_name.of_string_exn
let sec = Duration.of_sec

let invalid_soa = Dns_resolver_utils.invalid_soa

let root_servers = snd (List.split Dns_resolver_root.root_servers)
let a_root = List.hd root_servers

let rng i = Cstruct.create i

let follow_res =
  let module M = struct
    type t =
      [ `Out of Rcode.t * Name_rr_map.t * Name_rr_map.t * Dns_resolver_cache.t
      | `Query of [ `raw ] Domain_name.t * Dns_resolver_cache.t
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
  let cname = 250l, name "foo.com" in
  let circ_map = Name_rr_map.singleton (name "foo.com") Cname cname in
  let cache =
    Dns_cache.set empty 0L (name "foo.com") A AuthoritativeAnswer
      (`Entry (B (Cname, cname)))
  in
  Alcotest.check follow_res "CNAME single cycle is detected"
    (`Out (Rcode.NoError, circ_map, Name_rr_map.empty, cache))
    (Dns_resolver_cache.follow_cname cache 0L A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"));
  Alcotest.check follow_res "CNAME single cycle after timeout errors"
    (`Query (name "foo.com", cache))
    (Dns_resolver_cache.follow_cname cache (sec 251) A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"));
  let a = 250l, name "bar.com"
  and b = 500l, name "foo.com"
  in
  let cache =
    Dns_cache.set
      (Dns_cache.set empty 0L (name "bar.com") A
         AuthoritativeAnswer (`Entry (B (Cname, b))))
      0L (name "foo.com") A AuthoritativeAnswer (`Entry (B (Cname, a)))
  in
  let c_map =
    Name_rr_map.add (name "bar.com") Cname b
      (Name_rr_map.singleton (name "foo.com") Cname a)
  in
  Alcotest.check follow_res "CNAME cycle is detected"
    (`Out (Rcode.NoError, c_map, Name_rr_map.empty, cache))
    (Dns_resolver_cache.follow_cname cache 0L A
       ~name:(name "bar.com") 250l ~alias:(name "foo.com"));
  Alcotest.check follow_res "Query foo.com (since it timed out)"
    (`Query (name "foo.com", cache))
    (Dns_resolver_cache.follow_cname cache (sec 251) A
       ~name:(name "bar.com") 250l ~alias:(name "foo.com"))

let follow_cname_tests = [
  "follow_cname cycles", `Quick, follow_cname_cycle ;
]
(*
let resolve_ns_ret =
  let module M = struct
    type t = [ `NeedA of Domain_name.t | `NeedCname of Domain_name.t | `HaveIPS of Rr_map.Ipv4_set.t | `No | `NoDom ] * Dns_resolver_cache.t
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
              (Dns_resolver_cache.resolve_ns empty 0L (name "foo.com")))

let resolve_ns_cname () =
  let cname = Rr_map.(B (Cname, (250l, name "bar.com"))) in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.A (name "foo.com") 0L AuthoritativeAnswer (NoErr cname) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with CNAME returns needA"
              (`NeedCname (name "bar.com"), cache)
              (Dns_resolver_cache.resolve_ns cache 0L (name "foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired CNAME returns needA"
              (`NeedA (name "foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache (sec 251) (name "foo.com")))

let resolve_ns_noerr_aaaa () =
  let aaaa = Rr_map.(B (Aaaa, (250l, Ipv6_set.singleton (ip6 "::1")))) in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.AAAA (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr aaaa) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with AAAA returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired AAAA returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache (sec 251) (name "ns1.foo.com")))

let resolve_ns_a () =
  let a_rr = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4")))) in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a_rr) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with A returns haveIP"
              (`HaveIPS (Rr_map.Ipv4_set.singleton (ip "1.2.3.4")), cache)
              (Dns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with A returns NeedA after timeout"
              (`NeedA (name "ns1.foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache (sec 251) (name "ns1.foo.com")))

let resolve_ns_as () =
  let a_rrs = Rr_map.(B (A, (250l, Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.5")))))) in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a_rrs) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with multiple A returns all IPs"
              (`HaveIPS Rr_map.Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.5"))), cache)
              (Dns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with multiple A after TTL expired for all returns NeedA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache (sec 251) (name "ns1.foo.com")))

(* TODO: not sure whether the semantics is correct... now no more any errors
   from resolve_ns, no more result type *)
let resolve_ns_bad () =
  let (name_soa, bad_soa) = invalid_soa (name "ns1.foo.com") in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoData (name_soa, bad_soa)) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodata returns needa"
              (`No, cache)
              (Dns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired nodata returns NeedA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache (sec 301) (name "ns1.foo.com"))) ;
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoDom (name_soa, bad_soa)) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodom returns error"
              (`NoDom, cache)
              (Dns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with nodom returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache (sec 301) (name "ns1.foo.com"))) ;
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail (name_soa, bad_soa)) empty in
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with servfail returns error"
              (`No, cache)
              (Dns_resolver_cache.resolve_ns cache 0L (name "ns1.foo.com"))) ;
  Alcotest.(check resolve_ns_ret
              "looking for NS in cache with expired servfail returns needA"
              (`NeedA (name "ns1.foo.com"), cache)
              (Dns_resolver_cache.resolve_ns cache (sec 301) (name "ns1.foo.com")))

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
    (`NeedNS, empty) (Dns_resolver_cache.find_ns empty rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in empty cache for root `NeedNS"
    (`NeedNS, empty) (Dns_resolver_cache.find_ns empty rng 0L eds Domain_name.root)

let with_root =
  let cache =
    List.fold_left (fun cache (name, b) ->
        Dns_resolver_cache.maybe_insert
          Dns_enum.A name 0L Dns_resolver_entry.Additional
          (Dns_resolver_entry.NoErr b) cache)
      empty Dns_resolver_root.a_records
  in
  Dns_resolver_cache.maybe_insert
    Dns_enum.NS Domain_name.root 0L Dns_resolver_entry.Additional
    (Dns_resolver_entry.NoErr Dns_resolver_root.ns_records) cache

let find_ns_prefilled () =
  Alcotest.check find_ns_ret "looking for NS in empty cache `NeedNS"
    (`NeedNS, empty) (Dns_resolver_cache.find_ns with_root rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in empty cache for root `HaveIP"
    (`HaveIP a_root, empty)
    (Dns_resolver_cache.find_ns with_root rng 0L eds Domain_name.root)

let find_ns_cname () =
  let cname = Rr_map.(B (Cname, (250l, name "bar.com"))) in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr cname) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with CNAME returns cname"
    (`Cname (name "bar.com"), cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com"))

let find_ns_bad () =
  let (bad_name, bad_rr) = invalid_soa (name "foo.com") in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoData (bad_name, bad_rr)) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with nodata returns No"
    (`No, cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired nodata returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 301) eds (name "foo.com")) ;
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoDom (bad_name, bad_rr)) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with nodom returns No"
    (`No, cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired nodom returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 301) eds (name "foo.com")) ;
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_rr)) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with servfail returns no"
    (`No, cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired servfail returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 301) eds (name "foo.com"))

let find_ns_ns () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com")))) in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns) empty in
  Alcotest.check find_ns_ret "looking for NS in cache with NS returns NeedA"
    (`NeedGlue (name "foo.com"), cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (2500l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A and NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS and A returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a_exp () =
  let ns = Rr_map.(B (Ns, (2500l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A and NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A and NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Dns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_a_a_exp () =
  let ns =
    Rr_map.(B (Ns, (250l, Domain_name.Set.(add (name "ns1.foo.com") (singleton (name "ns2.foo.com"))))))
  and a1 =
    Rr_map.(B (A, (150l, Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.2"))))))
  and a2 =
    Rr_map.(B (A, (200l, Ipv4_set.singleton (ip "1.2.3.5"))))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a1)
         (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns2.foo.com") 0L AuthoritativeAnswer (NoErr a2)
            empty))
  in
  Alcotest.check find_ns_ret "looking for NS in cache with A, A and NS, NS returns HaveIP"
    (`HaveIP (ip "1.2.3.4"), cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A and A, NS, NS returns HaveIP"
    (`HaveIP (ip "1.2.3.5"), cache) (Dns_resolver_cache.find_ns cache rng (sec 151) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns Needglue foo.com"
    (`NeedGlue (name "foo.com"), cache) (Dns_resolver_cache.find_ns cache rng (sec 201) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Dns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired A, A, NS, NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Dns_resolver_cache.find_ns cache rng (sec 2001) eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 2501) eds (name "foo.com"))

let find_ns_ns_and_cname () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and cname = Rr_map.(B (Cname, (2500l, name "ns1.bar.com")))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr cname) empty)
  in
  (* TODO this is a bad cache entry, not sure whether this behaviour is good (following cnames) *)
  Alcotest.check find_ns_ret "looking for NS in cache with CNAME and NS returns NeedGlue"
    (`NeedA (name "ns1.bar.com"), cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired CNAME and NS returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

let find_ns_ns_and_aaaa () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and aaaa = Rr_map.(B (Aaaa, (2500l, Ipv6_set.singleton (ip6 "::1"))))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.AAAA (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr aaaa) empty)
  in
  Alcotest.check find_ns_ret "looking for NS in cache with AAAA and NS returns NeedGlue"
    (`NeedGlue (name "foo.com"), cache) (Dns_resolver_cache.find_ns cache rng 0L eds (name "foo.com")) ;
  Alcotest.check find_ns_ret "looking for NS in cache with expired NS and AAAA returns NeedNS"
    (`NeedNS, cache) (Dns_resolver_cache.find_ns cache rng (sec 251) eds (name "foo.com"))

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

let resolve ~rng a b c d = match Dns_resolver_cache.resolve ~rng a b c d with
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
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.org"))))
  in
  let cache = Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns) with_root in
  Alcotest.check resolve_res "looking for A for foo.com asks for NS org"
    (Ok (name "org", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A)

let resolve_with_ns_err () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and (bad_name, bad_soa) = invalid_soa (name "ns1.foo.com")
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoData (bad_name, bad_soa))
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com NoData requests NS foo.com"
    (Ok (name "foo.com", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoDom (bad_name, bad_soa))
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com NoDom errors"
    (Error "")
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_soa))
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com with com NS ns1.foo.com, ns1.foo.com ServFail requests NS foo.com"
    (Ok (name "foo.com", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_soa))
         (Dns_resolver_cache.maybe_insert Dns_enum.A (name "com") 0L AuthoritativeAnswer (ServFail (bad_name, bad_soa))
            with_root))
  in
  (* TODO: correctness? should request NS for .com! *)
  Alcotest.check resolve_res "looking for A com with com NS ns1.foo.com, ns1.foo.com ServFail, com A ServFail asks for A foo.com"
    (Ok (name "com", Dns_enum.A, a_root, cache))
    (resolve ~rng cache 0L (name "com") Dns_enum.A)

let resolve_with_ns_a () =
  let ns = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a)
         with_root)
  in
  Alcotest.check resolve_res "looking for A for foo.com asks for NS foo.com @ns1.foo.com"
    (Ok (name "foo.com", Dns_enum.NS, ip "1.2.3.4", cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A)

let resolve_with_ns_a_ns () =
  let ns = Rr_map.(B (Ns, (2500l, Domain_name.Set.singleton (name "ns1.foo.com"))))
  and a = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.4"))))
  and ns2 = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns2.foo.com"))))
  and a2 = Rr_map.(B (A, (250l, Ipv4_set.singleton (ip "1.2.3.5"))))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns1.foo.com") 0L AuthoritativeAnswer (NoErr a)
         (Dns_resolver_cache.maybe_insert Dns_enum.NS (name "foo.com") 0L AuthoritativeAnswer (NoErr ns2)
            (Dns_resolver_cache.maybe_insert Dns_enum.A (name "ns2.foo.com") 0L AuthoritativeAnswer (NoErr a2)
               with_root)))
  in
  Alcotest.check resolve_res "looking for A for foo.com asks for A foo.com @ns1.foo.com"
    (Ok (name "foo.com", Dns_enum.A, ip "1.2.3.5", cache))
    (resolve ~rng cache 0L (name "foo.com") Dns_enum.A) ;
  Alcotest.check resolve_res "looking for A after TTL for foo.com asks NS .com @a_root"
    (Ok (name "com", Dns_enum.NS, a_root, cache))
    (resolve ~rng cache (sec 251) (name "foo.com") Dns_enum.A)

let resolve_cycle () =
  let ns = Rr_map.(B (Ns, (2500l, Domain_name.Set.singleton (name "ns1.org"))))
  and ns2 = Rr_map.(B (Ns, (250l, Domain_name.Set.singleton (name "ns1.com"))))
  in
  let cache =
    Dns_resolver_cache.maybe_insert Dns_enum.NS (name "com") 0L AuthoritativeAnswer (NoErr ns)
      (Dns_resolver_cache.maybe_insert Dns_enum.NS (name "org") 0L AuthoritativeAnswer (NoErr ns2)
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
*)

let entry_eq a b =
  match a, b with
  | `Entry b, `Entry b' -> Rr_map.equalb b b'
  | `No_data (name, soa), `No_data (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | `No_domain (name, soa), `No_domain (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | `Serv_fail (name, soa), `Serv_fail (name', soa') -> Domain_name.equal name name' && Dns.Soa.compare soa soa' = 0
  | _, _ -> false

(* once again the complete thingy since I don't care about list ordering (Alcotest.list is order-enforcing) *)
let res =
  let module M = struct
    type t = (Rr_map.k * [ `raw ] Domain_name.t * Dns_cache.rank * Dns_cache.entry) list
    let pp ppf xs =
      let pp_elem ppf (t, n, r, e) =
        Fmt.pf ppf "%a %a (%a): %a" Domain_name.pp n Rr_map.ppk t Dns_cache.pp_rank r Dns_cache.pp_entry e
      in
      Fmt.pf ppf "%a" Fmt.(list ~sep:(unit ";@,") pp_elem) xs
    let equal a a' =
      let eq (t, n, r, e) (t', n', r', e') =
        Domain_name.equal n n' && t = t' &&
        Dns_cache.compare_rank r r' = 0 &&
        entry_eq e e'
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
  let q = name, `K (Rr_map.K A) in
  let dns = Packet.create header q (`Answer Packet.Answer.empty) in
  let bad_soa = invalid_soa name in
  Alcotest.check res "empty frame results in empty scrub"
    (Ok [ K A, name, Additional, `No_data (name, bad_soa) ])
    (Dns_resolver_utils.scrub name (snd q) dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer Packet.Answer.empty) in
  Alcotest.check res "empty authoritative frame results in empty scrub"
    (Ok [ K A, name, Additional, `No_data (name, bad_soa) ])
    (Dns_resolver_utils.scrub name (snd q) dns')

let scrub_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4") in
  let answer = Name_rr_map.singleton q_name A a in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "A record results in scrubbed A"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a))])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative A record results in scrubbed A"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.(add (ip "1.2.3.4") (singleton (ip "1.2.3.5"))) in
  let answer = Name_rr_map.singleton q_name A a in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "A records results in scrubbed A with same records"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative A records results in scrubbed A with same records"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_cname () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let cname = (1l, name "bar.com") in
  let answer = Name_rr_map.singleton q_name Cname cname in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "CNAME record results in scrubbed CNAME with same record"
    (Ok [ K Cname, q_name, NonAuthoritativeAnswer, `Entry (Rr_map.B (Cname, cname)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative CNAME record results in scrubbed CNAME with same record"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (Rr_map.B (Cname, cname))])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_soa () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let soa = {
    Soa.nameserver = name "a" ; hostmaster = name "b" ;
    serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
  } in
  let authority = Name_rr_map.singleton q_name Soa soa in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "SOA record results in NoData SOA"
    (Ok [ K A, q_name, Additional, `No_data (q_name, soa) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative SOA record results in NoData SOA"
    (Ok [ K A, q_name, AuthoritativeAuthority, `No_data (q_name, soa) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_bad_soa () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let soa = {
    Soa.nameserver = name "a" ; hostmaster = name "b" ;
    serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
  } in
  let authority = Name_rr_map.singleton (name "bar.com") Soa soa in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  let bad_soa = invalid_soa q_name in
  Alcotest.check res "bad SOA record results in NoData SOA"
    (Ok [ K A, q_name, Additional, `No_data (q_name, bad_soa) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative bad SOA record results in NoData SOA"
    (Ok [ K A, q_name, Additional, `No_data (q_name, bad_soa) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_soa_super () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let soa = {
    Soa.nameserver = name "a" ; hostmaster = name "b" ;
    serial = 1l ; refresh = 2l ; retry = 3l ; expiry = 4l ; minimum = 5l
  } in
  let authority = Name_rr_map.singleton (name "com") Soa soa in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "SOA record results in NoData SOA"
    (Ok [ K A, q_name, Additional, `No_data (name "com", soa) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr =
    let flags = Packet.Flags.singleton `Authoritative in
    (fst header, flags)
  in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative SOA record results in NoData SOA"
    (Ok [ K A, q_name, AuthoritativeAuthority, `No_data (name "com", soa) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_cname_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let alias = (1l, name "bar.com")
  and a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  in
  let answer =
    let an =
      Domain_name.Map.singleton q_name Rr_map.(add Cname alias (singleton A a))
    in
    `Answer (an, Name_rr_map.empty)
  in
  let dns = Packet.create header q answer in
  Alcotest.check res "CNAME and A record results in the A record :"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let q' = (q_name, `K (Rr_map.K Cname)) in
  let dns' = Packet.create header q' answer in
  Alcotest.check res "CNAME and A record, asking for CNAME results in the cname record :"
    (Ok [ K Cname, q_name, NonAuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q') dns') ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create hdr q answer in
  Alcotest.check res "authoritative CNAME and A record results in the A record"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns');
  let dns' = Packet.create hdr q' answer in
  Alcotest.check res "authoritative CNAME and A record, asking for CNAME, results in the CNAME record"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q') dns')

let scrub_authority_ns () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com")) in
  let authority = Name_rr_map.singleton q_name Ns ns in
  let dns = Packet.create header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "NS in authority results in NoData foo.com and NoErr NS"
    (Ok [ K Ns, q_name, Additional, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative NS in authority results in NoData foo.com and NoErr NS"
    (Ok [ K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_authority_ns () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  in
  let answer, authority =
    Name_rr_map.singleton q_name A a,
    Name_rr_map.singleton q_name Ns ns
  in
  let dns = Packet.create header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, and A in answer results in NoErr foo.com and NoErr NS"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, Additional, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, and A in answer results in NoErr foo.com and NoErr NS"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_authority_ns_add_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  in
  let answer, authority, additional =
    Name_rr_map.singleton q_name A a,
    Name_rr_map.singleton q_name Ns ns,
    Name_rr_map.singleton (name "ns1.foo.com") A a
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, glue in additional results in NoErr foo.com, NoErr NS, NoErr ns1.foo.com A"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, Additional, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, glue in additional results in NoErr foo.com, NoErr NS, NoErr ns1.foo.com A"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_authority_ns_bad_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  in
  let answer, authority, additional =
    Name_rr_map.singleton q_name A a,
    Name_rr_map.singleton q_name Ns ns,
    Name_rr_map.singleton (name "ns2.foo.com") A a
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, crap in additional results in NoErr foo.com and NoErr NS"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, Additional, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, crap in additional results in NoErr foo.com and NoErr NS"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_authority_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.5")
  and ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  in
  let answer, authority, additional =
    Name_rr_map.singleton q_name A a,
    Name_rr_map.singleton q_name Ns ns,
    Domain_name.Map.singleton (name "ns1.foo.com") Rr_map.(add A a' (singleton A a))
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, Additional, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a')) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = (fst header, Packet.Flags.singleton `Authoritative) in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a')) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_authority_ns_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.5")
  and ns = 1l, Domain_name.Host_set.(add (Domain_name.host_exn (name "ns2.foo.com"))
                                       (singleton (Domain_name.host_exn (name "ns1.foo.com"))))
  in
  let answer, authority, additional =
    Name_rr_map.singleton q_name A a,
    Name_rr_map.singleton q_name Ns ns,
    Name_rr_map.add (name "ns1.foo.com") A a
      (Name_rr_map.singleton (name "ns2.foo.com") A a')
  in
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, Additional, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ;
          K A, name "ns2.foo.com", Additional, `Entry (B (A, a')) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (answer, authority)) in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ;
          K A, name "ns2.foo.com", Additional, `Entry (B (A, a')) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_authority_ns_bad_ns_add_a_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.5")
  and ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  and ns' = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns2.foo.com"))
  in
  let answer, additional =
    `Answer (Name_rr_map.singleton q_name A a,
             Name_rr_map.add q_name Ns ns
               (Name_rr_map.singleton (name "com") Ns ns')),
    Name_rr_map.add (name "ns1.foo.com") A a
      (Name_rr_map.singleton (name "ns2.foo.com") A a')
  in
  let dns = Packet.create ~additional header q answer in
  Alcotest.check res "NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, Additional, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q answer in
  Alcotest.check res "authoritative NS in authority, A in answer, multiple A in additional results in NoErr foo.com, NoErr NS, NoErr As"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_authority_ns_add_a_bad () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  and ns' = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns3.foo.com"))
  and a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  in
  let authority, additional =
    Name_rr_map.singleton q_name Ns ns,
    Name_rr_map.add (name "ns1.foo.com") A a
      (Name_rr_map.singleton (name "ns1.foo.com") Ns ns')
  in
  let dns = Packet.create ~additional header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "NS in authority, A and NS in additional results in NoErr NS, NoErr As"
    (Ok [ K Ns, q_name, Additional, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative NS in authority, A and NS in additional results in NoErr NS, NoErr As"
    (Ok [ K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_authority_ns_add_a_aaaa () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  and aaaa = 1l, Rr_map.Ipv6_set.singleton (ip6 "::1")
  in
  let authority, additional =
    Name_rr_map.singleton q_name Ns ns,
    Domain_name.Map.singleton (name "ns1.foo.com") Rr_map.(add A a (singleton Aaaa aaaa))
  in
  let dns = Packet.create ~additional header q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "NS in authority, A and AAAA in additional results in NoErr NS, NoErr A, NoErr AAAA"
    (Ok [ K Ns, q_name, Additional, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ;
          K Aaaa, name "ns1.foo.com", Additional, `Entry (B (Aaaa, aaaa)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create ~additional hdr q (`Answer (Name_rr_map.empty, authority)) in
  Alcotest.check res "authoritative NS in authority, A and AAAA in additional results in NoErr NS, NoErr A, NoErr AAAA"
    (Ok [ K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ;
          K A, name "ns1.foo.com", Additional, `Entry (B (A, a)) ;
          K Aaaa, name "ns1.foo.com", Additional, `Entry (B (Aaaa, aaaa)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_a_authority_ns_a () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let a = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip "1.2.3.5")
  and ns = 1l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns1.foo.com"))
  in
  let answer =
    `Answer (Name_rr_map.singleton q_name A a,
             Domain_name.Map.singleton q_name Rr_map.(add Ns ns (singleton A a')))
  in
  let dns = Packet.create header q answer in
  Alcotest.check res "NS and crap in authority, A in answer results in NoErr foo.com, NoErr NS"
    (Ok [ K A, q_name, NonAuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, Additional, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create hdr q answer in
  Alcotest.check res "authoritative NS and crap in authority, A in answer results in NoErr foo.com, NoErr NS"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_bad_packets () =
  let q_name = name "foo.com" in
  let q = q_name, `K (Rr_map.K A) in
  let answer =
    Domain_name.Map.singleton (name "bar.com")
      Rr_map.(singleton A (1l, (Ipv4_set.singleton (ip "1.2.3.4"))))
  in
  let dns = Packet.create header q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "No results in scrubbed A with bad A"
    (Ok [ K A, q_name, Additional, `No_data (q_name, invalid_soa q_name)])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let dns' = Packet.create hdr q (`Answer (answer, Name_rr_map.empty)) in
  Alcotest.check res "authoritative no results in scrubbed A with bad A"
    (Ok [ K A, q_name, Additional, `No_data (q_name, invalid_soa q_name)])
    (Dns_resolver_utils.scrub q_name (snd q) dns')

let scrub_rfc2308_2_1 () =
  let q_name = name "an.example" in
  let q = q_name, `K (Rr_map.K A) in
  let soa = {
    Soa.nameserver = name "ns1.xx" ; hostmaster = name "hostmaster.ns1.xx" ;
    serial = 1l ; refresh = 1l ; retry = 2l ; expiry = 3l ; minimum = 4l
  }
  and ns = 1l, Domain_name.Host_set.(add (Domain_name.host_exn (name "ns1.xx"))
                                       (singleton (Domain_name.host_exn (name "ns2.xx"))))
  and alias = 1l, name "tripple.xx"
  and additional =
    Name_rr_map.add (name "ns1.xx") A (1l, Rr_map.Ipv4_set.singleton (ip "127.0.0.2"))
      (Name_rr_map.singleton (name "ns2.xx") A (1l, Rr_map.Ipv4_set.singleton (ip "127.0.0.3")))
  in
  let answer = Name_rr_map.singleton q_name Cname alias
  and authority =
    Domain_name.Map.singleton (name "xx") Rr_map.(add Soa soa (singleton Ns ns))
  in
  let dns = Packet.create ~additional header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, authority))) in
  (* considering what is valid in the response, it turns out only the cname is *)
  Alcotest.check res "Sec 2.1 type 1"
    (Ok [ K Cname, q_name, NonAuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let authority = Name_rr_map.singleton (name "xx") Soa soa in
  let dns = Packet.create header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, authority))) in
  Alcotest.check res "Sec 2.1 type 2"
    (Ok [ K Cname, q_name, NonAuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let dns = Packet.create header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, Name_rr_map.empty))) in
  Alcotest.check res "Sec 2.1 type 3"
    (Ok [ K Cname, q_name, NonAuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let authority = Name_rr_map.singleton (name "xx") Ns ns in
  let dns = Packet.create ~additional header q (`Rcode_error (Rcode.NXDomain, Opcode.Query, Some (answer, authority))) in
  Alcotest.check res "Sec 2.1 type 4"
    (Ok [ K Cname, q_name, NonAuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let dns = Packet.create ~additional header q (`Answer (answer, authority)) in
  Alcotest.check res "Sec 2.1 type referral response"
    (Ok [ K Cname, q_name, NonAuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns)


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
  let q = q_name, `K (Rr_map.K A) in
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let a = 300l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4") in
  let answer = `Answer (Name_rr_map.add q_name A a
                          (Name_rr_map.singleton (name "bar") A a),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "additional A records"
    (Ok [ K A, q_name, AuthoritativeAnswer, `Entry (B (A, a)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let alias = 300l, name "bar" in
  let answer = `Answer (Name_rr_map.add q_name Cname alias
                          (Name_rr_map.singleton (name "bar") A a),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "A and CNAME record"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let ns = 300l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "boo")) in
  let answer = `Answer (Name_rr_map.add q_name Cname alias
                          (Name_rr_map.singleton (name "bar") Ns ns),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and NS record in answer"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let answer = `Answer (Name_rr_map.singleton q_name Cname alias,
                        Name_rr_map.singleton q_name Ns ns)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and NS record in authority"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let answer = `Answer (Name_rr_map.add q_name Cname alias
                          (Name_rr_map.singleton (name "foobar") Ns ns),
                        Name_rr_map.empty)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and unrelated NS record in answer"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let answer = `Answer (Name_rr_map.singleton q_name Cname alias,
                        Name_rr_map.singleton (name "foobar") Ns ns)
  in
  let dns = Packet.create hdr q answer in
  Alcotest.check res "CNAME and unrelated NS record in authority"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let answer = `Answer (Name_rr_map.singleton q_name Cname alias,
                        Name_rr_map.empty)
  in
  let additional = Name_rr_map.singleton (name "bar") A a in
  let dns = Packet.create ~additional hdr q answer in
  Alcotest.check res "CNAME and glue record in additional"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let answer = `Answer (Name_rr_map.singleton q_name Cname alias,
                        Name_rr_map.singleton q_name Ns ns)
  in
  let additional = Name_rr_map.singleton (name "boo") A a in
  let dns = Packet.create ~additional hdr q answer in
  Alcotest.check res "CNAME and glue record in additional"
    (Ok [ K Cname, q_name, AuthoritativeAnswer, `Entry (B (Cname, alias)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns)


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
  let q = q_name, `K (Rr_map.K Mx) in
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let mx = 300l, Rr_map.Mx_set.singleton { Mx.preference = 10 ; mail_exchange = Domain_name.host_exn (name "bar") }
  and a = 300l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  in
  let mx_a = Domain_name.Map.singleton q_name Rr_map.(add A a (singleton Mx mx)) in
  let dns = Packet.create hdr q (`Answer (mx_a, Name_rr_map.empty)) in
  Alcotest.check res "additional A record"
    (Ok [ K Mx, q_name, AuthoritativeAnswer, `Entry (B (Mx, mx)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let mx_mx =
    Domain_name.Map.add q_name Rr_map.(add A a (singleton Mx mx))
      (Name_rr_map.singleton (name "bar") Mx mx)
  in
  let dns = Packet.create hdr q (`Answer (mx_mx, Name_rr_map.empty)) in
  Alcotest.check res "additional MX records"
    (Ok [ K Mx, q_name, AuthoritativeAnswer, `Entry (B (Mx, mx)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let mx_amx =
    Domain_name.Map.add q_name Rr_map.(add A a (singleton Mx mx))
      (Name_rr_map.singleton (name "bar") A a)
  in
  let dns = Packet.create hdr q (`Answer (mx_amx, Name_rr_map.empty)) in
  Alcotest.check res "MX record and an A record"
    (Ok [ K Mx, q_name, AuthoritativeAnswer, `Entry (B (Mx, mx)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let mx', additional =
    Domain_name.Map.singleton q_name Rr_map.(add A a (singleton Mx mx)),
    Name_rr_map.singleton (name "bar") A a
  in
  let dns = Packet.create ~additional hdr q (`Answer (mx', Name_rr_map.empty)) in
  Alcotest.check res "MX record and additional A record"
    (Ok [ K Mx, q_name, AuthoritativeAnswer, `Entry (B (Mx, mx)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let ns = 300l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "foobar")) in
  let mx_au, additional =
    (Name_rr_map.singleton q_name Mx mx,
     Name_rr_map.singleton q_name Ns ns),
    Name_rr_map.add (name "bar") A a
      (Name_rr_map.singleton (name "foobar") A a)
  in
  let dns = Packet.create ~additional hdr q (`Answer mx_au) in
  Alcotest.check res "MX record and authority and additional A record"
    (Ok [ K Mx, q_name, AuthoritativeAnswer, `Entry (B (Mx, mx)) ;
          K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let mx_au' =
    Name_rr_map.singleton q_name Mx mx,
    Name_rr_map.singleton (name "bar") Ns ns
  in
  let dns = Packet.create ~additional hdr q (`Answer mx_au') in
  Alcotest.check res "MX record and bad authority and additional A record"
    (Ok [ K Mx, q_name, AuthoritativeAnswer, `Entry (B (Mx, mx)) ])
    (Dns_resolver_utils.scrub q_name (snd q) dns)

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
  let q = q_name, `K (Rr_map.K Ns) in
  let hdr = fst header, Packet.Flags.singleton `Authoritative in
  let ns = 300l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "bar"))
  and a = 300l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")
  in
  let answer =
    Rr_map.K Ns, q_name, Dns_cache.AuthoritativeAnswer,
    `Entry (Rr_map.B (Ns, ns))
  in
  let data = Domain_name.Map.singleton q_name Rr_map.(add Ns ns (singleton A a)) in
  let dns = Packet.create hdr q (`Answer (data, Name_rr_map.empty)) in
  (* fail atm - get NS and A *)
  Alcotest.check res "additional A record"
    (Ok [ answer ]) (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let data =
    Name_rr_map.add q_name Ns ns
      (Name_rr_map.singleton (name "bar") Ns ns)
  in
  let dns = Packet.create hdr q (`Answer (data, Name_rr_map.empty)) in
  Alcotest.check res "additional NS records"
    (Ok [ answer ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let data =
    Name_rr_map.add q_name Ns ns (Name_rr_map.singleton (name "bar") A a)
  in
  let dns = Packet.create hdr q (`Answer (data, Name_rr_map.empty)) in
  Alcotest.check res "NS record and an A record"
    (Ok [ answer ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let data, additional =
    Name_rr_map.singleton q_name Ns ns,
    Name_rr_map.singleton q_name A a
  in
  let dns = Packet.create ~additional hdr q (`Answer (data, Name_rr_map.empty)) in
  (* should glue be respected? don't think it's worth it *)
  Alcotest.check res "NS record and additional A record"
    (Ok [ answer ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let data, additional =
    Name_rr_map.singleton q_name Ns ns, Name_rr_map.singleton (name "bar") A a
  in
  let dns = Packet.create ~additional hdr q (`Answer (data, Name_rr_map.empty)) in
  Alcotest.check res "NS record and additional A record with NS name"
    (Ok [ answer ])
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let ns' = 300l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "foobar")) in
  let data, au, additional =
    Name_rr_map.singleton q_name Ns ns,
    Name_rr_map.singleton q_name Ns ns',
    Name_rr_map.add (name "bar") A a (Name_rr_map.singleton (name "foobar") A a)
  in
  let dns = Packet.create ~additional hdr q (`Answer (data, au)) in
  let answer' = [
    answer ;
    K Ns, q_name, AuthoritativeAuthority, `Entry (B (Ns, ns')) ]
  in
  Alcotest.check res "NS record and authority and additional A record"
    (Ok answer')
    (Dns_resolver_utils.scrub q_name (snd q) dns) ;
  let au' = Name_rr_map.singleton (name "bar") Ns ns' in
  let dns = Packet.create ~additional hdr q (`Answer (data, au')) in
  Alcotest.check res "NS record and bad authority and additional A record"
    (Ok [ answer ])
    (Dns_resolver_utils.scrub q_name (snd q) dns)

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
  "scrub", scrub_tests ;
]

let () = Alcotest.run "DNS resolver tests" tests
