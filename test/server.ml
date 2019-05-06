(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Dns

let n_of_s = Domain_name.of_string_exn

module Trie = struct
  open Dns_trie

  let e =
    let module M = struct
      type t = e
      let pp = Dns_trie.pp_e
      let equal a b = match a, b with
        | `Delegation (na, (ttl, n)), `Delegation (na', (ttl', n')) ->
          Domain_name.equal na na' && ttl = ttl' && Domain_name.Set.equal n n'
        | `EmptyNonTerminal (nam, soa), `EmptyNonTerminal (nam', soa') ->
          Domain_name.equal nam nam' && Soa.compare soa soa' = 0
        | `NotFound (nam, soa), `NotFound (nam', soa') ->
          Domain_name.equal nam nam' && Soa.compare soa soa' = 0
        | `NotAuthoritative, `NotAuthoritative -> true
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let b_ok =
    let module M = struct
      type t = Rr_map.b
      let pp = Rr_map.pp_b
      let equal = Rr_map.equalb
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let l_ok =
    let module M = struct
      type t = Rr_map.b * (Domain_name.t * int32 * Domain_name.Set.t)
      let pp ppf (v, (name, ttl, ns)) =
        Fmt.pf ppf "%a auth %a TTL %lu %a" Rr_map.pp_b v Domain_name.pp name ttl
          Fmt.(list ~sep:(unit ",@,") Domain_name.pp) (Domain_name.Set.elements ns)
      let equal (a, (name, ttl, ns)) (a', (name', ttl', ns')) =
        ttl = ttl' && Domain_name.equal name name' && Domain_name.Set.equal ns ns' &&
        Rr_map.equalb a a'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let sn = Domain_name.Set.singleton
  let ip = Ipaddr.V4.of_string_exn

  let ins_zone name soa ttl ns t =
    insert name Rr_map.Ns (ttl, ns) (insert name Rr_map.Soa soa t)

  let lookup_b name key t = match lookup name key t with
    | Ok v -> Ok (Rr_map.B (key, v))
    | Error e -> Error e

  let simple () =
    Alcotest.(check (result l_ok e)
                "lookup for root returns NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_with_cname Domain_name.root A empty)) ;
    let soa = {
      Soa.nameserver = n_of_s "a" ; hostmaster = n_of_s "hs" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t = ins_zone Domain_name.root soa 6l (sn (n_of_s "a")) empty in
    Alcotest.(check (result l_ok e) "lookup_with_cname for .com is NoDomain"
                (Error (`NotFound (Domain_name.root, soa)))
                (lookup_with_cname (n_of_s "com") A t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for .com is NoDomain"
                (Error (`NotFound (Domain_name.root, soa)))
                (lookup_b (n_of_s "com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for SOA . is SOA"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (Domain_name.root, 6l, sn (n_of_s "a"))))
                (lookup_with_cname Domain_name.root Soa t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for SOA . is SOA"
                (Ok (Rr_map.B (Rr_map.Soa, soa)))
                (lookup_b Domain_name.root Soa t)) ;
    let a_record = (23l, Rr_map.Ipv4_set.singleton (ip "1.4.5.2")) in
    let t = insert (n_of_s "foo.com") Rr_map.A a_record t in
    Alcotest.(check (result l_ok e) "lookup_with_cname for A foo.com is A"
                (Ok (Rr_map.B (Rr_map.A, a_record),
                     (Domain_name.root, 6l, sn (n_of_s "a"))))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for A foo.com is A"
                (Ok (Rr_map.B (Rr_map.A, a_record)))
                (lookup_b (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for SOA com is ENT"
                (Error (`EmptyNonTerminal (Domain_name.root, soa)))
                (lookup_with_cname (n_of_s "com") Soa t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for SOA com is ENT"
                (Error (`EmptyNonTerminal (Domain_name.root, soa)))
                (lookup_b (n_of_s "com") Soa t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for SOA foo.com is NoDomain"
                (Error (`EmptyNonTerminal (Domain_name.root, soa)))
                (lookup_with_cname (n_of_s "foo.com") Soa t));
    Alcotest.(check (result b_ok e) "lookup_b for SOA foo.com is NoDomain"
                (Error (`EmptyNonTerminal (Domain_name.root, soa)))
                (lookup_b (n_of_s "foo.com") Soa t))

  let basic () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for SOA bar.com is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_with_cname (n_of_s "bar.com") Soa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for SOA bar.com is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_b (n_of_s "bar.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa)))
                (lookup_b (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Aaaa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "foo.com") Aaaa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for A foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for A foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Mx t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "foo.com") Mx t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for MX bar.foo.com (after insert) is NoDomain"
                (Error (`NotFound (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "bar.foo.com") Mx t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for MX bar.foo.com (after insert) is NoDomain"
                (Error (`NotFound (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "bar.foo.com") Mx t)) ;
    let a_record = (12l, Rr_map.Ipv4_set.singleton (ip "1.2.3.4")) in
    let t = insert (n_of_s "foo.com") Rr_map.A a_record t in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Aaaa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for AAAA foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "foo.com") Aaaa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for A foo.com (after insert) is Found"
                (Ok (Rr_map.B (Rr_map.A, a_record),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for A foo.com (after insert) is Found"
                (Ok (Rr_map.B (Rr_map.A, a_record)))
                (lookup_b (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") Mx t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for MX foo.com (after insert) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "foo.com") Mx t)) ;
    let t = remove (n_of_s "foo.com") A t in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for A foo.com (after insert and remove) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_with_cname (n_of_s "foo.com") A t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for A foo.com (after insert and remove) is NoData"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "foo.com") A t)) ;
    let t = remove_all (n_of_s "foo.com") t in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for SOA foo.com (after remove) is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_with_cname (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for SOA foo.com (after remove) is NotAuthoritative"
                (Error `NotAuthoritative)
                (lookup_b (n_of_s "foo.com") Soa t))

  let alias () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    let t = insert (n_of_s "bar.foo.com") Rr_map.Cname (14l, n_of_s "foo.bar.com") t in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for SOA bar.foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Cname, (14l, n_of_s "foo.bar.com")),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "bar.foo.com") Soa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for SOA bar.foo.com (after insert) is good"
                (Error (`EmptyNonTerminal (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "bar.foo.com") Soa t))

  let dele () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa)))
                (lookup_b (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "foo.com") Ns t)) ;
    let t = insert (n_of_s "bar.foo.com") Rr_map.Ns (12l, sn (n_of_s "ns3.bar.com")) t in
    Alcotest.(check (result l_ok e) "lookup_with_cname for A bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "bar.foo.com") A t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for A bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_b (n_of_s "bar.foo.com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for NS foo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "foo.bar.foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS foo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_b (n_of_s "foo.bar.foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "foobar.boo.bar.foo.com") Aaaa t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_b (n_of_s "foobar.boo.bar.foo.com") Aaaa t)) ;
    let t = ins_zone (n_of_s "a.b.bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t in
    Alcotest.(check (result l_ok e) "lookup_with_cname for NS a.b.bar.foo.com is ns1.foo.com"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com"))),
                     (n_of_s "a.b.bar.foo.com", 10l, sn (n_of_s "ns1.foo.com"))))
                (lookup_with_cname (n_of_s "a.b.bar.foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS a.b.bar.foo.com is ns1.foo.com"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "a.b.bar.foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_with_cname (n_of_s "foobar.boo.bar.foo.com") Aaaa t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (n_of_s "ns3.bar.com")))))
                (lookup_b (n_of_s "foobar.boo.bar.foo.com") Aaaa t))

  let r_fst = function Ok (v, _) -> Ok (v) | Error e -> Error e

  let rmzone () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let t =
      ins_zone (n_of_s "foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result b_ok e) "lookup_with_cname for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t))) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "foo.com") Ns t)) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result b_ok e)
                "lookup_with_cname for NS foo.com after removing zone is notauthoritative"
                (Error `NotAuthoritative)
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t'))) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS foo.com after removing zone is notauthoritative"
                (Error `NotAuthoritative)
                (lookup_b (n_of_s "foo.com") Ns t')) ;
    let t =
      ins_zone (n_of_s "bar.foo.com") soa 10l (sn (n_of_s "ns1.foo.com")) t
    in
    Alcotest.(check (result b_ok e) "lookup_with_cname for NS bar.foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "bar.foo.com") Ns t))) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS bar.foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "bar.foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e) "lookup_with_cname for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t))) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "foo.com") Ns t)) ;
    let t' = remove_zone (n_of_s "foo.com") t in
    Alcotest.(check (result b_ok e)
                "lookup_with_cname for NS bar.foo.com is good (after foo.com is removed)"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "bar.foo.com") Ns t'))) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS bar.foo.com is good (after foo.com is removed)"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "bar.foo.com") Ns t')) ;
    Alcotest.(check (result b_ok e)
                "lookup_with_cname for NS foo.com is not authoritative"
                (Error `NotAuthoritative)
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t'))) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS foo.com is not authoritative"
                (Error `NotAuthoritative)
                (lookup_b (n_of_s "foo.com") Ns t')) ;
    let t' = remove_zone (n_of_s "bar.foo.com") t in
    Alcotest.(check (result b_ok e)
                "lookup_with_cname for NS bar.foo.com is not authoritative"
                (Error (`NotFound (n_of_s "foo.com", soa)))
                (r_fst (lookup_with_cname (n_of_s "bar.foo.com") Ns t'))) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS bar.foo.com is not authoritative"
                (Error (`NotFound (n_of_s "foo.com", soa)))
                (lookup_b (n_of_s "bar.foo.com") Ns t')) ;
    Alcotest.(check (result b_ok e) "lookup_with_cname for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t'))) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS foo.com is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (n_of_s "ns1.foo.com")))))
                (lookup_b (n_of_s "foo.com") Ns t'))


  let tests = [
    "simple", `Quick, simple ;
    "basic", `Quick, basic ;
    "alias", `Quick, alias ;
    "delegation", `Quick, dele ;
    "rmzone", `Quick, rmzone ;
  ]
end

module S = struct

  let ip =
    let module M = struct
      type t = Ipaddr.V4.t
      let pp = Ipaddr.V4.pp
      let equal a b = Ipaddr.V4.compare a b = 0
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let ipset = Alcotest.(slist ip Ipaddr.V4.compare)

  let ip_of_s = Ipaddr.V4.of_string_exn

  let ts = Duration.of_sec 5

  let data =
    let ns = n_of_s "ns.one.com" in
    let soa = Soa.create ~serial:1l ns in
    Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa
      (Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, Domain_name.Set.singleton ns)
         (Dns_trie.insert ns Rr_map.A (300l, Rr_map.Ipv4_set.singleton Ipaddr.V4.localhost)
            Dns_trie.empty))

  let simple () =
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 0 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 0 (List.length tbn));
    let tbn = Dns_server.Primary.to_be_notified server Domain_name.root in
    Alcotest.(check int __LOC__ 0 (List.length tbn))

  let secondary () =
    let data =
      let ns =
        Domain_name.Set.(add (n_of_s "ns.one.com") (singleton (n_of_s "ns2.one.com")))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Rr_map.Ipv4_set.singleton (ip_of_s "10.0.0.2")) data)
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2"] (List.map fst tbn)

  let multiple_ips_secondary () =
    let data =
      let ns =
        Domain_name.Set.(add (n_of_s "ns.one.com") (singleton (n_of_s "ns2.one.com")))
      and ips =
        Rr_map.Ipv4_set.(add (ip_of_s "10.0.0.2") (singleton (ip_of_s "1.2.3.4")))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A (300l, ips) data)
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 2 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 2 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2" ; ip_of_s "1.2.3.4"] (List.map fst tbn)

  let multiple_secondaries () =
    let data' =
      let ns =
        Domain_name.Set.(add (n_of_s "ns.one.com")
                           (add (n_of_s "ns2.one.com")
                              (singleton (n_of_s "ns3.one.com"))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Rr_map.Ipv4_set.singleton (ip_of_s "10.0.0.2"))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Rr_map.Ipv4_set.singleton (ip_of_s "10.0.0.3"))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data' in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 2 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 2 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2";ip_of_s "10.0.0.3"]
      (List.map fst tbn)

  let multiple_secondaries_dups () =
    let data' =
      let ns =
        Domain_name.Set.(add (n_of_s "ns.one.com")
                           (add (n_of_s "ns2.one.com")
                              (singleton (n_of_s "ns3.one.com"))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Rr_map.Ipv4_set.(add (ip_of_s "10.0.0.2") (singleton (ip_of_s "10.0.0.3"))))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Rr_map.Ipv4_set.(add (ip_of_s "10.0.0.3") (singleton (ip_of_s "10.0.0.4"))))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data' in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 3 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 3 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2";ip_of_s "10.0.0.3";ip_of_s "10.0.0.4"]
      (List.map fst tbn)

  let secondaries_in_other_zone () =
    let data =
      let ns =
        Domain_name.Set.(add (n_of_s "ns.one.com")
                           (add (n_of_s "ns.foo.com")
                              (singleton (n_of_s "ns.bar.com"))))
      in
      let soa = Soa.create (n_of_s "ns.one.com")
      and soa' = Soa.create (n_of_s "ns.foo.com")
      and soa'' = Soa.create (n_of_s "ns.bar.com")
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa
           (Dns_trie.insert (n_of_s "foo.com") Rr_map.Soa soa'
              (Dns_trie.insert (n_of_s "bar.com") Rr_map.Soa soa''
                 (Dns_trie.insert (n_of_s "ns.foo.com") Rr_map.A
                    (300l, Rr_map.Ipv4_set.singleton (ip_of_s "10.0.0.2"))
                    (Dns_trie.insert (n_of_s "ns.bar.com") Rr_map.A
                       (300l, Rr_map.Ipv4_set.singleton (ip_of_s "10.0.0.3"))
                       (Dns_trie.insert (n_of_s "ns.one.com") Rr_map.A
                          (300l, Rr_map.Ipv4_set.singleton (ip_of_s "10.0.0.4"))
                          Dns_trie.empty))))))
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 2 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 2 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2";ip_of_s "10.0.0.3"]
      (List.map fst tbn)

  let secondary_via_key () =
    let keys =
      [ n_of_s ~hostname:false "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ~keys data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8"] (List.map fst tbn)

  let secondary_via_root_key () =
    let keys =
      [ n_of_s ~hostname:false "1.2.3.4.5.6.7.8._transfer",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ~keys data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8"] (List.map fst tbn)

  let secondaries_and_keys () =
    let keys =
      [ n_of_s ~hostname:false "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns =
        Domain_name.Set.(add (n_of_s "ns3.one.com")
                           (add (n_of_s "ns2.one.com")
                              (singleton (n_of_s "ns.one.com"))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Rr_map.Ipv4_set.singleton (ip_of_s "1.1.1.1"))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Rr_map.Ipv4_set.(add (ip_of_s "10.0.0.1") (singleton (ip_of_s "192.168.1.1"))))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ~keys data' in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 4 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 4 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "1.1.1.1" ; ip_of_s "5.6.7.8" ; ip_of_s "10.0.0.1" ; ip_of_s "192.168.1.1"]
      (List.map fst tbn)

  let secondaries_and_keys_dups () =
    let keys =
      [ n_of_s ~hostname:false "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns =
        Domain_name.Set.(add (n_of_s "ns3.one.com")
                           (add (n_of_s "ns2.one.com")
                              (singleton (n_of_s "ns.one.com"))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Rr_map.Ipv4_set.singleton (ip_of_s "5.6.7.8"))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Rr_map.Ipv4_set.(add (ip_of_s "10.0.0.1") (singleton (ip_of_s "192.168.1.1"))))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ~keys data' in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 3 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (n_of_s "one.com") in
    Alcotest.(check int __LOC__ 3 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8" ; ip_of_s "10.0.0.1" ; ip_of_s "192.168.1.1"]
      (List.map fst tbn)

  (* TODO more testing:
     - passive secondaries (tsig-signed SOA request)
     - ensure that with_data and update (handle_packet) actually notifies the to-be-notified
     - interaction of/with secondary (bootup, IXFR/AXFR, add/remove zone for root transfer keys, ...)
  *)

  let tests = [
    "simple", `Quick, simple ;
    "secondary", `Quick, secondary ;
    "multiple IPs of secondary", `Quick, multiple_ips_secondary ;
    "multiple secondaries", `Quick, multiple_secondaries ;
    "multiple secondaries with duplicates", `Quick, multiple_secondaries_dups ;
    "secondaries in other zone", `Quick, secondaries_in_other_zone ;
    "secondary via key", `Quick, secondary_via_key ;
    "secondary via root key", `Quick, secondary_via_root_key ;
    "secondaries and keys", `Quick, secondaries_and_keys ;
    "secondaries and keys dups", `Quick, secondaries_and_keys_dups ;
  ]
end

let tests = [
  "Trie", Trie.tests ;
  "Server", S.tests ;
]

let () =
  Nocrypto_entropy_unix.initialize ();
  Alcotest.run "DNS server tests" tests
