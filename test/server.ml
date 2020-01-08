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
          Domain_name.equal na na' && ttl = ttl' && Domain_name.Host_set.equal n n'
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
      type t = Rr_map.b * ([ `raw ] Domain_name.t * int32 * Domain_name.Host_set.t)
      let pp ppf (v, (name, ttl, ns)) =
        Fmt.pf ppf "%a auth %a TTL %lu %a" Rr_map.pp_b v Domain_name.pp name ttl
          Fmt.(list ~sep:(unit ",@,") Domain_name.pp) (Domain_name.Host_set.elements ns)
      let equal (a, (name, ttl, ns)) (a', (name', ttl', ns')) =
        ttl = ttl' && Domain_name.equal name name' && Domain_name.Host_set.equal ns ns' &&
        Rr_map.equalb a a'
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let sn a = Domain_name.Host_set.singleton (Domain_name.host_exn a)
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
    let t = ins_zone Domain_name.root soa 6l (sn (Domain_name.host_exn (n_of_s "a"))) empty in
    Alcotest.(check (result l_ok e) "lookup_with_cname for .com is NoDomain"
                (Error (`NotFound (Domain_name.root, soa)))
                (lookup_with_cname (n_of_s "com") A t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for .com is NoDomain"
                (Error (`NotFound (Domain_name.root, soa)))
                (lookup_b (n_of_s "com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for SOA . is SOA"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (Domain_name.root, 6l, sn (Domain_name.host_exn (n_of_s "a")))))
                (lookup_with_cname Domain_name.root Soa t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for SOA . is SOA"
                (Ok (Rr_map.B (Rr_map.Soa, soa)))
                (lookup_b Domain_name.root Soa t)) ;
    let a_record = (23l, Rr_map.Ipv4_set.singleton (ip "1.4.5.2")) in
    let t = insert (n_of_s "foo.com") Rr_map.A a_record t in
    Alcotest.(check (result l_ok e) "lookup_with_cname for A foo.com is A"
                (Ok (Rr_map.B (Rr_map.A, a_record),
                     (Domain_name.root, 6l, sn (Domain_name.host_exn (n_of_s "a")))))
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
      ins_zone (n_of_s "foo.com") soa 10l (sn (Domain_name.host_exn (n_of_s "ns1.foo.com"))) empty
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
                     (n_of_s "foo.com", 10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))))
                (lookup_with_cname (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa)))
                (lookup_b (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))),
                     (n_of_s "foo.com", 10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))))
                (lookup_with_cname (n_of_s "foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com"))))))
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
                     (n_of_s "foo.com", 10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))))
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
    let t = remove_ty (n_of_s "foo.com") A t in
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
      ins_zone (n_of_s "foo.com") soa 10l (sn (Domain_name.host_exn (n_of_s "ns1.foo.com"))) empty
    in
    let t = insert (n_of_s "bar.foo.com") Rr_map.Cname (14l, n_of_s "foo.bar.com") t in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for SOA bar.foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Cname, (14l, n_of_s "foo.bar.com")),
                     (n_of_s "foo.com", 10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))))
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
      ins_zone (n_of_s "foo.com") soa 10l (sn (Domain_name.host_exn (n_of_s "ns1.foo.com"))) empty
    in
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa),
                     (n_of_s "foo.com", 10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))))
                (lookup_with_cname (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for SOA foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Soa, soa)))
                (lookup_b (n_of_s "foo.com") Soa t)) ;
    Alcotest.(check (result l_ok e)
                "lookup_with_cname for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))),
                     (n_of_s "foo.com", 10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))))
                (lookup_with_cname (n_of_s "foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e)
                "lookup_b for NS foo.com (after insert) is good"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com"))))))
                (lookup_b (n_of_s "foo.com") Ns t)) ;
    let t = insert (n_of_s "bar.foo.com") Rr_map.Ns (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))) t in
    Alcotest.(check (result l_ok e) "lookup_with_cname for A bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
                (lookup_with_cname (n_of_s "bar.foo.com") A t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for A bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
                (lookup_b (n_of_s "bar.foo.com") A t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for NS foo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
                (lookup_with_cname (n_of_s "foo.bar.foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS foo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
                (lookup_b (n_of_s "foo.bar.foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
                (lookup_with_cname (n_of_s "foobar.boo.bar.foo.com") Aaaa t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
                (lookup_b (n_of_s "foobar.boo.bar.foo.com") Aaaa t)) ;
    let t = ins_zone (n_of_s "a.b.bar.foo.com") soa 10l (sn (Domain_name.host_exn (n_of_s "ns1.foo.com"))) t in
    Alcotest.(check (result l_ok e) "lookup_with_cname for NS a.b.bar.foo.com is ns1.foo.com"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))),
                     (n_of_s "a.b.bar.foo.com", 10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com")))))
                (lookup_with_cname (n_of_s "a.b.bar.foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS a.b.bar.foo.com is ns1.foo.com"
                (Ok (Rr_map.B (Rr_map.Ns, (10l, sn (Domain_name.host_exn (n_of_s "ns1.foo.com"))))))
                (lookup_b (n_of_s "a.b.bar.foo.com") Ns t)) ;
    Alcotest.(check (result l_ok e) "lookup_with_cname for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
                (lookup_with_cname (n_of_s "foobar.boo.bar.foo.com") Aaaa t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for AAAA foobar.boo.bar.foo.com is delegated"
                (Error (`Delegation (n_of_s "bar.foo.com", (12l, sn (Domain_name.host_exn (n_of_s "ns3.bar.com"))))))
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

  let zone_ok =
    let module M = struct
      type t = [ `raw ] Domain_name.t * Soa.t
      let pp ppf (zone, soa) =
        Fmt.pf ppf "zone %a soa %a" Domain_name.pp zone Soa.pp soa
      let equal (zone, soa) (zone', soa') =
        Domain_name.equal zone zone' && Soa.compare soa soa' = 0
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let zone () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let myzone = n_of_s "foo.com" in
    let t =
      ins_zone myzone soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    Alcotest.(check (result zone_ok e) __LOC__
                (Ok (myzone, soa))
                (zone myzone t));
    Alcotest.(check (result zone_ok e) __LOC__
                (Ok (myzone, soa))
                (zone (n_of_s "foobar.boo.bar.foo.com") t));
    Alcotest.(check (result zone_ok e) __LOC__
                (Ok (myzone, soa))
                (zone (n_of_s "_bar.foo.com") t));
    Alcotest.(check (result zone_ok e) __LOC__
                (Error `NotAuthoritative)
                (zone Domain_name.root t));
    Alcotest.(check (result zone_ok e) __LOC__
                (Error `NotAuthoritative)
                (zone (n_of_s "bar.com") t))

  let tests = [
    "simple", `Quick, simple ;
    "basic", `Quick, basic ;
    "alias", `Quick, alias ;
    "delegation", `Quick, dele ;
    "rmzone", `Quick, rmzone ;
    "zone", `Quick, zone ;
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
    let ns = Domain_name.host_exn (n_of_s "ns.one.com") in
    let soa = Soa.create ~serial:1l ns in
    Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa
      (Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, Domain_name.Host_set.singleton ns)
         (Dns_trie.insert ns Rr_map.A (300l, Rr_map.Ipv4_set.singleton Ipaddr.V4.localhost)
            Dns_trie.empty))

  let simple () =
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 0 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 0 (List.length tbn));
    let tbn = Dns_server.Primary.to_be_notified server Domain_name.(host_exn root) in
    Alcotest.(check int __LOC__ 0 (List.length tbn))

  let secondary () =
    let data =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns.one.com"))
                                 (singleton (host_exn (n_of_s "ns2.one.com")))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Rr_map.Ipv4_set.singleton (ip_of_s "10.0.0.2")) data)
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2"] (List.map fst tbn)

  let multiple_ips_secondary () =
    let data =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns.one.com"))
                                 (singleton (host_exn (n_of_s "ns2.one.com")))))
      and ips =
        Rr_map.Ipv4_set.(add (ip_of_s "10.0.0.2") (singleton (ip_of_s "1.2.3.4")))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A (300l, ips) data)
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 2 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 2 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2" ; ip_of_s "1.2.3.4"] (List.map fst tbn)

  let multiple_secondaries () =
    let data' =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns.one.com"))
                                 (add (host_exn (n_of_s "ns2.one.com"))
                                    (singleton (host_exn (n_of_s "ns3.one.com"))))))
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
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 2 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2";ip_of_s "10.0.0.3"]
      (List.map fst tbn)

  let multiple_secondaries_dups () =
    let data' =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns.one.com"))
                                 (add (host_exn (n_of_s "ns2.one.com"))
                                    (singleton (host_exn (n_of_s "ns3.one.com"))))))
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
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 3 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2";ip_of_s "10.0.0.3";ip_of_s "10.0.0.4"]
      (List.map fst tbn)

  let secondaries_in_other_zone () =
    let data =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns.one.com"))
                                 (add (host_exn (n_of_s "ns.foo.com"))
                                    (singleton (host_exn (n_of_s "ns.bar.com"))))))
      in
      let soa = Soa.create (Domain_name.host_exn (n_of_s "ns.one.com"))
      and soa' = Soa.create (Domain_name.host_exn (n_of_s "ns.foo.com"))
      and soa'' = Soa.create (Domain_name.host_exn (n_of_s "ns.bar.com"))
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
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 2 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2";ip_of_s "10.0.0.3"]
      (List.map fst tbn)

  let secondary_via_key () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ~keys data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8"] (List.map fst tbn)

  let secondary_via_root_key () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ~keys data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8"] (List.map fst tbn)

  let secondaries_and_keys () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns3.one.com"))
                                 (add (host_exn (n_of_s "ns2.one.com"))
                                    (singleton (host_exn (n_of_s "ns.one.com"))))))
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
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 4 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "1.1.1.1" ; ip_of_s "5.6.7.8" ; ip_of_s "10.0.0.1" ; ip_of_s "192.168.1.1"]
      (List.map fst tbn)

  let secondaries_and_keys_dups () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns3.one.com"))
                                 (add (host_exn (n_of_s "ns2.one.com"))
                                    (singleton (host_exn (n_of_s "ns.one.com"))))))
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
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 3 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8" ; ip_of_s "10.0.0.1" ; ip_of_s "192.168.1.1"]
      (List.map fst tbn)

  (* TODO more testing:
     - passive secondaries (tsig-signed SOA request)
     - ensure that with_data and update (handle_packet) actually notifies the to-be-notified
     - interaction of/with secondary (bootup, IXFR/AXFR, add/remove zone for root transfer keys, ...)
  *)

  let multiple_zones () =
    let keys =
      [ n_of_s "1.2.3.4.9.10.11.12._transfer",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns = Domain_name.(host_exn (n_of_s "ns.one.com")) in
      let ns' = Domain_name.Host_set.singleton ns
      and soa = Soa.create ~serial:1l ns
      in
      Dns_trie.insert (n_of_s "two.com") Rr_map.Ns (300l, ns')
        (Dns_trie.insert (n_of_s "two.com") Rr_map.Soa soa data)
    in
    let server = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ~keys data' in
    let s', notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    Alcotest.(check int __LOC__ 2 (List.length (snd (List.hd notifications))));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "two.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    let s'', notifications = Dns_server.Primary.timer s' Ptime.epoch (Int64.add ts 1L) in
    Alcotest.(check int __LOC__ 0 (List.length notifications));
    let _, notifications = Dns_server.Primary.timer s' Ptime.epoch (Int64.add ts (Duration.of_ms 700)) in
    Alcotest.(check int __LOC__ 0 (List.length notifications));
    let _, notifications = Dns_server.Primary.timer s' Ptime.epoch (Int64.add ts (Duration.of_sec 1)) in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    Alcotest.(check int __LOC__ 2 (List.length (snd (List.hd notifications))));
    let _, notifications = Dns_server.Primary.timer s'' Ptime.epoch (Int64.add ts (Duration.of_sec 2)) in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    Alcotest.(check int __LOC__ 2 (List.length (snd (List.hd notifications))))

  let test_secondary () =
    let keys =
      let key = Nocrypto.Base64.encode (Cstruct.create 32) in
      [ n_of_s "1.2.3.4.9.10.11.12._transfer.one.com",
        { Dnskey.flags = 0 ; algorithm = SHA256 ; key } ]
    in
    let s =
      Dns_server.Secondary.create ~rng:Nocrypto.Rng.generate
        ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign keys
    in
    let s', reqs = Dns_server.Secondary.timer s Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length reqs));
    Alcotest.(check int __LOC__ 1 (List.length (snd (List.hd reqs))));
    let s'', reqs' = Dns_server.Secondary.timer s' Ptime.epoch (Int64.add ts (Duration.of_sec 2)) in
    Alcotest.(check int __LOC__ 0 (List.length reqs'));
    let _s'', reqs'' = Dns_server.Secondary.timer s'' Ptime.epoch (Int64.add ts (Duration.of_sec 3)) in
    Alcotest.(check int __LOC__ 1 (List.length reqs''));
    Alcotest.(check int __LOC__ 1 (List.length (snd (List.hd reqs''))))

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
    "multiple zones", `Quick, multiple_zones ;
    "secondary create", `Quick, test_secondary ;
  ]
end

module A = struct
  open Dns_server

  (* authentication tests *)
  let simple_deny () =
    List.iter (fun zone ->
        List.iter (fun op ->
            Alcotest.(check bool __LOC__ false
                        (Authentication.access op ~zone)))
          Authentication.all_ops)
      [ Domain_name.root ; Domain_name.of_string_exn "example.com" ;
        Domain_name.of_string_exn "foo.bar.com" ]

  let simple_allow () =
    List.iteri (fun i (op, zone, key, res) ->
        Alcotest.(check bool ("simple allow " ^ string_of_int i) res
                    (Authentication.access ~key ~zone op)))
      (List.map
         (fun (a, b, c, d) -> a, Domain_name.of_string_exn b, Domain_name.of_string_exn c, d)
         [
           (`Notify, "example.com", "foo._notify", true) ;
           (`Transfer, "example.com", "foo._notify", false) ;
           (`Update, "example.com", "foo._notify", false) ;
           (`Notify, "example.com", "foo._transfer", true) ;
           (`Transfer, "example.com", "foo._transfer", true) ;
           (`Update, "example.com", "foo._transfer", false) ;
           (`Notify, "example.com", "foo._update", true) ;
           (`Transfer, "example.com", "foo._update", true) ;
           (`Update, "example.com", "foo._update", true) ;

           (`Notify, "example.com", "foo._notify.example.com", true) ;
           (`Transfer, "example.com", "foo._notify.example.com", false) ;
           (`Update, "example.com", "foo._notify.example.com", false) ;
           (`Notify, "example.com", "foo._transfer.example.com", true) ;
           (`Transfer, "example.com", "foo._transfer.example.com", true) ;
           (`Update, "example.com", "foo._transfer.example.com", false) ;
           (`Notify, "example.com", "foo._update.example.com", true) ;
           (`Transfer, "example.com", "foo._update.example.com", true) ;
           (`Update, "example.com", "foo._update.example.com", true) ;

           (`Notify, "foo.example.com", "foo._notify.example.com", true) ;
           (`Transfer, "foo.example.com", "foo._notify.example.com", false) ;
           (`Update, "foo.example.com", "foo._notify.example.com", false) ;
           (`Notify, "foo.example.com", "foo._transfer.example.com", true) ;
           (`Transfer, "foo.example.com", "foo._transfer.example.com", true) ;
           (`Update, "foo.example.com", "foo._transfer.example.com", false) ;
           (`Notify, "foo.example.com", "foo._update.example.com", true) ;
           (`Transfer, "foo.example.com", "foo._update.example.com", true) ;
           (`Update, "foo.example.com", "foo._update.example.com", true) ;

           (`Notify, "example2.com", "foo._notify.example.com", false) ;
           (`Transfer, "example2.com", "foo._notify.example.com", false) ;
           (`Update, "example2.com", "foo._notify.example.com", false) ;
           (`Notify, "example2.com", "foo._transfer.example.com", false) ;
           (`Transfer, "example2.com", "foo._transfer.example.com", false) ;
           (`Update, "example2.com", "foo._transfer.example.com", false) ;
           (`Notify, "example2.com", "foo._update.example.com", false) ;
           (`Transfer, "example2.com", "foo._update.example.com", false) ;
           (`Update, "example2.com", "foo._update.example.com", false) ;

           (`Notify, "com", "foo._notify.example.com", false) ;
           (`Transfer, "com", "foo._notify.example.com", false) ;
           (`Update, "com", "foo._notify.example.com", false) ;
           (`Notify, "com", "foo._transfer.example.com", false) ;
           (`Transfer, "com", "foo._transfer.example.com", false) ;
           (`Update, "com", "foo._transfer.example.com", false) ;
           (`Notify, "com", "foo._update.example.com", false) ;
           (`Transfer, "com", "foo._update.example.com", false) ;
           (`Update, "com", "foo._update.example.com", false) ;

           (`Notify, "", "foo._notify.example.com", false) ;
           (`Transfer, "", "foo._notify.example.com", false) ;
           (`Update, "", "foo._notify.example.com", false) ;
           (`Notify, "", "foo._transfer.example.com", false) ;
           (`Transfer, "", "foo._transfer.example.com", false) ;
           (`Update, "", "foo._transfer.example.com", false) ;
           (`Notify, "", "foo._update.example.com", false) ;
           (`Transfer, "", "foo._update.example.com", false) ;
           (`Update, "", "foo._update.example.com", false) ;
         ])

  let axfr_test = Alcotest.testable Packet.Axfr.pp Packet.Axfr.equal

  let rcode_test = Alcotest.testable Rcode.pp (fun a b -> Rcode.compare a b = 0)

  let ip_of_s = Ipaddr.V4.of_string_exn

  let soa = Soa.create ~serial:1l (Domain_name.host_exn (n_of_s "ns.one.com"))

  let example_zone =
    let ns =
      Domain_name.(Host_set.(add (host_exn (n_of_s "ns3.one.com"))
                               (add (host_exn (n_of_s "ns2.one.com"))
                                  (singleton (host_exn (n_of_s "ns.one.com"))))))
    in
    Name_rr_map.(add (n_of_s "one.com") Rr_map.Ns (300l, ns)
                   (add (n_of_s "ns.one.com") Rr_map.A
                      (300l, Rr_map.Ipv4_set.singleton (ip_of_s "1.2.3.4"))
                      (add (n_of_s "ns2.one.com") Rr_map.A
                         (300l, Rr_map.Ipv4_set.singleton (ip_of_s "5.6.7.8"))
                         (add (n_of_s "ns3.one.com") Rr_map.A
                            (300l, Rr_map.Ipv4_set.(add (ip_of_s "10.0.0.1") (singleton (ip_of_s "192.168.1.1"))))
                            empty))))

  let example_trie =
    Dns_trie.insert (n_of_s "one.com") Soa soa
      (Dns_trie.insert_map example_zone Dns_trie.empty)

  let server ?unauthenticated_zone_transfer () =
    let p = Dns_server.Primary.create ~rng:Nocrypto.Rng.generate ?unauthenticated_zone_transfer example_trie in
    Dns_server.Primary.server p

  let axfr () =
    let server = server () in
    let axfr = soa, example_zone in
    let axfr_req = n_of_s "one.com", `Axfr in
    let key = Some (n_of_s "foo._transfer.one.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Ok axfr)
                (handle_axfr_request server `Tcp key axfr_req));
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.Refused)
                (handle_axfr_request server `Udp key axfr_req));
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.NotAuth)
                (handle_axfr_request server `Tcp None axfr_req));
    let key = Some (n_of_s "foo._notify.one.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.NotAuth)
                (handle_axfr_request server `Tcp key axfr_req));
    let key = Some (n_of_s "foo._update.one.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Ok axfr)
                (handle_axfr_request server `Tcp key axfr_req));
    let key = Some (n_of_s "foo._transfer.two.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.NotAuth)
                (handle_axfr_request server `Tcp key axfr_req));
    let key = Some (n_of_s "foo._transfer.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Ok axfr)
                (handle_axfr_request server `Tcp key axfr_req));
    let key = Some (n_of_s "foo._transfer") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Ok axfr)
                (handle_axfr_request server `Tcp key axfr_req));
    let key = Some (n_of_s "foo._transfer.sub.one.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.NotAuth)
                (handle_axfr_request server `Tcp key axfr_req))

  let no_axfr () =
    let server = server () in
    let axfr_req = n_of_s "two.com", `Axfr in
    let key = Some (n_of_s "foo._transfer.one.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.NotAuth)
                (handle_axfr_request server `Tcp key axfr_req));
    let key = Some (n_of_s "foo._transfer.two.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.NotAuth)
                (handle_axfr_request server `Tcp key axfr_req));
    let key = Some (n_of_s "foo._transfer") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.NotAuth)
                (handle_axfr_request server `Tcp key axfr_req))

  let unauthenticated_axfr () =
    let server = server ~unauthenticated_zone_transfer:true () in
    let axfr = soa, example_zone in
    let axfr_req = n_of_s "one.com", `Axfr in
    let key = Some (n_of_s "foo._transfer.one.com") in
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Ok axfr)
                (handle_axfr_request server `Tcp key axfr_req));
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Error Rcode.Refused)
                (handle_axfr_request server `Udp key axfr_req));
    Alcotest.(check (result axfr_test rcode_test) __LOC__ (Ok axfr)
                (handle_axfr_request server `Tcp None axfr_req))

  let trie_test = Alcotest.testable Dns_trie.pp Dns_trie.equal

  let zone_test =
    let module M = struct
      type t = ([`raw] Domain_name.t * Soa.t) list
      let pp =
        let pp_one ppf (name, soa) =
          Fmt.pf ppf "zone %a soa %a" Domain_name.pp name Soa.pp soa
        in
        Fmt.(list ~sep:(unit ", ") pp_one)
      let equal a b =
        List.length a = List.length b &&
        List.for_all2 (fun (n,s) (n',s') ->
            Domain_name.equal n n' && Soa.compare s s' = 0)
          a b
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let basic_update () =
    let server = server () in
    let q = Packet.Question.create (n_of_s "one.com") Soa in
    let up = Domain_name.Map.empty, Domain_name.Map.empty in
    let key = n_of_s "foo._update.one.com" in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (example_trie, []))
                (handle_update server `Udp (Some key) q up));
    let q' = Packet.Question.create (n_of_s "two.com") Soa in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Error Rcode.NotAuth)
                (handle_update server `Udp (Some key) q' up));
    let key = n_of_s "foo._update.com" in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (example_trie, []))
                (handle_update server `Udp (Some key) q up));
    (* reason for this is the update is empty, and the key may create zones *)
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (example_trie, []))
                (handle_update server `Udp (Some key) q' up));
    let key = n_of_s "foo._update" in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (example_trie, []))
                (handle_update server `Udp (Some key) q up));
    let key = n_of_s "foo._transfer.one.com" in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Error Rcode.NotAuth)
                (handle_update server `Udp (Some key) q up));
    let key = n_of_s "foo._notify.one.com" in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Error Rcode.NotAuth)
                (handle_update server `Udp (Some key) q up));
    let key = n_of_s "foo._update.two.com" in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Error Rcode.NotAuth)
                (handle_update server `Udp (Some key) q up));
    let key = n_of_s "foo._update.two.com" in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Error Rcode.NotAuth)
                (handle_update server `Udp (Some key) q up))

  let actual_update () =
    let server = server () in
    let q = Packet.Question.create (n_of_s "one.com") Soa in
    let foo, entry_key, entry_val =
      n_of_s "foo.one.com", Rr_map.A,
      (300l, Rr_map.Ipv4_set.singleton (ip_of_s "127.0.0.1"))
    in
    let up =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo [
        Packet.Update.Add Rr_map.(B (entry_key, entry_val))
      ]
    in
    let key = n_of_s "foo._update.one.com" in
    let soa' = { soa with serial = Int32.succ soa.serial } in
    let trie' =
      Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa'
        (Dns_trie.insert foo entry_key entry_val example_trie)
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (trie', [ n_of_s "one.com", soa' ]))
                (handle_update server `Udp (Some key) q up));
    let soa'' = { soa' with serial = Int32.succ soa'.serial } in
    let up' =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo [ Packet.Update.Remove_all ]
    in
    let server' = with_data server trie' in
    let old_trie = Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa'' example_trie in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (old_trie, [ n_of_s "one.com", soa'' ]))
                (handle_update server' `Udp (Some key) q up'));
    let up' =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo [ Packet.Update.Remove (Rr_map.K entry_key) ]
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (old_trie, [ n_of_s "one.com", soa'' ]))
                (handle_update server' `Udp (Some key) q up'));
    let up' =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo [ Packet.Update.Remove_single (Rr_map.B (entry_key, entry_val)) ]
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (old_trie, [ n_of_s "one.com", soa'' ]))
                (handle_update server' `Udp (Some key) q up'))

  (* TODO test prereq and more updates *)

  let tests = [
    "simple deny auth", `Quick, simple_deny ;
    "simple allow auth", `Quick, simple_allow ;
    "AXFR", `Quick, axfr ;
    "no AXFR", `Quick, no_axfr ;
    "unauthenticated AXFR", `Quick, unauthenticated_axfr ;
    "basic update", `Quick, basic_update ;
    "actual update", `Quick, actual_update ;
  ]
end

let tests = [
  "Trie", Trie.tests ;
  "Server", S.tests ;
  "Authentication", A.tests ;
]

let () =
  Nocrypto_entropy_unix.initialize ();
  Alcotest.run "DNS server tests" tests
