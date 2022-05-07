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

  let glue_ok =
    let module M = struct
      type t = (int32 * Ipaddr.V4.Set.t) option * (int32 * Ipaddr.V6.Set.t) option
      let pp ppf (v4, v6) =
        let pp_v4 ppf v4 =
          Fmt.(list ~sep:(any ",") Ipaddr.V4.pp) ppf (Ipaddr.V4.Set.elements v4)
        and pp_v6 ppf v6 =
          Fmt.(list ~sep:(any ",") Ipaddr.V6.pp) ppf (Ipaddr.V6.Set.elements v6)
        in
        Fmt.pf ppf "V4 %a@ V6 %a"
          Fmt.(option ~none:(any "none") (pair ~sep:(any ", ") int32 pp_v4)) v4
          Fmt.(option ~none:(any "none") (pair ~sep:(any ", ") int32 pp_v6)) v6
      let equal a b = match a, b with
        | (None, None), (None, None) -> true
        | (Some (ttl, v4), None), (Some (ttl', v4'), None) ->
          ttl = ttl' && Ipaddr.V4.Set.equal v4 v4'
        | (None, Some (ttl, v6)), (None, Some (ttl', v6')) ->
          ttl = ttl' && Ipaddr.V6.Set.equal v6 v6'
        | (Some (ttl, v4), Some (ttl6, v6)), (Some (ttl', v4'), Some (ttl6', v6')) ->
          ttl = ttl' && Ipaddr.V4.Set.equal v4 v4' &&
            ttl6 = ttl6' && Ipaddr.V6.Set.equal v6 v6'
        | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let l_ok =
    let module M = struct
      type t = Rr_map.b * ([ `raw ] Domain_name.t * int32 * Domain_name.Host_set.t)
      let pp ppf (v, (name, ttl, ns)) =
        Fmt.pf ppf "%a auth %a TTL %lu %a" Rr_map.pp_b v Domain_name.pp name ttl
          Fmt.(list ~sep:(any ",@,") Domain_name.pp) (Domain_name.Host_set.elements ns)
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
    let a_record = (23l, Ipaddr.V4.Set.singleton (ip "1.4.5.2")) in
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
    let a_record = (12l, Ipaddr.V4.Set.singleton (ip "1.2.3.4")) in
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

  let no_soa () =
    let a_record = (23l, Ipaddr.V4.Set.singleton (ip "1.4.5.2")) in
    let t = insert (n_of_s "ns1.foo.com") Rr_map.A a_record empty in
    Alcotest.(check (result b_ok e) "lookup_with_cname for NS foo.com without SOA fails"
                (Error `NotAuthoritative)
                (r_fst (lookup_with_cname (n_of_s "foo.com") Ns t))) ;
    Alcotest.(check (result b_ok e) "lookup_with_cname for A ns1.foo.com without SOA fails"
                (Error `NotAuthoritative)
                (r_fst (lookup_with_cname (n_of_s "ns1.foo.com") A t))) ;
    Alcotest.(check (result b_ok e) "lookup_b for NS foo.com without SOA fails"
                (Error `NotAuthoritative)
                (lookup_b (n_of_s "foo.com") Ns t)) ;
    Alcotest.(check (result b_ok e) "lookup_b for A ns1.foo.com without SOA fails"
                (Error `NotAuthoritative)
                (lookup_b (n_of_s "ns1.foo.com") A t)) ;
    Alcotest.(check glue_ok "lookup_glue for ns1.foo.com without SOA finds ip"
                (Some a_record, None)
                (Dns_trie.lookup_glue (n_of_s "ns1.foo.com") t))

  let subdomain_zone () =
    let soa = {
      Soa.nameserver = n_of_s "ns1.foo.com" ;
      hostmaster = n_of_s "hs.foo.com" ;
      serial = 1l ; refresh = 10l ; retry = 5l ; expiry = 3l ; minimum = 4l
    } in
    let myzone = n_of_s "foo.com" in
    let t =
      ins_zone myzone soa 10l (sn (n_of_s "ns1.foo.com")) empty
    in
    match Dns_trie.entries myzone t with
    | Error _ -> Alcotest.fail "Expected some entries"
    | Ok (soa, entries) ->
      let sub = n_of_s "bar.foo.com"
      and sub_ns = sn (n_of_s "ns2.foo.com")
      in
      let t = ins_zone sub soa 10l sub_ns t in
      let t =
        insert (n_of_s "foo.bar.foo.com")
          Rr_map.A (10l, Ipaddr.V4.Set.singleton (ip "1.4.5.2")) t
      in
      match Dns_trie.entries myzone t with
      | Error _ -> Alcotest.fail "Expected some entries"
      | Ok (soa', entries') ->
        Alcotest.(check bool "SOA is the same" true (Soa.compare soa' soa = 0));
        let entries'' =
          match Domain_name.Map.find sub entries' with
          | Some rr ->
            Alcotest.(check int "exactly one rr (delegation)" 1 (Rr_map.cardinal rr));
            Alcotest.(check bool "it is the NS" true
                        (Rr_map.equal_rr Ns (Rr_map.get Ns rr) (10l, sub_ns)));
            Domain_name.Map.remove sub entries'
          | None -> Alcotest.fail "expected a NS record"
        in
        Alcotest.(check bool "rrs are the same" true
                    (Name_rr_map.equal entries entries''))

  let tests = [
    "simple", `Quick, simple ;
    "basic", `Quick, basic ;
    "alias", `Quick, alias ;
    "delegation", `Quick, dele ;
    "rmzone", `Quick, rmzone ;
    "zone", `Quick, zone ;
    "no soa", `Quick, no_soa ;
    "subdomain and entries", `Quick, subdomain_zone ;
  ]
end

module S = struct

  let ipv4 =
    let module M = struct
      type t = Ipaddr.V4.t
      let pp = Ipaddr.V4.pp
      let equal a b = Ipaddr.V4.compare a b = 0
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let ip =
    let module M = struct
      type t = Ipaddr.t
      let pp = Ipaddr.pp
      let equal a b = Ipaddr.compare a b = 0
    end in
    (module M : Alcotest.TESTABLE with type t = M.t)

  let ipset = Alcotest.(slist ip Ipaddr.compare)

  let ipv4_of_s = Ipaddr.V4.of_string_exn

  let ip_of_s s = Ipaddr.V4 (ipv4_of_s s)

  let ts = Duration.of_sec 5

  let data =
    let ns = Domain_name.host_exn (n_of_s "ns.one.com") in
    let soa = Soa.create ~serial:1l ns in
    Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa
      (Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, Domain_name.Host_set.singleton ns)
         (Dns_trie.insert ns Rr_map.A (300l, Ipaddr.V4.Set.singleton Ipaddr.V4.localhost)
            Dns_trie.empty))

  let simple () =
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate data in
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
           (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "10.0.0.2")) data)
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2"] (List.map fst tbn)

  let secondary_in_other_zone () =
    let data =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns.one.com"))
                                 (singleton (host_exn (n_of_s "ns2.two.com")))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.two.com") Rr_map.A
           (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "10.0.0.2")) data)
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate data in
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
        Ipaddr.V4.Set.(add (ipv4_of_s "10.0.0.2") (singleton (ipv4_of_s "1.2.3.4")))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A (300l, ips) data)
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate data in
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
           (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "10.0.0.2"))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "10.0.0.3"))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate data' in
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
           (300l, Ipaddr.V4.Set.(add (ipv4_of_s "10.0.0.2") (singleton (ipv4_of_s "10.0.0.3"))))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Ipaddr.V4.Set.(add (ipv4_of_s "10.0.0.3") (singleton (ipv4_of_s "10.0.0.4"))))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate data' in
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
                    (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "10.0.0.2"))
                    (Dns_trie.insert (n_of_s "ns.bar.com") Rr_map.A
                       (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "10.0.0.3"))
                       (Dns_trie.insert (n_of_s "ns.one.com") Rr_map.A
                          (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "10.0.0.4"))
                          Dns_trie.empty))))))
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 2 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 2 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "10.0.0.2";ip_of_s "10.0.0.3"]
      (List.map fst tbn)

  let secondary_via_key () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = Dnskey.F.empty ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate ~keys data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8"] (List.map fst tbn)

  let secondary_via_root_key () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer",
        { Dnskey.flags = Dnskey.F.empty ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate ~keys data in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 1 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 1 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "5.6.7.8"] (List.map fst tbn)

  let secondaries_and_keys () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = Dnskey.F.empty ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns3.one.com"))
                                 (add (host_exn (n_of_s "ns2.one.com"))
                                    (singleton (host_exn (n_of_s "ns.one.com"))))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "1.1.1.1"))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Ipaddr.V4.Set.(add (ipv4_of_s "10.0.0.1") (singleton (ipv4_of_s "192.168.1.1"))))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate ~keys data' in
    let _, notifications = Dns_server.Primary.timer server Ptime.epoch ts in
    Alcotest.(check int __LOC__ 4 (List.length notifications));
    let tbn = Dns_server.Primary.to_be_notified server (Domain_name.host_exn (n_of_s "one.com")) in
    Alcotest.(check int __LOC__ 4 (List.length tbn));
    Alcotest.check ipset __LOC__ [ip_of_s "1.1.1.1" ; ip_of_s "5.6.7.8" ; ip_of_s "10.0.0.1" ; ip_of_s "192.168.1.1"]
      (List.map fst tbn)

  let secondaries_and_keys_dups () =
    let keys =
      [ n_of_s "1.2.3.4.5.6.7.8._transfer.one.com",
        { Dnskey.flags = Dnskey.F.empty ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns =
        Domain_name.(Host_set.(add (host_exn (n_of_s "ns3.one.com"))
                                 (add (host_exn (n_of_s "ns2.one.com"))
                                    (singleton (host_exn (n_of_s "ns.one.com"))))))
      in
      Dns_trie.insert (n_of_s "one.com") Rr_map.Ns (300l, ns)
        (Dns_trie.insert (n_of_s "ns2.one.com") Rr_map.A
           (300l, Ipaddr.V4.Set.singleton (ipv4_of_s "5.6.7.8"))
           (Dns_trie.insert (n_of_s "ns3.one.com") Rr_map.A
              (300l, Ipaddr.V4.Set.(add (ipv4_of_s "10.0.0.1") (singleton (ipv4_of_s "192.168.1.1"))))
              data))
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate ~keys data' in
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
        { Dnskey.flags = Dnskey.F.empty ; algorithm = SHA256 ; key = Cstruct.create 10 } ]
    in
    let data' =
      let ns = Domain_name.(host_exn (n_of_s "ns.one.com")) in
      let ns' = Domain_name.Host_set.singleton ns
      and soa = Soa.create ~serial:1l ns
      in
      Dns_trie.insert (n_of_s "two.com") Rr_map.Ns (300l, ns')
        (Dns_trie.insert (n_of_s "two.com") Rr_map.Soa soa data)
    in
    let server = Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate ~keys data' in
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
      let key = String.make 32 '\000' |> Base64.encode_string |> Cstruct.of_string in
      [ n_of_s "1.2.3.4.9.10.11.12._transfer.one.com",
        { Dnskey.flags = Dnskey.F.empty ; algorithm = SHA256 ; key } ]
    in
    let s =
      Dns_server.Secondary.create ~rng:Mirage_crypto_rng.generate
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
    "secondary in non-authoritative zone", `Quick, secondary_in_other_zone ;
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

  let access_granted () =
    (* a list of "required" "provided" "expected result" *)
    let operations_and_permissions = [
      `Update, `Update, true ;
      `Transfer, `Update, true ;
      `Notify, `Update, true ;

      `Update, `Transfer, false ;
      `Transfer, `Transfer, true ;
      `Notify, `Transfer, true ;

      `Update, `Notify, false ;
      `Transfer, `Notify, false ;
      `Notify, `Notify, true ;
    ] in
    List.iteri (fun i (required, provided, exp) ->
        Alcotest.(check bool (__LOC__ ^ " test #" ^ string_of_int i) exp
                    (Authentication.access_granted ~required provided)))
      operations_and_permissions

  let test_zone_op =
    let module M = struct
      type t = [`host] Domain_name.t * Authentication.operation
      let equal (n, op) (n', op') = Domain_name.equal n n' && op = op'
      let pp ppf (n, op) =
        Fmt.pf ppf "zone %a op %s" Domain_name.pp n
          (Authentication.operation_to_string op)
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let host n = n_of_s n |> Domain_name.host_exn

  let zone_and_op () =
    (* a list of Domain_name.t and the expected zone and operation, if any *)
    let test_values = [
      Domain_name.root, None ;
      n_of_s "foo.com", None ;
      n_of_s "this.is.my.transfer.or.update.or.notify.foo.com", None ;
      n_of_s "this.is.my.transfer.or._update._or.notify.foo.com", None ;
      n_of_s "this.is.my.transfer.or._update.or.notify.foo.com", Some (host "or.notify.foo.com", `Update) ;
      n_of_s "_transfer.foo.com", Some (host "foo.com", `Transfer) ;
      n_of_s "_update._transfer", Some (host "", `Transfer) ;
      n_of_s "_update.foo._transfer.com", Some (host "com", `Transfer) ;
      n_of_s "_notify.foo._update.com", Some (host "com", `Update) ;
      n_of_s "_update.foo._notify.com", Some (host "com", `Notify) ;
      n_of_s "_transfer.foo._notify.com", Some (host "com", `Notify) ;
      n_of_s "_transfer.foo.notify.com", Some (host "foo.notify.com", `Transfer) ;
    ] in
    List.iteri (fun i (name, exp) ->
        Alcotest.(check (option test_zone_op)
                    (__LOC__ ^ " test #" ^ string_of_int i) exp
                    (Authentication.zone_and_operation name)))
      test_values

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

  let example_ns =
    Domain_name.(Host_set.(add (host_exn (n_of_s "ns3.one.com"))
                             (add (host_exn (n_of_s "ns2.one.com"))
                                (singleton (host_exn (n_of_s "ns.one.com"))))))
  let example_zone =
    Name_rr_map.(add (n_of_s "one.com") Rr_map.Ns (300l, example_ns)
                   (add (n_of_s "ns.one.com") Rr_map.A
                      (300l, Ipaddr.V4.Set.singleton (ip_of_s "1.2.3.4"))
                      (add (n_of_s "ns2.one.com") Rr_map.A
                         (300l, Ipaddr.V4.Set.singleton (ip_of_s "5.6.7.8"))
                         (add (n_of_s "ns3.one.com") Rr_map.A
                            (300l, Ipaddr.V4.Set.(add (ip_of_s "10.0.0.1") (singleton (ip_of_s "192.168.1.1"))))
                            empty))))

  let example_trie =
    Dns_trie.insert (n_of_s "one.com") Soa soa
      (Dns_trie.insert_map example_zone Dns_trie.empty)

  let server ?unauthenticated_zone_transfer () =
    let p = Primary.create ~rng:Mirage_crypto_rng.generate ?unauthenticated_zone_transfer example_trie in
    Primary.server p

  let answer_test = Alcotest.testable Packet.Answer.pp Packet.Answer.equal

  let h_q_test =
    let fl_test =
      let module M = struct
        type t = Packet.Flags.t
        let pp ppf t = Fmt.(list ~sep:(any ",") Packet.Flag.pp) ppf (Packet.Flags.elements t)
        let equal = Packet.Flags.equal
      end in
      (module M: Alcotest.TESTABLE with type t = M.t)
    in
    Alcotest.(result (pair fl_test answer_test)
                (pair rcode_test (option answer_test)))

  (* TODO test additional as well *)
  let h_q t q =
    match handle_question t q with Ok (a, b, _) -> Ok (a, b) | Error e -> Error e

  let question () =
    let server = server () in
    let query = Packet.Question.create (n_of_s "one.com") Soa in
    let answer = Name_rr_map.singleton (n_of_s "one.com") Soa soa
    and auth = Name_rr_map.singleton (n_of_s "one.com") Ns (300l, example_ns)
    in
    Alcotest.(check h_q_test __LOC__
                (Ok (Packet.Flags.singleton `Authoritative, (answer, auth)))
                (h_q server query));
    let query = Packet.Question.create (n_of_s "ns.one.com") A in
    let answer =
      Name_rr_map.singleton (n_of_s "ns.one.com") A
        (300l, Ipaddr.V4.Set.singleton (ip_of_s "1.2.3.4"))
    in
    Alcotest.(check h_q_test __LOC__
                (Ok (Packet.Flags.singleton `Authoritative, (answer, auth)))
                (h_q server query));
    let query = Packet.Question.create (n_of_s "one.com") Mx in
    let answer = Name_rr_map.empty
    and auth = Name_rr_map.singleton (n_of_s "one.com") Soa soa
    in
    Alcotest.(check h_q_test __LOC__
                (Ok (Packet.Flags.singleton `Authoritative, (answer, auth)))
                (h_q server query));
    let query = Packet.Question.create (n_of_s "foo.one.com") Mx in
    Alcotest.(check h_q_test __LOC__
                (Error (Rcode.NXDomain, Some (answer, auth)))
                (h_q server query));
    let query = Packet.Question.create (n_of_s "one.com") Ns in
    let answer = Name_rr_map.singleton (n_of_s "one.com") Ns (300l, example_ns)
    and auth = Name_rr_map.empty
    in
    Alcotest.(check h_q_test __LOC__
                (Ok (Packet.Flags.singleton `Authoritative, (answer, auth)))
                (h_q server query));
    let query = Packet.Question.create (n_of_s "two.com") Ns in
    Alcotest.(check h_q_test __LOC__
                (Error (Rcode.NotAuth, None))
                (h_q server query))

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

  let ixfr_test = Alcotest.testable Packet.Ixfr.pp Packet.Ixfr.equal

  let ixfr () =
    let primary = Primary.create ~rng:Mirage_crypto_rng.generate example_trie in
    let server = Primary.server primary in
    let cache = Primary.trie_cache primary in
    let key = Some (n_of_s "foo._transfer.one.com") in
    let ixfr_req = Packet.Question.create (n_of_s "one.com") Soa in
    Alcotest.(check (result ixfr_test rcode_test) __LOC__ (Ok (soa, `Empty))
                (handle_ixfr_request server cache `Tcp key ixfr_req soa));
    let soa' = { soa with serial = Int32.succ soa.serial } in
    let foo, entry_k, entry_v = n_of_s "foo.one.com", Rr_map.A, (300l, Ipaddr.V4.Set.singleton (ip_of_s "127.0.0.1")) in
    let trie' =
      Dns_trie.insert (n_of_s "one.com") Soa soa'
        (Dns_trie.insert foo entry_k entry_v (Primary.data primary))
    in
    let primary', _ = Primary.with_data primary Ptime.epoch 0L trie' in
    let server' = Primary.server primary' in
    let cache' = Primary.trie_cache primary' in
    let update =
      `Difference (soa, Name_rr_map.empty, Name_rr_map.singleton foo entry_k entry_v)
    in
    Alcotest.(check (result ixfr_test rcode_test) __LOC__ (Ok (soa', update))
                (handle_ixfr_request server' cache' `Tcp key ixfr_req soa));
    let soa'' = { soa with serial = Int32.succ soa'.serial } in
    let trie'' =
      Dns_trie.insert (n_of_s "one.com") Soa soa''
        (Dns_trie.remove foo entry_k entry_v trie')
    in
    let primary'', _ = Primary.with_data primary' Ptime.epoch 0L trie'' in
    let server'' = Primary.server primary'' in
    let cache'' = Primary.trie_cache primary'' in
    let update = `Difference (soa, Name_rr_map.empty, Name_rr_map.empty) in
    Alcotest.(check (result ixfr_test rcode_test) __LOC__ (Ok (soa'', update))
                (handle_ixfr_request server'' cache'' `Tcp key ixfr_req soa));
    let update' = `Difference (soa', Name_rr_map.singleton foo entry_k entry_v, Name_rr_map.empty) in
    Alcotest.(check (result ixfr_test rcode_test) __LOC__ (Ok (soa'', update'))
                (handle_ixfr_request server'' cache'' `Tcp key ixfr_req soa'));
    let soa''' = { soa with serial = Int32.pred soa.serial } in
    let update'' = `Full example_zone in
    Alcotest.(check (result ixfr_test rcode_test) __LOC__ (Ok (soa'', update''))
                (handle_ixfr_request server'' cache'' `Tcp key ixfr_req soa'''))

  let trie_test = Alcotest.testable Dns_trie.pp Dns_trie.equal

  let zone_test =
    let module M = struct
      type t = ([`raw] Domain_name.t * Soa.t) list
      let pp =
        let pp_one ppf (name, soa) =
          Fmt.pf ppf "zone %a soa %a" Domain_name.pp name Soa.pp soa
        in
        Fmt.(list ~sep:(any ", ") pp_one)
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
      (300l, Ipaddr.V4.Set.singleton (ip_of_s "127.0.0.1"))
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
                (handle_update server' `Udp (Some key) q up'));
    let up' =
      Domain_name.Map.empty,
      Domain_name.Map.singleton (n_of_s "one.com") [ Packet.Update.Remove (Rr_map.K Soa) ]
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (Dns_trie.empty, [ n_of_s "one.com", soa'' ]))
                (handle_update server' `Udp (Some key) q up'))

  let actual_update_hostname_key () =
    let server = server () in
    let q = Packet.Question.create (n_of_s "foo.one.com") Soa in
    let foo, entry_key, entry_val =
      n_of_s "foo.one.com", Rr_map.A,
      (300l, Ipaddr.V4.Set.singleton (ip_of_s "127.0.0.1"))
    in
    let up =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo [
        Packet.Update.Add Rr_map.(B (entry_key, entry_val))
      ]
    in
    let key = n_of_s "mykey._update.foo.one.com" in
    let soa' = { soa with serial = Int32.succ soa.serial } in
    let trie' =
      Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa'
        (Dns_trie.insert foo entry_key entry_val example_trie)
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (trie', [ n_of_s "one.com", soa' ]))
                (handle_update server `Udp (Some key) q up))

  let trie_with_two trie =
    Dns_trie.insert (n_of_s "two.com") Soa soa
      (Dns_trie.insert (n_of_s "two.com") Ns (300l, example_ns) trie)

  let update_zone_regression () =
    (* implementation incremented serial of all zones for one update *)
    let server =
      let initial_server = server () in
      Dns_server.with_data initial_server (trie_with_two initial_server.data)
    in
    let q = Packet.Question.create (n_of_s "one.com") Soa in
    let foo, entry_key, entry_val =
      n_of_s "foo.one.com", Rr_map.A,
      (300l, Ipaddr.V4.Set.singleton (ip_of_s "127.0.0.1"))
    in
    let up =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo [
        Packet.Update.Add Rr_map.(B (entry_key, entry_val))
      ]
    in
    let key = n_of_s "foo._update.one.com" in
    let soa_plus_1 = { soa with serial = Int32.succ soa.serial } in
    let trie_with_foo =
      Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa_plus_1
        (Dns_trie.insert foo entry_key entry_val server.data)
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (trie_with_foo, [ n_of_s "one.com", soa_plus_1 ]))
                (handle_update server `Udp (Some key) q up));
    let server_with_foo = Dns_server.with_data server trie_with_foo in
    let soa_plus_2 = { soa_plus_1 with serial = Int32.succ soa_plus_1.serial } in
    let trie_without_foo_soa_plus_2 =
      Dns_trie.insert (n_of_s "one.com") Rr_map.Soa soa_plus_2 server.data
    in
    let up =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo [ Packet.Update.Remove (Rr_map.K entry_key) ]
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (trie_without_foo_soa_plus_2, [ n_of_s "one.com", soa_plus_2 ]))
                (handle_update server_with_foo `Udp (Some key) q up));
    let foo_two = n_of_s "foo.two.com" in
    let key_two = n_of_s "foo._update.two.com" in
    let q_two = Packet.Question.create (n_of_s "two.com") Soa in
    let up =
      Domain_name.Map.empty,
      Domain_name.Map.singleton foo_two [
        Packet.Update.Add Rr_map.(B (entry_key, entry_val))
      ]
    in
    let server_without_foo_soa_plus2 =
      Dns_server.with_data server_with_foo trie_without_foo_soa_plus_2
    in
    let trie_with_foo_two =
      Dns_trie.insert (n_of_s "two.com") Rr_map.Soa soa_plus_1
        (Dns_trie.insert foo_two entry_key entry_val trie_without_foo_soa_plus_2)
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (trie_with_foo_two, [ n_of_s "two.com", soa_plus_1 ]))
                (handle_update server_without_foo_soa_plus2 `Udp (Some key_two) q_two up));
    let q_root = Packet.Question.create Domain_name.root Soa in
    let up =
      Domain_name.Map.empty,
      Domain_name.Map.add foo [ Packet.Update.Remove (Rr_map.K entry_key) ]
        (Domain_name.Map.singleton foo_two [ Packet.Update.Remove (Rr_map.K entry_key) ])
    in
    let server_with_foo_one_and_foo_two =
      Dns_server.with_data server_without_foo_soa_plus2
        (Dns_trie.insert foo entry_key entry_val trie_with_foo_two)
    in
    let key_root = n_of_s "foo._update" in
    let soa_plus_3 = { soa_plus_2 with serial = Int32.succ soa_plus_2.serial } in
    let exp_trie =
      Dns_trie.insert (n_of_s "one.com") Soa soa_plus_3
        (Dns_trie.insert (n_of_s "two.com") Soa soa_plus_2 trie_without_foo_soa_plus_2)
    in
    Alcotest.(check (result (pair trie_test zone_test) rcode_test)
                __LOC__ (Ok (exp_trie, [ n_of_s "two.com", soa_plus_2 ; n_of_s "one.com", soa_plus_3 ]))
                (handle_update server_with_foo_one_and_foo_two `Udp (Some key_root) q_root up))

  (* TODO test prereq and more updates *)

  let tests = [
    "access granted", `Quick, access_granted ;
    "zone and operation", `Quick, zone_and_op ;
    "simple deny auth", `Quick, simple_deny ;
    "simple allow auth", `Quick, simple_allow ;
    "question", `Quick, question ;
    "AXFR", `Quick, axfr ;
    "no AXFR", `Quick, no_axfr ;
    "unauthenticated AXFR", `Quick, unauthenticated_axfr ;
    "ixfr", `Quick, ixfr ;
    "basic update", `Quick, basic_update ;
    "actual update", `Quick, actual_update ;
    "actual update with hostname key", `Quick, actual_update_hostname_key ;
    "update zone regression", `Quick, update_zone_regression ;
  ]
end

module Axfr = struct
  let buf_axfr_test server axfr_req =
    let req =
      let header = 0x1234, Packet.Flags.empty in
      let res = Packet.create header axfr_req `Axfr_request in
      fst (Packet.encode `Tcp res)
    in
    let _server', answers, _notifies, _notify, _key =
      Dns_server.Primary.handle_buf server Ptime.epoch 0L `Tcp (Ipaddr.V4 Ipaddr.V4.localhost) 1234 req
    in
    answers

  let p_cs = Alcotest.testable Cstruct.hexdump_pp Cstruct.equal

  let axfr_server ?(trie = A.example_trie) () =
    Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate
      ~unauthenticated_zone_transfer:true trie

  let axfr_encoding () =
    let s = axfr_server () in
    let server = Dns_server.Primary.server s in
    let axfr = A.soa, A.example_zone in
    let axfr_req = n_of_s "one.com", `Axfr in
    Alcotest.(check (result A.axfr_test A.rcode_test) __LOC__ (Ok axfr)
                (Dns_server.handle_axfr_request server `Tcp None axfr_req));
    let cs = Cstruct.of_hex {|
12 34 84 00 00 01 00 09  00 00 00 00 03 6f 6e 65
03 63 6f 6d 00 00 fc 00  01 c0 0c 00 06 00 01 00
00 0e 10 00 26 02 6e 73  c0 0c 0a 68 6f 73 74 6d
61 73 74 65 72 c0 0c 00  00 00 01 00 01 51 80 00
00 1c 20 00 36 ee 80 00  00 0e 10 c0 0c 00 02 00
01 00 00 01 2c 00 02 c0  25 c0 0c 00 02 00 01 00
00 01 2c 00 06 03 6e 73  32 c0 0c c0 0c 00 02 00
01 00 00 01 2c 00 06 03  6e 73 33 c0 0c c0 25 00
01 00 01 00 00 01 2c 00  04 01 02 03 04 c0 65 00
01 00 01 00 00 01 2c 00  04 05 06 07 08 c0 77 00
01 00 01 00 00 01 2c 00  04 0a 00 00 01 c0 77 00
01 00 01 00 00 01 2c 00  04 c0 a8 01 01 c0 0c 00
06 00 01 00 00 0e 10 00  18 c0 25 c0 2a 00 00 00
01 00 01 51 80 00 00 1c  20 00 36 ee 80 00 00 0e
10|}
    in
    Alcotest.(check (list p_cs) __LOC__ [cs] (buf_axfr_test s axfr_req))

  let big_zone k =
    let big_txt_512 = Rr_map.Txt_set.of_list
        [ "12345678901234567890123456789012345678901234567890 \
           12345678901234567890123456789012345678901234567809 \
           12345678901234567890123456789012345678901234567089 \
           12345678901234567890123456789012345678901234560789 \
           123456789012345678901234567890123456789" ;
          "12345678901234567890123456789012345678901234056789 \
           12345678901234567890123456789012345678901230456789 \
           12345678901234567890123456789012345678901203456789 \
           12345678901234567890123456789012345678901023456789 \
           123456789012345678901234567890123456789"
        ]
    in
    let rec fill acc = function
      | 0 -> acc
      | n ->
        (* should lead to 1024 bytes binary size:
           name: yyy.<ptr> (= 4 + 2)
           type, class, ttl, rdlen: 10
           rd: 1 byte len + value (239) -> 240
           --> 256 bytes
        *)
        let name = n_of_s (Printf.sprintf "%03d.one.com" (2 * n + 1)) in
        let acc = Name_rr_map.add name Rr_map.Txt (300l, big_txt_512) acc in
        let name = n_of_s (Printf.sprintf "%03d.one.com" (2 * n)) in
        let acc = Name_rr_map.add name Rr_map.Txt (300l, big_txt_512) acc in
        fill acc (pred n)
    in
    fill A.example_zone k

  let trie_of_zone zone =
    Dns_trie.insert (n_of_s "one.com") Soa A.soa
      (Dns_trie.insert_map zone Dns_trie.empty)

  let zone add =
    let more = [
      "foobar00"; "foobar01"; "foobar02"; "foobar03"; "foobar04";
      "foobar05"; "foobar06"; "foobar07"; "foobar08"; "foobar09";
      "foobar10"; "foobar11"; "foobar12"; "foobar13"; "foobar14";
      "foobar15"; "foobar16"; "foobar17"; "foobar18"; "foobar19";
      "foobar20"; "foobar21"; "foobar22"; "foobar23"; "foobar24";
      "foobar25"; "foobar26"; "foobar27"; "foobar28"; "foobar29";
      "foobar30"; "foobar31"; "foobar32"; "foobar33"; "foobar34";
      "foobar35"; "foobar36"; "foobar37"; "foobar38"; "foobar39";
      "foobar40"; "foobar41"; "foobar42"; "foobar43"; "12345foobar44" ^ add
    ]
    in
    let z =
      Name_rr_map.add (n_of_s "one.com")
        Rr_map.Txt (300l, Rr_map.Txt_set.of_list more) (big_zone 62)
    in
    trie_of_zone z

  let axfr_encoding_big_zone_no_split () =
    (* big_zone 63 results in an AXFR which is 65241 bytes big *)
    (* the `more` below extends it to 65535 bytes (max size for a TCP frame) *)
    (* the biggest zone to fit into a single DNS packet *)
    let trie = zone "" in
    let s = axfr_server ~trie () in
    let axfr_req = n_of_s "one.com", `Axfr in
    let bufs = buf_axfr_test s axfr_req in
    Alcotest.(check int __LOC__ 1 (List.length bufs));
    Alcotest.(check int __LOC__ 65535 (Cstruct.length (List.hd bufs)));
    match Packet.decode (List.hd bufs) with
    | Ok _ -> ()
    | Error e ->
      Alcotest.fail ("AXFR decoding error " ^ Fmt.to_to_string Packet.pp_err e)

  let axfr_encoding_big_zone_one_split () =
    (* the first zone to split into multiple packets *)
    let trie = zone "1" in
    let s = axfr_server ~trie () in
    let axfr_req = n_of_s "one.com", `Axfr in
    let bufs = buf_axfr_test s axfr_req in
    Alcotest.(check int __LOC__ 2 (List.length bufs));
    Alcotest.(check int __LOC__ 65500 (Cstruct.length (List.hd bufs)));
    Alcotest.(check int __LOC__ 75 (Cstruct.length (List.hd (List.tl bufs))))

  let axfr_encoding_big_zone_multiple_splits () =
    (* a zone split over multiple packages *)
    let trie = trie_of_zone (big_zone 200) in
    let s = axfr_server ~trie () in
    let axfr_req = n_of_s "one.com", `Axfr in
    Alcotest.(check int __LOC__ 4 (List.length (buf_axfr_test s axfr_req)))

  let signed_zone add =
    let more = [
      "foobar00"; "foobar01"; "foobar02"; "foobar03"; "foobar04";
      "foobar05"; "foobar06"; "foobar07"; "foobar08"; "foobar09";
      "foobar10"; "foobar11"; "foobar12"; "foobar13"; "foobar14";
      "foobar15"; "foobar16"; "foobar17"; "foobar18"; "foobar19";
      "foobar20"; "foobar21"; "foobar22"; "foobar23"; "foobar24";
      "foobar25"; "foobar26"; "foobar27"; "foobar28"; "foobar29";
      "foobar30"; "foobar31"; "foobar32"; "foobar33"; "foobar34";
      "foobar35"; "foobar36"; "foobar37"; "foobar38"; "0foobar39" ^ add
    ]
    in
    let z =
      Name_rr_map.add (n_of_s "one.com")
        Rr_map.Txt (300l, Rr_map.Txt_set.of_list more) (big_zone 62)
    in
    trie_of_zone z

  let signed_buf_axfr_test server keyname key axfr_req =
    let req, mac =
      let header = 0x1234, Packet.Flags.empty in
      let res = Packet.create header axfr_req `Axfr_request in
      match Dns_tsig.encode_and_sign ~proto:`Tcp res Ptime.epoch key keyname with
      | Ok (buf, mac) -> buf, mac
      | Error _ -> assert false
    in
    let _server', answers, _notifies, _notify, keyname' =
      Dns_server.Primary.handle_buf server Ptime.epoch 0L `Tcp (Ipaddr.V4 Ipaddr.V4.localhost) 1234 req
    in
    assert (match keyname' with Some k -> Domain_name.equal k keyname | _ -> false);
    (List.iter (fun answer ->
         match Dns_tsig.decode_and_verify Ptime.epoch key keyname ~mac answer with
         | Ok _ -> ()
         | Error e ->
           Alcotest.fail ("error while verifying " ^ Fmt.to_to_string Dns_tsig.pp_e e))
        answers);
    answers

  let keyname, key =
    let key = String.make 32 '\000' |> Base64.encode_string |> Cstruct.of_string in
    n_of_s "1.2.3.4.9.10.11.12._transfer.one.com",
    { Dnskey.flags = Dnskey.F.empty ; algorithm = SHA256 ; key }

  let s trie =
    let keys = [ keyname, key ] in
    Dns_server.Primary.create ~rng:Mirage_crypto_rng.generate
      ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign ~keys trie

  let axfr_encoding_big_zone_no_split_tsig () =
    let trie = signed_zone "" in
    let s = s trie in
    let axfr_req = n_of_s "one.com", `Axfr in
    let bufs = signed_buf_axfr_test s keyname key axfr_req in
    Alcotest.(check int __LOC__ 1 (List.length bufs));
    Alcotest.(check int __LOC__ 65535 (Cstruct.length (List.hd bufs)))

  let axfr_encoding_big_zone_one_split_tsig () =
    let trie = signed_zone "0" in
    let s = s trie in
    let axfr_req = n_of_s "one.com", `Axfr in
    let bufs = signed_buf_axfr_test s keyname key axfr_req in
    Alcotest.(check int __LOC__ 2 (List.length bufs));
    Alcotest.(check int __LOC__ 65500 (Cstruct.length (List.hd bufs)));
    Alcotest.(check int __LOC__ 184 (Cstruct.length (List.hd (List.tl bufs))))

  let tests = [
    "encoding", `Quick, axfr_encoding ;
    "encoding big zone (no split)", `Quick, axfr_encoding_big_zone_no_split ;
    "encoding big zone (one split)", `Quick, axfr_encoding_big_zone_one_split ;
    "encoding big zone (multiple splits)", `Quick, axfr_encoding_big_zone_multiple_splits ;
    "encoding big zone with tsig (no split)", `Quick, axfr_encoding_big_zone_no_split_tsig ;
    "encoding big zone with tsig (one split)", `Quick, axfr_encoding_big_zone_one_split_tsig ;
  ]
end

module Zone = struct
  let name_map_ok =
    let module M = struct
      type t = Name_rr_map.t
      let pp = Name_rr_map.pp
      let equal = Name_rr_map.equal
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let err =
    let module M = struct
      type t = [ `Msg of string ]
      let pp ppf (`Msg s) = Fmt.string ppf s
      let equal _ _ = true
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

  let simple_zone = {|
$ORIGIN example.
$TTL 2560
@	SOA	ns 	root	1	86400	10800	1048576	2560
@	NS	ns
|}

  let parse_simple_zone () =
    let rrs =
      let z = n_of_s "example" in
      let ns_name = n_of_s "ns.example" in
      let ns = 2560l, Domain_name.(Host_set.singleton (host_exn ns_name)) in
      let soa = { Soa.nameserver = ns_name ; hostmaster = n_of_s "root.example" ;
                  serial = 1l ; refresh = 86400l ; retry = 10800l ;
                  expiry = 1048576l ; minimum = 2560l }
      in
      Name_rr_map.(add z Rr_map.Ns ns (singleton z Rr_map.Soa soa))
    in
    Alcotest.(check (result name_map_ok err) "parsing simple zone"
                (Ok rrs) (Dns_zone.parse simple_zone))

  let wildcard_zone = {|
$ORIGIN example.
$TTL 2560
@	SOA	ns 	root	1	86400	10800	1048576	2560
@	NS	ns
*       A       1.2.3.4
|}

  let parse_wildcard_zone () =
    let rrs =
      let z = n_of_s "example" in
      let ns_name = n_of_s "ns.example" in
      let minimum = 2560l in
      let ns = Domain_name.(Host_set.singleton (host_exn ns_name)) in
      let soa = { Soa.nameserver = ns_name ; hostmaster = n_of_s "root.example" ;
                  serial = 1l ; refresh = 86400l ; retry = 10800l ;
                  expiry = 1048576l ; minimum }
      in
      let a = Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn "1.2.3.4") in
      Name_rr_map.(add z Rr_map.Ns (minimum, ns)
                     (add z Rr_map.Soa soa
                        (singleton (n_of_s "*.example") Rr_map.A (minimum, a))))
    in
    Alcotest.(check (result name_map_ok err) "parsing wildcard zone"
                (Ok rrs) (Dns_zone.parse wildcard_zone))

  let rfc4592_zone = {|
$ORIGIN example.
example.                 3600 IN  SOA   ns.example.com. 	root	1	86400	10800	1048576	2560
example.                 3600     NS    ns.example.com.
example.                 3600     NS    ns.example.net.
*.example.               3600     TXT   "this is a wildcard"
*.example.               3600     MX    10 host1.example.
sub.*.example.           3600     TXT   "this is not a wildcard"
host1.example.           3600     A     192.0.2.1
_ssh._tcp.host1.example. 3600     SRV   1 2 3 host1
_ssh._tcp.host2.example. 3600     SRV   2 3 4 host1
subdel.example.          3600     NS    ns.example.com.
subdel.example.          3600     NS    ns.example.net.
|}

  let wc_txt = Rr_map.Txt_set.singleton "this is a wildcard"
  and sub_txt = Rr_map.Txt_set.singleton "this is not a wildcard"
  and wc_mx =
    let mx =
      let mail_exchange = Domain_name.host_exn (n_of_s "host1.example") in
      Mx.{ preference = 10 ; mail_exchange }
    in
    Rr_map.Mx_set.singleton mx
  and soa = { Soa.nameserver = n_of_s "ns.example.com" ; hostmaster = n_of_s "root.example" ;
              serial = 1l ; refresh = 86400l ; retry = 10800l ;
              expiry = 1048576l ; minimum = 2560l }
  and ns = Domain_name.(Host_set.(add (host_exn (n_of_s "ns.example.com"))
                                    (singleton (host_exn (n_of_s "ns.example.net")))))

  let parse_rfc4592_zone () =
    let rrs =
      let z = n_of_s "example" in
      let host1 = n_of_s "host1.example" in
      let host1_a = Ipaddr.V4.Set.singleton (Ipaddr.V4.of_string_exn "192.0.2.1")
      and srv1 =
        let srv = Srv.{ priority = 1 ; weight = 2 ; port = 3 ; target = Domain_name.host_exn host1 } in
        Rr_map.Srv_set.singleton srv
      and srv2 =
        let srv = Srv.{ priority = 2 ; weight = 3 ; port = 4 ; target = Domain_name.host_exn host1 } in
        Rr_map.Srv_set.singleton srv
      in
      let ttl = 3600l in
      let wc = n_of_s "*.example" in
      let subdel = n_of_s "subdel.example" in
      Name_rr_map.(add z Rr_map.Ns (ttl, ns)
                     (add z Rr_map.Soa soa
                        (add wc Rr_map.Txt (ttl, wc_txt)
                           (add wc Rr_map.Mx (ttl, wc_mx)
                              (add (n_of_s "sub.*.example") Rr_map.Txt (ttl, sub_txt)
                                 (add host1 Rr_map.A (ttl, host1_a)
                                    (add (n_of_s "_ssh._tcp.host1.example") Rr_map.Srv (ttl, srv1)
                                       (add (n_of_s "_ssh._tcp.host2.example") Rr_map.Srv (ttl, srv2)
                                          (singleton subdel Rr_map.Ns (ttl, ns))))))))))
    in
    Alcotest.(check (result name_map_ok err) "parsing rfc4592 zone"
                (Ok rrs) (Dns_zone.parse rfc4592_zone))

  let rfc4592_questions () =
    match Dns_zone.parse rfc4592_zone with
    | Error `Msg f -> Alcotest.failf "couldn't parse zone: %s" f
    | Ok data ->
      let trie = Dns_trie.insert_map data Dns_trie.empty in
      match Dns_trie.check trie with
      | Error e ->
        Alcotest.failf "dns trie check failed %a" Dns_trie.pp_zone_check e
      | Ok () ->
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for MX host3 matches wildcard"
                (Ok (Rr_map.B (Rr_map.Mx, (3600l, wc_mx))))
                (Trie.lookup_b (n_of_s "host3.example") Rr_map.Mx trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for A host3 is nodata"
                (Error (`EmptyNonTerminal (n_of_s "example", soa)))
                (Trie.lookup_b (n_of_s "host3.example") Rr_map.A trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for TXT foo.bar matches wildcard"
                (Ok (Rr_map.B (Rr_map.Txt, (3600l, wc_txt))))
                (Trie.lookup_b (n_of_s "foo.bar.example") Rr_map.Txt trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for MX host1 is nodata"
                (Error (`EmptyNonTerminal (n_of_s "example", soa)))
                (Trie.lookup_b (n_of_s "host1.example") Rr_map.Mx trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for MX sub.* is nodata"
                (Error (`EmptyNonTerminal (n_of_s "example", soa)))
                (Trie.lookup_b (n_of_s "sub.*.example") Rr_map.Mx trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for SRV _telnet._tcp.host1 is nodata"
                (Error (`NotFound (n_of_s "example", soa)))
                (Trie.lookup_b (n_of_s "_telnet._tcp.host1.example") Rr_map.Srv trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for A host.subdel is nodata"
                (Error (`Delegation (n_of_s "subdel.example", (3600l, ns))))
                (Trie.lookup_b (n_of_s "host.subdel.example") Rr_map.A trie));
        (* for the curious from RFC 4592, 2.2.1:
           The final example highlights one common misconception about
           wildcards.  A wildcard "blocks itself" in the sense that a wildcard
           does not match its own subdomains.  That is, "*.example."  does not
           match all names in the "example." zone; it fails to match the names
           below "*.example.". To cover names under "*.example.", another
           wildcard domain name is needed--"*.*.example."--which covers all but
           its own subdomains.
        *)
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for MX ghost.* is nodata"
                (Error (`NotFound (n_of_s "example", soa)))
                (Trie.lookup_b (n_of_s "ghost.*.example") Rr_map.Mx trie));
        (* some more checks *)
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for TXT host3 matches wildcard"
                    (Ok (Rr_map.B (Rr_map.Txt, (3600l, wc_txt))))
                    (Trie.lookup_b (n_of_s "host3.example") Rr_map.Txt trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for TXT foo.host1 is nodata"
                (Error (`NotFound (n_of_s "example", soa)))
                (Trie.lookup_b (n_of_s "foo.host1.example") Rr_map.Txt trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for TXT sub.* is sub_txt"
                (Ok (Rr_map.B (Rr_map.Txt, (3600l, sub_txt))))
                (Trie.lookup_b (n_of_s "sub.*.example") Rr_map.Txt trie));
        Alcotest.(check (result Trie.b_ok Trie.e) "lookup_b for TXT example is nodata"
                (Error (`EmptyNonTerminal (n_of_s "example", soa)))
                (Trie.lookup_b (n_of_s "example") Rr_map.Txt trie))

  let parse_zone_with_glue () =
    let zone = {|$ORIGIN example.
$TTL 3600
@	SOA	ns	root	1	86400	10800	1048576	3600
@	NS	ns.example.org.
@	NS	ns.example.net.

ns.example.net.	A	5.6.7.8
ns.example.org.	A	1.2.3.4


|}
    in
    let _, trie = Dns_zone.decode_zones [ "example", zone ] in
    match Dns_trie.lookup (n_of_s "example") Rr_map.Ns trie with
    | Error _ -> Alcotest.fail "couldn't find NS for example"
    | Ok (_, name_servers) ->
      let ns =
        Domain_name.(Host_set.of_list [
            host_exn (n_of_s "ns.example.org");
            host_exn (n_of_s "ns.example.net");
          ])
      in
      Alcotest.(check bool "NS for example are correct" true
                  (Domain_name.Host_set.equal ns name_servers));
      (match Dns_trie.lookup_glue (n_of_s "ns.example.org") trie with
       | Some (_, ips), None ->
         Alcotest.(check bool "IP for ns.example.org is correct" true
                     Ipaddr.V4.Set.(equal (singleton (Ipaddr.V4.of_string_exn "1.2.3.4")) ips))
       | _ -> Alcotest.fail "expected some IPv4 addresses for NS");
      (match Dns_trie.lookup_glue (n_of_s "ns.example.net") trie with
       | Some (_, ips), None ->
         Alcotest.(check bool "IP for ns.example.net is correct" true
                     Ipaddr.V4.Set.(equal (singleton (Ipaddr.V4.of_string_exn "5.6.7.8")) ips))
           | _ -> Alcotest.fail "expected some IPv4 addresses for NS");
      match Dns_server.text (n_of_s "example") trie with
      | Ok data ->
        Alcotest.(check string "text (decode_zones z) = z" zone data)
      | Error _ -> Alcotest.fail "failed to encode zone"

  let parse_zone_with_glue_sub () =
    let zone = {|$ORIGIN example.
$TTL 3600
@	SOA	ns	root	1	86400	10800	1048576	3600
@	NS	ns
@	NS	a.b
b	NS	a.b
ns	A	5.6.7.8

a.b	A	1.2.3.4


|}
    in
    let _, trie = Dns_zone.decode_zones [ "example", zone ] in
    match Dns_trie.lookup (n_of_s "example") Rr_map.Ns trie with
    | Error _ -> Alcotest.fail "couldn't find NS for example"
    | Ok (_, name_servers) ->
      let ns =
        Domain_name.(Host_set.of_list [
            host_exn (n_of_s "ns.example");
            host_exn (n_of_s "a.b.example");
          ])
      in
      Alcotest.(check bool "NS for example are correct" true
                  (Domain_name.Host_set.equal ns name_servers));
      (match Dns_trie.lookup_glue (n_of_s "ns.example") trie with
       | Some (_, ips), None ->
         Alcotest.(check bool "IP for ns.example is correct" true
                     Ipaddr.V4.Set.(equal (singleton (Ipaddr.V4.of_string_exn "5.6.7.8")) ips))
       | _ -> Alcotest.fail "expected some IPv4 addresses for NS");
      (match Dns_trie.lookup_glue (n_of_s "a.b.example") trie with
       | Some (_, ips), None ->
         Alcotest.(check bool "IP for a.b.example is correct" true
                     Ipaddr.V4.Set.(equal (singleton (Ipaddr.V4.of_string_exn "1.2.3.4")) ips))
       | _ -> Alcotest.fail "expected some IPv4 addresses for NS");
      (match Dns_trie.lookup (n_of_s "b.example") Rr_map.Soa trie with
       | Error `Delegation _ -> ()
       | _ -> Alcotest.fail "expected delegation for b.example");
      (match Dns_trie.lookup (n_of_s "a.b.example") Rr_map.Soa trie with
       | Error `Delegation _ -> ()
       | _ -> Alcotest.fail "expected delegation for a.b.example");
      match Dns_server.text (n_of_s "example") trie with
      | Ok data ->
        Alcotest.(check string "text (decode_zones z) = z" zone data)
      | Error _ -> Alcotest.fail "failed to encode zone"

    let loc_zone = {|
$ORIGIN example.
$TTL 2560
@	SOA	ns 	root	1	86400	10800	1048576	2560
@	NS	ns
a LOC 0 0 0.1 N 59 59 59.999 W -1.00 10. 1.01m 1m
|}

  let parse_loc_zone () =
    let rrs =
      let z = n_of_s "example" in
      let ns_name = n_of_s "ns.example" in
      let minimum = 2560l in
      let ns = 2560l, Domain_name.(Host_set.singleton (host_exn ns_name)) in
      let soa = { Soa.nameserver = ns_name ; hostmaster = n_of_s "root.example" ;
                  serial = 1l ; refresh = 86400l ; retry = 10800l ;
                  expiry = 1048576l ; minimum }
      in
      let loc = Loc.parse ((0l, 0l, 0.1), true) ((59l, 59l, 59.999), false) ~-.1. (10., 1.01, 1.) in
      Name_rr_map.(add z Rr_map.Ns ns
        (add z Rr_map.Soa soa
          (singleton (n_of_s "a.example") Rr_map.Loc (minimum, Rr_map.Loc_set.singleton  loc))
        )
      )
    in
    Alcotest.(check (result name_map_ok err) "parsing loc zone"
                (Ok rrs) (Dns_zone.parse loc_zone))

  let tests = [
    "parsing simple zone", `Quick, parse_simple_zone ;
    "parsing wildcard zone", `Quick, parse_wildcard_zone ;
    "parsing RFC 4592 zone", `Quick, parse_rfc4592_zone ;
    "RFC 4592 questions", `Quick, rfc4592_questions ;
    "parse zone with additional glue", `Quick, parse_zone_with_glue ;
    "parse zone with additional glue and sub", `Quick, parse_zone_with_glue_sub ;
    "parse loc zone", `Quick, parse_loc_zone ;
  ]
end

let tests = [
  "Trie", Trie.tests ;
  "Server", S.tests ;
  "Authentication", A.tests ;
  "AXFR", Axfr.tests ;
  "Zone", Zone.tests ;
]

let () =
  Mirage_crypto_rng_unix.initialize ();
  Alcotest.run "DNS server tests" tests
