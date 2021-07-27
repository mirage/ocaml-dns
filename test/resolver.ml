(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

let empty = Dns_cache.empty 100

let ip = Ipaddr.of_string_exn
let ip4 = Ipaddr.V4.of_string_exn
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
      [ `Out of Rcode.t * Name_rr_map.t * Name_rr_map.t
      | `Query of [ `raw ] Domain_name.t
      ] * Dns_cache.t
    let pp ppf (r, _) = match r with
      | `Out (rcode, answer, authority) -> Fmt.pf ppf "out %a answer %a authority %a" Rcode.pp rcode Name_rr_map.pp answer Name_rr_map.pp authority
      | `Query name -> Fmt.pf ppf "query %a" Domain_name.pp name
    let equal (a, _) (b, _) = match a, b with
      | `Out (rc, an, au), `Out (rc', an', au') ->
        Rcode.compare rc rc' = 0 && Name_rr_map.equal an an' && Name_rr_map.equal au au'
      | `Query name, `Query name' -> Domain_name.equal name name'
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
    (`Out (Rcode.NoError, circ_map, Name_rr_map.empty), cache)
    (Dns_resolver_cache.follow_cname cache 0L A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"));
  Alcotest.check follow_res "CNAME single cycle after timeout errors"
    (`Query (name "foo.com"), cache)
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
    (`Out (Rcode.NoError, c_map, Name_rr_map.empty), cache)
    (Dns_resolver_cache.follow_cname cache 0L A
       ~name:(name "bar.com") 250l ~alias:(name "foo.com"));
  Alcotest.check follow_res "Query foo.com (since it timed out)"
    (`Query (name "foo.com"), cache)
    (Dns_resolver_cache.follow_cname cache (sec 251) A
       ~name:(name "bar.com") 250l ~alias:(name "foo.com"))

let follow_cnames () =
  let cname = 250l, name "bar.com" in
  let map = Name_rr_map.singleton (name "foo.com") Cname cname in
  let cache =
    Dns_cache.set empty 0L (name "foo.com") A AuthoritativeAnswer
      (`Entry (B (Cname, cname)))
  in
  Alcotest.check follow_res "CNAME is followed"
    (`Query (name "bar.com"), cache)
    (Dns_resolver_cache.follow_cname cache 0L A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"));
  Alcotest.check follow_res "CNAME after timeout errors"
    (`Query (name "foo.com"), cache)
    (Dns_resolver_cache.follow_cname cache (sec 251) A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"));
  let a_val = (250l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")) in
  let a = Rr_map.(B (A, a_val)) in
  let cache =
    Dns_cache.set cache 0L (name "bar.com") A AuthoritativeAnswer (`Entry a)
  in
  let map = Name_rr_map.add (name "bar.com") A a_val map in
  Alcotest.check follow_res "CNAME is followed"
    (`Out (Rcode.NoError, map, Name_rr_map.empty), cache)
    (Dns_resolver_cache.follow_cname cache 0L A
       ~name:(name "foo.com") 250l ~alias:(name "foo.com"))

let follow_cname_tests = [
  "follow_cname cycles", `Quick, follow_cname_cycle ;
  "follow_cname works", `Quick, follow_cnames ;
]

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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4") in
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
  let a = 1l, Rr_map.Ipv4_set.(add (ip4 "1.2.3.4") (singleton (ip4 "1.2.3.5"))) in
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
  and a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.5")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.5")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.5")
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
  and a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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
  let a = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
  and a' = 1l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.5")
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
      Rr_map.(singleton A (1l, (Ipv4_set.singleton (ip4 "1.2.3.4"))))
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
    Name_rr_map.add (name "ns1.xx") A (1l, Rr_map.Ipv4_set.singleton (ip4 "127.0.0.2"))
      (Name_rr_map.singleton (name "ns2.xx") A (1l, Rr_map.Ipv4_set.singleton (ip4 "127.0.0.3")))
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
  let a = 300l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4") in
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
  and a = 300l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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
  and a = 300l, Rr_map.Ipv4_set.singleton (ip4 "1.2.3.4")
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

let handle_query_res =
  let module M = struct
    type t = [
      | `Reply of Packet.Flags.t * Packet.reply
      | `Query of [`raw] Domain_name.t * ([`raw] Domain_name.t * Packet.Question.qtype) * Ipaddr.t
    ] * Dns_cache.t
    let pp ppf = function
      | `Reply (flags, reply), _ ->
        Fmt.pf ppf "reply flags %a, %a"
          Fmt.(list ~sep:(unit ", ") Packet.Flag.pp_short) (Packet.Flags.elements flags)
          Packet.pp_reply reply
      | `Query (zone, (qname, qtype), ip), _ ->
        Fmt.pf ppf "zone %a, query %a (%a), IP %a"
          Domain_name.pp zone Domain_name.pp qname
          Packet.Question.pp_qtype qtype Ipaddr.pp ip
    let equal a b = match fst a, fst b with
      | `Reply (f1, r1), `Reply (f2, r2) ->
        Packet.Flags.equal f1 f2 && Packet.equal_reply r1 r2
      | `Query (z1, (q1, t1), ip1), `Query (z2, (q2, t2), ip2) ->
        Domain_name.equal z1 z2 && Domain_name.equal q1 q2 &&
        Packet.Question.compare_qtype t1 t2 = 0 &&
        Ipaddr.compare ip1 ip2 = 0
      | _ -> false
    end in
    (module M: Alcotest.TESTABLE with type t = M.t)

let handle_query_with_cname () =
  let cache =
    let cname = 300l, name "reynir.dk" in
    let ns = 300l, Domain_name.Host_set.singleton (Domain_name.host_exn (name "ns.reynir.dk")) in
    let a = 300l, Rr_map.Ipv4_set.singleton (ip4 "127.0.0.1") in
    let cache =
      Dns_cache.set empty 0L (name "www.reynir.dk") Cname AuthoritativeAnswer (`Entry (B (Cname, cname)))
    in
    let cache =
      Dns_cache.set cache 0L (name "reynir.dk") Ns AuthoritativeAnswer (`Entry (B (Ns, ns)))
    in
    Dns_cache.set cache 0L (name "ns.reynir.dk") A AuthoritativeAnswer (`Entry (B (A, a)))
  in
  Alcotest.check handle_query_res "..."
    (`Query (name "reynir.dk", (name "reynir.dk", `K (Rr_map.K A)), ip "127.0.0.1"), cache)
    (Dns_resolver_cache.handle_query cache ~rng 0L (name "www.reynir.dk", `K (Rr_map.K A)))

let handle_query_tests = [
  "cname", `Quick, handle_query_with_cname ;
]

let tests = [
  "follow_cname", follow_cname_tests ;
  "scrub", scrub_tests ;
  "handle query", handle_query_tests ;
]

let () = Alcotest.run "DNS resolver tests" tests
