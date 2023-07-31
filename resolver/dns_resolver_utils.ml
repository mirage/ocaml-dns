(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns
open Dns_resolver_cache

let src = Logs.Src.create "dns_resolver_util" ~doc:"DNS resolver util"
module Log = (val Logs.src_log src : Logs.LOG)

type e = E : 'a Rr_map.key * 'a Dns_cache.entry -> e

let invalid_soa name =
  let p pre =
    Result.value ~default:name
      (Result.bind
         (Domain_name.prepend_label name "invalid")
         (fun n -> Domain_name.prepend_label n pre))
  in
  {
    Soa.nameserver = p "ns" ; hostmaster = p "hostmaster" ;
    serial = 1l ; refresh = 16384l ; retry = 2048l ;
    expiry = 1048576l ; minimum = 300l
  }

let noerror bailiwick (_, flags) ~signed q_name q_type (answer, authority) additional =
  (* maybe should be passed explicitly (when we don't do qname minimisation) *)
  let in_bailiwick name = Domain_name.is_subdomain ~domain:bailiwick ~subdomain:name in
  (* ANSWER *)
  let answers, anames =
    match Domain_name.Map.find q_name answer with
    | None ->
      (* NODATA (no answer, but SOA (or not) in authority) *)
      begin
        (* RFC2308, Sec 2.2 "No data":
           - answer is empty
           - authority has a) SOA + NS, b) SOA, or c) nothing *)
        (* an example for this behaviour is NS:
           asking for AAAA www.soup.io, get empty answer + SOA in authority
           asking for AAAA coffee.soup.io, get empty answer + authority *)
        (* the "sub" should be relaxed - for dig ns mail.mehnert.org I get soa in mehnert.org!
           --> but how to discover SOA/zone boundaries? *)
        let rank =
          if Packet.Flags.mem `Authoritative flags then
            Dns_cache.AuthoritativeAuthority signed
          else
            Dns_cache.Additional
        in
        match
          Domain_name.Map.fold (fun name rr_map acc ->
              if Domain_name.is_subdomain ~subdomain:q_name ~domain:name then
                match Rr_map.find Soa rr_map with
                | Some soa -> (name, soa) :: acc
                | None -> acc
              else
                acc)
            authority []
        with
        | (name, soa)::_ ->
          begin match q_type with
            | `Any -> [] (* i really don't know how to handle ANY NoDATA*)
            | `K Rr_map.K k -> [ q_name, E (k, `No_data (name, soa)), rank ]
        (* this is wrong for the normal iterative algorithm:
            it asks for foo.com @root, and get .com NS in AU and A in AD
        | [] when not (Packet.Header.FS.mem `Truncation flags) ->
          Log.warn (fun m -> m "noerror answer, but nothing in authority whose sub is %a in %a, invalid_soa!"
                        pp_question (q_name, q_type) Name_rr_map.pp authority) ;
          [ q_type, q_name, Additional, `No_data (q_name, invalid_soa q_name) ] *)
          end
        | [] -> [] (* general case when we get an answer from root server *)
      end, Domain_name.Set.empty
    | Some rr_map ->
      let rank =
        if Packet.Flags.mem `Authoritative flags then
          Dns_cache.AuthoritativeAnswer signed
        else
          Dns_cache.NonAuthoritativeAnswer
      in
      (* collect those rrsets which are of interest depending on q_type! *)
      match q_type with
      | `Any ->
        Rr_map.fold (fun (B (k, v)) (acc, names) ->
            (q_name, E (k, `Entry v), rank) :: acc,
            Domain_name.Host_set.fold (fun n acc ->
                Domain_name.Set.add (Domain_name.raw n) acc)
              (Rr_map.names k v) names)
          rr_map ([], Domain_name.Set.empty)
      | `K (Rr_map.K Cname) ->
        begin match Rr_map.find Cname rr_map with
          | Some v -> [ q_name, E (Cname, `Entry v), rank ],
                      Domain_name.Host_set.fold (fun n acc ->
                          Domain_name.Set.add (Domain_name.raw n) acc)
                        (Rr_map.names Cname v) Domain_name.Set.empty
          | None ->
            (* case no cname *)
            Log.warn (fun m -> m "noerror answer with right name, but no cname in %a, invalid soa for %a"
                          Name_rr_map.pp answer pp_question (q_name, q_type));
            [ q_name, E (Cname, `No_data (q_name, invalid_soa q_name)), rank ],
            Domain_name.Set.empty
        end
      | `K (Rr_map.K k) -> match Rr_map.find k rr_map with
        | Some v ->
          [ q_name, E (k, `Entry v), rank ],
          Domain_name.Host_set.fold (fun n acc ->
              Domain_name.Set.add (Domain_name.raw n) acc)
            (Rr_map.names k v) Domain_name.Set.empty
        | None -> match Rr_map.find Cname rr_map with
          | None ->
            (* case neither TYP nor cname *)
            Log.warn (fun m -> m "noerror answer with right name, but not TYP nor cname in %a, invalid soa for %a"
                          Name_rr_map.pp answer pp_question (q_name, q_type));
            [ q_name, E (k, `No_data (q_name, invalid_soa q_name)), rank ],
            Domain_name.Set.empty
          | Some cname ->
            (* explicitly register as CNAME so it'll be found *)
            (* should we try to find further records for the new alias? *)
            [ q_name, E (Cname, `Entry cname), rank ],
            Domain_name.Set.singleton (snd cname)
  in

  (* AUTHORITY - NS and DS records, also nsec and nsec3 *)
  let ns, nsnames =
    (* authority points us to NS of q_name! *)
    (* we collect a list of NS records and the ns names *)
    (* TODO need to be more careful, q: foo.com a: foo.com a 1.2.3.4 au: foo.com ns blablubb.com ad: blablubb.com A 1.2.3.4 *)
    let rank s =
      if Packet.Flags.mem `Authoritative flags then
        Dns_cache.AuthoritativeAuthority (signed && s)
      else
        Dns_cache.Additional
    in
    let ns, others, names =
      Domain_name.Map.fold (fun name map (ns_acc, other_acc, s) ->
          if in_bailiwick name then
            let ns, s =
              match Rr_map.find Ns map with
              | None -> ns_acc, s
              | Some (ns : int32 * Domain_name.Host_set.t) ->
                (name, ns) :: ns_acc, Domain_name.Host_set.fold (fun n acc ->
                    Domain_name.Set.add (Domain_name.raw n) acc)
                  (snd ns) s
            in
            let others = match Rr_map.find Nsec map with
              | None -> other_acc
              | Some n -> (name, E (Nsec, `Entry n), rank true) :: other_acc
            in
            let others = match Rr_map.find Nsec3 map with
              | None -> others
              | Some n -> (name, E (Nsec3, `Entry n), rank true) :: others
            in
            let others = match Rr_map.find Ds map with
              | None -> others
              | Some n -> (name, E (Ds, `Entry n), rank true) :: others
            in
            ns, others, s
          else
            ns_acc, other_acc, s)
        authority
        ([], [], Domain_name.Set.empty)
    in
    List.fold_left (fun acc (name, ns) ->
        (name, E (Ns, `Entry ns), rank false) :: acc)
      others ns, names
  in

  (* ADDITIONAL *)
  (* maybe only these thingies which are subdomains of q_name? *)
  (* preserve A/AAAA records only for NS lookups? *)
  (* now we have processed:
     - answer (filtered to where name = q_name)
     - authority with SOA and NS entries
     - names from these answers, and authority
     - additional section can contain glue records if needed
     - only A and AAAA records are of interest for glue *)
  let glues =
    let names = Domain_name.Set.union anames nsnames in
    let names = Domain_name.Set.filter in_bailiwick names in
    Domain_name.Set.fold (fun name acc ->
        match Domain_name.Map.find name additional with
        | None -> acc
        | Some map ->
          let a = match Rr_map.find A map with
            | None -> acc
            | Some v -> (name, E (A, `Entry v), Dns_cache.Additional) :: acc
          in
          match Rr_map.find Aaaa map with
          | None -> a
          | Some v -> (name, E (Aaaa, `Entry v), Dns_cache.Additional) :: a)
      names []
  in
  (* This is defined in RFC2181, Sec9 -- answer is unique if authority or
     additional is non-empty *)
  let answer_complete =
    not (Domain_name.Map.is_empty authority && Domain_name.Map.is_empty additional)
  in
  match answers, ns with
  | [], [] when not answer_complete && Packet.Flags.mem `Truncation flags ->
    (* special handling for truncated replies.. better not add anything *)
    Log.warn (fun m -> m "truncated reply for %a, ignoring completely"
                  pp_question (q_name, q_type));
    []
  | [], [] ->
    (* not sure if this can happen, maybe discard everything? *)
    Log.warn (fun m -> m "reply without answers or ns invalid so for %a"
                  pp_question (q_name, q_type));
    begin match q_type with
      | `Any -> []
      | `K Rr_map.K k -> [ q_name, E (k,`No_data (q_name, invalid_soa q_name)), Dns_cache.Additional ]
    end
  | _, _ -> answers @ ns @ glues

let find_soa name authority =
  let rec go name =
    match Domain_name.Map.find name authority with
    | None -> go (Domain_name.drop_label_exn name)
    | Some rrmap -> match Rr_map.(find Soa rrmap) with
      | None -> go (Domain_name.drop_label_exn name)
      | Some soa -> name, soa
  in
  try Some (go name) with Invalid_argument _ -> None

let nxdomain (_, flags) ~signed name data =
  (* we can't do much if authoritiative is not set (some auth dns do so) *)
  (* There are cases where answer is non-empty, but contains a CNAME *)
  (* RFC 2308 Sec 1 + 2.1 show that NXDomain is for the last QNAME! *)
  (* -> need to potentially extract CNAME(s) *)
  let answer, authority = match data with
    | None -> Name_rr_map.empty, Name_rr_map.empty
    | Some x -> x
  in
  let cnames =
    let rec go acc name =
      match Domain_name.Map.find name answer with
      | None -> acc
      | Some rrmap -> match Rr_map.(find Cname rrmap) with
        | None -> acc
        | Some (ttl, alias) -> go ((name, (ttl, alias)) :: acc) alias
    in
    go [] name
  in
  let soa = find_soa name authority in
  (* since NXDomain have CNAME semantics, we store them as CNAME *)
  let rank =
    if Packet.Flags.mem `Authoritative flags then
      Dns_cache.AuthoritativeAnswer signed
    else
      Dns_cache.NonAuthoritativeAnswer
  in
  (* we conclude NXDomain, there are 3 cases we care about:
     no soa in authority and no cname answer -> inject an invalid_soa (avoid loops)
     a matching soa, no cname -> NoDom q_name
     _, a matching cname -> NoErr q_name with cname
  *)
  let entries =
    let soa = match soa with
      | None -> name, invalid_soa name
      | Some x -> x
    in
    match cnames with
    | [] -> [ name, E (Cname, `No_domain soa) ]
    | rrs -> List.map (fun (name, cname) -> (name, E (Cname, `Entry cname))) rrs
  in
  (* the cname does not matter *)
  List.map (fun (name, res) -> name, res, rank) entries

let scrub zone ~signed qtype p =
  Log.debug (fun m -> m "scrubbing (bailiwick %a) data %a"
                 Domain_name.pp zone Packet.pp p);
  let qname = fst p.question in
  match p.Packet.data with
  | `Answer data ->
    Ok (noerror zone p.header ~signed qname qtype data p.additional)
  | `Rcode_error (Rcode.NXDomain, _, data) ->
    Ok (nxdomain p.Packet.header ~signed qname data)
  | e -> Error (Packet.rcode_data e)
