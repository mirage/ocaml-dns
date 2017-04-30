(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Dns_packet

open Dns_resolver_entry

open Rresult.R.Infix

module N = Dns_name.DomSet
module NM = Dns_name.DomMap

let invalid_soa name =
  let p pre =
    match Dns_name.(prepend name "invalid" >>= fun n -> prepend n pre) with
    | Ok name -> name
    | Error _ -> name
  in
  let soa = {
    nameserver = p "ns" ; hostmaster = p "hostmaster" ;
    serial = 1l ; refresh = 16384l ; retry = 2048l ;
    expiry = 1048576l ; minimum = 300l
  } in
  { name ; ttl = 300l ; rdata = SOA soa }

let noerror q hdr dns =
  (* ANSWER *)
  let answers, anames =
    match List.filter (fun rr -> Dns_name.equal rr.name q.q_name) dns.answer with
    | [] ->
      (* NODATA (no answer, but SOA (or not) in authority) *)
      begin
        (* RFC2308, Sec 2.2 "No data":
           - answer is empty
           - authority has a) SOA + NS, b) SOA, or c) nothing *)
        (* an example for this behaviour is NS:
           asking for AAAA www.soup.io, get empty answer + SOA in authority
           asking for AAAA coffee.soup.io, get empty answer + authority *)
        (* XXX don't think the Dns_name.sub check is worth it - could be equal *)
        let rank = if hdr.authoritative then AuthoritativeAuthority else Additional in
        match
          List.partition
            (fun rr -> Dns_name.sub ~subdomain:q.q_name ~domain:rr.name &&
                       match rr.rdata with SOA _ -> true | _ -> false)
            dns.authority
        with
        | [ soa ], _ -> [ q.q_type, q.q_name, rank, NoData soa ]
        | [], [] -> [ q.q_type, q.q_name, Additional, NoData (invalid_soa q.q_name) ]
        | _, _ -> [] (* general case when we get an answer from root server *)
      end, N.empty
    | answer ->
      let rank = if hdr.authoritative then AuthoritativeAnswer else NonAuthoritativeAnswer in
      match List.partition (fun rr -> match rr.rdata with CNAME _ -> true | _ -> false) answer with
      | [], entries ->
        (* XXX: if non-empty, we should require authority to be set? does it help? *)
        [ q.q_type, q.q_name, rank, NoErr entries ], rr_names entries
      | [ cname ], [] ->
        (* explicitly register as CNAME so it'll be found *)
        [ Dns_enum.CNAME, q.q_name, rank, NoErr [ cname ] ], N.empty
      | _, _ ->
        (* case multiple cnames or cname and sth else *)
        (* fail hard already here!? -- there's either multiple cname or cname and others *)
        [ q.q_type, q.q_name, rank, NoData (invalid_soa q.q_name) ], N.empty
  in

  (* AUTHORITY - NS records *)
  let ns, nsnames =
    (* authority points us to NS of q_name! *)
    (* we collect a list of NS records and the ns names *)
    match
      List.fold_left (fun acc rr ->
          if Dns_name.equal q.q_name rr.name then
            match rr.rdata with
            | NS _ -> rr :: acc
            | _ -> acc
          else acc) [] dns.authority
    with
    | [] -> [], N.empty
    | ns ->
      let rank = if hdr.authoritative then AuthoritativeAuthority else Additional in
      [ Dns_enum.NS, q.q_name, rank, NoErr ns ], rr_names ns
  in

  (* ADDITIONAL *)
  (* now we have processed:
     - answer (filtered to where name = q_name)
     - authority with SOA and NS entries
     - names from these answers, and authority
     - additional section can contain glue records if needed
     - only A and AAAA records are of interest for glue *)
  let glues =
    let names = N.union anames nsnames in
    let aaaaa =
      List.fold_left (fun acc rr ->
          if N.mem rr.name names then
            let a, aaaa = try NM.find rr.name acc with Not_found -> [], [] in
            match rr.rdata with
            | A _ -> NM.add rr.name (rr :: a, aaaa) acc
            | AAAA _ -> NM.add rr.name (a, rr :: aaaa) acc
            | _ -> acc
          else acc)
        NM.empty dns.additional
    in
    List.flatten
      (List.map (fun (nam, (a, aaaa)) ->
           let f t = function
             | [] -> []
             | rr -> [ t, nam, Additional, NoErr rr ]
           in
           f Dns_enum.A a @ f Dns_enum.AAAA aaaa)
          (NM.bindings aaaaa))
  in
  match answers, ns with
  | [], [] ->
    (* not sure if this can happen, maybe discard everything? *)
    [ q.q_type, q.q_name, Additional, NoData (invalid_soa q.q_name) ]
  | _, _ -> answers @ ns @ glues

let nxdomain q hdr dns =
  (* we can't do much if authoritiative is not set (some auth dns do so) *)
  (* XXX: PICS or it didn't happen... which DNS doesn't set authoritative bit? *)
  (* There are cases where answer is non-empty, but contains a CNAME *)
  (* described in RFC 2308 Sec 2.1 - we ignore all the CNAMEs *)
  (* we're now looking for a SOA *)
  let soa =
    match
      List.filter
        (fun x -> match x.rdata with SOA _ -> true | _ -> false)
        dns.authority
    with
    | [ soa ] -> soa
    | _ -> invalid_soa q.q_name
  in
  (* since NXDomain have CNAME semantics, we store them as CNAME *)
  let rank = if hdr.authoritative then AuthoritativeAnswer else NonAuthoritativeAnswer in
  [ Dns_enum.CNAME, q.q_name, rank, NoDom soa ]

let scrub q hdr dns =
  match hdr.rcode with
  | Dns_enum.NoError -> Ok (noerror q hdr dns)
  | Dns_enum.NXDomain -> Ok (nxdomain q hdr dns)
  | _ -> Error (`Msg "dunno")
