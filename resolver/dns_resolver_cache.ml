(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Dns_resolver_entry

module V = struct
  type entry = int64 * rank * res
  type t = All of entry | Entries of entry Dns_enum.RRMap.t

  let weight = function
    | All _ -> 1
    | Entries tm -> Dns_enum.RRMap.cardinal tm

  let pp_entry ppf (crea, rank, res) =
    Fmt.pf ppf "%a %Lu %a" pp_rank rank crea pp_res res

  let pp ppf = function
    | All e -> Fmt.pf ppf "all %a" pp_entry e
    | Entries tm ->
      Fmt.pf ppf "entries: %a"
        Fmt.(list ~sep:(unit ";@,") (pair Dns_enum.pp_rr_typ pp_entry))
        (Dns_enum.RRMap.bindings tm)
end

module LRU = Lru.F.Make(Dns_name)(V)

type t = LRU.t

let empty = LRU.empty

let items = LRU.items

let capacity = LRU.capacity

let pp = LRU.pp Fmt.(pair ~sep:(unit ": ") Dns_name.pp V.pp)

module N = Dns_name.DomSet

let update_ttl created ts rr =
  let used = Duration.to_sec (Int64.sub ts created) in
  match Int32.to_int rr.Dns_packet.ttl - used with
  | x when x < 0 -> None
  | ttl -> Some { rr with Dns_packet.ttl = Int32.of_int ttl }

let update_res created ts res =
  let up = update_ttl created ts in
  let ups =
    List.fold_left
      (fun acc rr -> match up rr with None -> acc | Some x -> x :: acc)
      []
  in
  match res with
  | NoData soa ->
    (match up soa with Some soa -> Some (NoData soa) | None -> None)
  | NoDom soa ->
    (match up soa with Some soa -> Some (NoDom soa) | None -> None)
  | ServFail soa ->
    (match up soa with Some soa -> Some (ServFail soa) | None -> None)
  | NoErr rrs ->
    (match ups rrs with [] -> None | rrs -> Some (NoErr rrs))

let cached t ts typ nam =
  match LRU.find nam t with
  | None ->
    Logs.debug (fun m -> m "found nothing %a" Dns_name.pp nam) ;
    Error `Cache_miss
  | Some (V.All (created, _, res), t) ->
    Logs.debug (fun m -> m "found all %a (%a) %a" Dns_name.pp nam Dns_enum.pp_rr_typ typ pp_res res) ;
    begin match update_res created ts res with
      | None -> Error `Cache_drop
      | Some r -> Ok (r, t)
    end
  | Some (V.Entries tm, t) ->
    match Dns_enum.RRMap.find typ tm with
    | exception Not_found ->
      Logs.debug (fun m -> m "found entries for %a, but no matching rr typ (%a)" Dns_name.pp nam Dns_enum.pp_rr_typ typ) ;
      Error `Cache_miss
    | (created, _, res) ->
      Logs.debug (fun m -> m "found something %a (%a) %a" Dns_name.pp nam Dns_enum.pp_rr_typ typ pp_res res) ;
      match update_res created ts res with
      | None ->
        Logs.debug (fun m -> m "didn't survive") ;
        Error `Cache_drop
      | Some r -> Ok (r, t)

(* according to RFC1035, section 7.3, a TTL of a week is a good maximum value! *)
(* XXX: we may want to define a minimum as well (5 minutes? 30 minutes?
   use SOA expiry?) MS used to use 24 hours in internet explorer

from RFC1034 on this topic:
The idea is that if cached data is known to come from a particular zone,
and if an authoritative copy of the zone's SOA is obtained, and if the
zone's SERIAL has not changed since the data was cached, then the TTL of
the cached data can be reset to the zone MINIMUM value if it is smaller.
This usage is mentioned for planning purposes only, and is not
recommended as yet.

and 2308, Sec 4:
   Despite being the original defined meaning, the first of these, the
   minimum TTL value of all RRs in a zone, has never in practice been
   used and is hereby deprecated.

and 1035 6.2:
   The MINIMUM value in the SOA should be used to set a floor on the TTL of data
   distributed from a zone.  This floor function should be done when the data is
   copied into a response.  This will allow future dynamic update protocols to
   change the SOA MINIMUM field without ambiguous semantics.

*)
let week = Int32.of_int Duration.(to_sec (of_day 7))
let smooth_rr rr =
  if rr.Dns_packet.ttl > week then begin
    Logs.warn (fun m -> m "reduced TTL of %a to one week" Dns_packet.pp_rr rr) ;
    { rr with Dns_packet.ttl = week }
  end else
    rr

let smooth_ttl = function
  | NoErr rrs -> NoErr (List.map smooth_rr rrs)
  | NoData rr -> NoData (smooth_rr rr)
  | NoDom rr -> NoDom (smooth_rr rr)
  | ServFail rr -> ServFail (smooth_rr rr)

let maybe_insert typ nam ts rank res t =
  let entry tm =
    let full = (ts, rank, smooth_ttl res) in
    match typ, res with
    | Dns_enum.CNAME, _ -> V.All full
    | _, NoDom _ -> V.All full
    | _, _ -> V.Entries (Dns_enum.RRMap.add typ full tm)
  in
  match LRU.find ~promote:false nam t with
  | None -> LRU.add nam (entry Dns_enum.RRMap.empty) t
  | Some (V.All (ts', rank', res'), t) ->
    begin match update_res ts' ts res' with
      | None -> LRU.add nam (entry Dns_enum.RRMap.empty) t
      | Some _ ->
        match compare_rank rank rank' with
        | `Bigger -> t
        | `Equal | `Smaller -> LRU.add nam (entry Dns_enum.RRMap.empty) t
    end
  | Some (V.Entries tm, t) ->
    match Dns_enum.RRMap.find typ tm with
    | exception Not_found -> LRU.add nam (entry tm) t
    | (ts', rank', res') ->
      match update_res ts' ts res' with
      | None -> LRU.add nam (entry tm) t
      | Some _ ->
        match compare_rank rank rank' with
        | `Bigger -> t
        | `Equal | `Smaller -> LRU.add nam (entry tm) t

let resolve_ns t ts name =
  match cached t ts Dns_enum.A name with
  | Error _ -> Ok (`NeedA name, t)
  | Ok (NoErr answer, t) ->
    (match
       List.fold_left (fun acc rr -> match rr.Dns_packet.rdata with
           | Dns_packet.A ip -> ip :: acc
           | _ -> acc)
         [] answer
     with
     | [] -> Ok (`NeedA name, t)
     | ips -> Ok (`HaveIP ips, t))
  | _ -> Error ()

let root_servers =
  List.map Ipaddr.V4.of_string_exn [ "141.1.1.1" ; "8.8.8.8" ]
(*    (* a.root-servers.net *) "198.41.0.4" (* , 2001:503:ba3e::2:30 VeriSign, Inc. *) ;
    (* b.root-servers.net *) "192.228.79.201" (* , 2001:500:84::b University of Southern California (ISI) *) ;
    (* c.root-servers.net *) "192.33.4.12" (* , 2001:500:2::c Cogent Communications *) ;
    (* d.root-servers.net *) "199.7.91.13" (* , 2001:500:2d::d University of Maryland *) ;
    (* e.root-servers.net *) "192.203.230.10" (* , 2001:500:a8::e NASA (Ames Research Center) *) ;
    (* f.root-servers.net *) "192.5.5.241" (* , 2001:500:2f::f Internet Systems Consortium, Inc. *) ;
    (* g.root-servers.net *) "192.112.36.4" (* , 2001:500:12::d0d US Department of Defense (NIC) *) ;
    (* h.root-servers.net *) "198.97.190.53" (* , 2001:500:1::53 US Army (Research Lab) *) ;
    (* i.root-servers.net *) "192.36.148.17" (* , 2001:7fe::53 Netnod *) ;
    (* j.root-servers.net *) "192.58.128.30" (* , 2001:503:c27::2:30 VeriSign, Inc. *) ;
    (* k.root-servers.net *) "193.0.14.129" (* , 2001:7fd::1 RIPE NCC *) ;
    (* l.root-servers.net *) "199.7.83.42" (* , 2001:500:9f::42 ICANN *) ;
      (* m.root-servers.net *) "202.12.27.33" (* , 2001:dc3::35 WIDE Project *)
      ] *)

let pick xs =
  match xs with
  | [] -> `No
  | xs ->
  let r = Random.int (List.length xs) in
  List.nth xs r

let find_ns t ?(overlay = fun _ -> None) ts name =
  let open Rresult.R.Infix in
  if Dns_name.equal name Dns_name.root then `HaveIP root_servers, t
  else match overlay name with
    | Some ip -> `HaveIP [ip], t
    | None ->
      match cached t ts Dns_enum.NS name with
    | Error _ -> `NeedNS, t
    | Ok (NoErr answers, t) ->
      (match
         (* correctness? this fails if there's a single non-NS answer for this
            query -- if resolve_ns fails -- can we ever insert such a RR? *)
         List.fold_left (fun acc rr ->
             acc >>= fun (rs, t) ->
             match rr.Dns_packet.rdata with
             | Dns_packet.CNAME name -> Ok (`Cname name :: rs, t)
             | Dns_packet.NS name -> resolve_ns t ts name >>= fun (x, t) -> Ok (x :: rs, t)
             | _ -> Error ())
           (Ok ([], t))
           answers
       with
       | Error () -> `No, t
       (* this _used_ to use the RNG *)
       | Ok ([ `Cname name ], t) -> `Cname name, t
       | Ok ([], t) -> `No, t
       | Ok (r::rs, t) ->
         pick (List.filter (function `HaveIP _ -> true | _ -> false) (r::rs)), t)
    | Ok (_, t) -> `No, t

let resolve t ?overlay ts name typ =
  (* the top-to-bottom approach *)
  (* goal is to find the query to send out.
      we're applying qname minimisation on the way down

     it's a bit complicated, OTOH we're doing qname minimisation, but also may
     have to jump to other names (of NS or CNAME) - which is slightly intricate
*)
  let rec go t stash typ cur rest ips =
    Logs.debug (fun m -> m "resolve called with stash %a typ %a cur %a rest %a ips %a"
                   Fmt.(list ~sep:(unit ", ") Dns_name.pp) (N.elements stash)
                   Dns_enum.pp_rr_typ typ Dns_name.pp cur
                   Dns_name.pp (Dns_name.of_strings_exn ~hostname:false rest)
                   Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp_hum) ips) ;
    match find_ns t ?overlay ts cur with
    | `HaveIP ips, t ->
      Logs.debug (fun m -> m "resolve: have ips %a" Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp_hum) ips) ;
      begin match rest with
        | [] -> Ok (cur, typ, ips, t)
        | hd::tl -> go t stash typ (Dns_name.prepend_exn cur hd) tl ips
      end
    | `NeedNS, t ->
      Logs.debug (fun m -> m "resolve: needns") ;
      Ok (cur, Dns_enum.NS, ips, t)
    | `Cname name, t ->
      Logs.debug (fun m -> m "resolve: cname %a" Dns_name.pp name) ;
      begin match rest with
        | [] ->
          let rest = List.rev (Dns_name.to_strings name) in
          go t (N.add name stash) typ Dns_name.root rest []
        | hd::tl -> go t stash typ (Dns_name.prepend_exn ~hostname:false cur hd) tl ips
      end
    | `No, t ->
      Logs.debug (fun m -> m "resolve: no!") ;
      (* in the NXDomain case, this is wrong (but we can't do much about it) *)
      (* this opens the door to amplification attacks :/ *)
      let name = Dns_name.of_strings_exn ~hostname:false (rest @ Dns_name.to_strings cur) in
      Ok (name, typ, ips, t)
(*      begin match rest with
        | [] -> Ok (cur, typ, ips, t)
        | hd::tl -> go t stash typ (Dns_name.prepend_exn ~hostname:false cur hd) tl ips
        end*)
    | `NeedA name, t ->
      Logs.debug (fun m -> m "resolve: needA %a" Dns_name.pp name) ;
      if N.mem name stash then begin
        (* XXX: this needs more work regarding glue records -- done in resolver.ml
           it happens when NS foo.com? -> NS 50 ns1.foo.com, NS 50 ns2.foo.com,
           ns1.foo.com A 1 1.2.3.4, ns2.foo.com A 1 1.2.3.5 *)
        (*if Dns_name.sub ~subdomain:name ~domain:cur then
            let par = Dns_name.parent cur in
            match find_ns t ts par with
            | `HaveIP ips, t -> Ok (cur, Dns_enum.NS, ips, t)
            | `NeedNS, t -> Ok (par, Dns_enum.NS, root_servers, t)
            | `No, t -> Ok (par, Dns_enum.NS, root_servers, t)
            | `NeedA nam, t -> go t (N.add name stash) Dns_enum.A Dns_name.root (List.rev (Dns_name.to_strings nam)) root_servers
          else begin
            Logs.err (fun m -> m "cycle detected in nameserver search for %a: %a (%a)"
                         Dns_name.pp cur Dns_name.pp name
                         (Fmt.list ~sep:(Fmt.unit ";") Dns_name.pp) (N.elements stash)) ;
            Error "cycle detected"
          end *)
        Error "cycle detected"
      end else
        let n = List.rev (Dns_name.to_strings name) in
        go t (N.add name stash) Dns_enum.A Dns_name.root n []
  in
  go t (N.singleton name) typ Dns_name.root (List.rev (Dns_name.to_strings name)) []

let follow_cname t ts typ name answer =
  let rec follow t names acc curr =
    match
      match curr with
      | [x] -> (match x.Dns_packet.rdata with Dns_packet.CNAME n -> Some n | _ -> None)
      | _ -> None
    with
    | None ->
      Logs.debug (fun m -> m "followed names %a noerror"
                     Fmt.(list ~sep:(unit ", ") Dns_name.pp) (N.elements names)) ;
      `NoError (acc, t)
    | Some n ->
      Logs.debug (fun m -> m "looking in %d for (names %a) %a (%a)"
                     (LRU.items t)
                     Fmt.(list ~sep:(unit ", ") Dns_name.pp) (N.elements names)
                     Dns_name.pp n Dns_enum.pp_rr_typ typ) ;
      if N.mem n names then begin
        Logs.debug (fun m -> m "cycle detected") ;
        `Cycle (acc, t)
      end else
        match cached t ts typ n with
        | Error _ ->
          Logs.debug (fun m -> m "cache miss, need to query %a" Dns_name.pp n) ;
          `Query (n, t)
        | Ok (NoErr ans, t) ->
          Logs.debug (fun m -> m "noerr, follow again") ;
          follow t (N.add n names) (acc@ans) ans
        | Ok (NoDom soa, t) ->
          Logs.debug (fun m -> m "nodom") ;
          `NoDom ((acc, soa), t)
        | Ok (NoData soa, t) ->
          Logs.debug (fun m -> m "nodata") ;
          `NoData ((acc, soa), t)
        (* XXX: the last case here is not asymmetric... the acc is dropped
           TODO: write tests and evalute what we need (what clients expect) *)
        | Ok (ServFail soa, t) ->
          Logs.debug (fun m -> m "servfail") ;
          `ServFail (soa, t)
  in
  follow t (N.singleton name) answer answer

let names = Dns_packet.rr_names

let additionals t ts rrs =
  (* TODO: also AAAA *)
  N.fold (fun nam (acc, t) ->
      match cached t ts Dns_enum.A nam with
      | Ok (NoErr answers, t) -> answers @ acc, t
      | _ -> acc, t)
    (names rrs)
    ([], t)

let answer t ts q id =
  let packet t add rcode answer authority =
    let header = { Dns_packet.id ; query = false ; operation = Dns_enum.Query ;
                   authoritative = false ; truncation = false ;
                   recursion_desired = true ; recursion_available = true ;
                   authentic_data = false ; checking_disabled = false ;
                   rcode }
    (* XXX: we should look for a fixpoint here ;) *)
    and additional, t = if add then additionals t ts answer else [], t
    and question = [ q ]
    in
    (header, { Dns_packet.question ; answer ; authority ; additional }), t
  in
  match cached t ts q.Dns_packet.q_type q.Dns_packet.q_name with
  | Error _ -> `Query (q.Dns_packet.q_name, t)
  | Ok (NoDom authority, t) ->
    `Packet (packet t false Dns_enum.NXDomain [] [authority])
  | Ok (NoData authority, t) ->
    `Packet (packet t false Dns_enum.NoError [] [authority])
  | Ok (ServFail authority, t) ->
    `Packet (packet t false Dns_enum.ServFail [] [authority])
  | Ok (NoErr answer, t) -> match q.Dns_packet.q_type with
    | Dns_enum.CNAME -> `Packet (packet t false Dns_enum.NoError answer [])
    | _ ->
      match follow_cname t ts q.Dns_packet.q_type q.Dns_packet.q_name answer with
      | `NoError (answer, t) -> `Packet (packet t true Dns_enum.NoError answer [])
      | `Cycle (answer, t) -> `Packet (packet t true Dns_enum.NoError answer [])
      | `Query (n, t) -> `Query (n, t)
      | `NoDom ((answer, soa), t) -> `Packet (packet t true Dns_enum.NXDomain answer [soa])
      | `NoData ((answer, soa), t) -> `Packet (packet t true Dns_enum.NoError answer [soa])
      | `ServFail (soa, t) -> `Packet (packet t true Dns_enum.ServFail [] [soa])

let handle_query t ?overlay sender sport ts q qid =
  match answer t ts q qid with
  | `Packet ((header, packet), t) ->
    let buf = Cstruct.create 512 in
    let l = Dns_packet.encode_query buf header packet in
    `Answer (Cstruct.sub buf 0 l, (sender, sport)), t
  | `Query (name, t) ->
    match resolve t ?overlay ts name q.Dns_packet.q_type with
    | Ok (name, typ, ips, t) ->
      (* this _used_ to use the RNG *)
      (match ips with
       | [] -> `Nothing, t
       | ip::_ -> `Query (name, typ, ip), t)
    | Error _ -> `Nothing, t
