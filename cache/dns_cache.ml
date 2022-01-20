(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

let src = Logs.Src.create "dns_cache" ~doc:"DNS cache"
module Log = (val Logs.src_log src : Logs.LOG)

type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer of bool
  | AuthoritativeAuthority of bool
  | ZoneGlue
  | NonAuthoritativeAnswer
  | Additional

let compare_rank a b = match a, b with
  | ZoneFile, ZoneFile -> 0
  | ZoneFile, _ -> 1
  | _, ZoneFile -> -1
  | ZoneTransfer, ZoneTransfer -> 0
  | ZoneTransfer, _ -> 1
  | _, ZoneTransfer -> -1
  | AuthoritativeAnswer signed, AuthoritativeAnswer signed' ->
    Bool.compare signed signed'
  | AuthoritativeAnswer _, _ -> 1
  | _, AuthoritativeAnswer _ -> -1
  | AuthoritativeAuthority signed, AuthoritativeAuthority signed' ->
    Bool.compare signed signed'
  | AuthoritativeAuthority _, _ -> 1
  | _, AuthoritativeAuthority _ -> -1
  | ZoneGlue, ZoneGlue -> 0
  | ZoneGlue, _ -> 1
  | _, ZoneGlue -> -1
  | NonAuthoritativeAnswer, NonAuthoritativeAnswer -> 0
  | NonAuthoritativeAnswer, _ -> 1
  | _, NonAuthoritativeAnswer -> -1
  | Additional, Additional -> 0

let pp_rank ppf = function
  | ZoneFile -> Fmt.string ppf "zone file data"
  | ZoneTransfer -> Fmt.string ppf "zone transfer data"
  | AuthoritativeAnswer signed ->
    Fmt.pf ppf "authoritative answer data (signed: %B)" signed
  | AuthoritativeAuthority signed ->
    Fmt.pf ppf "authoritative authority data (signed: %B)" signed
  | ZoneGlue -> Fmt.string ppf "zone file glue"
  | NonAuthoritativeAnswer -> Fmt.string ppf "non-authoritative answer"
  | Additional -> Fmt.string ppf "additional data"

type 'a entry = [
  | `Entry of 'a
  | `No_data of [ `raw ] Domain_name.t * Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Soa.t
  | `Serv_fail of [ `raw ] Domain_name.t * Soa.t
]

module RRMap = Map.Make(struct
    type t = Rr_map.k
    let compare = Rr_map.comparek
  end)

module Entry = struct
  type meta = int64 * rank
  let pp_meta ppf (ts, rank) =
    Fmt.pf ppf "%a created %Lu" pp_rank rank ts

  type rr_map_entry =
    | Entry of Rr_map.b
    | No_data of [ `raw ] Domain_name.t * Soa.t
    | Serv_fail of [ `raw ] Domain_name.t * Soa.t
  let pp_map_entry ppf entry = match entry with
    | Entry b -> Fmt.pf ppf "entry %a" Rr_map.pp_b b
    | No_data (name, soa) -> Fmt.pf ppf "no data %a SOA %a" Domain_name.pp name Soa.pp soa
    | Serv_fail (name, soa) -> Fmt.pf ppf "server fail %a SOA %a" Domain_name.pp name Soa.pp soa
  let to_entry : type a. a Rr_map.key -> rr_map_entry -> a entry = fun typ r -> match r with
    | Entry (B (k, v)) -> begin match Rr_map.K.compare typ k with Gmap.Order.Eq -> `Entry v | _ -> assert false end
    | No_data (name, soa) -> `No_data (name, soa)
    | Serv_fail (name, soa) -> `Serv_fail (name, soa)
  let of_entry typ = function
    | `Entry v -> Entry (B (typ, v))
    | `No_data (name, soa) -> No_data (name, soa)
    | `Serv_fail (name, soa) -> Serv_fail (name, soa)
    | _ -> assert false

  type t =
    | No_domain of meta * [ `raw ] Domain_name.t * Soa.t
    | Rr_map of (meta * rr_map_entry) RRMap.t

  (* Part of the LRU.Weighted interface *)
  let weight = function
    | No_domain _ -> 1
    | Rr_map tm -> RRMap.cardinal tm

  let pp_entry ppf (meta, entry) = Fmt.pf ppf "e (%a) %a" pp_meta meta pp_map_entry entry

  let pp ppf = function
    | No_domain (meta, name, soa) ->
      Fmt.pf ppf "no domain (%a) %a SOA %a" pp_meta meta Domain_name.pp name Soa.pp soa
    | Rr_map rr ->
      Fmt.pf ppf "entries: %a"
        Fmt.(list ~sep:(any ";@,") (pair Rr_map.ppk pp_entry))
        (RRMap.bindings rr)
end

module Key = struct
  type t = [ `raw ] Domain_name.t
  let compare = Domain_name.compare
end

module LRU = Lru.F.Make(Key)(Entry)

type t = LRU.t

let metrics =
  let f = function
    | `Lookup -> "lookups"
    | `Hit -> "hits"
    | `Miss -> "misses"
    | `Drop -> "drops"
    | `Insert -> "insertions"
  in
  let metrics = Dns.counter_metrics ~f "dns-cache" in
  (fun x -> Metrics.add metrics (fun x -> x) (fun d -> d x))

let empty = LRU.empty

let size = LRU.size

let capacity = LRU.capacity

let pp = LRU.pp Fmt.(pair ~sep:(any ": ") Domain_name.pp Entry.pp)

module N = Domain_name.Set

let compute_updated_ttl ~created ~now ttl =
  Int32.sub ttl (Int32.of_int (Duration.to_sec (Int64.sub now created)))

let pp_entry key ppf entry =
  let pp_ns ppf (name, soa) = Fmt.pf ppf "%a SOA %a" Domain_name.pp name Soa.pp soa in
  match entry with
  | `Entry v -> Fmt.pf ppf "entry %a" Rr_map.pp_b (B (key, v))
  | `No_data ns -> Fmt.(append (any "no data ") pp_ns) ppf ns
  | `No_domain ns -> Fmt.(append (any "no domain ") pp_ns) ppf ns
  | `Serv_fail ns -> Fmt.(append (any "serv fail ") pp_ns) ppf ns

let get_ttl k = function
  | `Entry v -> Rr_map.ttl k v
  | `No_data (_, soa) -> soa.Soa.minimum
  | `No_domain (_, soa) -> soa.Soa.minimum
  | `Serv_fail (_, soa) -> soa.Soa.minimum

let with_ttl : type a . a Rr_map.key -> int32 -> a entry -> a entry = fun k ttl r -> match r with
  | `Entry v ->
    let v' = Rr_map.with_ttl k v ttl in
    `Entry v'
  | `No_data (name, soa) -> `No_data (name, { soa with Soa.minimum = ttl })
  | `No_domain (name, soa) -> `No_domain (name, { soa with Soa.minimum = ttl })
  | `Serv_fail (name, soa) -> `Serv_fail (name, { soa with Soa.minimum = ttl })

let find cache name query_type =
  match LRU.find name cache with
  | None -> None, Error `Cache_miss
  | Some No_domain (meta, name, soa) -> None, Ok (meta, `No_domain (name, soa))
  | Some Rr_map resource_records ->
    Some resource_records,
    match RRMap.find_opt (K query_type) resource_records with
    | Some (meta, entry) -> Ok (meta, Entry.to_entry query_type entry)
    | None -> Error `Cache_miss

let insert cache ?map ts name query_type rank entry =
  let meta = ts, rank in
  let cache = match entry with
    | `No_domain (name', soa) -> LRU.add name (No_domain (meta, name', soa)) cache
    | `Entry _ | `No_data _ | `Serv_fail _ ->
      let map = match map with None -> RRMap.empty | Some x -> x in
      let map' = RRMap.add (K query_type) (meta, Entry.of_entry query_type entry) map in
      LRU.add name (Rr_map map') cache
  in
  (* Make sure we are within memory bounds *)
  LRU.trim cache

let update_ttl typ entry ~created ~now =
  let ttl = get_ttl typ entry in
  let updated_ttl = compute_updated_ttl ~created ~now ttl in
  if updated_ttl < 0l then Error `Cache_drop else Ok (with_ttl typ updated_ttl entry)

let get cache ts name query_type =
  metrics `Lookup;
  match snd (find cache name query_type) with
  | Error e -> metrics `Miss; cache, Error e
  | Ok ((created, rank), entry) ->
    match update_ttl query_type entry ~created ~now:ts with
    | Ok entry' -> metrics `Hit; LRU.promote name cache, Ok (entry', rank)
    | Error e -> metrics `Drop; cache, Error e

let find_any cache name =
  match LRU.find name cache with
  | None -> Error `Cache_miss
  | Some No_domain (meta, name, soa) -> Ok (`No_domain (meta, name, soa))
  | Some Rr_map rrs -> Ok (`Entries rrs)

let get_any cache ts name =
  metrics `Lookup;
  match find_any cache name with
  | Error e -> metrics `Miss; cache, Error e
  | Ok r ->
    let ttl created curr =
      let ttl = compute_updated_ttl ~created ~now:ts curr in
      if ttl < 0l then Error `Cache_drop else Ok ttl
    in
    LRU.promote name cache,
    match r with
    | `No_domain ((created, rank), name, soa) ->
      begin match ttl created soa.Soa.minimum with
        | Error _ as e -> metrics `Drop; e
        | Ok minimum ->
          metrics `Hit; Ok (`No_domain (name, { soa with Soa.minimum }), rank)
      end
    | `Entries rrs ->
      let rrs, r =
        RRMap.fold (fun _k ((created, rank), v) (acc, r) ->
            match v with
            | Entry.Entry B (k, v) ->
              begin match ttl created (Rr_map.ttl k v) with
                | Ok ttl ->
                  let v' = Rr_map.with_ttl k v ttl in
                  Rr_map.add k v' acc, rank
                | Error _ -> acc, r
              end
            | _ -> acc, r) rrs (Rr_map.empty, Additional)
      in
      match Rr_map.is_empty rrs with
      | true -> metrics `Drop; Error `Cache_drop
      | false -> metrics `Hit; Ok (`Entries rrs, r)

let get_or_cname : type a . t -> int64 -> [`raw] Domain_name.t -> a Rr_map.key ->
  t * ([ a entry | `Alias of int32 * [`raw] Domain_name.t] * rank,
       [ `Cache_drop | `Cache_miss ]) result =
  fun cache ts name query_type ->
  metrics `Lookup;
  let map_result : _ -> t * ([ a entry | `Alias of int32 * [`raw] Domain_name.t] * rank, [ `Cache_drop | `Cache_miss ]) result = function
    | Error e -> metrics `Miss; cache, Error e
    | Ok ((created, rank), entry) ->
      match update_ttl query_type entry ~created ~now:ts with
      | Ok entry' -> metrics `Hit; LRU.promote name cache, Ok ((entry', rank) :> [ _ entry | `Alias of int32 * [`raw] Domain_name.t ] * rank)
      | Error e -> metrics `Drop; cache, Error e
  in
  match find cache name query_type with
  | Some map, r ->
    begin match RRMap.find_opt (K Cname) map with
      | Some ((created, rank), Entry.Entry (B (Cname, (ttl, name)))) ->
        let ttl = compute_updated_ttl ~created ~now:ts ttl in
        if ttl < 0l then
          map_result r
        else begin
          metrics `Hit;
          LRU.promote name cache, Ok (`Alias (ttl, name), rank)
        end
      | _ -> map_result r
    end
  | _, e -> map_result e

let get_nsec3 cache ts name =
  metrics `Lookup;
  let zone_labels = Domain_name.count_labels name in
  let nsec3_rrs =
    LRU.fold (fun ename entry acc ->
        if
          Domain_name.is_subdomain ~domain:name ~subdomain:ename &&
          Domain_name.count_labels ename - 1 = zone_labels
        then
          match entry with
          | Rr_map rrs ->
            begin
            match RRMap.find_opt (K Nsec3) rrs with
              | Some ((created, _), (Entry (B (Nsec3, v)) as e)) ->
                begin match update_ttl Nsec3 (Entry.to_entry Nsec3 e) ~created ~now:ts with
                  | Ok _ -> (ename, snd v) :: acc
                  | Error _ -> acc
                end
              | _ -> acc
          end
          | _ -> acc
        else
          acc)
      [] cache
  in
  match nsec3_rrs with
  | [] ->
    metrics `Miss;
    cache, Error `Cache_miss
  | xs ->
    metrics `Hit;
    List.fold_right LRU.promote (List.map fst xs) cache,
    Ok xs

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
(* according to RFC1035, section 7.3, a TTL of a week is a good
   maximum value! *)
let week = Int32.of_int Duration.(to_sec (of_day 7))

let clip_ttl_to_week query_type entry =
  let ttl = get_ttl query_type entry in
  if ttl < week then entry else with_ttl query_type week entry

let pp_query ppf (name, query_type) =
  Fmt.pf ppf "%a (%a)" Domain_name.pp name Packet.Question.pp_qtype query_type

let set cache ts name query_type rank entry  =
  let entry' = clip_ttl_to_week query_type entry in
  let cache' map = insert cache ?map ts name query_type rank entry' in
  match find cache name query_type with
  | map, Error _ ->
    Log.debug (fun m -> m "set: %a nothing found, adding: %a"
                   pp_query (name, `K (K query_type)) (pp_entry query_type) entry');
    metrics `Insert; cache' map
  | map, Ok ((created, rank'), entry) ->
    Log.debug (fun m -> m "set: %a found rank %a insert rank %a: %d"
                   pp_query (name, `K (K query_type)) pp_rank rank' pp_rank rank (compare_rank rank' rank));
    match update_ttl query_type entry ~created ~now:ts, compare_rank rank' rank with
    | Ok _, 1 -> cache
    | _ -> metrics `Insert; cache' map
