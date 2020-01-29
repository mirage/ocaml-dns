(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Dns

type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer
  | AuthoritativeAuthority
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
  | AuthoritativeAnswer, AuthoritativeAnswer -> 0
  | AuthoritativeAnswer, _ -> 1
  | _, AuthoritativeAnswer -> -1
  | AuthoritativeAuthority, AuthoritativeAuthority -> 0
  | AuthoritativeAuthority, _ -> 1
  | _, AuthoritativeAuthority -> -1
  | ZoneGlue, ZoneGlue -> 0
  | ZoneGlue, _ -> 1
  | _, ZoneGlue -> -1
  | NonAuthoritativeAnswer, NonAuthoritativeAnswer -> 0
  | NonAuthoritativeAnswer, _ -> 1
  | _, NonAuthoritativeAnswer -> -1
  | Additional, Additional -> 0

let pp_rank ppf r = Fmt.string ppf (match r with
    | ZoneFile -> "zone file data"
    | ZoneTransfer -> "zone transfer data"
    | AuthoritativeAnswer -> "authoritative answer data"
    | AuthoritativeAuthority -> "authoritative authority data"
    | ZoneGlue -> "zone file glue"
    | NonAuthoritativeAnswer -> "non-authoritative answer"
    | Additional -> "additional data")

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
  let to_entry = function
    | Entry b -> `Entry b
    | No_data (name, soa) -> `No_data (name, soa)
    | Serv_fail (name, soa) -> `Serv_fail (name, soa)
  let of_entry = function
    | `Entry b -> Entry b
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
        Fmt.(list ~sep:(unit ";@,") (pair Rr_map.ppk pp_entry))
        (RRMap.bindings rr)
end

module Key = struct
  type t = [ `raw ] Domain_name.t
  let equal a b = Domain_name.equal a b
  let hash r v = Hashtbl.seeded_hash r v
end

module LRU = Lru.M.MakeSeeded(Key)(Entry)

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

let empty size = LRU.create ~random:true size

let size = LRU.size

let capacity = LRU.capacity

let pp = LRU.pp Fmt.(pair ~sep:(unit ": ") Domain_name.pp Entry.pp)

module N = Domain_name.Set

let update_ttl ~created ~now ttl =
  Int32.sub ttl (Int32.of_int (Duration.to_sec (Int64.sub now created)))

type entry = [
  | `Entry of Rr_map.b
  | `No_data of [ `raw ] Domain_name.t * Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Soa.t
  | `Serv_fail of [ `raw ] Domain_name.t * Soa.t
]

let pp_entry ppf entry =
  let pp_ns ppf (name, soa) = Fmt.pf ppf "%a SOA %a" Domain_name.pp name Soa.pp soa in
  match entry with
  | `Entry b -> Fmt.pf ppf "entry %a" Rr_map.pp_b b
  | `No_data ns -> Fmt.(prefix (unit "no data ") pp_ns) ppf ns
  | `No_domain ns -> Fmt.(prefix (unit "no domain ") pp_ns) ppf ns
  | `Serv_fail ns -> Fmt.(prefix (unit "serv fail ") pp_ns) ppf ns

let get_ttl = function
  | `Entry b -> Rr_map.get_ttl b
  | `No_data (_, soa) -> soa.Soa.minimum
  | `No_domain (_, soa) -> soa.Soa.minimum
  | `Serv_fail (_, soa) -> soa.Soa.minimum

let with_ttl ttl = function
  | `Entry b -> `Entry (Rr_map.with_ttl b ttl)
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
    | Some (meta, entry) -> Ok (meta, Entry.to_entry entry)
    | None -> Error `Cache_miss

let insert cache ?map ts name query_type rank entry =
  let meta = ts, rank in
  (match entry with
   | `No_domain (name', soa) -> LRU.add name (No_domain (meta, name', soa)) cache
   | `Entry _ | `No_data _ | `Serv_fail _ ->
     let map = match map with None -> RRMap.empty | Some x -> x in
     let map' = RRMap.add (K query_type) (meta, Entry.of_entry entry) map in
     LRU.add name (Rr_map map') cache);
  (* Make sure we are within memory bounds *)
  LRU.trim cache

let update_ttl entry ~created ~now =
  let ttl = get_ttl entry in
  let updated_ttl = update_ttl ~created ~now ttl in
  if updated_ttl < 0l then Error `Cache_drop else Ok (with_ttl updated_ttl entry)

let get cache ts name query_type =
  metrics `Lookup;
  match snd (find cache name query_type) with
  | Error e -> metrics `Miss; Error e
  | Ok ((created, _), entry) ->
    match update_ttl entry ~created ~now:ts with
    | Ok entry' -> metrics `Hit; LRU.promote name cache; Ok entry'
    | Error e -> metrics `Drop; Error e

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

let clip_ttl_to_week entry =
  let ttl = get_ttl entry in
  if ttl < week then entry else with_ttl week entry

let pp_query ppf (name, query_type) =
  Fmt.pf ppf "%a (%a)" Domain_name.pp name Packet.Question.pp_qtype query_type

let set cache ts name query_type rank entry  =
  let entry' = clip_ttl_to_week entry in
  let cache' map = insert cache ?map ts name query_type rank entry' in
  match find cache name query_type with
  | map, Error _ ->
    Logs.debug (fun m -> m "set: %a nothing found, adding: %a"
                   pp_query (name, `K (K query_type)) pp_entry entry');
    metrics `Insert; cache' map
  | map, Ok ((_, rank'), _) ->
    Logs.debug (fun m -> m "set: %a found rank %a insert rank %a: %d"
                   pp_query (name, `K (K query_type)) pp_rank rank' pp_rank rank (compare_rank rank' rank));
    match compare_rank rank' rank with
    | 1 -> ()
    | _ -> metrics `Insert; cache' map
