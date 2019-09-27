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

module V = struct
  type meta = int64 * rank
  let pp_meta ppf (crea, rank) =
    Fmt.pf ppf "%a created %Lu" pp_rank rank crea

  type rr_map_entry =
    | Entry of Rr_map.b
    | No_data of [ `raw ] Domain_name.t * Soa.t
    | Serv_fail of [ `raw ] Domain_name.t * Soa.t
  let pp_map_entry ppf entry = match entry with
    | Entry b -> Fmt.pf ppf "entry %a" Rr_map.pp_b b
    | No_data (name, soa) -> Fmt.pf ppf "no data %a SOA %a" Domain_name.pp name Soa.pp soa
    | Serv_fail (name, soa) -> Fmt.pf ppf "server fail %a SOA %a" Domain_name.pp name Soa.pp soa
  let to_res = function
    | Entry b -> `Entry b
    | No_data (name, soa) -> `No_data (name, soa)
    | Serv_fail (name, soa) -> `Serv_fail (name, soa)
  let of_res = function
    | `Entry b -> Entry b
    | `No_data (name, soa) -> No_data (name, soa)
    | `Serv_fail (name, soa) -> Serv_fail (name, soa)
    | _ -> assert false

  type t =
    | Alias of meta * int32 * [ `raw ] Domain_name.t
    | No_domain of meta * [ `raw ] Domain_name.t * Soa.t
    | Rr_map of (meta * rr_map_entry) RRMap.t

  (* Part of the LRU.Weighted interface *)
  let weight = function
    | Alias _ | No_domain _ -> 1
    | Rr_map tm -> RRMap.cardinal tm

  let pp_entry ppf (meta, entry) = Fmt.pf ppf "e (%a) %a" pp_meta meta pp_map_entry entry

  let pp ppf = function
    | Alias (meta, ttl, a) ->
      Fmt.pf ppf "alias (%a) TTL %lu %a" pp_meta meta ttl Domain_name.pp a
    | No_domain (meta, name, soa) ->
      Fmt.pf ppf "no domain (%a) %a SOA %a" pp_meta meta Domain_name.pp name Soa.pp soa
    | Rr_map rr ->
      Fmt.pf ppf "entries: %a"
        Fmt.(list ~sep:(unit ";@,") (pair Rr_map.ppk pp_entry))
        (RRMap.bindings rr)
end

module D = struct
  type t = [ `raw ] Domain_name.t
  let compare = Domain_name.compare
end

module LRU = Lru.F.Make(D)(V)

type t = LRU.t

let pp_question ppf (name, typ) =
  Fmt.pf ppf "%a (%a)" Domain_name.pp name Packet.Question.pp_qtype typ

type stats = {
  hit : int ;
  miss : int ;
  drop : int ;
  insert : int ;
}

let s = ref { hit = 0 ; miss = 0 ; drop = 0 ; insert = 0 }

let _pp_stats pf s =
  Fmt.pf pf "cache: %d hits %d misses %d drops %d inserts" s.hit s.miss s.drop s.insert

let _stats () = !s

(* this could need a `Timeout error result *)

let empty = LRU.empty

let size = LRU.size

let capacity = LRU.capacity

let pp = LRU.pp Fmt.(pair ~sep:(unit ": ") Domain_name.pp V.pp)

module N = Domain_name.Set

let update_ttl ~created ~now ttl =
  Int32.sub ttl (Int32.of_int (Duration.to_sec (Int64.sub now created)))

type entry = [
  | `Alias of int32 * [ `raw ] Domain_name.t
  | `Entry of Rr_map.b
  | `No_data of [ `raw ] Domain_name.t * Soa.t
  | `No_domain of [ `raw ] Domain_name.t * Soa.t
  | `Serv_fail of [ `raw ] Domain_name.t * Soa.t
]

let pp_entry ppf entry =
  let pp_ns ppf (name, soa) = Fmt.pf ppf "%a SOA %a" Domain_name.pp name Soa.pp soa in
  match entry with
  | `Alias (ttl, name) -> Fmt.pf ppf "alias TTL %lu %a" ttl Domain_name.pp name
  | `Entry b -> Fmt.pf ppf "entry %a" Rr_map.pp_b b
  | `No_data ns -> Fmt.(prefix (unit "no data ") pp_ns) ppf ns
  | `No_domain ns -> Fmt.(prefix (unit "no domain ") pp_ns) ppf ns
  | `Serv_fail ns -> Fmt.(prefix (unit "serv fail ") pp_ns) ppf ns

let get_ttl = function
  | `Alias (ttl, _) -> ttl
  | `Entry b -> Rr_map.get_ttl b
  | `No_data (_, soa) -> soa.Soa.minimum
  | `No_domain (_, soa) -> soa.Soa.minimum
  | `Serv_fail (_, soa) -> soa.Soa.minimum

let with_ttl ttl = function
  | `Alias (_, name) -> `Alias (ttl, name)
  | `Entry b -> `Entry (Rr_map.with_ttl b ttl)
  | `No_data (name, soa) -> `No_data (name, { soa with Soa.minimum = ttl })
  | `No_domain (name, soa) -> `No_domain (name, { soa with Soa.minimum = ttl })
  | `Serv_fail (name, soa) -> `Serv_fail (name, { soa with Soa.minimum = ttl })

let find_lru t name typ =
  match LRU.find name t with
  | None -> None, Error `Cache_miss
  | Some Alias (meta, ttl, alias) -> None, Ok (meta, `Alias (ttl, alias))
  | Some No_domain (meta, name, soa) -> None, Ok (meta, `No_domain (name, soa))
  | Some Rr_map tm ->
    Some tm,
    try
      let meta, entry = RRMap.find (K typ) tm in
      Ok (meta, V.to_res entry)
    with
    | Not_found -> Error `Cache_miss

let insert_lru t ?map name typ created rank res =
  s := { !s with insert = succ !s.insert };
  let meta = created, rank in
  let t' = match res with
    | `No_domain (name', soa) -> LRU.add name (No_domain (meta, name', soa)) t
    | `Alias (ttl, alias) -> LRU.add name (Alias (meta, ttl, alias)) t
    | `Entry _ | `No_data _ | `Serv_fail _ ->
      let map = match map with None -> RRMap.empty | Some x -> x in
      let map' = RRMap.add (K typ) (meta, V.of_res res) map in
      LRU.add name (Rr_map map') t
  in
  LRU.trim t'

let update_ttl_res e ~created ~now =
  let ttl = get_ttl e in
  let updated_ttl = update_ttl ~created ~now ttl in
  if updated_ttl < 0l then Error `Cache_drop else Ok (with_ttl updated_ttl e)

let get t ts typ nam =
  match snd (find_lru t nam typ) with
  | Error e ->
    s := { !s with miss = succ !s.miss };
    Error e
  | Ok ((created, _), e) ->
    match update_ttl_res e ~created ~now:ts with
    | Ok e' ->
      s := { !s with hit = succ !s.hit };
      Ok (e', LRU.promote nam t)
    | Error e ->
      s := { !s with drop = succ !s.drop };
      Error e

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

let smooth_ttl e =
  let ttl = get_ttl e in
  if ttl < week then e else with_ttl week e

let set t ts typ nam rank e  =
  let entry = smooth_ttl e in
  match find_lru t nam typ with
  | map, Error _ ->
    Logs.debug (fun m -> m "maybe_insert: %a nothing found, adding: %a"
                   pp_question (nam, `K (K typ)) pp_entry entry);
    insert_lru ?map t nam typ ts rank entry
  | map, Ok ((_, rank'), entry) ->
    Logs.debug (fun m -> m "maybe_insert: %a found rank %a insert rank %a: %d"
                   pp_question (nam, `K (K typ)) pp_rank rank' pp_rank rank (compare_rank rank' rank));
    match compare_rank rank' rank with
    | 1 -> t
    | _ -> insert_lru ?map t nam typ ts rank entry
