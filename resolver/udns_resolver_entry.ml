(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Udns

type rank =
  | ZoneFile
  | ZoneTransfer
  | AuthoritativeAnswer
  | AuthoritativeAuthority
  | ZoneGlue
  | NonAuthoritativeAnswer
  | Additional

let compare_rank a b = match a, b with
  | ZoneFile, ZoneFile -> `Equal
  | ZoneFile, _ -> `Bigger
  | _, ZoneFile -> `Smaller
  | ZoneTransfer, ZoneTransfer -> `Equal
  | ZoneTransfer, _ -> `Bigger
  | _, ZoneTransfer -> `Smaller
  | AuthoritativeAnswer, AuthoritativeAnswer -> `Equal
  | AuthoritativeAnswer, _ -> `Bigger
  | _, AuthoritativeAnswer -> `Smaller
  | AuthoritativeAuthority, AuthoritativeAuthority -> `Equal
  | AuthoritativeAuthority, _ -> `Bigger
  | _, AuthoritativeAuthority -> `Smaller
  | ZoneGlue, ZoneGlue -> `Equal
  | ZoneGlue, _ -> `Bigger
  | _, ZoneGlue -> `Smaller
  | NonAuthoritativeAnswer, NonAuthoritativeAnswer -> `Equal
  | NonAuthoritativeAnswer, _ -> `Bigger
  | _, NonAuthoritativeAnswer -> `Smaller
  | Additional, Additional -> `Equal

let pp_rank ppf r = Fmt.string ppf (match r with
    | ZoneFile -> "zone file data"
    | ZoneTransfer -> "zone transfer data"
    | AuthoritativeAnswer -> "authoritative answer data"
    | AuthoritativeAuthority -> "authoritative authority data"
    | ZoneGlue -> "zone file glue"
    | NonAuthoritativeAnswer -> "non-authoritative answer"
    | Additional -> "additional data")

type res =
  | NoErr of Rr_map.b
  | NoData of Domain_name.t * (int32 * Soa.t)
  | NoDom of Domain_name.t * (int32 * Soa.t)
  | ServFail of Domain_name.t * (int32 * Soa.t)

let decrease_ttl amount = function
  | NoErr b ->
    let ttl = Int32.sub (Rr_map.get_ttl b) amount in
    if ttl < 0l then None else Some (NoErr (Rr_map.with_ttl b ttl))
  | NoData (name, (ttl, soa)) ->
    let ttl = Int32.sub ttl amount in
    if ttl < 0l then None else Some (NoData (name, (ttl, soa)))
  | NoDom (name, (ttl, soa)) ->
    let ttl = Int32.sub ttl amount in
    if ttl < 0l then None else Some (NoDom (name, (ttl, soa)))
  | ServFail (name, (ttl, soa)) ->
    let ttl = Int32.sub ttl amount in
    if ttl < 0l then None else Some (ServFail (name, (ttl, soa)))

let smooth_ttl maximum = function
  | NoErr b ->
    let ttl = Rr_map.get_ttl b in
    NoErr (Rr_map.with_ttl b (min maximum ttl))
  | NoData (name, (ttl, soa)) -> NoData (name, (min maximum ttl, soa))
  | NoDom (name, (ttl, soa)) -> NoDom (name, (min maximum ttl, soa))
  | ServFail (name, (ttl, soa)) -> ServFail (name, (min maximum ttl, soa))

let to_map =
  let doit name soa =
    Domain_name.Map.singleton name Rr_map.(singleton Soa soa)
  in
  function
  | NoErr _ -> assert false
  | NoData (name, (_, soa)) -> doit name soa
  | NoDom (name, (_, soa)) -> doit name soa
  | ServFail (name, (_, soa)) -> doit name soa

let pp_res ppf = function
  | NoErr rr -> Fmt.pf ppf "NoError %a" Rr_map.pp_b rr
  | NoData (name, (ttl, soa)) -> Fmt.pf ppf "NoData (NoError) %a TTL %lu %a" Domain_name.pp name ttl Soa.pp soa
  | NoDom (name, (ttl, soa)) -> Fmt.pf ppf "NXDomain %a TTL %lu %a" Domain_name.pp name ttl Soa.pp soa
  | ServFail (name, (ttl, soa)) -> Fmt.pf ppf "servfail %a TTL %lu %a" Domain_name.pp name ttl Soa.pp soa

