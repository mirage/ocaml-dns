(* (c) 2017 Hannes Mehnert, all rights reserved *)

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
  | NoErr of Udns_packet.rr list
  | NoData of Udns_packet.rr
  | NoDom of Udns_packet.rr
  | ServFail of Udns_packet.rr

let pp_res ppf = function
  | NoErr rrs -> Fmt.pf ppf "NoError %a" Udns_packet.pp_rrs rrs
  | NoData soa -> Fmt.pf ppf "NoData (NoError) SOA %a" Udns_packet.pp_rr soa
  | NoDom soa -> Fmt.pf ppf "NXDomain SOA %a" Udns_packet.pp_rr soa
  | ServFail soa -> Fmt.pf ppf "servfail SOA %a" Udns_packet.pp_rr soa

