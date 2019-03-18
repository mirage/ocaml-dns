(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult
open R.Infix

let src = Logs.Src.create "dns_server" ~doc:"DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module IPM = Map.Make(Ipaddr.V4)

let guard p err = if p then Ok () else Error err

type proto = [ `Tcp | `Udp ]

let s_header h =
  { h with Udns_packet.authoritative = true ; query = false ;
           recursion_available = false ; authentic_data = false }

let err header v rcode =
  let header =
    let hdr = s_header header in
    let authoritative = if rcode = Udns_enum.NotAuth then false else true in
    { hdr with Udns_packet.authoritative }
  in
  Udns_packet.error header v rcode


module Authentication = struct

  type a = Udns_trie.t -> proto -> Domain_name.t option -> string -> Domain_name.t -> bool

  type t = Udns_trie.t * a list

  let keys (keys, _) = keys

  type operation = [
    | `Key_management
    | `Update
    | `Transfer
  ]

  let operation_to_string = function
    | `Key_management -> "_key-management"
    | `Update -> "_update"
    | `Transfer -> "_transfer"

  let operation_name ?(zone = Domain_name.root) op =
    Domain_name.prepend_exn ~hostname:false zone (operation_to_string op)

  let is_op op name =
    let arr = Domain_name.to_array name in
    Array.exists (String.equal (operation_to_string op)) arr

  let find_zone_ips name =
    (* the name of a key is primaryip.secondaryip._transfer.zone
       e.g. 192.168.42.2_1053.192.168.42.1._transfer.mirage
       alternative: <whatever>.primaryip._transfer.zone *)
    let arr = Domain_name.to_array name in
    try
      let rec go idx = if Array.get arr idx = "_transfer" then idx else go (succ idx) in
      let zone_idx = go 0 in
      let zone = Domain_name.of_array (Array.sub arr 0 zone_idx) in
      let start = succ zone_idx in
      let ip_port start =
        try
          let subarr = Array.sub arr start 4 in
          let content, port =
            let last = Array.get subarr 0 in
            match Astring.String.cut ~sep:"_" last with
            | None -> last, 53
            | Some (a, b) -> a, int_of_string b
          in
          Array.set subarr 0 content ;
          let host = Domain_name.of_array subarr in
          (match Ipaddr.V4.of_string (Domain_name.to_string host) with
           | Error _ -> None
           | Ok ip -> Some ip), port
        with Invalid_argument _ -> None, 53
      in
      match ip_port (start + 4), ip_port start with
      | _, (None, _) -> None
      | (None, _), (Some ip, po) -> Some (zone, (ip, po), None)
      | (Some primary, pport), (Some secondary, sport) ->
        Some (zone, (primary, pport), Some (secondary, sport))
    with Invalid_argument _ -> None

  let find_ns s (trie, _) zone =
    let tx = operation_name ~zone `Transfer in
    let accumulate name _ acc =
      match find_zone_ips name, s with
      | None, _ -> acc
      | Some (_, prim, _), `P ->
        let (ip, port) = prim in
        (name, ip, port) :: acc
      | Some (_, _, Some sec), `S ->
        let (ip, port) = sec in
        (name, ip, port) :: acc
      | Some (_, _, None), `S -> acc
    in
    Udns_trie.folde tx Udns_map.Dnskey trie accumulate []

  let secondaries t zone = find_ns `S t zone

  let primaries t zone = find_ns `P t zone

  let all_operations =
    List.map operation_to_string [ `Key_management ; `Update ; `Transfer ]

  let zone name =
    let arr = Domain_name.to_array name in
    let len = Array.length arr in
    let rec go idx =
      if idx = len
      then len
      else if List.exists (String.equal (Array.get arr idx)) all_operations
      then idx
      else go (succ idx)
    in
    let zidx = go 0 in
    Domain_name.of_array (Array.sub arr 0 zidx)

  let soa name =
    let soa = { Udns_packet.nameserver = name ; hostmaster = name ;
                serial = 0l ; refresh = 16384l ; retry = 2048l ;
                expiry = 1048576l ; minimum = 300l }
    in
    (300l, soa)

  let add_key trie name key =
    let zone = zone name in
    let soa =
      match Udns_trie.lookup zone Udns_map.Soa trie with
      | Ok (ttl, soa) ->
        let soa' = { soa with Udns_packet.serial = Int32.succ soa.Udns_packet.serial } in
        (ttl, soa')
      | Error _ ->
        soa name
    in
    let keys = match Udns_trie.lookup name Udns_map.Dnskey trie with
      | Error _ -> Udns_map.DnskeySet.singleton key
      | Ok keys ->
        Log.warn (fun m -> m "replacing unexpected Dnskey (name %a, have %a, got %a)"
                     Domain_name.pp name
                     Fmt.(list ~sep:(unit ",") Udns_packet.pp_dnskey)
                     (Udns_map.DnskeySet.elements keys)
                     Udns_packet.pp_dnskey key ) ;
        Udns_map.DnskeySet.singleton key
    in
    let trie' = Udns_trie.insert zone Udns_map.Soa soa trie in
    Udns_trie.insert name Udns_map.Dnskey keys trie'

  let of_keys keys =
    List.fold_left (fun trie (name, key) -> add_key trie name key)
      Udns_trie.empty keys

  let remove_key trie name =
    let trie' = Udns_trie.remove name Udns_enum.DNSKEY trie in
    let zone = zone name in
    match Udns_trie.entries zone trie' with
    | Ok (_soa, []) -> Udns_trie.remove_zone zone trie'
    | Ok _ -> trie'
    | Error e ->
      Log.warn (fun m -> m "expected a zone for dnskeys, got error %a"
                  Udns_trie.pp_e e) ;
      trie'

  let find_key t name =
    match Udns_trie.lookup name Udns_map.Dnskey (fst t) with
    | Ok keys ->
      if Udns_map.DnskeySet.cardinal keys = 1 then
        Some (Udns_map.DnskeySet.choose keys)
      else begin
        Log.warn (fun m -> m "found multiple (%d) keys for %a"
                     (Udns_map.DnskeySet.cardinal keys)
                     Domain_name.pp name) ;
        None
      end
    | Error e ->
      Log.warn (fun m -> m "error %a while looking up key %a" Udns_trie.pp_e e
                   Domain_name.pp name) ;
      None

  let handle_update keys us =
    List.fold_left (fun (keys, actions) -> function
        | Udns_packet.Remove_all name
        | Udns_packet.Remove (name, Udns_enum.DNSKEY)
        | Udns_packet.Remove_single (name, Udns_packet.DNSKEY _) ->
          let keys = remove_key keys name in
          keys, `Removed_key name :: actions
        | Udns_packet.Add rr ->
          begin match rr.Udns_packet.rdata with
            | Udns_packet.DNSKEY key ->
              let name = rr.Udns_packet.name in
              let keys = add_key keys name key in
              keys, `Added_key name :: actions
            | rdata ->
              Log.warn (fun m -> m "only accepting Dnskey here, got %a"
                           Udns_packet.pp_rdata rdata) ;
              keys, actions
          end
        | u ->
          Log.warn (fun m -> m "only Dnskey, not sure what you intended %a"
                       Udns_packet.pp_rr_update u) ;
          keys, actions)
      (keys, []) us

  let tsig_auth _ _ keyname op zone =
    match keyname with
    | None -> false
    | Some subdomain ->
      let root = Domain_name.of_string_exn ~hostname:false op
      and zone = Domain_name.prepend_exn ~hostname:false zone op
      in
      Domain_name.sub ~subdomain ~domain:zone
      || Domain_name.sub ~subdomain ~domain:root

  let authorise (data, authorised) proto keyname zone operation =
    let op = operation_to_string operation in
    List.exists (fun a -> a data proto keyname op zone) authorised
end

type t = {
  data : Udns_trie.t ;
  auth : Authentication.t ;
  rng : int -> Cstruct.t ;
  tsig_verify : Udns_packet.tsig_verify ;
  tsig_sign : Udns_packet.tsig_sign ;
}

let text name t =
  let buf = Buffer.create 1024 in
  Rresult.R.reword_error
    (Fmt.to_to_string Udns_trie.pp_e)
    (Udns_trie.fold name t.data
       (fun name v () ->
          Buffer.add_string buf (Udns_map.text name v) ;
          Buffer.add_char buf '\n')
       ()) >>| fun () ->
  Buffer.contents buf


let create data auth rng tsig_verify tsig_sign =
  { data ; auth ; rng ; tsig_verify ; tsig_sign }

let to_ns_rrs name ttl ns =
  Domain_name.Set.fold (fun ns acc ->
      { Udns_packet.name ; ttl ; rdata = Udns_packet.NS ns } :: acc)
    ns []

let to_soa name ttl soa =
  [ { Udns_packet.name ; ttl ; rdata = Udns_packet.SOA soa } ]

let find_glue trie typ name names =
  let a, aaaa =
    let open Domain_name.Set in
    match typ with
    | Udns_enum.A -> singleton name, empty
    | Udns_enum.AAAA -> empty, singleton name
    | Udns_enum.ANY -> singleton name, singleton name
    | _ -> empty, empty
  in
  let find_rr typ name =
    match Udns_trie.lookupb name typ trie with
    | Ok (v, _) -> Udns_map.to_rr name v
    | _ -> []
  in
  Domain_name.Set.fold (fun name acc ->
      (if Domain_name.Set.mem name a then [] else find_rr Udns_enum.A name) @
      (if Domain_name.Set.mem name aaaa then [] else find_rr Udns_enum.AAAA name) @
      acc)
    names []

let lookup trie hdr q =
  let open Udns_packet in
  let answer ?(authoritative = true) ?(rcode = Udns_enum.NoError) ?(an = []) ?(au = []) ?(ad = []) () =
    (* TODO: should randomize answers + ad? *)
    (* TODO: should dedup at a higher layer (v instead of rr) *)
    let hdr = s_header hdr in
    let hdr = { hdr with authoritative ; rcode } in
    let authority =
      List.filter (fun a ->
          not (List.exists (fun an -> Udns_packet.rr_equal an a) an))
        au
    in
    let additional =
      List.filter (fun a ->
          not (List.exists (fun rr -> Udns_packet.rr_equal rr a) (an@authority)))
        ad
    in
    Ok (hdr, `Query { question = [ q ] ; answer = an ; authority ; additional })
  in
  match Udns_trie.lookupb q.q_name q.q_type trie with
  | Ok (v, (name, ttl, ns)) ->
    let an = Udns_map.to_rr q.q_name v
    and au = to_ns_rrs name ttl ns
    in
    let ad =
      let names = Domain_name.Set.union (Udns_map.names v) ns in
      find_glue trie q.q_type q.q_name names
    in
    answer ~an ~au ~ad ()
  | Error (`Delegation (name, (ttl, ns))) ->
    let ad =
      Domain_name.Set.fold (fun name acc ->
          (* TODO aaaa records! *)
          match Udns_trie.lookup_ignore name Udns_enum.A trie with
          | Ok (Udns_map.B (Udns_map.A, _) as v) -> Udns_map.to_rr name v @ acc
          | _ -> acc)
        ns []
    in
    answer ~authoritative:false ~au:(to_ns_rrs name ttl ns) ~ad ()
  | Error (`EmptyNonTerminal (zname, ttl, soa)) ->
    answer ~au:(to_soa zname ttl soa) ()
  | Error (`NotFound (zname, ttl, soa)) ->
    answer ~rcode:Udns_enum.NXDomain ~au:(to_soa zname ttl soa) ()
  | Error `NotAuthoritative -> Error Udns_enum.NotAuth

let axfr trie proto q zone =
  (if proto = `Udp then begin
      Log.err (fun m -> m "refusing AXFR query via UDP") ;
      Error Udns_enum.Refused
    end else
     Ok ()) >>= fun () ->
  match Udns_trie.entries zone trie with
  | Ok (soa, rrs) ->
    let answer = soa :: rrs @ [ soa ]
    and question = q.Udns_packet.question
    and authority = []
    and additional = []
    in
    Ok (`Query { Udns_packet.question ; answer ; authority ; additional })
  | Error `Delegation _
  | Error `NotAuthoritative
  | Error `NotFound _ ->
    Log.err (fun m -> m "AXFR attempted on %a, where we're not authoritative"
                 Domain_name.pp zone) ;
    Error Udns_enum.NXDomain

let axfr t proto key q zone =
  (if Authentication.authorise t.auth proto key zone `Key_management then begin
      Log.info (fun m -> m "key-management key %a authorised for AXFR %a"
                   Fmt.(option ~none:(unit "none") Domain_name.pp) key
                   Udns_packet.pp_query q) ;
      Ok (Authentication.keys t.auth)
    end else if Authentication.authorise t.auth proto key zone `Transfer then begin
      Log.info (fun m -> m "transfer key %a authorised for AXFR %a"
                   Fmt.(option ~none:(unit "none") Domain_name.pp) key
                   Udns_packet.pp_query q) ;
      Ok t.data
    end else
     Error Udns_enum.NotAuth) >>= fun trie ->
  axfr trie proto q zone

let lookup t proto key hdr q =
  let trie =
    if Authentication.authorise t.auth proto key q.Udns_packet.q_name `Key_management then begin
      Log.info (fun m -> m "key-management key %a authorised for lookup %a"
                   Fmt.(option ~none:(unit "none") Domain_name.pp) key
                   Udns_packet.pp_question q) ;
      Authentication.keys t.auth
    end else
      t.data
  in
  lookup trie hdr q

let safe_decode buf =
  match Udns_packet.decode buf with
  | Error `Partial ->
    Log.err (fun m -> m "partial frame (length %d)@.%a" (Cstruct.len buf) Cstruct.hexdump_pp buf) ;
    Error Udns_enum.FormErr
  | Error (`DisallowedRRTyp _ | `DisallowedClass _ | `UnsupportedClass _ as e) ->
    Log.err (fun m -> m "refusing %a while decoding@.%a"
                 Udns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Udns_enum.Refused
  | Error (`BadRRTyp _ | `BadClass _ | `UnsupportedOpcode _ as e) ->
    Log.err (fun m -> m "not implemented %a while decoding@.%a"
                 Udns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Udns_enum.NotImp
  | Error (`BadContent x) ->
    Log.err (fun m -> m "bad content error %s while decoding@.%a"
                 x Cstruct.hexdump_pp buf) ;
    Error Udns_enum.FormErr
  | Error (`Bad_edns_version i) ->
    Log.err (fun m -> m "bad edns version error %u while decoding@.%a"
                 i Cstruct.hexdump_pp buf) ;
    Error Udns_enum.BadVersOrSig
  | Error e ->
    Log.err (fun m -> m "error %a while decoding@.%a"
                 Udns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Udns_enum.FormErr
  | Ok v -> Ok v

let handle_query t proto key header query =
  match query.Udns_packet.question with
  | [ q ] ->
    let open Udns_enum in
    begin match q.Udns_packet.q_type with
      | AXFR ->
        axfr t proto key query q.Udns_packet.q_name >>= fun answer ->
        let hdr = s_header header in
        Ok (hdr, answer)
      | A | NS | CNAME | SOA | PTR | MX | TXT | AAAA | SRV | ANY | CAA | SSHFP | TLSA | DNSKEY ->
        lookup t proto key header q
      | r ->
        Log.err (fun m -> m "refusing query type %a" Udns_enum.pp_rr_typ r) ;
        Error Udns_enum.Refused
    end
  | qs ->
    Log.err (fun m -> m "%d questions %a, bailing"
                (List.length qs)
                Fmt.(list ~sep:(unit ",@ ") Udns_packet.pp_question) qs) ;
    Error Udns_enum.FormErr

let in_zone zone name = Domain_name.sub ~subdomain:name ~domain:zone

(* this implements RFC 2136 Section 2.4 + 3.2 *)
let handle_rr_prereq trie zone acc = function
  | Udns_packet.Name_inuse name ->
    guard (in_zone zone name) Udns_enum.NotZone >>= fun () ->
    begin match Udns_trie.lookupb name Udns_enum.A trie with
      | Ok _ | Error (`EmptyNonTerminal _) -> Ok acc
      | _ -> Error Udns_enum.NXDomain
    end
  | Udns_packet.Exists (name, typ) ->
    guard (in_zone zone name) Udns_enum.NotZone >>= fun () ->
    begin match Udns_trie.lookupb name typ trie with
      | Ok _ -> Ok acc
      | _ -> Error Udns_enum.NXRRSet
    end
  | Udns_packet.Not_name_inuse name ->
    guard (in_zone zone name) Udns_enum.NotZone >>= fun () ->
    begin match Udns_trie.lookupb name Udns_enum.A trie with
      | Error (`NotFound _) -> Ok acc
      | _ -> Error Udns_enum.YXDomain
    end
  | Udns_packet.Not_exists (name, typ) ->
    guard (in_zone zone name) Udns_enum.NotZone >>= fun () ->
    begin match Udns_trie.lookupb name typ trie with
      | Error (`EmptyNonTerminal _ | `NotFound _) -> Ok acc
      | _ -> Error Udns_enum.YXRRSet
    end
  | Udns_packet.Exists_data (name, rdata) ->
    guard (in_zone zone name) Udns_enum.NotZone >>= fun () ->
    Ok ({ Udns_packet.name ; ttl = 0l ; rdata } :: acc)

let check_exists trie rrs =
  let map = Udns_map.of_rrs rrs in
  Domain_name.Map.fold (fun name map r ->
      r >>= fun () ->
      Udns_map.fold (fun v r ->
          r >>= fun () ->
          match Udns_trie.lookupb name (Udns_map.to_rr_typ v) trie with
          | Ok (v', _) when Udns_map.equal_b v v' -> Ok ()
          | _ -> Error Udns_enum.NXRRSet)
        map r)
    map (Ok ())

(* RFC 2136 Section 2.5 + 3.4.2 *)
(* we partially ignore 3.4.2.3 and 3.4.2.4 by not special-handling of NS, SOA *)
let handle_rr_update trie = function
  | Udns_packet.Remove (name, typ) ->
    begin match typ with
      | Udns_enum.ANY ->
        Log.warn (fun m -> m "ignoring request to remove %a %a"
                      Udns_enum.pp_rr_typ typ Domain_name.pp name) ;
        trie
      | Udns_enum.SOA ->
        (* this does not follow 2136, but we want to be able to remove a zone *)
        Udns_trie.remove_zone name trie
      | _ -> Udns_trie.remove name typ trie
    end
  | Udns_packet.Remove_all name -> Udns_trie.remove name Udns_enum.ANY trie
  | Udns_packet.Remove_single (name, rdata) ->
    let typ = Udns_packet.rdata_to_rr_typ rdata in
    begin match typ with
      | Udns_enum.ANY | Udns_enum.SOA ->
        Log.warn (fun m -> m "ignoring request to remove %a %a %a"
                      Udns_enum.pp_rr_typ typ Domain_name.pp name
                      Udns_packet.pp_rdata rdata) ;
        trie
      | _ ->
        begin match Udns_trie.lookupb name typ trie with
          | Ok (Udns_map.B (Udns_map.Cname, _), _) when Udns_enum.CNAME = typ ->
            (* we could be picky and require rdata.name == alias *)
            Udns_trie.remove name typ trie
          | Ok (Udns_map.B (Udns_map.Cname, _), _) ->
            Log.warn (fun m -> m "ignoring request to remove %a %a %a (got a cname on lookup)"
                          Udns_enum.pp_rr_typ typ Domain_name.pp name Udns_packet.pp_rdata rdata) ;
            trie
          | Ok (v, _) ->
            Log.info (fun m -> m "removing single entry");
            begin match Udns_map.remove_rdata v rdata with
              | None ->
                Log.info (fun m -> m "removed single entry, none leftover");
                Udns_trie.remove name typ trie
              | Some v ->
                Log.info (fun m -> m "removed single entry, leftover: %a" Udns_map.pp_b v);
                Udns_trie.insertb name v trie
            end
          | Error e ->
            Log.warn (fun m -> m "error %a while looking up %a %a %a for removal"
                          Udns_trie.pp_e e Udns_enum.pp_rr_typ typ
                          Domain_name.pp name Udns_packet.pp_rdata rdata) ;
            trie
        end
    end
  | Udns_packet.Add rr ->
    let typ = Udns_packet.rdata_to_rr_typ rr.Udns_packet.rdata in
    begin match typ with
      | Udns_enum.ANY ->
        Log.warn (fun m -> m "ignoring request to add %a" Udns_packet.pp_rr rr) ;
        trie
      | _ ->
        match rr.Udns_packet.rdata with
        | Udns_packet.Raw (_, _) | Udns_packet.TSIG _ ->
          Log.warn (fun m -> m "ignoring request to add %a" Udns_packet.pp_rr rr) ;
          trie
        | _ ->
          match Udns_trie.lookupb rr.Udns_packet.name typ trie with
          | Ok (Udns_map.B (Udns_map.Cname, (_, alias)), _) ->
            Log.warn (fun m -> m "found a CNAME %a, won't add %a"
                          Domain_name.pp alias Udns_packet.pp_rr rr) ;
            trie
          | Ok (v, _) ->
            begin match Udns_map.add_rdata v rr.Udns_packet.rdata with
              | None ->
                Log.warn (fun m -> m "error while adding %a to %a"
                              Udns_packet.pp_rr rr Udns_map.pp_b v) ;
                trie
              | Some v ->
                Udns_trie.insertb rr.Udns_packet.name v trie
            end
          | Error _ ->
            (* here we allow arbitrary, even out-of-zone updates.  this is
               crucial for the resolver operation as we have it right now:
               add . 300 NS resolver ; add resolver . 300 A 141.1.1.1 would
               otherwise fail (no SOA for . / delegation for resolver) *)
            begin match Udns_map.of_rdata rr.Udns_packet.ttl rr.Udns_packet.rdata with
              | None ->
                Log.warn (fun m -> m "couldn't convert rdata %a" Udns_packet.pp_rr rr) ;
                trie
              | Some v -> Udns_trie.insertb rr.Udns_packet.name v trie
            end
    end

let notify t l now zone soa =
  (* we use
     1. the NS records of the zone
     2. the IP addresses of secondary servers which have transfer keys
     3. the TCP connections requesting (signed) SOA in l *)
  let ips =
    match Udns_trie.lookup zone Udns_map.Ns t.data with
    | Ok (_, ns) ->
      let secondaries = Domain_name.Set.remove soa.Udns_packet.nameserver ns in
      (* TODO AAAA records *)
      Domain_name.Set.fold (fun ns acc ->
          let ips = match Udns_trie.lookup ns Udns_map.A t.data with
            | Ok (_, ips) ->
              Udns_map.Ipv4Set.fold (fun ip acc -> IPM.add ip 53 acc) ips IPM.empty
            | _ ->
              Log.err (fun m -> m "lookup for A %a returned nothing as well"
                          Domain_name.pp ns) ;
              IPM.empty
          in
          IPM.union (fun _ a _ -> Some a) ips acc)
        secondaries IPM.empty
    | _ -> IPM.empty
  in
  let ips = match Authentication.secondaries t.auth zone with
    | Ok name_ip_ports ->
      List.fold_left (fun m (_, ip, port) -> IPM.add ip port m) ips name_ip_ports
    | Error e ->
      Logs.warn (fun m -> m "no secondaries keys found (err %a)" Udns_trie.pp_e e) ;
      ips
  in
  let ips =
    List.fold_left (fun m (_, ip, port) -> IPM.add ip port m)
      ips
      (List.filter (fun (zone', _, _) -> Domain_name.equal zone zone') l)
  in
  Log.debug (fun m -> m "notifying %a %a" Domain_name.pp zone
                Fmt.(list ~sep:(unit ", ") (pair ~sep:(unit ":") Ipaddr.V4.pp int))
                (IPM.bindings ips)) ;
  let notify =
    let question = [ { Udns_packet.q_name = zone ; q_type = Udns_enum.SOA } ] in
    let answer =
      [ { Udns_packet.name = zone ; ttl = 0l ; rdata = Udns_packet.SOA soa } ]
    in
    { Udns_packet.question ; answer ; authority = [] ; additional = [] }
  in
  let one ip port =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) t.rng in
    let header = {
      Udns_packet.id ; query = true ; operation = Udns_enum.Notify ;
      authoritative = true ; truncation = false ; recursion_desired = false ;
      recursion_available = false ;authentic_data = false ;
      checking_disabled = false ; rcode = Udns_enum.NoError
    }
    in
    (now, 0, ip, port, header, notify)
  in
  IPM.fold (fun ip port acc -> one ip port :: acc) ips []

let update_data trie zone u =
  List.fold_left (fun r pre ->
      r >>= fun acc ->
      handle_rr_prereq trie zone acc pre)
    (Ok []) u.Udns_packet.prereq >>= fun acc ->
  check_exists trie acc >>= fun () ->
  let trie' = List.fold_left handle_rr_update trie u.Udns_packet.update in
  (match Udns_trie.check trie' with
   | Ok () -> Ok ()
   | Error e ->
     Log.err (fun m -> m "check after update returned %a" Udns_trie.pp_err e) ;
     Error Udns_enum.FormErr) >>= fun () ->
  match Udns_trie.lookup zone Udns_map.Soa trie, Udns_trie.lookup zone Udns_map.Soa trie' with
  | Ok (_, oldsoa), Ok (_, soa) when oldsoa.Udns_packet.serial < soa.Udns_packet.serial ->
    Ok (trie', Some soa)
  | _, Ok (ttl, soa) ->
    let soa = { soa with Udns_packet.serial = Int32.succ soa.Udns_packet.serial } in
    let trie'' = Udns_trie.insert zone Udns_map.Soa (ttl, soa) trie' in
    Ok (trie'', Some soa)
  | _, _ -> Ok (trie', None)

let handle_update t l ts proto key u =
  (* first of all, see whether we think we're authoritative for the zone *)
  let zone = Udns_packet.(u.zone.q_name) in
  guard (List.for_all (fun u -> in_zone zone (Udns_packet.rr_update_name u)) u.Udns_packet.update)
    Udns_enum.NotZone >>= fun () ->
  if Authentication.authorise t.auth proto key zone `Key_management then begin
     Log.info (fun m -> m "key-management key %a authorised for update %a"
                   Fmt.(option ~none:(unit "none") Domain_name.pp) key
                   Udns_packet.pp_update u) ;
     let keys, _actions =
       Authentication.(handle_update (keys t.auth) u.Udns_packet.update)
     in
     let t = { t with auth = (keys, snd t.auth) } in
     Ok (t, [])
   end else if Authentication.authorise t.auth proto key zone `Update then begin
     Log.info (fun m -> m "update key %a authorised for update %a"
                   Fmt.(option ~none:(unit "none") Domain_name.pp) key
                   Udns_packet.pp_update u) ;
     update_data t.data zone u >>= fun (data', soa) ->
     let t = { t with data = data' } in
     let notifies = match soa with
       | None -> []
       | Some soa -> notify t l ts zone soa
     in
     Ok (t, notifies)
   end else
     Error Udns_enum.NotAuth

let raw_server_error buf rcode =
  (* copy id from header, retain opcode, set rcode to ServFail
     if we receive a fragment < 12 bytes, it's not worth bothering *)
  if Cstruct.len buf < 12 then
    None
  else
    let hdr = Cstruct.create 12 in
    (* manually copy the id from the incoming buf *)
    Cstruct.BE.set_uint16 hdr 0 (Cstruct.BE.get_uint16 buf 0) ;
    (* flip query or response *)
    let q = Cstruct.get_uint8 buf 2 lsr 7 = 0 in
    let notq = if q then 0x80 else 0x00 in
    (* manually copy the opcode from the incoming buf *)
    Cstruct.set_uint8 hdr 2 (notq lor ((Cstruct.get_uint8 buf 2) land 0x78)) ;
    (* set rcode *)
    Cstruct.set_uint8 hdr 3 ((Udns_enum.rcode_to_int rcode) land 0xF) ;
    let extended_rcode = Udns_enum.rcode_to_int rcode lsr 4 in
    if extended_rcode = 0 then
      Some hdr
    else
      (* need an edns! *)
      let edns = Udns_packet.opt ~extended_rcode () in
      let buf = Udns_packet.encode_opt edns in
      Cstruct.BE.set_uint16 hdr 10 1 ;
      Some (Cstruct.append hdr buf)

let handle_tsig ?mac t now header v tsig off buf =
  match off, tsig with
  | None, _ | _, None -> Ok None
  | Some off, Some (name, tsig) ->
    let algo = tsig.Udns_packet.algorithm in
    let key =
      match Authentication.find_key t.auth name with
      | None -> None
      | Some key ->
        match Udns_packet.dnskey_to_tsig_algo key with
        | Some a when a = algo -> Some key
        | _ -> None
    in
    t.tsig_verify ?mac now v header name ~key tsig (Cstruct.sub buf 0 off) >>= fun (tsig, mac, key) ->
    Ok (Some (name, tsig, mac, key))

module Primary = struct

  (* TODO: there's likely a better data structure for outstanding notifications *)
  (* the list of zone, ip, port, keyname is whom to notify *)
  type s =
    t *
    (Domain_name.t * Ipaddr.V4.t * int) list *
    (int64 * int * Ipaddr.V4.t * int * Udns_packet.header * Udns_packet.query) list

  let server (t, _, _) = t

  let data (t, _, _) = t.data

  let with_data (t, l, n) data = { t with data }, l, n

  let create ?(keys = []) ?(a = []) ~tsig_verify ~tsig_sign ~rng data =
    let keys = Authentication.of_keys keys in
    let t = create data (keys, a) rng tsig_verify tsig_sign in
    let notifications =
      let f name (_, soa) acc =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name) ;
        acc @ notify t [] 0L name soa
      in
      match Udns_trie.folde Domain_name.root Udns_map.Soa data f [] with
      | Ok ns -> ns
      | Error e ->
        Logs.warn (fun m -> m "error %a while collecting zones" Udns_trie.pp_e e) ;
        []
    in
    (t, [], notifications)

  let tcp_soa_query proto q =
    match proto, q.Udns_packet.question with
    | `Tcp, [ query ] when query.Udns_packet.q_type = Udns_enum.SOA ->
      Ok query.Udns_packet.q_name
    | _ -> Error ()

  let handle_frame (t, l, ns) ts ip port proto key header v =
    match v, header.Udns_packet.query with
    | `Query q, true ->
      handle_query t proto key header q >>= fun answer ->
      let l' = match tcp_soa_query proto q, key with
        | Ok zone, Some key when Authentication.is_op `Transfer key ->
          let other (z, i, p) =
            not (Domain_name.equal z zone && Ipaddr.V4.compare i ip = 0 && p = port)
          in
          (zone, ip, port) :: List.filter other l
        | _ -> l
      in
      Ok ((t, l', ns), Some answer, [])
    | `Update u, true ->
      (* TODO: intentional? all other notifications apart from the new ones are dropped *)
      handle_update t l ts proto key u >>= fun (t', ns) ->
      let out =
        let edns = Udns_packet.opt () in
        List.map (fun (_, _, ip, port, hdr, q) ->
            (ip, port, fst (Udns_packet.encode ~edns `Udp hdr (`Query q))))
          ns
      in
      let answer =
        s_header header,
        `Update { u with Udns_packet.prereq = [] ; update = [] ; addition = [] }
      in
      Ok ((t', l, ns), Some answer, out)
    | `Notify _, false ->
      let notifications =
        List.filter (fun (_, _, ip', _, hdr', _) ->
            not (Ipaddr.V4.compare ip ip' = 0 && header.Udns_packet.id = hdr'.Udns_packet.id))
          ns
      in
      Ok ((t, l, notifications), None, [])
    | _, false ->
      (* this happens when the other side is a tinydns and we're sending notify *)
      Log.err (fun m -> m "ignoring unsolicited answer, replying with FormErr") ;
      Error Udns_enum.FormErr
    | `Notify _, true ->
      Log.err (fun m -> m "ignoring unsolicited notify request") ;
      Ok ((t, l, ns), None, [])

  let handle (t, l, ns) now ts proto ip port buf =
    match
      safe_decode buf >>= fun ((header, v, opt, tsig), tsig_off) ->
      guard (not header.Udns_packet.truncation) Udns_enum.FormErr >>= fun () ->
      Ok ((header, v, opt, tsig), tsig_off)
    with
    | Error rcode -> (t, l, ns), raw_server_error buf rcode, []
    | Ok ((header, v, opt, tsig), tsig_off) ->
      Log.debug (fun m -> m "%a sent %a" Ipaddr.V4.pp ip
                    Udns_packet.pp (header, v, opt, tsig)) ;
      let handle_inner keyname =
        match handle_frame (t, l, ns) ts ip port proto keyname header v with
        | Ok (t, Some (header, answer), out) ->
          let max_size, edns = Udns_packet.reply_opt opt in
          (* be aware, this may be truncated... here's where AXFR is assembled! *)
          (t, Some (Udns_packet.encode ?max_size ?edns proto header answer), out)
        | Ok (t, None, out) -> (t, None, out)
        | Error rcode -> ((t, l, ns), err header v rcode, [])
      in
      match handle_tsig t now header v tsig tsig_off buf with
      | Error data -> ((t, l, ns), data, [])
      | Ok None ->
        begin match handle_inner None with
          | t, None, out -> t, None, out
          | t, Some (cs, _), out -> t, Some cs, out
        end
      | Ok (Some (name, tsig, mac, key)) ->
        match handle_inner (Some name) with
        | (a, None, out) -> (a, None, out)
        | (a, Some (buf, max_size), out) ->
          match t.tsig_sign ~max_size ~mac name tsig ~key buf with
          | None ->
            Log.warn (fun m -> m "couldn't use %a to tsig sign" Domain_name.pp name) ;
            (a, None, out)
          | Some (buf, _) -> (a, Some buf, out)

  let closed (t, l, ns) ip port =
    let l' =
      List.filter (fun (_, ip', port') ->
          not (Ipaddr.V4.compare ip ip' = 0 && port = port'))
        l
    in
    (t, l', ns)

  let retransmit = Array.map Duration.of_sec [| 5 ; 12 ; 25 ; 40 ; 60 |]

  let timer (t, l, ns) now =
    let max = pred (Array.length retransmit) in
    let encode hdr q = fst @@ Udns_packet.encode `Udp hdr (`Query q) in
    let notifications, out =
      List.fold_left (fun (ns, acc) (ts, count, ip, port, hdr, q) ->
          if Int64.add ts retransmit.(count) < now then
            (if count = max then begin
                Log.warn (fun m -> m "retransmitting to %a:%d the last time %a %a"
                             Ipaddr.V4.pp ip port Udns_packet.pp_header hdr
                             Udns_packet.pp_query q) ;
                ns
              end else
               (ts, succ count, ip, port, hdr, q) :: ns),
            (ip, port, encode hdr q) :: acc
          else
            (ts, count, ip, port, hdr, q) :: ns, acc)
        ([], []) ns
    in
    (t, l, notifications), out
end

module Secondary = struct

  type state =
    | Transferred of int64
    | Requested_soa of int64 * int * int * Cstruct.t
    | Requested_axfr of int64 * int * Cstruct.t

  (* TODO undefined what happens if there are multiple transfer keys for zone x *)
  type s = t * (state * Ipaddr.V4.t * int * Domain_name.t) Domain_name.Map.t

  let server (t, _) = t

  let data (t, _) = t.data

  let with_data (t, zones) data = ({ t with data }, zones)

  let zones (_, zones) = fst (List.split (Domain_name.Map.bindings zones))

  let create ?(a = []) ?primary ~tsig_verify ~tsig_sign ~rng keylist =
    (* two kinds of keys: aaa._key-management and ip1.ip2._transfer.zone *)
    let keys = Authentication.of_keys keylist in
    let zones =
      let f name _ zones =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name) ;
        match Authentication.primaries (keys, []) name with
        | Ok [] -> begin match primary with
            | None ->
              Log.warn (fun m -> m "no nameserver found for %a" Domain_name.pp name) ;
              zones
            | Some ip ->
              List.fold_left (fun zones (keyname, _) ->
                  if
                    Authentication.is_op `Transfer keyname &&
                    Domain_name.sub ~domain:name ~subdomain:keyname
                  then begin
                    Log.app (fun m -> m "adding zone %a with key %a and ip %a"
                                Domain_name.pp name Domain_name.pp keyname
                                Ipaddr.V4.pp ip) ;
                    let v = Requested_soa (0L, 0, 0, Cstruct.empty), ip, 53, keyname in
                    Domain_name.Map.add name v zones
                  end else begin
                    Log.warn (fun m -> m "no transfer key found for %a" Domain_name.pp name) ;
                    zones
                  end) zones keylist
          end
        | Ok primaries ->
          List.fold_left (fun zones (keyname, ip, port) ->
              Log.app (fun m -> m "adding transfer key %a for zone %a"
                           Domain_name.pp keyname Domain_name.pp name) ;
              let v = Requested_soa (0L, 0, 0, Cstruct.empty), ip, port, keyname in
              Domain_name.Map.add name v zones)
            zones primaries
        | Error e ->
          Logs.warn (fun m -> m "error %a while looking up keys for %a" Udns_trie.pp_e e Domain_name.pp name) ;
          zones
      in
      match Udns_trie.folde Domain_name.root Udns_map.Soa keys f Domain_name.Map.empty with
      | Ok zones -> zones
      | Error e ->
        Log.warn (fun m -> m "error %a while collecting zones" Udns_trie.pp_e e) ;
        Domain_name.Map.empty
    in
    (create Udns_trie.empty (keys, a) rng tsig_verify tsig_sign, zones)

  let maybe_sign ?max_size t name signed original_id buf =
    match Authentication.find_key t.auth name with
    | Some key ->
      begin match Udns_packet.dnskey_to_tsig_algo key with
        | Some algorithm ->
          begin match Udns_packet.tsig ~algorithm ~original_id ~signed () with
            | None -> Log.err (fun m -> m "creation of tsig failed") ; None
            | Some tsig -> match t.tsig_sign ?mac:None ?max_size name tsig ~key buf with
              | None -> Log.err (fun m -> m "signing failed") ; None
              | Some res -> Some res
          end
        | None -> Log.err (fun m -> m "couldn't convert algorithm to tsig") ; None
      end
    | _ -> Log.err (fun m -> m "key %a not found (or multiple)" Domain_name.pp name) ; None

  let header rng () =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) rng in
    id, { Udns_packet.id ; query = true ; operation = Udns_enum.Query ;
          authoritative = false ; truncation = false ;
          recursion_desired = false ; recursion_available = false ;
          authentic_data = false ; checking_disabled = false ;
          rcode = Udns_enum.NoError }

  let axfr t proto now ts q_name name =
    let id, header = header t.rng ()
    and question = [ { Udns_packet.q_name ; q_type = Udns_enum.AXFR } ]
    in
    let query = { Udns_packet.question ; answer = [] ; authority = [] ; additional = [] } in
    let buf, max_size = Udns_packet.encode proto header (`Query query) in
    match maybe_sign ~max_size t name now id buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_axfr (ts, id, mac), buf)

  let query_soa ?(retry = 0) t proto now ts q_name name =
    let id, header = header t.rng ()
    and question = [ { Udns_packet.q_name ; q_type = Udns_enum.SOA } ]
    in
    let query = { Udns_packet.question ; answer = [] ; authority = [] ; additional = [] } in
    let buf, max_size = Udns_packet.encode proto header (`Query query) in
    match maybe_sign ~max_size t name now id buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_soa (ts, retry, id, mac), buf)

  let timer (t, zones) p_now now =
    (* what is there to be done?
       - request SOA on every soa.refresh interval
       - if the primary server is not reachable, try every time after soa.retry
       - once soa.expiry is over (from the initial SOA request), don't serve the zone anymore

       - axfr (once soa is through and we know we have stale data) is retried every 5 seconds
       - if we don't have a soa yet for the zone, retry every 5 seconds as well
    *)
    let t, out =
      Domain_name.Map.fold (fun zone (st, ip, port, name) ((t, zones), acc) ->
          let maybe_out data =
            let st, out = match data with
              | None -> st, acc
              | Some (st, out) -> st, (`Tcp, ip, port, out) :: acc
            in
            ((t, Domain_name.Map.add zone (st, ip, port, name) zones), out)
          in

          match Udns_trie.lookup zone Udns_map.Soa t.data, st with
          | Ok (_, soa), Transferred ts ->
            (* TODO: integer overflows (Int64.add) *)
            let r = Duration.of_sec (Int32.to_int soa.Udns_packet.refresh) in
            maybe_out
              (if Int64.add ts r < now then
                 query_soa t `Tcp p_now now zone name
               else
                 None)
          | Ok (_, soa), Requested_soa (ts, retry, _, _) ->
            let expiry = Duration.of_sec (Int32.to_int soa.Udns_packet.expiry) in
            if Int64.add ts expiry < now then begin
              Log.warn (fun m -> m "expiry expired, dropping zone %a"
                           Domain_name.pp zone) ;
              let data = Udns_trie.remove_zone zone t.data in
              (({ t with data }, zones), acc)
            end else
              let retry = succ retry in
              let e = Duration.of_sec (retry * Int32.to_int soa.Udns_packet.retry) in
              maybe_out
                (if Int64.add ts e < now then
                   query_soa ~retry t `Tcp p_now ts zone name
                 else
                   None)
          | Error _, Requested_soa (ts, retry, _, _) ->
            let e = Duration.of_sec 5 in
            maybe_out
              (if Int64.add ts e < now || ts = 0L then
                 let retry = succ retry in
                 query_soa ~retry t `Tcp p_now ts zone name
               else
                 None)
          | _, Requested_axfr (ts, _, _) ->
            let e = Duration.of_sec 5 in
            maybe_out
              (if Int64.add ts e < now then
                 axfr t `Tcp p_now ts zone name
               else
                 None)
          | Error e, _ ->
            Log.err (fun m -> m "unclear how we ended up here zone %a, error %a while looking for soa"
                        Domain_name.pp zone Udns_trie.pp_e e) ;
            maybe_out None)
        zones ((t, Domain_name.Map.empty), [])
    in
    t, out

  let handle_notify t zones now ts ip query =
    match query.Udns_packet.question with
    | [ q ] ->
      begin match q.Udns_packet.q_type with
        | Udns_enum.SOA ->
          let zone = q.Udns_packet.q_name in
          begin match Domain_name.Map.find zone zones with
            | None -> (* we don't know anything about the notified zone *)
              Log.warn (fun m -> m "ignoring notify for %a, no such zone"
                           Domain_name.pp q.Udns_packet.q_name) ;
              Error Udns_enum.Refused
            | Some (_, ip', port', name) when Ipaddr.V4.compare ip ip' = 0 ->
              Log.debug (fun m -> m "received notify for %a, replying and requesting SOA"
                            Domain_name.pp q.Udns_packet.q_name) ;
              (* TODO should we look in zones and if there's a fresh Requested_soa, leave it as is? *)
              let zones, out =
                match query_soa t `Tcp now ts zone name with
                | None -> zones, []
                | Some (st, buf) ->
                  Domain_name.Map.add zone (st, ip, port', name) zones,
                  [ (`Tcp, ip, port', buf) ]
              in
              Ok (zones, out)
            | Some (_, ip', _, _) ->
              Log.warn (fun m -> m "ignoring notify for %a from %a (%a is primary)"
                           Domain_name.pp q.Udns_packet.q_name
                           Ipaddr.V4.pp ip Ipaddr.V4.pp ip') ;
              Error Udns_enum.Refused
          end
        | t ->
          Log.warn (fun m -> m "ignoring notify %a with type %a"
                       Domain_name.pp q.Udns_packet.q_name Udns_enum.pp_rr_typ t) ;
          Error Udns_enum.FormErr
      end
    | qs ->
      Log.warn (fun m -> m "ignoring notify with zero or multiple questions: %a"
                   Fmt.(list ~sep:(unit ",@,") Udns_packet.pp_question) qs) ;
      Error Udns_enum.FormErr

  let check_valid_axfr zone rrs =
    List.fold_left (fun r rr ->
        r >>= fun (first, more) ->
        guard more Udns_enum.FormErr >>= fun () ->
        let is_soa =
          match rr.Udns_packet.rdata with
          | Udns_packet.SOA _ -> Domain_name.equal zone rr.Udns_packet.name
          | _ -> false
        in
        (if first then
           guard is_soa Udns_enum.FormErr >>= fun () ->
           Ok true
         else if is_soa then
           Ok false
         else
           Ok true) >>= fun more ->
        guard (in_zone zone rr.Udns_packet.name) Udns_enum.FormErr >>= fun () ->
        (Ok (false, more)))
      (Ok (true, true)) rrs >>= fun (first, more) ->
    guard (not first && not more) Udns_enum.FormErr >>= fun () ->
    match rrs with
    | _soa::tl -> Ok tl
    | [] -> Error Udns_enum.FormErr

  let handle_answer t zones now ts keyname header query =
    match query.Udns_packet.question with
    | [ q ] ->
      let zone = q.Udns_packet.q_name in
      begin match Domain_name.Map.find zone zones with
        | None ->
          Log.warn (fun m -> m "ignoring %a (%a), unknown zone"
                       Domain_name.pp q.Udns_packet.q_name
                       Udns_enum.pp_rr_typ q.Udns_packet.q_type) ;
          Error Udns_enum.Refused
        | Some (st, ip, port, name) ->
          Log.debug (fun m -> m "in %a (name %a) got answer %a"
                        Domain_name.pp q.Udns_packet.q_name Domain_name.pp name
                        Udns_packet.pp_rrs query.Udns_packet.answer) ;
          (* TODO use NotAuth instead of Refused here? *)
          Rresult.R.of_option
            ~none:(fun () ->
                Log.err (fun m -> m "refusing (not authenticated)") ;
                Error Udns_enum.Refused)
            keyname >>= fun key_name ->
          guard (Domain_name.equal name key_name) Udns_enum.Refused >>= fun () ->
          begin match st, q.Udns_packet.q_type with
            | Requested_axfr (_, id', _), Udns_enum.AXFR when header.Udns_packet.id = id' ->
              Logs.info (fun m -> m "received AXFR (key %a) for %a: %a"
                            Domain_name.pp key_name Domain_name.pp zone
                            Udns_packet.pp_query query) ;
              (* TODO if incomplete, accumulate rr in state till complete *)
              (* (a) check completeness of AXFR:  *)
              (* (b) build vs from query.answer *)
              (* (c) drop zone from trie *)
              (* (d) insert vs into trie *)
              (* first ensure that all entries are in the zone! *)
              check_valid_axfr zone query.Udns_packet.answer >>= fun rrs ->
              let trie =
                let trie = Udns_trie.remove_zone zone t.data
                and map = Udns_map.of_rrs rrs
                in
                Udns_trie.insert_map map trie
              in
              let zones = Domain_name.Map.add zone (Transferred ts, ip, port, name) zones in
              Ok ({ t with data = trie }, zones, [])
            | Requested_soa (_, retry, id', _), Udns_enum.SOA when header.Udns_packet.id = id' ->
              Log.debug (fun m -> m "received SOA after %d retries" retry) ;
              (* request AXFR now in case of serial is higher! *)
              begin match Udns_trie.lookup zone Udns_map.Soa t.data with
                | Ok (_, cached_soa) ->
                  begin match
                      List.fold_left
                        (fun r rr ->
                           match r, rr.Udns_packet.rdata with
                           | Some x, _ -> Some x
                           | None, Udns_packet.SOA soa -> Some soa
                           | x, _ -> x)
                        None query.Udns_packet.answer
                    with
                    | None ->
                      Log.err (fun m -> m "didn't get a SOA answer for %a from %a"
                                  Domain_name.pp q.Udns_packet.q_name Ipaddr.V4.pp ip) ;
                      Error Udns_enum.FormErr
                    | Some fresh ->
                      (* TODO: > with wraparound in mind *)
                      if fresh.Udns_packet.serial > cached_soa.Udns_packet.serial then
                        match axfr t `Tcp now ts zone name with
                        | None ->
                          Log.warn (fun m -> m "trouble creating axfr for %a (using %a)"
                                       Domain_name.pp zone Domain_name.pp name) ;
                          (* TODO: reset state? *)
                          Ok (t, zones, [])
                        | Some (st, buf) ->
                          Log.debug (fun m -> m "requesting AXFR for %a now!" Domain_name.pp zone) ;
                          let zones = Domain_name.Map.add zone (st, ip, port, name) zones in
                          Ok (t, zones, [ (`Tcp, ip, port, buf) ])
                      else begin
                        Log.info (fun m -> m "received soa (%a) for %a is not newer than cached (%a), moving on"
                                     Udns_packet.pp_soa fresh Domain_name.pp zone Udns_packet.pp_soa cached_soa) ;
                        let zones = Domain_name.Map.add zone (Transferred ts, ip, port, name) zones in
                        Ok (t, zones, [])
                      end
                  end
                | Error _ ->
                  Log.info (fun m -> m "couldn't find soa, requesting AXFR") ;
                  begin match axfr t `Tcp now ts zone name with
                    | None -> Log.warn (fun m -> m "trouble building axfr") ; Ok (t, zones, [])
                    | Some (st, buf) ->
                      Log.debug (fun m -> m "requesting AXFR for %a now!" Domain_name.pp zone) ;
                      let zones = Domain_name.Map.add zone (st, ip, port, name) zones in
                      Ok (t, zones, [ (`Tcp, ip, port, buf) ])
                  end
              end
            | _ ->
              Log.warn (fun m -> m "ignoring %a (%a) unmatched state"
                           Domain_name.pp q.Udns_packet.q_name
                           Udns_enum.pp_rr_typ q.Udns_packet.q_type) ;
              Error Udns_enum.Refused
          end
      end
    | qs ->
      Log.warn (fun m -> m "ignoring answer with questions: %a"
                   Fmt.(list ~sep:(unit ",@,") Udns_packet.pp_question) qs) ;
      Error Udns_enum.FormErr

  let handle_update t zones now ts proto keyname u =
    (* TODO: handle prereq *)
    let zname = u.Udns_packet.zone.Udns_packet.q_name in
    (* TODO: can allow weaker keys for nsupdates we proxy *)
    guard (Authentication.authorise t.auth proto keyname zname `Key_management) Udns_enum.NotAuth >>= fun () ->
    Log.info (fun m -> m "key-management key %a authorised for update %a"
                 Fmt.(option ~none:(unit "none") Domain_name.pp) keyname
                 Udns_packet.pp_update u) ;
    let ups = u.Udns_packet.update in
    guard (List.for_all (fun u -> in_zone zname (Udns_packet.rr_update_name u)) ups) Udns_enum.NotZone >>= fun () ->
    let keys, actions = Authentication.(handle_update (keys t.auth) ups) in
    let t = { t with auth = (keys, snd t.auth) } in
    let zones, outs =
      (* this is asymmetric - for transfer key additions, we send SOA requests *)
      List.fold_left (fun (zones, outs) -> function
          | `Added_key keyname ->
            begin match Authentication.find_zone_ips keyname with
              | None -> (zones, outs)
              | Some (zname, (pip, pport), _) ->
                match query_soa t `Tcp now ts zname keyname with
                | None ->
                  Log.err (fun m -> m "couldn't query soa for %a" Domain_name.pp zname) ;
                  (zones, outs)
                | Some (state, out) ->
                  let zones = Domain_name.Map.add zname (state, pip, pport, keyname) zones in
                  (zones, (`Tcp, pip, pport, out) :: outs)
            end
          | `Removed_key keyname ->
            let zone = Authentication.zone keyname in
            let zones' = match Domain_name.Map.find zone zones with
              | Some (_, _, _, kname) when Domain_name.equal keyname kname ->
                Domain_name.Map.remove zone zones
              | _ -> zones
            in
            (zones', outs))
        (zones, []) actions
    in
    Ok ((t, zones), outs)

  let handle_frame (t, zones) now ts ip proto keyname header v =
    match v, header.Udns_packet.query with
    | `Query q, true ->
      handle_query t proto keyname header q >>= fun answer ->
      Ok ((t, zones), Some answer, [])
    | `Query q, false ->
      handle_answer t zones now ts keyname header q >>= fun (t, zones, out) ->
      Ok ((t, zones), None, out)
    | `Update u, true ->
      handle_update t zones now ts proto keyname u >>= fun (t', out) ->
      let answer =
        let update = { u with Udns_packet.prereq = [] ; update = [] ; addition = [] } in
        (s_header header, `Update update)
      in
      Ok (t', Some answer, out)
    | `Update _, false -> (* TODO: answer from primary, need to forward to client *)
      Error Udns_enum.FormErr
    | `Notify n, true ->
      handle_notify t zones now ts ip n >>= fun (zones, out) ->
      let answer =
        let n = { n with Udns_packet.answer = [] ; authority = [] ; additional = [] } in
        (s_header header, `Notify n)
      in
      Ok ((t, zones), Some answer, out)
    | `Notify _, false ->
      Log.err (fun m -> m "ignoring notify response (we don't send notifications)") ;
      Ok ((t, zones), None, [])

  let find_mac zones header = function
    | `Query q when not header.Udns_packet.query ->
      begin match q.Udns_packet.question with
        | [ q ] ->
          begin match Domain_name.Map.find q.Udns_packet.q_name zones with
            | None -> None
            | Some (Requested_axfr (_, _id_, mac), _, _, _) -> Some mac
            | Some (Requested_soa (_, _, _id, mac), _, _, _) -> Some mac
            | _ -> None
          end
        | _ -> None
      end
    | _ -> None

  let handle (t, zones) now ts proto ip buf =
    match
      safe_decode buf >>= fun ((header, v, opt, tsig), tsig_off) ->
      guard (not header.Udns_packet.truncation) Udns_enum.FormErr >>= fun () ->
      Ok ((header, v, opt, tsig), tsig_off)
    with
    | Error rcode -> ((t, zones), raw_server_error buf rcode, [])
    | Ok ((header, v, opt, tsig), tsig_off) ->
      let handle_inner name =
        match handle_frame (t, zones) now ts ip proto name header v with
        | Ok (t, Some (header, answer), out) ->
          let max_size, edns = Udns_packet.reply_opt opt in
          (t, Some (Udns_packet.encode ?max_size ?edns proto header answer), out)
        | Ok (t, None, out) -> (t, None, out)
        | Error rcode -> ((t, zones), err header v rcode, [])
      in
      let mac = find_mac zones header v in
      match handle_tsig ?mac t now header v tsig tsig_off buf with
      | Error data -> ((t, zones), data, [])
      | Ok None ->
        begin match handle_inner None with
          | (t, None, out) -> (t, None, out)
          | (t, Some (buf, _), out) -> (t, Some buf, out)
        end
      | Ok (Some (name, tsig, mac, key)) ->
        match handle_inner (Some name) with
        | (a, Some (buf, max_size), out) ->
          begin match t.tsig_sign ~max_size ~mac name tsig ~key buf with
            | None ->
              Log.warn (fun m -> m "couldn't use %a to tsig sign"
                           Domain_name.pp name) ;
              (a, None, out)
            | Some (buf, _) -> (a, Some buf, out)
          end
        | (a, None, out) -> (a, None, out)

  let closed (t, zones) now ts ip' port' =
    let xs =
      Domain_name.Map.fold (fun zone (_, ip, port, keyname) acc ->
          if Ipaddr.V4.compare ip ip' = 0 && port = port' then
            match Authentication.find_zone_ips keyname with
            | Some (_, _, None) ->
              begin match query_soa t `Tcp now ts zone keyname with
                | None -> acc
                | Some (st, data) ->
                  ((zone, (st, ip, port, keyname)), (`Tcp, ip, port, data)) :: acc
              end
            | _ -> acc
          else acc)
        zones []
    in
    let zones', out = List.split xs in
    let zones'' = List.fold_left (fun z (zone, v) -> Domain_name.Map.add zone v z) zones zones' in
    (t, zones''), out
end
