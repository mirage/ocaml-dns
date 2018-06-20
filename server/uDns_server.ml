(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult
open R.Infix

let src = Logs.Src.create "dns_server" ~doc:"DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

let guard p err = if p then Ok () else Error err

type proto = [ `Tcp | `Udp ]

let s_header h =
  { h with Dns_packet.authoritative = true ; query = false ;
           recursion_available = false ; authentic_data = false }

let err header v rcode =
  let header =
    let hdr = s_header header in
    let authoritative = if rcode = Dns_enum.NotAuth then false else true in
    { hdr with Dns_packet.authoritative }
  in
  Dns_packet.error header v rcode

type a = Dns_trie.t -> proto -> Domain_name.t option -> string -> Domain_name.t -> bool

type t = {
  data : Dns_trie.t ;
  authorised : a list ;
  rng : int -> Cstruct.t ;
  tsig_verify : Dns_packet.tsig_verify ;
  tsig_sign : Dns_packet.tsig_sign ;
}

let text name t =
  let buf = Buffer.create 1024 in
  Rresult.R.reword_error
    (Fmt.to_to_string Dns_trie.pp_e)
    (Dns_trie.fold name t.data
       (fun name v () ->
          (* TODO again Dnskey need to be treat specially, contains secrets *)
          match v with
          | Dns_map.V (Dns_map.Dnskey, _) -> ()
          | _ ->
            Buffer.add_string buf (Dns_map.text name v) ;
            Buffer.add_char buf '\n')
       ()) >>| fun () ->
  Buffer.contents buf

type operation =
  | Key_management
  | Update
  | Transfer

let operation_to_string = function
  | Key_management -> "_key-management"
  | Update -> "_update"
  | Transfer -> "_transfer"

let all_operations =
  List.map operation_to_string [ Key_management ; Update ; Transfer ]

let tsig_auth _ _ keyname op zone =
  match keyname with
  | None -> false
  | Some subdomain ->
    let root = Domain_name.of_string_exn ~hostname:false op
    and zone = Domain_name.prepend_exn ~hostname:false zone op
    in
    Domain_name.sub ~subdomain ~domain:zone || Domain_name.sub ~subdomain ~domain:root

let authorise t proto keyname zone operation =
  let op = operation_to_string operation in
  List.exists (fun a -> a t.data proto keyname op zone) t.authorised

let create data authorised rng tsig_verify tsig_sign =
  { data ; authorised ; rng ; tsig_verify ; tsig_sign }

let to_ns_rrs name ttl ns =
  Domain_name.Set.fold (fun ns acc ->
      { Dns_packet.name ; ttl ; rdata = Dns_packet.NS ns } :: acc)
    ns []

let to_soa name ttl soa =
  [ { Dns_packet.name ; ttl ; rdata = Dns_packet.SOA soa } ]

let find_glue trie typ name names =
  let a, aaaa =
    let open Domain_name.Set in
    match typ with
    | Dns_enum.A -> singleton name, empty
    | Dns_enum.AAAA -> empty, singleton name
    | Dns_enum.ANY -> singleton name, singleton name
    | _ -> empty, empty
  in
  let find_rr typ name =
    match Dns_trie.lookup name typ trie with
    | Ok (v, _) -> Dns_map.to_rr name v
    | _ -> []
  in
  Domain_name.Set.fold (fun name acc ->
      (if Domain_name.Set.mem name a then [] else find_rr Dns_enum.A name) @
      (if Domain_name.Set.mem name aaaa then [] else find_rr Dns_enum.AAAA name) @
      acc)
    names []

let lookup trie hdr q =
  let open Dns_packet in
  let answer ?(authoritative = true) ?(rcode = Dns_enum.NoError) ?(an = []) ?(au = []) ?(ad = []) () =
    (* TODO: should randomize answers + ad? *)
    (* TODO: should dedup at a higher layer (v instead of rr) *)
    let hdr = s_header hdr in
    let hdr = { hdr with authoritative ; rcode } in
    (* TODO: temporary precaution, should be relaxed later (once we support DNSSec) *)
    let au =
      List.filter (fun a ->
          match a.Dns_packet.rdata with Dns_packet.DNSKEY _ -> false | _ -> true)
        au
    in
    let authority =
      List.filter (fun a ->
          not (List.exists (fun an -> Dns_packet.rr_equal an a) an))
        au
    in
    let additional =
      List.filter (fun a ->
          not (List.exists (fun rr -> Dns_packet.rr_equal rr a) (an@authority)))
        ad
    in
    Ok (hdr, `Query { question = [ q ] ; answer = an ; authority ; additional })
  in
  match Dns_trie.lookup q.q_name q.q_type trie with
  | Ok (v, (name, ttl, ns)) ->
    let an = Dns_map.to_rr q.q_name v
    and au = to_ns_rrs name ttl ns
    in
    let ad =
      let names = Domain_name.Set.union (Dns_map.names v) ns in
      find_glue trie q.q_type q.q_name names
    in
    answer ~an ~au ~ad ()
  | Error (`Delegation (name, (ttl, ns))) ->
    let ad =
      Domain_name.Set.fold (fun name acc ->
          (* TODO aaaa records! *)
          match Dns_trie.lookup_ignore name Dns_enum.A trie with
          | Ok (Dns_map.V (Dns_map.A, _) as v) -> Dns_map.to_rr name v @ acc
          | _ -> acc)
        ns []
    in
    answer ~authoritative:false ~au:(to_ns_rrs name ttl ns) ~ad ()
  | Error (`EmptyNonTerminal (zname, ttl, soa)) ->
    answer ~au:(to_soa zname ttl soa) ()
  | Error (`NotFound (zname, ttl, soa)) ->
    answer ~rcode:Dns_enum.NXDomain ~au:(to_soa zname ttl soa) ()
  | Error `NotAuthoritative -> Error Dns_enum.NotAuth

let axfr t proto key q zone =
  (if proto = `Udp then begin
      Log.err (fun m -> m "refusing AXFR query via UDP") ;
      Error Dns_enum.Refused
    end else
     Ok ()) >>= fun () ->
  (if authorise t proto key zone Key_management then
     Ok true
   else if authorise t proto key zone Transfer then
     Ok false
   else
     Error Dns_enum.NotAuth) >>= fun keys ->
  match Dns_trie.entries zone t.data with
  | Ok (soa, rrs) ->
    let rrs =
      if keys then
        rrs
      else
        let not_dnskey rr =
          Dns_packet.(match rr.rdata with DNSKEY _ -> false | _ -> true)
        in
        List.filter not_dnskey rrs
    in
    let answer = soa :: rrs @ [ soa ]
    and question = q.Dns_packet.question
    and authority = []
    and additional = []
    in
    Ok (`Query { Dns_packet.question ; answer ; authority ; additional })
  | Error `Delegation _
  | Error `NotAuthoritative
  | Error `NotFound _ ->
    Log.err (fun m -> m "AXFR attempted on %a, where we're not authoritative"
                 Domain_name.pp zone) ;
    Error Dns_enum.NXDomain

let key_retrieval t proto key hdr q =
  guard (authorise t proto key q.Dns_packet.q_name Key_management)
    Dns_enum.NotAuth >>= fun () ->
  lookup t.data hdr q

let safe_decode buf =
  match Dns_packet.decode buf with
  | Error `Partial ->
    Log.err (fun m -> m "partial frame (length %d)@.%a" (Cstruct.len buf) Cstruct.hexdump_pp buf) ;
    Error Dns_enum.FormErr
  | Error (`DisallowedRRTyp _ | `DisallowedClass _ | `UnsupportedClass _ as e) ->
    Log.err (fun m -> m "refusing %a while decoding@.%a"
                 Dns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Dns_enum.Refused
  | Error (`BadRRTyp _ | `BadClass _ | `UnsupportedOpcode _ as e) ->
    Log.err (fun m -> m "not implemented %a while decoding@.%a"
                 Dns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Dns_enum.NotImp
  | Error (`BadContent x) ->
    Log.err (fun m -> m "bad content error %s while decoding@.%a"
                 x Cstruct.hexdump_pp buf) ;
    Error Dns_enum.FormErr
  | Error (`Bad_edns_version i) ->
    Log.err (fun m -> m "bad edns version error %u while decoding@.%a"
                 i Cstruct.hexdump_pp buf) ;
    Error Dns_enum.BadVersOrSig
  | Error e ->
    Log.err (fun m -> m "error %a while decoding@.%a"
                 Dns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Dns_enum.FormErr
  | Ok v -> Ok v

let handle_query t proto key header query =
  match query.Dns_packet.question with
  | [ q ] ->
    let open Dns_enum in
    begin match q.Dns_packet.q_type with
      | AXFR ->
        axfr t proto key query q.Dns_packet.q_name >>= fun answer ->
        let hdr = s_header header in
        Ok (hdr, answer)
      | DNSKEY -> key_retrieval t proto key header q
      (* TODO: IXFR -> *)
      | A | NS | CNAME | SOA | PTR | MX | TXT | AAAA | SRV | ANY | CAA | SSHFP | TLSA ->
        lookup t.data header q
      | r ->
        Log.err (fun m -> m "refusing query type %a" Dns_enum.pp_rr_typ r) ;
        Error Dns_enum.Refused
    end
  | qs ->
    Log.err (fun m -> m "%d questions %a, bailing"
                (List.length qs)
                Fmt.(list ~sep:(unit ",@ ") Dns_packet.pp_question) qs) ;
    Error Dns_enum.FormErr

let in_zone zone name = Domain_name.sub ~subdomain:name ~domain:zone

(* this implements RFC 2136 Section 2.4 + 3.2 *)
let handle_rr_prereq trie zone acc = function
  | Dns_packet.Name_inuse name ->
    guard (in_zone zone name) Dns_enum.NotZone >>= fun () ->
    begin match Dns_trie.lookup name Dns_enum.A trie with
      | Ok _ | Error (`EmptyNonTerminal _) -> Ok acc
      | _ -> Error Dns_enum.NXDomain
    end
  | Dns_packet.Exists (name, typ) ->
    guard (in_zone zone name) Dns_enum.NotZone >>= fun () ->
    begin match Dns_trie.lookup name typ trie with
      | Ok _ -> Ok acc
      | _ -> Error Dns_enum.NXRRSet
    end
  | Dns_packet.Not_name_inuse name ->
    guard (in_zone zone name) Dns_enum.NotZone >>= fun () ->
    begin match Dns_trie.lookup name Dns_enum.A trie with
      | Error (`NotFound _) -> Ok acc
      | _ -> Error Dns_enum.YXDomain
    end
  | Dns_packet.Not_exists (name, typ) ->
    guard (in_zone zone name) Dns_enum.NotZone >>= fun () ->
    begin match Dns_trie.lookup name typ trie with
      | Error (`EmptyNonTerminal _ | `NotFound _) -> Ok acc
      | _ -> Error Dns_enum.YXRRSet
    end
  | Dns_packet.Exists_data (name, rdata) ->
    guard (in_zone zone name) Dns_enum.NotZone >>= fun () ->
    Ok ({ Dns_packet.name ; ttl = 0l ; rdata } :: acc)

let check_exists trie rrs =
  let map = Dns_map.of_rrs rrs in
  Domain_name.Map.fold (fun name map r ->
      r >>= fun () ->
      Dns_map.fold (fun v r ->
          r >>= fun () ->
          match Dns_trie.lookup name (Dns_map.to_rr_typ v) trie with
          | Ok (v', _) when Dns_map.equal_v v v' -> Ok ()
          | _ -> Error Dns_enum.NXRRSet)
        map r)
    map (Ok ())

(* RFC 2136 Section 2.5 + 3.4.2 *)
(* we partially ignore 3.4.2.3 and 3.4.2.4 by not special-handling of NS, SOA *)
let handle_rr_update trie = function
  | Dns_packet.Remove (name, typ) ->
    begin match typ with
      | Dns_enum.ANY ->
        Log.warn (fun m -> m "ignoring request to remove %a %a"
                      Dns_enum.pp_rr_typ typ Domain_name.pp name) ;
        trie
      | Dns_enum.SOA ->
        (* this does not follow 2136, but we want to be able to remove a zone *)
        Dns_trie.remove_zone name trie
      | _ -> Dns_trie.remove name typ trie
    end
  | Dns_packet.Remove_all name -> Dns_trie.remove name Dns_enum.ANY trie
  | Dns_packet.Remove_single (name, rdata) ->
    let typ = Dns_packet.rdata_to_rr_typ rdata in
    begin match typ with
      | Dns_enum.ANY | Dns_enum.SOA ->
        Log.warn (fun m -> m "ignoring request to remove %a %a %a"
                      Dns_enum.pp_rr_typ typ Domain_name.pp name
                      Dns_packet.pp_rdata rdata) ;
        trie
      | _ ->
        begin match Dns_trie.lookup name typ trie with
          | Ok (Dns_map.V (Dns_map.Cname, _), _) when Dns_enum.CNAME = typ ->
            (* we could be picky and require rdata.name == alias *)
            Dns_trie.remove name typ trie
          | Ok (Dns_map.V (Dns_map.Cname, _), _) ->
            Log.warn (fun m -> m "ignoring request to remove %a %a %a (got a cname on lookup)"
                          Dns_enum.pp_rr_typ typ Domain_name.pp name Dns_packet.pp_rdata rdata) ;
            trie
          | Ok (v, _) ->
            begin match Dns_map.remove_rdata v rdata with
              | None -> Dns_trie.remove name typ trie
              | Some v -> Dns_trie.insert name v trie
            end
          | Error e ->
            Log.warn (fun m -> m "error %a while looking up %a %a %a for removal"
                          Dns_trie.pp_e e Dns_enum.pp_rr_typ typ
                          Domain_name.pp name Dns_packet.pp_rdata rdata) ;
            trie
        end
    end
  | Dns_packet.Add rr ->
    let typ = Dns_packet.rdata_to_rr_typ rr.Dns_packet.rdata in
    begin match typ with
      | Dns_enum.ANY ->
        Log.warn (fun m -> m "ignoring request to add %a" Dns_packet.pp_rr rr) ;
        trie
      | _ ->
        match rr.Dns_packet.rdata with
        | Dns_packet.Raw (_, _) | Dns_packet.TSIG _ ->
          Log.warn (fun m -> m "ignoring request to add %a" Dns_packet.pp_rr rr) ;
          trie
        | _ ->
          match Dns_trie.lookup rr.Dns_packet.name typ trie with
          | Ok (Dns_map.V (Dns_map.Cname, (_, alias)), _) ->
            Log.warn (fun m -> m "found a CNAME %a, won't add %a"
                          Domain_name.pp alias Dns_packet.pp_rr rr) ;
            trie
          | Ok (v, _) ->
            begin match Dns_map.add_rdata v rr.Dns_packet.rdata with
              | None ->
                Log.warn (fun m -> m "error while adding %a to %a"
                              Dns_packet.pp_rr rr Dns_map.pp_v v) ;
                trie
              | Some v ->
                Dns_trie.insert rr.Dns_packet.name v trie
            end
          | Error _ ->
            (* here we allow arbitrary, even out-of-zone updates.  this is
               crucial for the resolver operation as we have it right now:
               add . 300 NS resolver ; add resolver . 300 A 141.1.1.1 would
               otherwise fail (no SOA for . / delegation for resolver) *)
            begin match Dns_map.of_rdata rr.Dns_packet.ttl rr.Dns_packet.rdata with
              | None ->
                Log.warn (fun m -> m "couldn't convert rdata %a" Dns_packet.pp_rr rr) ;
                trie
              | Some v -> Dns_trie.insert rr.Dns_packet.name v trie
            end
    end

let find_zone_ips name =
  (* the name of a key is primaryip.secondaryip._transfer.zone
     e.g. 192.168.42.2_1053.192.168.42.1._transfer.mirage
  *)
  let arr = Domain_name.to_array name in
  try
    let rec go idx = if Array.get arr idx = "_transfer" then idx else go (succ idx) in
    let zone_idx = go 0 in
    let zone = Domain_name.of_array (Array.sub arr 0 zone_idx) in
    let start = succ zone_idx in
    let ip_port start =
      let subarr = Array.sub arr start 4 in
      let content, port =
        let last = Array.get subarr 0 in
        match Astring.String.cut ~sep:"_" last with
        | None -> last, 53
        | Some (a, b) -> a, int_of_string b
      in
      Array.set subarr 0 content ;
      let host = Domain_name.of_array subarr in
      Ipaddr.V4.of_string (Domain_name.to_string host), port
    in
    match ip_port (start + 4), ip_port start with
    | (None, _), _ | _, (None, _) -> None
    | (Some primary, pport), (Some secondary, sport) ->
      Some (zone, (primary, pport), (secondary, sport))
  with
    Invalid_argument _ -> None

module IPS = Set.Make(Ipaddr.V4)
module IPM = Map.Make(Ipaddr.V4)

let notify rng now trie zone soa =
  (* we use both the NS records of the zone, and the IP addresses of secondary
     servers which have transfer keys for the zone *)
  let ips =
    match Dns_trie.lookup zone Dns_enum.NS trie with
    | Ok (Dns_map.V (Dns_map.Ns, (_, ns)), _) ->
      let secondaries = Domain_name.Set.remove soa.Dns_packet.nameserver ns in
      (* TODO AAAA records *)
      Domain_name.Set.fold (fun ns acc ->
          let ips = match Dns_trie.lookup ns Dns_enum.A trie with
            | Ok (Dns_map.V (Dns_map.A, (_, ips)), _) -> IPS.of_list ips
            | _ ->
              Log.err (fun m -> m "lookup for A %a returned nothing as well"
                          Domain_name.pp ns) ;
              IPS.empty
          in
          IPS.union ips acc) secondaries IPS.empty
    | _ -> IPS.empty
  and key_ip_ports =
    let tx = Domain_name.prepend_exn ~hostname:false zone (operation_to_string Transfer) in
    let accumulate name _ acc =
      match find_zone_ips name with
      | None ->
        Log.err (fun m -> m "failed to parse secondary IP: %a" Domain_name.pp name) ;
        acc
      | Some (_, _prim, (secondary, port)) -> IPM.add secondary port acc
    in
    match
      Dns_trie.folde tx Dns_map.Dnskey trie accumulate IPM.empty
    with
    | Error e ->
      Log.err (fun m -> m "no keys found for %a: %a" Domain_name.pp tx Dns_trie.pp_e e) ; IPM.empty
    | Ok es -> es
  in
  let ips = IPS.fold (fun ip m -> IPM.add ip 53 m) ips IPM.empty in
  let ips = IPM.union (fun _ _ p -> Some p) ips key_ip_ports in
  Log.debug (fun m -> m "notifying %a %a" Domain_name.pp zone
                Fmt.(list ~sep:(unit ", ") (pair ~sep:(unit ":") Ipaddr.V4.pp_hum int))
                (IPM.bindings ips)) ;
  let notify =
    let question = [ { Dns_packet.q_name = zone ; q_type = Dns_enum.SOA } ] in
    let answer =
      [ { Dns_packet.name = zone ; ttl = 0l ; rdata = Dns_packet.SOA soa } ]
    in
    { Dns_packet.question ; answer ; authority = [] ; additional = [] }
  in
  let one ip port =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) rng in
    let header = {
      Dns_packet.id ; query = true ; operation = Dns_enum.Notify ;
      authoritative = true ; truncation = false ; recursion_desired = false ;
      recursion_available = false ;authentic_data = false ;
      checking_disabled = false ; rcode = Dns_enum.NoError
    }
    in
    (now, 0, ip, port, header, notify)
  in
  IPM.fold (fun ip port acc -> one ip port :: acc) ips []

let handle_update t ts proto key u =
  (* first of all, see whether we think we're authoritative for the zone *)
  let zone = Dns_packet.(u.zone.q_name) in
  let need_key =
    let f subdomain =
      List.exists (fun p ->
          let domain = Domain_name.prepend_exn ~hostname:false zone p in
          Domain_name.sub ~subdomain ~domain)
        all_operations
    in
    Dns_packet.(List.exists f (List.map rr_update_name u.update))
  in
  (if authorise t proto key zone Key_management then
     Ok ()
   else if not need_key && authorise t proto key zone Update then
     Ok ()
   else
     Error Dns_enum.NotAuth) >>= fun () ->
  let trie = t.data in
  List.fold_left (fun r pre ->
      r >>= fun acc ->
      handle_rr_prereq trie zone acc pre)
    (Ok []) u.Dns_packet.prereq >>= fun acc ->
  check_exists trie acc >>= fun () ->
  List.fold_left (fun acc up ->
      acc >>= fun () ->
      guard (in_zone zone (Dns_packet.rr_update_name up)) Dns_enum.NotZone)
    (Ok ()) u.Dns_packet.update >>= fun () ->
  let trie = List.fold_left handle_rr_update trie u.Dns_packet.update in
  (match Dns_trie.check trie with
   | Ok () -> Ok ()
   | Error e ->
     Log.err (fun m -> m "check after update returned %a" Dns_trie.pp_err e) ;
     Error Dns_enum.FormErr) >>= fun () ->
  match Dns_trie.lookup zone Dns_enum.SOA t.data, Dns_trie.lookup zone Dns_enum.SOA trie with
  | Ok (Dns_map.V (Dns_map.Soa, (_, oldsoa)), _), Ok (Dns_map.V (Dns_map.Soa, (_, soa)), _) when oldsoa.Dns_packet.serial < soa.Dns_packet.serial ->
    let notifies = notify t.rng ts trie zone soa in
    Ok (trie, notifies)
  | _, Ok (Dns_map.V (Dns_map.Soa, (ttl, soa)), _) ->
    let soa = { soa with Dns_packet.serial = Int32.succ soa.Dns_packet.serial } in
    let trie = Dns_trie.insert zone (Dns_map.V (Dns_map.Soa, (ttl, soa))) trie in
    let notifies = notify t.rng ts trie zone soa in
    Ok (trie, notifies)
  | _, _ -> Ok (trie, [])

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
    Cstruct.set_uint8 hdr 3 ((Dns_enum.rcode_to_int rcode) land 0xF) ;
    let extended_rcode = Dns_enum.rcode_to_int rcode lsr 4 in
    if extended_rcode = 0 then
      Some hdr
    else
      (* need an edns! *)
      let edns = Dns_packet.opt ~extended_rcode () in
      let buf = Dns_packet.encode_opt edns in
      Cstruct.BE.set_uint16 hdr 10 1 ;
      Some (Cstruct.append hdr buf)


let find_key trie name p =
  match Dns_trie.lookup_ignore name Dns_enum.DNSKEY trie with
  | Ok (Dns_map.V (Dns_map.Dnskey, keys)) -> List.filter p keys
  | _ -> []

let handle_tsig ?mac t now header v tsig off buf =
  match off, tsig with
  | None, _ | _, None -> Ok None
  | Some off, Some (name, tsig) ->
    let algo = tsig.Dns_packet.algorithm in
    let key =
      let p k =
        match Dns_packet.dnskey_to_tsig_algo k with
        | Some a when a = algo -> true | _ -> false
      in
      match find_key t.data name p with
      | [key] -> Some key
      | _ -> None
    in
    t.tsig_verify ?mac now v header name ~key tsig (Cstruct.sub buf 0 off) >>= fun (tsig, mac, key) ->
    Ok (Some (name, tsig, mac, key))

module Primary = struct

  (* TODO: there's likely a better data structure for outstanding notifications *)
  type s =
    t * (int64 * int * Ipaddr.V4.t * int * Dns_packet.header * Dns_packet.query) list

  let server (t, _) = t

  let data (t, _) = t.data

  let with_data (t, n) data = { t with data }, n

  let create ?(a = []) ~tsig_verify ~tsig_sign ~rng data =
    let notifications =
      let f name (_, soa) acc =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name) ;
        acc @ notify rng 0L data name soa
      in
      match Dns_trie.folde Domain_name.root Dns_map.Soa data f [] with
      | Ok ns -> ns
      | Error e ->
        Logs.warn (fun m -> m "error %a while collecting zones" Dns_trie.pp_e e) ;
        []
    in
    let t = create data a rng tsig_verify tsig_sign in
    (t, notifications)

  let handle_frame (t, ns) ts ip proto key header v =
    match v, header.Dns_packet.query with
    | `Query q, true ->
      handle_query t proto key header q >>= fun answer ->
      Ok ((t, ns), Some answer, [])
    | `Update u, true ->
      (* TODO: intentional? all other notifications apart from the new ones are dropped *)
      handle_update t ts proto key u >>= fun (data, ns) ->
      let out =
        let edns = Dns_packet.opt () in
        List.map (fun (_, _, ip, port, hdr, q) ->
            (ip, port, fst (Dns_packet.encode ~edns `Udp hdr (`Query q))))
          ns
      in
      let answer =
        s_header header,
        `Update { u with Dns_packet.prereq = [] ; update = [] ; addition = [] }
      in
      Ok (({ t with data }, ns), Some answer, out)
    | `Notify _, false ->
      let notifications =
        List.filter (fun (_, _, ip', _, hdr', _) ->
            not (Ipaddr.V4.compare ip ip' = 0 && header.Dns_packet.id = hdr'.Dns_packet.id))
          ns
      in
      Ok ((t, notifications), None, [])
    | _, false ->
      (* this happens when the other side is a tinydns and we're sending notify *)
      Log.err (fun m -> m "ignoring unsolicited answer, replying with FormErr") ;
      Error Dns_enum.FormErr
    | `Notify _, true ->
      Log.err (fun m -> m "ignoring unsolicited request") ;
      Ok ((t, ns), None, [])

  let handle (t, ns) now ts proto ip buf =
    match
      safe_decode buf >>= fun ((header, v, opt, tsig), tsig_off) ->
      guard (not header.Dns_packet.truncation) Dns_enum.FormErr >>= fun () ->
      Ok ((header, v, opt, tsig), tsig_off)
    with
    | Error rcode -> (t, ns), raw_server_error buf rcode, []
    | Ok ((header, v, opt, tsig), tsig_off) ->
      Log.debug (fun m -> m "%a sent %a" Ipaddr.V4.pp_hum ip
                    Dns_packet.pp (header, v, opt, tsig)) ;
      let handle_inner keyname =
        match handle_frame (t, ns) ts ip proto keyname header v with
        | Ok (t, Some (header, answer), out) ->
          let max_size, edns =
            match opt with
            | None -> None, None
            | Some edns -> Some edns.Dns_packet.payload_size, Some edns
          in
          (* be aware, this may be truncated... here's where AXFR is assembled! *)
          (t, Some (Dns_packet.encode ?max_size ?edns proto header answer), out)
        | Ok (t, None, out) -> (t, None, out)
        | Error rcode -> ((t, ns), err header v rcode, [])
      in
      match handle_tsig t now header v tsig tsig_off buf with
      | Error data -> ((t, ns), Some data, [])
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

  let retransmit = Array.map Duration.of_sec [| 5 ; 12 ; 25 ; 40 ; 60 |]

  let timer (t, ns) now =
    let max = pred (Array.length retransmit) in
    let encode hdr q = fst @@ Dns_packet.encode `Udp hdr (`Query q) in
    let notifications, out =
      List.fold_left (fun (ns, acc) (ts, count, ip, port, hdr, q) ->
          if Int64.add ts retransmit.(count) < now then
            (if count = max then begin
                Log.warn (fun m -> m "retransmitting to %a:%d the last time %a %a"
                             Ipaddr.V4.pp_hum ip port Dns_packet.pp_header hdr
                             Dns_packet.pp_query q) ;
                ns
              end else
               (ts, succ count, ip, port, hdr, q) :: ns),
            (ip, port, encode hdr q) :: acc
          else
            (ts, count, ip, port, hdr, q) :: ns, acc)
        ([], []) ns
    in
    (t, notifications), out
end

module Secondary = struct

  type state =
    | Transferred of int64
    | Requested_soa of int64 * int * int * Cstruct.t
    | Requested_axfr of int64 * int * Cstruct.t

  type s = t * (state * Ipaddr.V4.t * int * Domain_name.t) Domain_name.Map.t

  let server (t, _) = t

  let data (t, _) = t.data

  let with_data (t, zones) data = ({ t with data }, zones)

  let zones (_, zones) = fst (List.split (Domain_name.Map.bindings zones))

  let create ?(a = []) ~tsig_verify ~tsig_sign ~rng keys =
    (* two kinds of keys: aaa._key-management and ip1.ip2._transfer.zone *)
    let trie, zones =
      List.fold_left (fun (trie, zones) (name, key) ->
          match find_zone_ips name with
          | None when Domain_name.sub ~subdomain:name ~domain:(Domain_name.of_string_exn ~hostname:false (operation_to_string Key_management)) ->
            Log.info (fun m -> m "adding key management key %a" Domain_name.pp name) ;
            (Dns_trie.insert name (Dns_map.V (Dns_map.Dnskey, [ key ])) trie, zones)
          | Some (zone, (pip, pport), _) ->
            Log.info (fun m -> m "adding transfer key %a for %a" Domain_name.pp name Domain_name.pp zone) ;
            let zones =
              let v = (Requested_soa (0L, 0, 0, Cstruct.empty), pip, pport, name) in
              Domain_name.Map.add zone v zones
            in
            (Dns_trie.insert name (Dns_map.V (Dns_map.Dnskey, [ key ])) trie, zones)
          | _ ->
            Log.warn (fun m -> m "don't know what to do with %a, ignoring" Domain_name.pp name) ;
            (trie, zones))
        (Dns_trie.empty, Domain_name.Map.empty) keys
    in
    (create trie a rng tsig_verify tsig_sign, zones)

  let maybe_sign ?max_size sign trie name signed original_id buf =
    match find_key trie name (fun _ -> true) with
    | [key] ->
      begin match Dns_packet.dnskey_to_tsig_algo key with
        | Some algorithm ->
          begin match Dns_packet.tsig ~algorithm ~original_id ~signed () with
            | None -> Log.err (fun m -> m "creation of tsig failed") ; None
            | Some tsig -> match sign ?mac:None ?max_size name tsig ~key buf with
              | None -> Log.err (fun m -> m "signing failed") ; None
              | Some res -> Some res
          end
        | None -> Log.err (fun m -> m "couldn't convert algorithm to tsig") ; None
      end
    | _ -> Log.err (fun m -> m "key not found (or multiple)") ; None

  let header rng () =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) rng in
    id, { Dns_packet.id ; query = true ; operation = Dns_enum.Query ;
          authoritative = false ; truncation = false ;
          recursion_desired = false ; recursion_available = false ;
          authentic_data = false ; checking_disabled = false ;
          rcode = Dns_enum.NoError }

  let axfr t proto now ts q_name name =
    let id, header = header t.rng ()
    and question = [ { Dns_packet.q_name ; q_type = Dns_enum.AXFR } ]
    in
    let query = { Dns_packet.question ; answer = [] ; authority = [] ; additional = [] } in
    let buf, max_size = Dns_packet.encode proto header (`Query query) in
    match maybe_sign ~max_size t.tsig_sign t.data name now id buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_axfr (ts, id, mac), buf)

  let query_soa ?(retry = 0) t proto now ts q_name name =
    let id, header = header t.rng ()
    and question = [ { Dns_packet.q_name ; q_type = Dns_enum.SOA } ]
    in
    let query = { Dns_packet.question ; answer = [] ; authority = [] ; additional = [] } in
    let buf, max_size = Dns_packet.encode proto header (`Query query) in
    match maybe_sign ~max_size t.tsig_sign t.data name now id buf with
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

          match Dns_trie.lookup_direct zone Dns_map.Soa t.data, st with
          | Ok (_, soa), Transferred ts ->
            (* TODO: integer overflows (Int64.add) *)
            let r = Duration.of_sec (Int32.to_int soa.Dns_packet.refresh) in
            maybe_out
              (if Int64.add ts r < now then
                 query_soa t `Tcp p_now now zone name
               else
                 None)
          | Ok (_, soa), Requested_soa (ts, retry, _, _) ->
            let expiry = Duration.of_sec (Int32.to_int soa.Dns_packet.expiry) in
            if Int64.add ts expiry < now then begin
              Log.warn (fun m -> m "expiry expired, dropping zone %a"
                           Domain_name.pp zone) ;
              let data = Dns_trie.remove_zone zone t.data in
              (({ t with data }, zones), acc)
            end else
              let retry = succ retry in
              let e = Duration.of_sec (retry * Int32.to_int soa.Dns_packet.retry) in
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
                        Domain_name.pp zone Dns_trie.pp_e e) ;
            maybe_out None)
        zones ((t, Domain_name.Map.empty), [])
    in
    t, out

  let handle_notify t zones now ts ip query =
    match query.Dns_packet.question with
    | [ q ] ->
      begin match q.Dns_packet.q_type with
        | Dns_enum.SOA ->
          let zone = q.Dns_packet.q_name in
          begin match Domain_name.Map.find zone zones with
            | exception Not_found -> (* we don't know anything about the notified zone *)
              Log.warn (fun m -> m "ignoring notify for %a, no such zone"
                           Domain_name.pp q.Dns_packet.q_name) ;
              Error Dns_enum.Refused
            | (_, ip', port', name) when Ipaddr.V4.compare ip ip' = 0 ->
              Log.debug (fun m -> m "received notify for %a, replying and requesting SOA"
                            Domain_name.pp q.Dns_packet.q_name) ;
              (* TODO should we look in zones and if there's a fresh Requested_soa, leave it as is? *)
              let zones, out =
                match query_soa t `Tcp now ts zone name with
                | None -> zones, []
                | Some (st, buf) ->
                  Domain_name.Map.add zone (st, ip, port', name) zones,
                  [ (`Tcp, ip, port', buf) ]
              in
              Ok (zones, out)
            | (_, ip', _, _) ->
              Log.warn (fun m -> m "ignoring notify for %a from %a (%a is primary)"
                           Domain_name.pp q.Dns_packet.q_name
                           Ipaddr.V4.pp_hum ip Ipaddr.V4.pp_hum ip') ;
              Error Dns_enum.Refused
          end
        | t ->
          Log.warn (fun m -> m "ignoring notify %a with type %a"
                       Domain_name.pp q.Dns_packet.q_name Dns_enum.pp_rr_typ t) ;
          Error Dns_enum.FormErr
      end
    | qs ->
      Log.warn (fun m -> m "ignoring notify with zero or multiple questions: %a"
                   Fmt.(list ~sep:(unit ",@,") Dns_packet.pp_question) qs) ;
      Error Dns_enum.FormErr

  let handle_answer t zones now ts keyname key header query =
    match query.Dns_packet.question with
    | [ q ] ->
      let zone = q.Dns_packet.q_name in
      begin match Domain_name.Map.find zone zones with
        | exception Not_found ->
          Log.warn (fun m -> m "ignoring %a (%a), unknown zone"
                       Domain_name.pp q.Dns_packet.q_name
                       Dns_enum.pp_rr_typ q.Dns_packet.q_type) ;
          Error Dns_enum.Refused
        | (st, ip, port, name) ->
          Log.debug (fun m -> m "in %a (keyname %a) got answer %a"
                        Domain_name.pp q.Dns_packet.q_name Domain_name.pp name
                        Dns_packet.pp_rrs query.Dns_packet.answer) ;
          (* TODO use NotAuth instead of Refused here? *)
          Rresult.R.of_option
            ~none:(fun () ->
                Log.err (fun m -> m "refusing (not authenticated)") ;
                Error Dns_enum.Refused)
            keyname >>= fun key_name ->
          guard (Domain_name.equal name key_name) Dns_enum.Refused >>= fun () ->
          Rresult.R.of_option ~none:(fun () -> Error Dns_enum.Refused) key >>= fun key ->
          begin match st, q.Dns_packet.q_type with
            | Requested_axfr (_, id', _), Dns_enum.AXFR when header.Dns_packet.id = id' ->
              (* TODO (a) check completeness of AXFR -- if not, accumulate q in state till complete *)
              (* (b) build vs from query.answer *)
              (* (c) drop zone from trie *)
              (* (d) insert vs into trie *)
              (* (e) insert dnskey into trie *)
              (* NOTE we don't need to preserve any other key than the one used,
                      because we have at most one transfer key in a zone *)
              (* first ensure that all entries are in the zone! *)
              List.fold_left (fun r rr ->
                  r >>= fun () ->
                  guard (in_zone zone rr.Dns_packet.name) Dns_enum.FormErr)
                (Ok ()) query.Dns_packet.answer >>= fun () ->
              let trie =
                let trie = Dns_trie.remove_zone zone t.data
                and map = Dns_map.of_rrs query.Dns_packet.answer
                in
                Dns_trie.insert_map map trie
              in
              let trie = Dns_trie.insert key_name (Dns_map.V (Dns_map.Dnskey, [ key ])) trie in
              let zones = Domain_name.Map.add zone (Transferred ts, ip, port, name) zones in
              Ok ({ t with data = trie }, zones, [])
            | Requested_soa (_, retry, id', _), Dns_enum.SOA when header.Dns_packet.id = id' ->
              Log.debug (fun m -> m "received SOA after %d retries" retry) ;
              (* request AXFR now in case of serial is higher! *)
              begin match
                  Dns_trie.lookup zone Dns_enum.SOA t.data,
                  List.find
                    (fun rr -> match rr.Dns_packet.rdata with Dns_packet.SOA _ -> true | _ -> false)
                    query.Dns_packet.answer
                with
                | exception Not_found ->
                  Log.err (fun m -> m "didn't get a SOA answer for %a from %a"
                              Domain_name.pp q.Dns_packet.q_name Ipaddr.V4.pp_hum ip) ;
                  Error Dns_enum.FormErr
                | Ok (Dns_map.V (Dns_map.Soa, (_, cached_soa)), _), fresh_soa ->
                  (* TODO: > with wraparound in mind *)
                  let fresh = match fresh_soa.Dns_packet.rdata with Dns_packet.SOA soa -> soa | _ -> assert false in
                  if fresh.Dns_packet.serial > cached_soa.Dns_packet.serial then
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
                                 Dns_packet.pp_soa fresh Domain_name.pp zone Dns_packet.pp_soa cached_soa) ;
                    let zones = Domain_name.Map.add zone (Transferred ts, ip, port, name) zones in
                    Ok (t, zones, [])
                  end
                | Error _, _ ->
                  Log.info (fun m -> m "couldn't find soa, requesting AXFR") ;
                  begin match axfr t `Tcp now ts zone name with
                    | None -> Log.warn (fun m -> m "trouble building axfr") ; Ok (t, zones, [])
                    | Some (st, buf) ->
                      Log.debug (fun m -> m "requesting AXFR for %a now!" Domain_name.pp zone) ;
                      let zones = Domain_name.Map.add zone (st, ip, port, name) zones in
                      Ok (t, zones, [ (`Tcp, ip, port, buf) ])
                  end
                | Ok (v, _), _ ->
                  Log.warn (fun m -> m "expected SOA for %a, but found %a"
                               Domain_name.pp zone Dns_map.pp_v v) ;
                  Ok (t, zones, [])
              end
            | _ ->
              Log.warn (fun m -> m "ignoring %a (%a) unmatched state"
                           Domain_name.pp q.Dns_packet.q_name
                           Dns_enum.pp_rr_typ q.Dns_packet.q_type) ;
              Error Dns_enum.Refused
          end
      end
    | qs ->
      Log.warn (fun m -> m "ignoring answer with questions: %a"
                   Fmt.(list ~sep:(unit ",@,") Dns_packet.pp_question) qs) ;
      Error Dns_enum.FormErr

  let handle_rr_update t now ts zname (zones, trie, outs) u =
    let rm_zone trie key =
      match Domain_name.Map.find zname zones with
      | exception Not_found ->
        Log.warn (fun m -> m "couldn't find zone %a" Domain_name.pp zname) ;
        (zones, trie, outs)
      | (_, _, _, keyname) when Domain_name.equal key keyname ->
        (Domain_name.Map.remove key zones, Dns_trie.remove_zone zname trie, outs)
      | (_, _, _, keyname) ->
        Log.warn (fun m -> m "key %a not registered for zone %a (but %a is)"
                     Domain_name.pp key Domain_name.pp zname Domain_name.pp keyname) ;
        (zones, trie, outs)
    in
    match u with
    | Dns_packet.Remove_all name ->
      let trie = Dns_trie.remove name Dns_enum.DNSKEY trie in
      rm_zone trie name
    | Dns_packet.Remove (name, Dns_enum.DNSKEY) ->
      let trie = Dns_trie.remove name Dns_enum.DNSKEY trie in
      rm_zone trie name
    | Dns_packet.Remove_single (name, Dns_packet.DNSKEY key) ->
      begin match Dns_trie.lookup name Dns_enum.DNSKEY trie with
        | Ok (Dns_map.V (Dns_map.Dnskey, _) as v, _) ->
          begin match Dns_map.remove_rdata v (Dns_packet.DNSKEY key) with
            | None ->
              let trie = Dns_trie.remove name Dns_enum.DNSKEY trie in
              rm_zone trie name
            | Some keys ->
              let trie = Dns_trie.insert name keys trie in
              (zones, trie, outs)
          end
        | Ok (v, _) ->
          Log.warn (fun m -> m "looked for DNSKEY %a, found %a, ignoring" Domain_name.pp name Dns_map.pp_v v) ;
          (zones, trie, outs)
        | Error e ->
          Log.err (fun m -> m "error %a while looking up DNSKEY for %a, didn't remove %a"
                      Dns_trie.pp_e e Domain_name.pp name Dns_packet.pp_dnskey key) ;
          (zones, trie, outs)
      end
    | Dns_packet.Add rr ->
      begin match rr.Dns_packet.rdata with
        | Dns_packet.DNSKEY key ->
          let name = rr.Dns_packet.name in
          begin match find_zone_ips name with
            | Some (zname', (pip, pport), _) when Domain_name.equal zname zname' ->
              let keys = match Dns_trie.lookup name Dns_enum.DNSKEY trie with
                | Ok (Dns_map.V (Dns_map.Dnskey, keys), _) -> key :: keys
                | _ -> [ key ]
              in
              let trie' = Dns_trie.insert name (Dns_map.V (Dns_map.Dnskey, keys)) trie in
              let t = { t with data = trie' } in
              begin match query_soa t `Tcp now ts zname name with
                | None ->
                  Log.err (fun m -> m "couldn't query soa for %a" Domain_name.pp zname) ;
                  (zones, trie, outs)
                | Some (state, out) ->
                  let zones = Domain_name.Map.add zname (state, pip, pport, name) zones in
                  (zones, trie', (`Tcp, pip, pport, out) :: outs)
              end
            | Some (zname', _, _) ->
              Log.err (fun m -> m "found zone name %a in %a, expected %a"
                          Domain_name.pp zname' Domain_name.pp name Domain_name.pp zname) ;
              (zones, trie, outs)
            | None ->
              Log.err (fun m -> m "couldn't find ip and zone name in %a" Domain_name.pp name) ;
              (zones, trie, outs)
          end
        | _ ->
          Log.warn (fun m -> m "ignoring add %a" Dns_packet.pp_rr_update u);
          (zones, trie, outs)
      end
    | u ->
      (* TODO: should be forwarded to primary *)
      Log.warn (fun m -> m "ignoring update %a" Dns_packet.pp_rr_update u) ;
      (zones, trie, outs)

  let handle_update t zones now ts proto keyname u =
    (* TODO: handle prereq *)
    let zname = u.Dns_packet.zone.Dns_packet.q_name in
    (* TODO: can allow weaker keys for nsupdates we proxy *)
    guard (authorise t proto keyname zname Key_management) Dns_enum.NotAuth >>= fun () ->
    let ups = u.Dns_packet.update in
    guard (List.for_all (fun u -> in_zone zname (Dns_packet.rr_update_name u)) ups) Dns_enum.NotZone >>= fun () ->
    let zones, trie, outs =
      List.fold_left (handle_rr_update t now ts zname) (zones, t.data, []) ups
    in
    Ok (trie, zones, outs)

  let handle_frame (t, zones) now ts ip proto keyname key header v =
    match v, header.Dns_packet.query with
    | `Query q, true ->
      handle_query t proto keyname header q >>= fun answer ->
      Ok ((t, zones), Some answer, [])
    | `Query q, false ->
      handle_answer t zones now ts keyname key header q >>= fun (t, zones, out) ->
      Ok ((t, zones), None, out)
    | `Update u, true ->
      handle_update t zones now ts proto keyname u >>= fun (data, zones, out) ->
      let answer =
        let update = { u with Dns_packet.prereq = [] ; update = [] ; addition = [] } in
        (s_header header, `Update update)
      in
      Ok (({ t with data }, zones), Some answer, out)
    | `Update _, false -> (* TODO: answer from primary, need to forward to client *)
      Error Dns_enum.FormErr
    | `Notify n, true ->
      handle_notify t zones now ts ip n >>= fun (zones, out) ->
      let answer =
        let n = { n with Dns_packet.answer = [] ; authority = [] ; additional = [] } in
        (s_header header, `Notify n)
      in
      Ok ((t, zones), Some answer, out)
    | `Notify _, false ->
      Log.err (fun m -> m "ignoring notify response (we don't send notifications)") ;
      Ok ((t, zones), None, [])

  let find_mac zones header = function
    | `Query q when not header.Dns_packet.query ->
      begin match q.Dns_packet.question with
        | [ q ] ->
          begin match Domain_name.Map.find q.Dns_packet.q_name zones with
            | exception Not_found -> None
            | Requested_axfr (_, _id_, mac), _, _, _ -> Some mac
            | Requested_soa (_, _, _id, mac), _, _, _ -> Some mac
            | _ -> None
          end
        | _ -> None
      end
    | _ -> None

  let handle (t, zones) now ts proto ip buf =
    match
      safe_decode buf >>= fun ((header, v, opt, tsig), tsig_off) ->
      guard (not header.Dns_packet.truncation) Dns_enum.FormErr >>= fun () ->
      Ok ((header, v, opt, tsig), tsig_off)
    with
    | Error rcode -> ((t, zones), raw_server_error buf rcode, [])
    | Ok ((header, v, opt, tsig), tsig_off) ->
      let handle_inner name key =
        match handle_frame (t, zones) now ts ip proto name key header v with
        | Ok (t, Some (header, answer), out) ->
          let max_size, edns = match opt with
            | None -> None, None
            | Some e -> Some e.Dns_packet.payload_size, Some e
          in
          (t, Some (Dns_packet.encode ?max_size ?edns proto header answer), out)
        | Ok (t, None, out) -> (t, None, out)
        | Error rcode -> ((t, zones), err header v rcode, [])
      in
      let mac = find_mac zones header v in
      match handle_tsig ?mac t now header v tsig tsig_off buf with
      | Error data -> ((t, zones), Some data, [])
      | Ok None ->
        begin match handle_inner None None with
          | (t, None, out) -> (t, None, out)
          | (t, Some (buf, _), out) -> (t, Some buf, out)
        end
      | Ok (Some (name, tsig, mac, key)) ->
        match handle_inner (Some name) (Some key) with
        | (a, Some (buf, max_size), out) ->
          begin match t.tsig_sign ~max_size ~mac name tsig ~key buf with
            | None ->
              Log.warn (fun m -> m "couldn't use %a to tsig sign"
                           Domain_name.pp name) ;
              (a, None, out)
            | Some (buf, _) -> (a, Some buf, out)
          end
        | (a, None, out) -> (a, None, out)
end
