(* (c) 2017 Hannes Mehnert, all rights reserved *)

open Rresult
open R.Infix

let src = Logs.Src.create "dns_server" ~doc:"DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

let guard p err = if p then Ok () else Error err

type proto = [ `Tcp | `Udp ]

let size = function
  | `Udp -> 450
  | `Tcp -> 4056
  | `Tls _ -> 4000

type a = Dns_trie.t -> proto -> Dns_name.t option -> string -> Dns_name.t -> bool

type t = {
  data : Dns_trie.t ;
  authorised : a list ;
  rng : int -> Cstruct.t ;
  tsig_verify : Dns_packet.tsig_verify ;
  tsig_sign : Dns_packet.tsig_sign ;
}

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
    let root = Dns_name.of_string_exn ~hostname:false op
    and zone = Dns_name.prepend_exn ~hostname:false zone op
    in
    Dns_name.sub ~subdomain ~domain:zone || Dns_name.sub ~subdomain ~domain:root

let authorise t proto keyname zone operation =
  let op = operation_to_string operation in
  List.exists (fun a -> a t.data proto keyname op zone) t.authorised

let create data authorised rng tsig_verify tsig_sign  =
  { data ; authorised ; rng ; tsig_verify ; tsig_sign }

let to_ns_rrs name ttl ns =
  Dns_name.DomSet.fold (fun ns acc ->
      { Dns_packet.name ; ttl ; rdata = Dns_packet.NS ns } :: acc)
    ns []

let to_soa name ttl soa =
  [ { Dns_packet.name ; ttl ; rdata = Dns_packet.SOA soa } ]

let find_glue trie typ name names =
  let a, aaaa =
    let open Dns_name.DomSet in
    match typ with
    | Dns_enum.A -> singleton name, empty
    | Dns_enum.AAAA -> empty, singleton name
    | Dns_enum.ANY -> singleton name, singleton name
    | _ -> empty, empty
  in
  let find_rr typ name =
    match Dns_trie.lookup_a name typ trie with
    | Ok (v, _) -> Dns_map.to_rr name v
    | _ -> []
  in
  Dns_name.DomSet.fold (fun name acc ->
      (if Dns_name.DomSet.mem name a then [] else find_rr Dns_enum.A name) @
      (if Dns_name.DomSet.mem name aaaa then [] else find_rr Dns_enum.AAAA name) @
      acc)
    names []

let lookup trie hdr max q =
  let open Dns_packet in
  let answer ?(hdr = hdr) ?(an = []) ?(au = []) ?(ad = []) () =
    (* TODO: should randomize answers + ad? *)
    (* TODO: should dedup at a higher layer (v instead of rr) *)
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
    let q =
      { question = [ q ] ; answer = an ; authority ; additional }
    (* TODO: this is bad -- rethink allocation strategy *)
    and b = Cstruct.create max
    in
    let l = encode_query b hdr q in
    Ok (Cstruct.sub b 0 l)
  in
  match Dns_trie.lookup_a q.q_name q.q_type trie with
  | Ok (v, (name, ttl, ns)) ->
    let an = Dns_map.to_rr q.q_name v
    and au = to_ns_rrs name ttl ns
    in
    let ad =
      let names = Dns_name.DomSet.union (Dns_map.names v) ns in
      find_glue trie q.q_type q.q_name names
    in
    answer ~an ~au ~ad ()
  | Error (`Delegation (name, (ttl, ns, rr))) ->
    let hdr = { hdr with authoritative = false } in
    answer ~hdr ~au:(to_ns_rrs name ttl ns) ~ad:rr ()
  | Error (`EmptyNonTerminal (zname, ttl, soa)) ->
    answer ~au:(to_soa zname ttl soa) ()
  | Error (`NotFound (zname, ttl, soa)) ->
    let hdr = { hdr with rcode = Dns_enum.NXDomain } in
    answer ~hdr ~au:(to_soa zname ttl soa) ()
  | Error `NotAuthoritative ->
    let hdr =
      { hdr with rcode = Dns_enum.NotAuth ; authoritative = false }
    in
    answer ~hdr ()

let axfr t proto key hdr q zone =
  (if authorise t proto key zone Key_management then
     Ok true
   else if authorise t proto key zone Transfer then
     Ok false
   else
     Error Dns_enum.NotAuth) >>= fun keys ->
  match Dns_trie.entries zone t.data with
  | Ok (soa, rrs) ->
    let rrs =
      if keys then rrs
      else
        let not_dnskey rr =
          Dns_packet.(match rr.rdata with DNSKEY _ -> false | _ -> true)
        in
        List.filter not_dnskey rrs
    in
    let b = Cstruct.create (size proto) in
    let q =
      let answer = soa :: rrs @ [ soa ] in
      { Dns_packet.question = q.Dns_packet.question ; answer ; authority = [] ;
        additional = [] }
    in
    (* TODO: never truncate! answer in multiple packets, leave space for tsig!
             (but we only ever use TCP for AXFR, thanks to a filter above! *)
    let l = Dns_packet.encode_query b hdr q in
    Ok (Cstruct.sub b 0 l)
  | Error `Delegation _
  | Error `NotAuthoritative
  | Error `NotFound _ ->
    Log.err (fun m -> m "AXFR attempted on %a, where we're not authoritative"
                 Dns_name.pp zone) ;
    Error Dns_enum.NXDomain

let key_retrieval t proto key hdr q =
  guard (authorise t proto key q.Dns_packet.q_name Key_management)
    Dns_enum.NotAuth >>= fun () ->
  lookup t.data hdr (size proto) q

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
  | Error e ->
    Log.err (fun m -> m "error %a while decoding@.%a"
                 Dns_packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Dns_enum.FormErr
  | Ok v -> Ok v

let handle_query t proto key header query =
  match query.Dns_packet.question with
  | [ q ] ->
    let hdr =
      { header with Dns_packet.query = false ;
                    authoritative = true ;
                    recursion_available = false ;
                    authentic_data = false }
    in
    let open Dns_enum in
    begin match q.Dns_packet.q_type with
      | AXFR | ANY when proto = `Udp ->
        Logs.err (fun m -> m "refusing %a query via UDP" Dns_enum.pp_rr_typ q.Dns_packet.q_type) ;
        Error Dns_enum.Refused
      | AXFR -> axfr t proto key hdr query q.Dns_packet.q_name
      | DNSKEY -> key_retrieval t proto key hdr q
      (* TODO: IXFR -> *)
      | A | NS | CNAME | SOA | PTR | MX | TXT | AAAA | SRV | ANY | CAA ->
        lookup t.data hdr (size proto) q
      | r ->
        Log.err (fun m -> m "refusing query type %a" Dns_enum.pp_rr_typ r) ;
        Error Dns_enum.Refused
    end
  | _ ->
    Log.err (fun m -> m "none or multiple questions, bailing") ;
    Error Dns_enum.FormErr

let in_zone zone name = Dns_name.sub ~subdomain:name ~domain:zone

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
  Dns_name.DomMap.fold (fun name map r ->
      r >>= fun () ->
      Dns_map.fold (fun v r ->
          r >>= fun () ->
          match Dns_trie.lookup name (Dns_map.to_rr_typ v) trie with
          | Ok v' when Dns_map.equal_v v v' -> Ok ()
          | _ -> Error Dns_enum.NXRRSet)
        map r)
    map (Ok ())

(* RFC 2136 Section 2.5 + 3.4.2 *)
(* we never complain, we just ignore errors *)
let handle_rr_update zname trie = function
  | Dns_packet.Remove (name, typ) ->
    begin match typ with
      | Dns_enum.ANY | Dns_enum.NS ->
        Log.warn (fun m -> m "ignoring request to remove %a %a"
                      Dns_enum.pp_rr_typ typ Dns_name.pp name) ;
        trie
      | Dns_enum.SOA ->
        (* this does not follow 2136, but we want to be able to remove a zone *)
        Dns_trie.remove_zone name trie
      | _ -> Dns_trie.remove name typ trie
    end
  | Dns_packet.Remove_all name ->
    if Dns_name.equal zname name then begin
      Log.warn (fun m -> m "ignoring request to remove entire zone %a"
                    Dns_name.pp name) ;
      trie
    end else
      Dns_trie.remove name Dns_enum.ANY trie
  | Dns_packet.Remove_single (name, rdata) ->
    let typ = Dns_packet.rdata_to_rr_typ rdata in
    begin match typ with
      | Dns_enum.ANY | Dns_enum.SOA ->
        Log.warn (fun m -> m "ignoring request to remove %a %a %a"
                      Dns_enum.pp_rr_typ typ Dns_name.pp name
                      Dns_packet.pp_rdata rdata) ;
        trie
      | _ ->
        begin match Dns_trie.lookup name typ trie with
          | Ok (Dns_map.V (Dns_map.K.Cname, _)) when Dns_enum.CNAME = typ ->
            (* we could be picky and require rdata.name == alias *)
            Dns_trie.remove name typ trie
          | Ok (Dns_map.V (Dns_map.K.Cname, _)) ->
            Log.warn (fun m -> m "ignoring request to remove %a %a %a (got a cname on lookup)"
                          Dns_enum.pp_rr_typ typ Dns_name.pp name Dns_packet.pp_rdata rdata) ;
            trie
          | Ok v ->
            begin match Dns_map.remove_rdata v rdata with
              | None -> Dns_trie.remove name typ trie
              | Some v -> Dns_trie.insert name v trie
            end
          | Error e ->
            Log.warn (fun m -> m "error %a while looking up %a %a %a for removal"
                          Dns_trie.pp_e e Dns_enum.pp_rr_typ typ
                          Dns_name.pp name Dns_packet.pp_rdata rdata) ;
            trie
        end
    end
  | Dns_packet.Add rr ->
    (* in contrast to 2136, we allow to add SOA - zone creation! *)
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
          | Ok (Dns_map.V (Dns_map.K.Cname, (_, alias))) ->
            Log.warn (fun m -> m "found a CNAME %a, won't add %a"
                          Dns_name.pp alias Dns_packet.pp_rr rr) ;
            trie
          | Ok v ->
            begin match Dns_map.add_rdata v rr.Dns_packet.rdata with
              | None ->
                Log.warn (fun m -> m "error while adding %a to %a"
                              Dns_packet.pp_rr rr Dns_map.pp_v v) ;
                trie
              | Some v ->
                Dns_trie.insert rr.Dns_packet.name v trie
            end
          | Error (`EmptyNonTerminal _ | `NotFound _) ->
            begin match Dns_map.of_rdata rr.Dns_packet.ttl rr.Dns_packet.rdata with
              | None ->
                Log.warn (fun m -> m "couldn't convert rdata %a" Dns_packet.pp_rr rr) ;
                trie
              | Some v -> Dns_trie.insert rr.Dns_packet.name v trie
            end
          | Error e ->
            Log.warn (fun m -> m "error %a on lookup while adding %a"
                          Dns_trie.pp_e e Dns_packet.pp_rr rr) ;
            trie
    end

let extract_zone_and_ip ?(secondary = false) name =
  (* the name of a key is primaryip.secondaryip._transfer.zone *)
  let arr = Dns_name.to_array name in
  try
    let rec go idx = if Array.get arr idx = "_transfer" then idx else go (succ idx) in
    let zone_idx = go 0 in
    let zone = Dns_name.of_array (Array.sub arr 0 zone_idx) in
    let mip = succ zone_idx + if secondary then 0 else 4 in
    let host = Dns_name.of_array (Array.sub arr mip 4) in
    match Ipaddr.V4.of_string (Dns_name.to_string host) with
    | None -> None
    | Some ip -> Some (zone, ip)
  with
    Invalid_argument _ -> None

module IPS = Set.Make(Ipaddr.V4)

let notify rng now trie zone soa =
  (* we use both the NS records of the zone, and the IP addresses of secondary
     servers which have transfer keys for the zone *)
  let ips =
    match Dns_trie.lookup zone Dns_enum.NS trie with
    | Ok (Dns_map.V (Dns_map.K.Ns, (_, ns, glue))) ->
      let secondaries = Dns_name.DomSet.remove soa.Dns_packet.nameserver ns in
      (* TODO: AAAA records *)
      Dns_name.DomSet.fold (fun ns acc ->
          let ips =
            match Dns_name.DomMap.find ns glue with
            | exception Not_found -> None
            | ((_, []), _) -> None
            | ((_, xs), _) -> Some xs
          in
          let ips = match ips with
            | None ->
              Log.debug (fun m -> m "no address record found in glue for %a"
                            Dns_name.pp ns) ;
              begin match Dns_trie.lookup ns Dns_enum.A trie with
                | Ok (Dns_map.V (Dns_map.K.A, (_, ips))) -> IPS.of_list ips
                | _ ->
                  Log.err (fun m -> m "lookup for A %a returned nothing as well"
                              Dns_name.pp ns) ;
                  IPS.empty
              end
            | Some ips -> IPS.of_list ips
          in
          IPS.union ips acc) secondaries IPS.empty
    | _ -> IPS.empty
  and key_ips =
    let tx = Dns_name.prepend_exn ~hostname:false zone (operation_to_string Transfer) in
    match Dns_trie.keys tx trie with
    | Error () ->
      Logs.err (fun m -> m "no keys found for %a" Dns_name.pp tx) ; IPS.empty
    | Ok es ->
      List.fold_left (fun acc (n, _) ->
          match extract_zone_and_ip ~secondary:true n with
          | None ->
            Logs.err (fun m -> m "failed to parse secondary IP: %a" Dns_name.pp n) ;
            acc
          | Some (_, ip) -> IPS.add ip acc)
        IPS.empty es
  in
  let ips = IPS.union ips key_ips in
  Logs.debug (fun m -> m "notifying %a %a" Dns_name.pp zone
                 Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp_hum) (IPS.elements ips)) ;
  let notify =
    let question = [ { Dns_packet.q_name = zone ; q_type = Dns_enum.SOA } ] in
    let answer =
      [ { Dns_packet.name = zone ; ttl = 0l ; rdata = Dns_packet.SOA soa } ]
    in
    { Dns_packet.question ; answer ; authority = [] ; additional = [] }
  in
  let one ip =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) rng in
    let header = {
      Dns_packet.id ; query = true ; operation = Dns_enum.Notify ;
      authoritative = true ; truncation = false ; recursion_desired = false ;
      recursion_available = false ;authentic_data = false ;
      checking_disabled = false ; rcode = Dns_enum.NoError
    }
    in
    (now, 0, ip, header, notify)
  in
  IPS.fold (fun ip acc -> one ip :: acc) ips []

let handle_update t ts proto key header u =
  (* first of all, see whether we think we're authoritative for the zone *)
  let zone = Dns_packet.(u.zone.q_name) in
  let need_key =
    let f subdomain =
      List.exists (fun p ->
          let domain = Dns_name.prepend_exn ~hostname:false zone p in
          Dns_name.sub ~subdomain ~domain)
        all_operations
    in
    Dns_packet.(List.exists (fun up -> f (rr_update_name up)) u.update)
  in
  (if authorise t proto key zone Key_management then
     Ok ()
   else if not need_key && authorise t proto key zone Update then
     Ok ()
   else
     Error Dns_enum.NotAuth) >>= fun () ->
  (* TODO: should we explicitly forbid root zone modifications? *)
  let trie = t.data in
  match Dns_trie.lookup zone Dns_enum.SOA trie with
  | Ok (Dns_map.V (Dns_map.K.Soa, (ttl, soa))) ->
    List.fold_left (fun r pre ->
        r >>= fun acc ->
        handle_rr_prereq trie zone acc pre)
      (Ok []) u.Dns_packet.prereq >>= fun acc ->
    check_exists trie acc >>= fun () ->
    let updates, glues =
      let p u = in_zone zone (Dns_packet.rr_update_name u) in
      List.partition p u.Dns_packet.update
    in
    let trie = List.fold_left (handle_rr_update zone) trie updates in
    (* TODO: still need safety to have at least one glue address record for NS *)
    (match glues, Dns_trie.lookup zone Dns_enum.NS trie with
     | [], _ -> Ok trie
     | glues, Ok (Dns_map.V (Dns_map.K.Ns, (ttl, ns, glue))) ->
       List.fold_left (fun r up ->
           r >>= fun glue ->
           match up with
           | Dns_packet.Add rr when Dns_name.DomSet.mem rr.Dns_packet.name ns ->
             let a_glue, aaaa_glue = match Dns_name.DomMap.find rr.Dns_packet.name glue with
               | exception Not_found -> ((0l, []), (0l, []))
               | glue -> glue
             in
             (match rr.Dns_packet.rdata with
              | Dns_packet.A ip ->
                Ok ((ttl, ip :: snd a_glue), aaaa_glue)
              | Dns_packet.AAAA ip6 ->
                Ok (a_glue, (ttl, ip6 :: snd aaaa_glue))
              | _ -> Error Dns_enum.NotZone) >>= fun glues ->
             Ok (Dns_name.DomMap.add rr.Dns_packet.name glues glue)
           | Dns_packet.Remove (name, typ) when Dns_name.DomSet.mem name ns ->
             begin match Dns_name.DomMap.find name glue, typ with
               | exception Not_found -> Error Dns_enum.NotZone
               | (_, aaaa), Dns_enum.A ->
                 Ok (Dns_name.DomMap.add name ((0l, []), aaaa) glue)
               | (a, _), Dns_enum.AAAA ->
                 Ok (Dns_name.DomMap.add name (a, (0l, [])) glue)
               | _ -> Error Dns_enum.NotZone
             end
           | Dns_packet.Remove_all name when Dns_name.DomSet.mem name ns ->
             Ok (Dns_name.DomMap.remove name glue)
           | Dns_packet.Remove_single (name, data) when Dns_name.DomSet.mem name ns ->
             let add = function
               | ((_, []), (_, [])) -> Dns_name.DomMap.remove name glue
               | entry -> Dns_name.DomMap.add name entry glue
             in
             begin match Dns_name.DomMap.find name glue, data with
               | exception Not_found -> Ok glue
               | ((ttla, a), aaaa), Dns_packet.A ip ->
                 Ok (add ((ttla, List.filter (fun ip' -> not (Ipaddr.V4.compare ip' ip = 0)) a), aaaa))
               | (a, (ttlaaaa, aaaa)), Dns_packet.AAAA ip6 ->
                 Ok (add (a, (ttlaaaa, List.filter (fun ip' -> not (Ipaddr.V6.compare ip' ip6 = 0)) aaaa)))
               | _ -> Error Dns_enum.NotZone
             end
           | _ -> Error Dns_enum.NotZone)
         (Ok glue) glues >>= fun glue ->
       Ok (Dns_trie.insert zone (Dns_map.V (Dns_map.K.Ns, (ttl, ns, glue))) trie)
     | _, _ -> Error Dns_enum.NotZone) >>= fun trie ->
    let soa = { soa with Dns_packet.serial = Int32.succ soa.Dns_packet.serial } in
    let trie = Dns_trie.insert zone (Dns_map.V (Dns_map.K.Soa, (ttl, soa))) trie in
    let answer = Dns_packet.answer header (`Update u) in
    let notifies = notify t.rng ts trie zone soa in
    Ok (trie, answer, notifies)
  | _ -> Error Dns_enum.NXDomain

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
    Cstruct.set_uint8 hdr 3 (Dns_enum.rcode_to_int rcode) ;
    Some hdr

let find_key trie name p =
  match Dns_trie.lookup_ignore name Dns_enum.DNSKEY trie with
  | Ok (Dns_map.V (Dns_map.K.Dnskey, keys)) -> List.filter p keys
  | _ -> []

let handle_tsig ?mac t now header v off buf =
  match off, Dns_packet.find_tsig v with
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
  type nonrec t =
    t * (int64 * int * Ipaddr.V4.t * Dns_packet.header * Dns_packet.query) list

  let create now ?(a = []) ~tsig_verify ~tsig_sign ~rng ?(zones = []) data =
    let notifications =
      List.fold_left (fun acc zone ->
          match Dns_trie.lookup zone Dns_enum.SOA data with
          | Ok (Dns_map.V (Dns_map.K.Soa, (_, soa))) ->
            acc @ notify rng now data zone soa
          | _ -> acc) [] zones
    in
    let t = create data a rng tsig_verify tsig_sign in
    (t, notifications)

  let handle_frame (t, ns) ts ip proto header key v =
    match v, header.Dns_packet.query with
    | `Query q, true ->
      handle_query t proto key header q >>= fun answer ->
      Ok ((t, ns), Some answer, [])
    | `Update u, true ->
      (* TODO: intentional? all other notifications apart from the new ones are dropped *)
      handle_update t ts proto key header u >>= fun (data, answer, notifications) ->
      let out = List.map (fun (_, _, ip, hdr, q) ->
          let buf = Cstruct.create 512 in
          let l = Dns_packet.encode_query buf hdr q in
          ip, Cstruct.sub buf 0 l)
          notifications
      in
      Ok (({ t with data }, notifications), answer, out)
    | `Notify _, false ->
      let notifications =
        List.filter (fun (_, _, ip', hdr', _) ->
            not (Ipaddr.V4.compare ip ip' = 0 && header.Dns_packet.id = hdr'.Dns_packet.id))
          ns
      in
      Ok ((t, notifications), None, [])
    | _, false ->
      Log.err (fun m -> m "ignoring unsolicited answer, replying with FormErr") ;
      Error Dns_enum.FormErr
    | `Notify _, true ->
      Log.err (fun m -> m "ignoring unsolicited request") ;
      Ok ((t, ns), None, [])

  let handle (t, ns) now ts proto ip buf =
    match
      safe_decode buf >>= fun ((header, v), tsig_off) ->
      guard (not header.Dns_packet.truncation) Dns_enum.FormErr >>= fun () ->
      Ok ((header, v), tsig_off)
    with
    | Error rcode -> (t, ns), raw_server_error buf rcode, []
    | Ok ((header, v), tsig_off) ->
      Log.debug (fun m -> m "%a sent %a" Ipaddr.V4.pp_hum ip Dns_packet.pp (header, v)) ;
      match handle_tsig t now header v tsig_off buf with
      | Error data -> ((t, ns), Some data, [])
      | Ok None ->
        begin match handle_frame (t, ns) ts ip proto header None v with
          | Ok x -> x
          | Error rcode -> ((t, ns), Dns_packet.error header v rcode, [])
        end
      | Ok (Some (name, tsig, mac, key)) ->
        match handle_frame (t, ns) ts ip proto header (Some name) v with
        | Ok (a, Some answer, out) ->
          begin match t.tsig_sign ~mac name tsig ~key answer with
            | None -> (a, None, out)
            | Some (buf, _) -> (a, Some buf, out)
          end
        | Ok res -> res
        | Error rcode ->
          let answer = match Dns_packet.error header v rcode with
            | None -> None
            | Some err -> match t.tsig_sign ~mac name tsig ~key err with
              | None -> None
              | Some (buf, _) -> Some buf
          in
          ((t, ns), answer, [])

  let retransmit = Array.map Duration.of_sec [| 5 ; 12 ; 25 ; 40 ; 60 |]

  let timer (t, ns) now =
    let max = Array.length retransmit in
    let notifications, out =
      List.fold_left (fun (ns, acc) (ts, count, ip, hdr, q) ->
          if Int64.add ts retransmit.(count) < now then
            (if count = max then begin
                Log.warn (fun m -> m "retransmitting to %a the last time %a %a"
                              Ipaddr.V4.pp_hum ip Dns_packet.pp_header hdr
                              Dns_packet.pp_query q) ;
                ns
              end else
               (ts, succ count, ip, hdr, q) :: ns),
            (ip, hdr, q) :: acc
          else
            (ts, count, ip, hdr, q) :: ns, acc)
        ([], []) ns
    in
    let out = List.map (fun (ip, hdr, q) ->
        let buf = Cstruct.create 512 in
        let l = Dns_packet.encode_query buf hdr q in
        let b = Cstruct.sub buf 0 l in
        (ip, b))
        out
    in
    (t, notifications), out
end

module Secondary = struct
  type state =
    | Transferred of int64
    | Requested_axfr of int64 * int * Cstruct.t
    | Requested_soa of int64 * int * Cstruct.t

  type nonrec t =
    t * (state * Ipaddr.V4.t * Dns_name.t) Dns_name.DomMap.t

  let create ?(a = []) ~tsig_verify ~tsig_sign ~rng keys =
    (* two kinds of keys: aaa._key-management and ip1.ip2._transfer.zone *)
    let trie, zones =
      List.fold_left (fun (trie, zones) (name, key) ->
          match extract_zone_and_ip name with
          | None when Dns_name.sub ~subdomain:name ~domain:(Dns_name.of_string_exn ~hostname:false (operation_to_string Key_management)) ->
            Log.info (fun m -> m "adding key management key %a" Dns_name.pp name) ;
            (Dns_trie.insert name (Dns_map.V (Dns_map.K.Dnskey, [ key ])) trie, zones)
          | Some (zone, ip) ->
            Log.info (fun m -> m "adding transfer key %a for %a" Dns_name.pp name Dns_name.pp zone) ;
            let zones =
              let v = (Transferred 0L, ip, name) in
              Dns_name.DomMap.add zone v zones
            in
            (Dns_trie.insert name (Dns_map.V (Dns_map.K.Dnskey, [ key ])) trie, zones)
          | _ ->
            Log.warn (fun m -> m "don't know what to do with %a, ignoring" Dns_name.pp name) ;
            (trie, zones))
        (Dns_trie.empty, Dns_name.DomMap.empty) keys
    in
    (create trie a rng tsig_verify tsig_sign, zones)

  let maybe_sign sign trie name signed original_id buf =
    match find_key trie name (fun _ -> true) with
    | [key] ->
      begin match Dns_packet.dnskey_to_tsig_algo key with
        | Some algorithm ->
          begin match Dns_packet.tsig ~algorithm ~original_id ~signed () with
            | None -> Log.err (fun m -> m "creation of tsig failed") ; None
            | Some tsig -> match sign ?mac:None name tsig ~key buf with
              | None -> Log.err (fun m -> m "signing failed") ; None
              | Some res -> Some res
          end
        | None -> Log.err (fun m -> m "couldn't convert algorithm to tsig") ; None
      end
    | _ -> Log.err (fun m -> m "key not found (or multiple)") ; None

  let header rng () =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) rng in
    { Dns_packet.id ; query = true ; operation = Dns_enum.Query ;
      authoritative = false ; truncation = false ;
      recursion_desired = false ; recursion_available = false ;
      authentic_data = false ; checking_disabled = false ;
      rcode = Dns_enum.NoError }

  let axfr t now ts q_name name =
    let header = header t.rng ()
    and question = [ { Dns_packet.q_name ; q_type = Dns_enum.AXFR } ]
    in
    let query = { Dns_packet.question ; answer = [] ; authority = [] ; additional = [] } in
    let buf = Cstruct.create 512 in
    let l = Dns_packet.encode_query buf header query in
    let buf = Cstruct.sub buf 0 l in
    Log.debug (fun m -> m "out %a@.%a" Dns_packet.pp (header, `Query query) Cstruct.hexdump_pp buf) ;
    match maybe_sign t.tsig_sign t.data name now header.Dns_packet.id buf with
    | None -> None
    | Some (buf, mac) ->
      Log.debug (fun m -> m "buf@.%a" Cstruct.hexdump_pp buf) ;
      Some (Requested_axfr (ts, header.Dns_packet.id, mac), buf)

  let query_soa t now ts q_name name =
    let header = header t.rng ()
    and question = [ { Dns_packet.q_name ; q_type = Dns_enum.SOA } ]
    in
    let query = { Dns_packet.question ; answer = [] ; authority = [] ; additional = [] } in
    let buf = Cstruct.create 512 in
    let l = Dns_packet.encode_query buf header query in
    let buf = Cstruct.sub buf 0 l in
    Log.debug (fun m -> m "out %a@.%a" Dns_packet.pp (header, `Query query) Cstruct.hexdump_pp buf) ;
    match maybe_sign t.tsig_sign t.data name now header.Dns_packet.id buf with
    | None -> None
    | Some (buf, mac) ->
      Log.debug (fun m -> m "buf@.%a" Cstruct.hexdump_pp buf) ;
      Some (Requested_soa (ts, header.Dns_packet.id, mac), buf)

  let timer (t, zones) p_now now =
    let zones, out =
      Dns_name.DomMap.fold (fun zone (st, ip, name) (zones, acc) ->
          let change =
            match Dns_trie.lookup zone Dns_enum.SOA t.data with
            | Ok (Dns_map.V (Dns_map.K.Soa, (_, soa))) ->
              begin match st with
                | Transferred ts ->
                  (* TODO: integer overflows (Int64.add) *)
                  let r = Duration.of_sec (Int32.to_int soa.Dns_packet.refresh) in
                  if Int64.add ts r < now then
                    query_soa t p_now now zone name
                  else
                    None
                | Requested_soa (ts, _, _) | Requested_axfr (ts, _, _) ->
                  let e = Duration.of_sec (Int32.to_int soa.Dns_packet.expiry) in
                  if Int64.add ts e < now then
                    query_soa t p_now now zone name
                  else
                    None
              end
            | Ok v ->
              Log.err (fun m -> m "looked up SOA %a, got %a"
                           Dns_name.pp zone Dns_map.pp_v v) ;
              None
            | Error e ->
              Log.warn (fun m -> m "error %a while looking up SOA %a, querying SOA"
                           Dns_trie.pp_e e Dns_name.pp zone) ;
              query_soa t p_now now zone name
          in
          let st, out = match change with
            | None -> st, acc
            | Some (st, out) -> st, (`Udp, ip, out) :: acc
          in
          Dns_name.DomMap.add zone (st, ip, name) zones, out)
        zones (Dns_name.DomMap.empty, [])
    in
    (t, zones), out

  let handle_notify t zones now ts ip header query =
    match query.Dns_packet.question with
    | [ q ] ->
      begin match q.Dns_packet.q_type with
        | Dns_enum.SOA ->
          let zone = q.Dns_packet.q_name in
          begin match Dns_name.DomMap.find zone zones with
            | exception Not_found -> (* we don't know anything about the notified zone *)
              Log.warn (fun m -> m "ignoring notify for %a, no such zone"
                            Dns_name.pp q.Dns_packet.q_name) ;
              Error Dns_enum.Refused
            | (_, ip', name) when Ipaddr.V4.compare ip ip' = 0 ->
              Log.debug (fun m -> m "received notify for %a, replying and requesting SOA"
                             Dns_name.pp q.Dns_packet.q_name) ;
              let answer =
                let hdr = { header with Dns_packet.authoritative = true ;
                                        recursion_available = false ;
                                        authentic_data = false }
                in
                Dns_packet.answer hdr (`Query query)
              in
              let zones, out =
                match query_soa t now ts zone name with
                | None -> zones, []
                | Some (st, buf) ->
                  Dns_name.DomMap.add zone (st, ip, name) zones,
                  [ (`Udp, ip, buf) ]
              in
              Ok (zones, answer, out)
            | (_, ip', _) ->
              Log.warn (fun m -> m "ignoring notify for %a from %a (%a is primary"
                            Dns_name.pp q.Dns_packet.q_name
                            Ipaddr.V4.pp_hum ip Ipaddr.V4.pp_hum ip') ;
              Error Dns_enum.Refused
          end
        | t ->
          Log.warn (fun m -> m "ignoring notify %a with type %a"
                        Dns_name.pp q.Dns_packet.q_name Dns_enum.pp_rr_typ t) ;
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
      begin match Dns_name.DomMap.find zone zones with
        | exception Not_found ->
          Log.warn (fun m -> m "ignoring %a (%a), unknown zone"
                        Dns_name.pp q.Dns_packet.q_name
                        Dns_enum.pp_rr_typ q.Dns_packet.q_type) ;
          Error Dns_enum.Refused
        | (st, ip, name) ->
          Log.debug (fun m -> m "in %a (keyname %a) got answer %a"
                         Dns_name.pp q.Dns_packet.q_name Dns_name.pp name
                         Dns_packet.pp_rrs query.Dns_packet.answer) ;
          Rresult.R.of_option
            ~none:(fun () ->
                Log.err (fun m -> m "refusing (not authenticated)") ;
                Error Dns_enum.Refused)
            keyname >>= fun key_name ->
          guard (Dns_name.equal name key_name) Dns_enum.Refused >>= fun () ->
          Rresult.R.of_option ~none:(fun () -> Error Dns_enum.Refused) key >>= fun key ->
          begin match st, q.Dns_packet.q_type with
            | Requested_axfr (_, id', _), Dns_enum.AXFR when header.Dns_packet.id = id' ->
              (* TODO (a) check completeness of AXFR *)
              (* (b) build vs from query.answer *)
              (* (c) drop zone from trie *)
              (* (d) insert vs into trie *)
              (* (e) insert dnskey into trie *)
              (* TODO: do we need to preserve other keys than the current!? *)
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
              let trie = Dns_trie.insert key_name (Dns_map.V (Dns_map.K.Dnskey, [ key ])) trie in
              let zones = Dns_name.DomMap.add zone (Transferred ts, ip, name) zones in
              Ok ({ t with data = trie }, zones, [])
            | Requested_soa (_, id', _), Dns_enum.SOA when header.Dns_packet.id = id' ->
              (* request AXFR now in case of serial is higher! *)
              begin match
                  Dns_trie.lookup zone Dns_enum.SOA t.data,
                  List.find
                    (fun rr -> match rr.Dns_packet.rdata with Dns_packet.SOA _ -> true | _ -> false)
                    query.Dns_packet.answer
                with
                | exception Not_found ->
                  Log.err (fun m -> m "didn't get a SOA answer for %a from %a"
                               Dns_name.pp q.Dns_packet.q_name Ipaddr.V4.pp_hum ip) ;
                  Error Dns_enum.FormErr
                | Ok (Dns_map.V (Dns_map.K.Soa, (_, cached_soa))), fresh_soa ->
                  (* TODO: > with wraparound in mind *)
                  let fresh = match fresh_soa.Dns_packet.rdata with Dns_packet.SOA soa -> soa | _ -> assert false in
                  if fresh.Dns_packet.serial > cached_soa.Dns_packet.serial then
                    match axfr t now ts zone name with
                    | None ->
                      Log.warn (fun m -> m "trouble creating axfr for %a (using %a)"
                                    Dns_name.pp zone Dns_name.pp name) ;
                      (* TODO: reset state? *)
                      Ok (t, zones, [])
                    | Some (st, buf) ->
                      Log.debug (fun m -> m "requesting AXFR for %a now!" Dns_name.pp zone) ;
                      let zones = Dns_name.DomMap.add zone (st, ip, name) zones in
                      Ok (t, zones, [ (`Tcp, ip, buf) ])
                  else begin
                    Log.info (fun m -> m "received soa (%a) for %a is not newer than cached (%a), moving on"
                                  Dns_packet.pp_soa fresh Dns_name.pp zone Dns_packet.pp_soa cached_soa) ;
                    let zones = Dns_name.DomMap.add zone (Transferred ts, ip, name) zones in
                    Ok (t, zones, [])
                  end
                | Error _, _ ->
                  Log.info (fun m -> m "couldn't find soa, requesting AXFR") ;
                  begin match axfr t now ts zone name with
                    | None -> Log.warn (fun m -> m "trouble building axfr") ; Ok (t, zones, [])
                    | Some (st, buf) ->
                      Log.debug (fun m -> m "requesting AXFR for %a now!" Dns_name.pp zone) ;
                      let zones = Dns_name.DomMap.add zone (st, ip, name) zones in
                      Ok (t, zones, [ (`Tcp, ip, buf) ])
                  end
                | Ok v, _ ->
                  Log.warn (fun m -> m "expected SOA for %a, but found %a"
                                Dns_name.pp zone Dns_map.pp_v v) ;
                  Ok (t, zones, [])
              end
            | _ ->
              Log.warn (fun m -> m "ignoring %a (%a) unmatched state"
                            Dns_name.pp q.Dns_packet.q_name
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
      match Dns_name.DomMap.find zname zones with
      | exception Not_found ->
        Log.warn (fun m -> m "couldn't find zone %a" Dns_name.pp zname) ;
        (zones, trie, outs)
      | (_, _, keyname) when Dns_name.equal key keyname ->
        (Dns_name.DomMap.remove key zones, Dns_trie.remove_zone zname trie, outs)
      | (_, _, keyname) ->
        Log.warn (fun m -> m "key %a not registered for zone %a (but %a is)"
                      Dns_name.pp key Dns_name.pp zname Dns_name.pp keyname) ;
        (zones, trie, outs)
    in
    match u with
    | Dns_packet.Remove (name, Dns_enum.DNSKEY) ->
      let trie = Dns_trie.remove name Dns_enum.DNSKEY trie in
      rm_zone trie name
    | Dns_packet.Remove_single (name, Dns_packet.DNSKEY key) ->
      begin match Dns_trie.lookup name Dns_enum.DNSKEY trie with
        | Ok (Dns_map.V (Dns_map.K.Dnskey, _) as v) ->
          begin match Dns_map.remove_rdata v (Dns_packet.DNSKEY key) with
            | None ->
              let trie = Dns_trie.remove name Dns_enum.DNSKEY trie in
              rm_zone trie name
            | Some keys ->
              let trie = Dns_trie.insert name keys trie in
              (zones, trie, outs)
          end
        | Ok v ->
          Log.warn (fun m -> m "looked for DNSKEY %a, found %a, ignoring" Dns_name.pp name Dns_map.pp_v v) ;
          (zones, trie, outs)
        | Error e ->
          Log.err (fun m -> m "error %a while looking up DNSKEY for %a, didn't remove %a"
                        Dns_trie.pp_e e Dns_name.pp name Dns_packet.pp_dnskey key) ;
          (zones, trie, outs)
      end
    | Dns_packet.Add rr ->
      begin match rr.Dns_packet.rdata with
        | Dns_packet.DNSKEY key ->
          let name = rr.Dns_packet.name in
          begin match extract_zone_and_ip name with
            | Some (zname', ip) when Dns_name.equal zname zname' ->
              let keys = match Dns_trie.lookup name Dns_enum.DNSKEY trie with
                | Ok (Dns_map.V (Dns_map.K.Dnskey, keys)) -> key :: keys
                | _ -> [ key ]
              in
              let trie' = Dns_trie.insert name (Dns_map.V (Dns_map.K.Dnskey, keys)) trie in
              let t = { t with data = trie' } in
              begin match query_soa t now ts zname name with
                | None ->
                  Log.err (fun m -> m "couldn't query soa for %a" Dns_name.pp zname) ;
                  (zones, trie, outs)
                | Some (state, out) ->
                  let zones = Dns_name.DomMap.add zname (state, ip, name) zones in
                  (zones, trie', (`Udp, ip, out) :: outs)
              end
            | Some (zname', _) ->
              Log.err (fun m -> m "found zone name %a in %a, expected %a"
                           Dns_name.pp zname' Dns_name.pp name Dns_name.pp zname) ;
              (zones, trie, outs)
            | None ->
              Log.err (fun m -> m "couldn't find ip and zone name in %a" Dns_name.pp name) ;
              (zones, trie, outs)
          end
        | _ ->
          Log.warn (fun m -> m "ignoring add %a" Dns_packet.pp_rr_update u);
          (zones, trie, outs)
      end
    | u ->
      (* TODO: should handle Dns_packet.Remove_all? *)
      (* TODO: should be forwarded to primary *)
      Log.warn (fun m -> m "ignoring update %a" Dns_packet.pp_rr_update u) ;
      (zones, trie, outs)

    let handle_update t zones now ts proto keyname header u =
      (* TODO: handle prereq *)
      let zname = u.Dns_packet.zone.Dns_packet.q_name in
      (* TODO: can allow weaker keys for nsupdates we proxy *)
      guard (authorise t proto keyname zname Key_management) Dns_enum.NotAuth >>= fun () ->
      let ups = u.Dns_packet.update in
      guard (List.for_all (fun u -> in_zone zname (Dns_packet.rr_update_name u)) ups) Dns_enum.NotZone >>= fun () ->
      let zones, trie, outs =
        List.fold_left (handle_rr_update t now ts zname) (zones, t.data, []) ups
      in
      let answer = Dns_packet.answer header (`Update u) in
      Ok (trie, zones, answer, outs)

  let handle_frame (t, zones) now ts ip proto header keyname key v =
    match v, header.Dns_packet.query with
    | `Query q, true ->
      handle_query t proto keyname header q >>= fun answer ->
      Ok ((t, zones), Some answer, [])
    | `Query q, false ->
      handle_answer t zones now ts keyname key header q >>= fun (t, zones, out) ->
      Ok ((t, zones), None, out)
    | `Update u, true ->
      handle_update t zones now ts proto keyname header u >>= fun (data, zones, answer, out) ->
      Ok (({ t with data }, zones), answer, out)
    | `Update _, false -> (* TODO: answer from primary, need to forward to client *)
      Error Dns_enum.FormErr
    | `Notify n, true ->
      handle_notify t zones now ts ip header n >>= fun (zones, answer, out) ->
      Ok ((t, zones), answer, out)
    | `Notify _, false ->
      Log.err (fun m -> m "ignoring notify response (we don't send notifications)") ;
      Ok ((t, zones), None, [])

  let find_mac zones header = function
    | `Query q when not header.Dns_packet.query ->
      begin match q.Dns_packet.question with
        | [ q ] ->
          begin match Dns_name.DomMap.find q.Dns_packet.q_name zones with
            | exception Not_found -> None
            | Requested_axfr (_, _id_, mac), _, _ -> Some mac
            | Requested_soa (_, _id_, mac), _, _ -> Some mac
            | _ -> None
          end
        | _ -> None
      end
    | _ -> None

  let handle (t, zones) now ts proto ip buf =
    match
      safe_decode buf >>= fun ((header, v), tsig_off) ->
      guard (not header.Dns_packet.truncation) Dns_enum.FormErr >>= fun () ->
      Ok ((header, v), tsig_off)
    with
    | Error rcode -> ((t, zones), raw_server_error buf rcode, [])
    | Ok ((header, v), tsig_off) ->
      Log.debug (fun m -> m "%a sent %a" Ipaddr.V4.pp_hum ip Dns_packet.pp (header, v)) ;
      let mac = find_mac zones header v in
      match handle_tsig ?mac t now header v tsig_off buf with
      | Error data -> ((t, zones), Some data, [])
      | Ok None ->
        begin
          match handle_frame (t, zones) now ts ip proto header None None v with
          | Ok x -> x
          | Error rcode -> ((t, zones), Dns_packet.error header v rcode, [])
        end
      | Ok (Some (name, tsig, mac, key)) ->
        match handle_frame (t, zones) now ts ip proto header (Some name) (Some key) v with
        | Ok (a, Some answer, out) ->
          begin match t.tsig_sign ~mac name tsig ~key answer with
            | None -> (a, None, out)
            | Some (buf, _) -> (a, Some buf, out)
          end
        | Ok res -> res
        | Error rcode ->
          let err = match Dns_packet.error header v rcode with
            | None -> None
            | Some err -> match t.tsig_sign ~mac name tsig ~key err with
              | None -> None
              | Some (buf, _) -> Some buf
          in
          ((t, zones), err, [])
end
