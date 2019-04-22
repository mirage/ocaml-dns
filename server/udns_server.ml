(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult
open R.Infix
open Udns

let src = Logs.Src.create "dns_server" ~doc:"DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module IPM = Map.Make(Ipaddr.V4)

let guard p err = if p then Ok () else Error err

type proto = [ `Tcp | `Udp ]

module Authentication = struct

  type operation = [
    | `Update
    | `Transfer
  ]

  type a = Udns_trie.t -> proto -> ?key:Domain_name.t -> operation -> zone:Domain_name.t -> bool

  type t = Udns_trie.t * a list

  let operation_to_string = function
    | `Update -> "_update"
    | `Transfer -> "_transfer"

  let is_op op name =
    (* TODO should check that op is at the beginning? *)
    let arr = Domain_name.to_array name in
    Array.exists (String.equal (operation_to_string op)) arr

  let find_zone_ips name =
    (* the name of a key is primaryip.secondaryip._transfer.zone
       e.g. 192.168.42.2.192.168.42.1._transfer.mirage
       alternative: <whatever>.primaryip._transfer.zone *)
    let arr = Domain_name.to_array name in
    let transfer = operation_to_string `Transfer in
    try
      let rec go idx = if Array.get arr idx = transfer then idx else go (succ idx) in
      let zone_idx = go 0 in
      let zone = Domain_name.of_array (Array.sub arr 0 zone_idx) in
      let start = succ zone_idx in
      let ip start =
        try
          let subarr = Array.sub arr start 4 in
          let host = Domain_name.of_array subarr in
          match Ipaddr.V4.of_string (Domain_name.to_string host) with
          | Error _ -> None
          | Ok ip -> Some ip
        with Invalid_argument _ -> None
      in
      match ip (start + 4), ip start with
      | _, None -> None
      | None, Some ip -> Some (zone, ip, None)
      | Some primary, Some secondary -> Some (zone, primary, Some secondary)
    with Invalid_argument _ -> None

  let find_ns s (trie, _) zone =
    let accumulate name _ acc =
      if Domain_name.sub ~domain:zone ~subdomain:name && is_op `Transfer name then
        match find_zone_ips name, s with
        | None, _ -> acc
        | Some (_, prim, _), `P -> (name, prim) :: acc
        | Some (_, _, Some sec), `S -> (name, sec) :: acc
        | Some (_, _, None), `S -> acc
      else
        acc
    in
    Udns_trie.fold Rr_map.Dnskey trie accumulate []

  let secondaries t zone = find_ns `S t zone

  let primaries t zone = find_ns `P t zone

  let all_operations =
    List.map operation_to_string [ `Update ; `Transfer ]

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
    { Soa.nameserver = name ; hostmaster = name ;
      serial = 0l ; refresh = 16384l ; retry = 2048l ;
      expiry = 1048576l ; minimum = 300l }

  let add_keys trie name keys' =
    let zone = zone name in
    let soa =
      match Udns_trie.lookup zone Rr_map.Soa trie with
      | Ok soa -> { soa with Soa.serial = Int32.succ soa.Soa.serial }
      | Error _ -> soa name
    in
    let keys = match Udns_trie.lookup name Rr_map.Dnskey trie with
      | Error _ -> keys'
      | Ok (_, keys) ->
        Log.warn (fun m -> m "replacing unexpected Dnskeys (name %a, have %a, got %a)"
                     Domain_name.pp name
                     Fmt.(list ~sep:(unit ",") Dnskey.pp)
                     (Rr_map.Dnskey_set.elements keys)
                     Fmt.(list ~sep:(unit ";") Dnskey.pp)
                     (Rr_map.Dnskey_set.elements keys) ) ;
        keys'
    in
    let trie' = Udns_trie.insert zone Rr_map.Soa soa trie in
    Udns_trie.insert name Rr_map.Dnskey (0l, keys) trie'

  let of_keys keys =
    List.fold_left (fun trie (name, key) ->
        add_keys trie name (Rr_map.Dnskey_set.singleton key))
      Udns_trie.empty keys

  let find_key t name =
    match Udns_trie.lookup name Rr_map.Dnskey (fst t) with
    | Ok (_, keys) ->
      if Rr_map.Dnskey_set.cardinal keys = 1 then
        Some (Rr_map.Dnskey_set.choose keys)
      else begin
        Log.warn (fun m -> m "found multiple (%d) keys for %a"
                     (Rr_map.Dnskey_set.cardinal keys)
                     Domain_name.pp name) ;
        None
      end
    | Error e ->
      Log.warn (fun m -> m "error %a while looking up key %a" Udns_trie.pp_e e
                   Domain_name.pp name) ;
      None

  let tsig_auth _ _ ?key op ~zone =
    match key with
    | None -> false
    | Some subdomain ->
      let op_string = operation_to_string op in
      let root = Domain_name.of_string_exn ~hostname:false op_string
      and zone = Domain_name.prepend_exn ~hostname:false zone op_string
      in
      Domain_name.sub ~subdomain ~domain:zone
      || Domain_name.sub ~subdomain ~domain:root

  let authorise (data, authorised) proto ?key ~zone operation =
    List.exists (fun a -> a data proto ?key operation ~zone) authorised
end

type t = {
  data : Udns_trie.t ;
  auth : Authentication.t ;
  rng : int -> Cstruct.t ;
  tsig_verify : Tsig_op.verify ;
  tsig_sign : Tsig_op.sign ;
}

let text name data =
  match Udns_trie.entries name data with
  | Error e ->
    Error (`Msg (Fmt.strf "text: couldn't find zone %a: %a" Domain_name.pp name Udns_trie.pp_e e))
  | Ok (soa, map) ->
    let buf = Buffer.create 1024 in
    let origin, default_ttl =
      Buffer.add_string buf
        ("$ORIGIN " ^ Domain_name.to_string ~trailing:true name ^ "\n") ;
      let ttl = soa.minimum in
      Buffer.add_string buf
        ("$TTL " ^ Int32.to_string ttl ^ "\n") ;
      name, ttl
    in
    Buffer.add_string buf (Rr_map.text ~origin ~default_ttl name Soa soa) ;
    Buffer.add_char buf '\n' ;
    let out map =
      Domain_name.Map.iter (fun name rrs ->
          Rr_map.iter (fun b ->
              Buffer.add_string buf (Rr_map.text_b ~origin ~default_ttl name b) ;
              Buffer.add_char buf '\n')
            rrs)
        map
    in
    let is_special name _ =
      (* if only domain-name had proper types *)
      let arr = Domain_name.to_array name in
      match Array.get arr (pred (Array.length arr)) with
      | exception Invalid_argument _ -> false
      | lbl -> try String.get lbl 0 = '_' with Not_found -> false
    in
    let service, entries = Domain_name.Map.partition is_special map in
    out entries ;
    Buffer.add_char buf '\n' ;
    out service ;
    Ok (Buffer.contents buf)

let create ?(tsig_verify = Tsig_op.no_verify) ?(tsig_sign = Tsig_op.no_sign) data auth rng =
  { data ; auth ; rng ; tsig_verify ; tsig_sign }

let find_glue trie names =
  Domain_name.Set.fold (fun name map ->
      match
        match Udns_trie.lookup_glue name trie with
        | Some v4, Some v6 -> Some Rr_map.(add A v4 (singleton Aaaa v6))
        | Some v4, None -> Some (Rr_map.singleton A v4)
        | None, Some v6 -> Some (Rr_map.singleton Aaaa v6)
        | None, None -> None
      with
      | None -> map
      | Some rrs -> Domain_name.Map.add name rrs map)
    names Domain_name.Map.empty

let authoritative =
  (* TODO should copy recursion desired *)
  Packet.Flags.singleton `Authoritative

let err_flags = function
  | Rcode.NotAuth -> Packet.Flags.empty
  | _ -> authoritative

let lookup trie (name, typ) =
  (* TODO: should randomize answers + ad? *)
  let r = match typ with
    | `Any -> Udns_trie.lookup_any name trie
    | `K (Rr_map.K k) -> match Udns_trie.lookup_with_cname name k trie with
      | Ok (B (k, v), au) -> Ok (Rr_map.singleton k v, au)
      | Error e -> Error e
  in
  match r with
  | Ok (an, (au, ttl, ns)) ->
    let answer = Domain_name.Map.singleton name an in
    let authority =
      Name_rr_map.remove_sub (Name_rr_map.singleton au Ns (ttl, ns)) answer
    in
    let additional =
      let names =
        Rr_map.(fold (fun (B (k, v)) s -> Domain_name.Set.union (names k v) s) an ns)
      in
      Name_rr_map.remove_sub
        (Name_rr_map.remove_sub (find_glue trie names) answer)
        authority
    in
    Ok (authoritative, (answer, authority), Some additional)
  | Error (`Delegation (name, (ttl, ns))) ->
    let authority = Name_rr_map.singleton name Ns (ttl, ns) in
    Ok (Packet.Flags.empty, (Name_rr_map.empty, authority), Some (find_glue trie ns))
  | Error (`EmptyNonTerminal (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Ok (authoritative, (Name_rr_map.empty, authority), None)
  | Error (`NotFound (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Error (Rcode.NXDomain, Some (Name_rr_map.empty, authority))
  | Error `NotAuthoritative -> Error (Rcode.NotAuth, None)

let axfr trie proto (zone, _) =
  if proto = `Udp then begin
    Log.err (fun m -> m "refusing AXFR query via UDP") ;
    Error Rcode.Refused
  end else
    match Udns_trie.entries zone trie with
    | Ok (soa, entries) -> Ok (soa, entries)
    | Error e ->
      Log.err (fun m -> m "AXFR attempted on %a, where we're not authoritative %a"
                  Domain_name.pp zone Udns_trie.pp_e e) ;
      Error Rcode.NXDomain

let axfr t proto key ((zone, _) as question) =
  if Authentication.authorise t.auth proto ?key ~zone `Transfer then begin
    Log.info (fun m -> m "transfer key %a authorised for AXFR %a"
                 Fmt.(option ~none:(unit "none") Domain_name.pp) key
                 Packet.Question.pp question) ;
    axfr t.data proto question
  end else
    Error Rcode.NotAuth

let safe_decode buf =
  match Packet.decode buf with
  | Error e ->
    Logs.err (fun m -> m "error %a while decoding, giving up" Packet.pp_err e);
    Error Rcode.FormErr
(*  | Error `Partial ->
    Log.err (fun m -> m "partial frame (length %d)@.%a" (Cstruct.len buf) Cstruct.hexdump_pp buf) ;
    Packet.create <<no header>> <<no question>> Udns_enum.FormErr
  | Error (`Bad_edns_version i) ->
    Log.err (fun m -> m "bad edns version error %u while decoding@.%a"
                 i Cstruct.hexdump_pp buf) ;
    Error Udns_enum.BadVersOrSig
  | Error (`Not_implemented (off, msg)) ->
    Log.err (fun m -> m "not implemented at %d: %s while decoding@.%a"
                off msg Cstruct.hexdump_pp buf) ;
    Error Udns_enum.NotImp
  | Error e ->
    Log.err (fun m -> m "error %a while decoding@.%a"
                 Packet.pp_err e Cstruct.hexdump_pp buf) ;
    Error Udns_enum.FormErr *)
  | Ok v -> Ok v

let handle_question t (name, typ) =
  (* TODO white/blacklist of allowed qtypes? what about ANY and UDP? *)
  match typ with
  | `Axfr -> assert false (* this won't happen, decoder constructs `Axfr -- but we need some evidence... *)
  | (`K _ | `Any) as k -> lookup t.data (name, k)
(*  | r ->
    Log.err (fun m -> m "refusing query type %a" Rr.pp r) ;
    Error (Rcode.Refused, None) *)

(* this implements RFC 2136 Section 2.4 + 3.2 *)
let handle_rr_prereq trie name = function
  | Packet.Update.Name_inuse ->
    begin match Udns_trie.lookup name A trie with
      | Ok _ | Error (`EmptyNonTerminal _) -> Ok ()
      | _ -> Error Rcode.NXDomain
    end
  | Packet.Update.Exists (K typ) ->
    begin match Udns_trie.lookup name typ trie with
      | Ok _ -> Ok ()
      | _ -> Error Rcode.NXRRSet
    end
  | Packet.Update.Not_name_inuse ->
    begin match Udns_trie.lookup name A trie with
      | Error (`NotFound _) -> Ok ()
      | _ -> Error Rcode.YXDomain
    end
  | Packet.Update.Not_exists (K typ) ->
    begin match Udns_trie.lookup name typ trie with
      | Error (`EmptyNonTerminal _ | `NotFound _) -> Ok ()
      | _ -> Error Rcode.YXRRSet
    end
  | Packet.Update.Exists_data Rr_map.(B (k, v)) ->
    match Udns_trie.lookup name k trie with
    | Ok v' when Rr_map.equal_rr k v v' -> Ok ()
    | _ -> Error Rcode.NXRRSet

(* RFC 2136 Section 2.5 + 3.4.2 *)
(* we partially ignore 3.4.2.3 and 3.4.2.4 by not special-handling of NS, SOA *)
let handle_rr_update trie name = function
  | Packet.Update.Remove (K typ) ->
    begin match typ with
      | Soa ->
        (* this does not follow 2136, but we want to be able to remove a zone *)
        Udns_trie.remove_zone name trie
      | _ -> Udns_trie.remove name typ trie
    end
  | Packet.Update.Remove_all -> Udns_trie.remove_all name trie
  | Packet.Update.Remove_single Rr_map.(B (k, rem) as b) ->
    begin match Udns_trie.lookup name k trie with
      | Error e ->
        Log.warn (fun m -> m "error %a while looking up %a %a for removal"
                     Udns_trie.pp_e e Domain_name.pp name Rr_map.pp_b b) ;
        trie
      | Ok v ->
        match Rr_map.remove_rr k v rem with
        | None ->
          Log.info (fun m -> m "removed single %a entry %a (stored %a) none leftover"
                       Domain_name.pp name Rr_map.pp_b b Rr_map.pp_b Rr_map.(B (k, v)));
          Udns_trie.remove name k trie
        | Some v' ->
          Log.info (fun m -> m "removed single %a entry %a (stored %a), now %a"
                       Domain_name.pp name Rr_map.pp_b b Rr_map.pp_b Rr_map.(B (k, v))
                       Rr_map.pp_b Rr_map.(B (k, v')) );
          Udns_trie.insert name k v' trie
    end
  | Packet.Update.Add Rr_map.(B (k, add) as b) ->
    (* turns out, RFC 2136, 3.4.2.2 says "SOA with smaller or equal serial is silently ignored" *)
    begin match Udns_trie.lookup name k trie with
      | Ok old ->
        let newval = Rr_map.union_rr k old add in
        Log.info (fun m -> m "added %a: %a (stored %a), now %a"
                     Domain_name.pp name Rr_map.pp_b b Rr_map.pp_b (Rr_map.B (k, old))
                     Rr_map.pp_b (Rr_map.B (k, newval))) ;
        Udns_trie.insert name k newval trie
      | Error _ ->
        (* here we allow arbitrary, even out-of-zone updates.  this is
           crucial for the resolver operation as we have it right now:
           add . 300 NS resolver ; add resolver . 300 A 141.1.1.1 would
           otherwise fail (no SOA for . / delegation for resolver) *)
        Log.info (fun m -> m "inserting %a (stored nothing), now %a"
                     Domain_name.pp name Rr_map.pp_b b) ;
        Udns_trie.insert name k add trie
    end

module Notification = struct
  (* TODO dnskey authentication of outgoing packets (preserve in connections, name of key should be enough) *)
  (* TODO protocol selection - dnskey name again? what about those in zonefile? *)
  (* needed for passive secondaries (behind NAT etc.) such as let's encrypt,
     which initiated a signed! TCP session *)

  type connections = (Ipaddr.V4.t * int) list Domain_name.Map.t

  let secondaries trie zone =
    match Udns_trie.lookup_with_cname zone Rr_map.Soa trie with
    | Ok (B (Soa, soa), (_, _, ns)) ->
      let secondaries = Domain_name.Set.remove soa.Soa.nameserver ns in
      (* TODO AAAA records / use lookup_glue? *)
      Domain_name.Set.fold (fun ns acc ->
          match Udns_trie.lookup ns Rr_map.A trie with
          | Ok (_, ips) -> ips
          | _ ->
            Log.err (fun m -> m "lookup for A %a returned nothing as well"
                        Domain_name.pp ns) ;
            acc)
        secondaries Rr_map.Ipv4_set.empty
    | _ -> Rr_map.Ipv4_set.empty

  let key_ips auth zone =
    let name_ip_ports = Authentication.secondaries auth zone in
    List.fold_left (fun acc (_, ip) -> ip :: acc)
      [] name_ip_ports

  let insert data keys conn name ip port =
    let ips =
      Rr_map.Ipv4_set.(union (secondaries data name) (of_list (key_ips keys name)))
    in
    if Rr_map.Ipv4_set.mem ip ips then begin
      Log.warn (fun m -> m "IP %a already in notification list" Ipaddr.V4.pp ip);
      conn
    end else begin
      Log.info (fun m -> m "inserting notifications for %a %a:%d"
                   Domain_name.pp name Ipaddr.V4.pp ip port);
      let cur = match Domain_name.Map.find name conn with
        | None -> []
        | Some xs -> xs
      in
      Domain_name.Map.add name ((ip, port)::cur) conn
    end

  let remove conn ip port =
    let is_not_it name (ip', port') =
      if Ipaddr.V4.compare ip ip' = 0 && port = port' then begin
        Log.info (fun m -> m "removing notification for %a %a:%d"
                     Domain_name.pp name Ipaddr.V4.pp ip port);
        false
      end else true
    in
    Domain_name.Map.fold (fun name conns new_map ->
      match List.filter (is_not_it name) conns with
      | [] -> new_map
      | xs -> Domain_name.Map.add name xs new_map)
      conn Domain_name.Map.empty

  (* that's udp only *)
  module IPM = struct
    include Map.Make(struct
        type t = Ipaddr.V4.t * int
        let compare (ip, p) (ip', p') = match Ipaddr.V4.compare ip ip' with
          | 0 -> compare p p'
          | x -> x
      end)
    let find k t = try Some (find k t) with Not_found -> None
  end

  (* outstanding notifications, with timestamp and retry count
     (at most one per zone per ip*port) *)
  type outstanding = (int64 * int * Packet.t) Domain_name.Map.t IPM.t

  (* operations:
     - timer occured, retransmit outstanding or drop
     - send out notification for a given zone
     - a (signed?) notify response came in, drop it from outstanding
  *)
  let retransmit = Array.map Duration.of_sec [| 5 ; 12 ; 25 ; 40 ; 60 |]

  let retransmit ns now =
    let max = pred (Array.length retransmit) in
    IPM.fold (fun (ip, port) map (new_ns, out) ->
        let new_map, out =
          Domain_name.Map.fold
            (fun name (ts, count, packet) (new_map, out) ->
               if Int64.add ts retransmit.(count) < now then
                 (if count = max then begin
                     Log.warn (fun m -> m "retransmitting notify to %a:%d the last time %a"
                                 Ipaddr.V4.pp ip port Packet.pp packet) ;
                    new_map
                   end else
                    (Domain_name.Map.add name (ts, succ count, packet) new_map)),
                 (ip, port, fst (Packet.encode `Udp packet)) :: out
               else
                 (Domain_name.Map.add name (ts, count, packet) new_map, out))
            map (Domain_name.Map.empty, out)
        in
        (if Domain_name.Map.is_empty new_map then new_ns else IPM.add (ip, port) new_map new_ns),
        out)
      ns (IPM.empty, [])

  let notify conn ns server now zone soa =
    (* we use
       1. the NS records of the zone (port 53 as default)
       2. the IP addresses of secondary servers which have transfer keys (port encoded in name)
       3. the TCP connections which requested (signed) SOA in l *)
    let ips = Rr_map.Ipv4_set.(elements (union (secondaries server.data zone)
                                           (of_list (key_ips server.auth zone))))
    in
    let tcp_ip_ports = match Domain_name.Map.find zone conn with
      | None -> []
      | Some conns -> conns
    in
    Log.debug (fun m -> m "notifying %a %a (and tcp %a)" Domain_name.pp zone
                  Fmt.(list ~sep:(unit ", ") Ipaddr.V4.pp) ips
                  Fmt.(list ~sep:(unit ", ") (pair ~sep:(unit ":") Ipaddr.V4.pp int))
                  tcp_ip_ports) ;
    let packet =
      let question = Packet.Question.create zone Soa
      and header =
        let id = Randomconv.int ~bound:(1 lsl 16 - 1) server.rng in
        (id, authoritative)
      in
      Packet.create header question (`Notify (Some soa))
    in
    let add_to_ns ns ip port =
      let data = (now, 0, packet) in
      let map = match IPM.find (ip, port) ns with
        | None -> Domain_name.Map.empty
        | Some map -> map
      in
      let map' = Domain_name.Map.add zone data map in
      IPM.add (ip, port) map' ns
    in
    let ns', outs =
      let port = 53 in
      List.fold_left (fun (ns, outs) ip ->
          let ns = add_to_ns ns ip port in
          ns, (ip, port, fst (Packet.encode `Udp packet)) :: outs)
        (ns, []) ips
    in
    let tcp_outs =
      List.fold_left (fun acc (ip, port) ->
          (ip, port, fst (Packet.encode `Udp packet)) :: acc) [] tcp_ip_ports
    in
    ns', outs @ tcp_outs

  let received_reply ns ip port reply =
    match IPM.find (ip, port) ns with
    | None -> ns
    | Some map ->
      let map' = match Domain_name.Map.find (fst reply.Packet.question) map with
        | Some (_, _, request) ->
          begin match Packet.reply_matches_request ~request reply with
            | Ok r ->
              let map' = Domain_name.Map.remove (fst reply.question) map in
              (match r with `Notify_ack -> () | r -> Log.warn (fun m -> m "expected notify_ack, got %a" Packet.pp_reply r));
              map'
            | Error e ->
              Log.warn (fun m -> m "notify reply didn't match our request %a (request %a, reply %a)"
                           Packet.pp_mismatch e Packet.pp request Packet.pp reply);
              map
          end
        | _ -> map
      in
      if Domain_name.Map.is_empty map' then
        IPM.remove (ip, port) ns
      else
        IPM.add (ip, port) map' ns
end

let in_zone zone name = Domain_name.sub ~subdomain:name ~domain:zone

let update_data trie zone (prereq, update) =
  let in_zone = in_zone zone in
  Domain_name.Map.fold (fun name prereqs acc ->
      acc >>= fun () ->
      guard (in_zone name) Rcode.NotZone >>= fun () ->
      List.fold_left (fun acc prereq ->
          acc >>= fun () ->
          handle_rr_prereq trie name prereq)
        (Ok ()) prereqs)
    prereq (Ok ()) >>= fun () ->
  Domain_name.Map.fold (fun name updates acc ->
      acc >>= fun trie ->
      guard (in_zone name) Rcode.NotZone >>| fun () ->
      List.fold_left (fun trie update ->
          handle_rr_update trie name update)
        trie updates)
    update (Ok trie) >>= fun trie' ->
  (match Udns_trie.check trie' with
   | Ok () -> Ok ()
   | Error e ->
     Log.err (fun m -> m "check after update returned %a" Udns_trie.pp_zone_check e) ;
     Error Rcode.YXRRSet) >>= fun () ->
  if Udns_trie.equal trie trie' then
    (* should this error out? - RFC 2136 3.4.2.7 says NoError at the end *)
    Ok (trie, None)
  else match Udns_trie.lookup zone Soa trie, Udns_trie.lookup zone Soa trie' with
    | Ok oldsoa, Ok soa when Soa.newer ~old:oldsoa soa -> Ok (trie', Some (zone, soa))
    | _, Ok soa ->
      let soa = { soa with Soa.serial = Int32.succ soa.Soa.serial } in
      let trie'' = Udns_trie.insert zone Soa soa trie' in
      Ok (trie'', Some (zone, soa))
    | _, _ -> Ok (trie', None)

let handle_update t proto key (zone, _) u =
  if Authentication.authorise t.auth proto ?key ~zone `Update then begin
    Log.info (fun m -> m "update key %a authorised for update %a"
                 Fmt.(option ~none:(unit "none") Domain_name.pp) key
                 Packet.Update.pp u) ;
    update_data t.data zone u >>| fun (data', stuff) ->
    { t with data = data' }, stuff
  end else
    Error Rcode.NotAuth

let handle_tsig ?mac t now p buf =
  match p.Packet.tsig with
  | None -> Ok None
  | Some (name, tsig, off) ->
    let algo = tsig.Tsig.algorithm in
    let key =
      match Authentication.find_key t.auth name with
      | None -> None
      | Some key ->
        match Tsig.dnskey_to_tsig_algo key with
        | Ok a when a = algo -> Some key
        | _ -> None
    in
    t.tsig_verify ?mac now p name ?key tsig (Cstruct.sub buf 0 off) >>= fun (tsig, mac, key) ->
    Ok (Some (name, tsig, mac, key))

module Primary = struct

  (* TODO: there's likely a better data structure for outstanding notifications *)
  (* the list of zone, ip, port, keyname is whom to notify *)
  type s =
    t * Notification.connections * Notification.outstanding

  let server (t, _, _) = t

  let data (t, _, _) = t.data

  let with_data (t, l, n) now data =
    (* we're the primary and need to notify our friends! *)
    let n', out =
      Udns_trie.fold Soa data
        (fun name soa (n, outs) ->
           match Udns_trie.lookup name Soa t.data with
           | Error _ ->
             let n', outs' = Notification.notify l n t now name soa in
             (n', outs @ outs')
           | Ok old when Soa.newer ~old soa ->
             let n', outs' = Notification.notify l n t now name soa in
             (n', outs @ outs')
           | Ok _ -> (n, outs))
        (n, [])
    in
    ({ t with data }, l, n'), out

  let create ?(keys = []) ?(a = []) ?tsig_verify ?tsig_sign ~rng data =
    let keys = Authentication.of_keys keys in
    let t = create ?tsig_verify ?tsig_sign data (keys, a) rng in
    let notifications =
      let f name soa ns =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name) ;
        (* we drop notifications, the first call to timer will solve this :) *)
        fst (Notification.notify Domain_name.Map.empty ns t 0L name soa)
      in
      Udns_trie.fold Rr_map.Soa data f Notification.IPM.empty
    in
    t, Domain_name.Map.empty, notifications

  let tcp_soa_query proto (name, typ) =
    match proto, typ with
    | `Tcp, `K (Rr_map.K Soa) -> Ok name
    | _ -> Error ()

  let handle_packet (t, l, ns) ts proto ip port p key =
    match p.Packet.data with
    | `Query ->
      (* if there was a (transfer-key) signed SOA, and tcp, we add to notification list! *)
      let l' = match tcp_soa_query proto p.question, key with
        | Ok zone, Some key when Authentication.is_op `Transfer key ->
          Notification.insert t.data t.auth l zone ip port
        | _ -> l
      in
      let answer =
        let flags, data, additional = match handle_question t p.question with
          | Ok (flags, data, additional) -> flags, `Answer data, additional
          | Error (rcode, data) -> err_flags rcode, `Rcode_error (rcode, Opcode.Query, data), None
        in
        Packet.create ?additional (fst p.header, flags) p.question data
      in
      (t, l', ns), Some answer, [], None
    | `Update u ->
      let t', (flags, answer), stuff =
        match handle_update t proto key p.question u with
        | Ok (t', stuff) -> t', (authoritative, `Notify_ack), stuff
        | Error rcode -> t, (err_flags rcode, `Rcode_error (rcode, Opcode.Update, None)), None
      in
      let ns, out = match stuff with
        | None -> ns, []
        | Some (zone, soa) -> Notification.notify l ns t' ts zone soa
      in
      let answer' = Packet.create (fst p.header, flags) p.question answer in
      (t', l, ns), Some answer', out, None
    | `Axfr_request ->
      let flags, answer = match axfr t proto key p.question with
        | Ok data -> authoritative, `Axfr_reply data
        | Error rcode -> err_flags rcode, `Rcode_error (rcode, Opcode.Query, None)
      in
      let answer = Packet.create (fst p.header, flags) p.question answer in
      (t, l, ns), Some answer, [], None
    | `Axfr_reply data ->
      Logs.warn (fun m -> m "unsolicited AXFR reply %a, ignoring" Packet.Axfr.pp data);
      (t, l, ns), None, [], None
    | `Notify_ack ->
      let ns' = Notification.received_reply ns ip port p in
      (t, l, ns'), None, [], None
    | `Notify soa ->
      Log.warn (fun m -> m "unsolicited notify request %a (replying anyways)"
                   Fmt.(option ~none:(unit "no") Soa.pp) soa) ;
      let reply = Packet.create (fst p.header, authoritative) p.question `Notify_ack in
      (t, l, ns), Some reply, [], Some (`Notify soa)
    | p ->
      Log.err (fun m -> m "ignoring unsolicited %a" Packet.pp_data p) ;
      (t, l, ns), None, [], None

  let handle_buf t now ts proto ip port buf =
    match
      safe_decode buf >>| fun res ->
      Log.debug (fun m -> m "from %a received:@[%a@]" Ipaddr.V4.pp ip Packet.pp res) ;
      res
    with
    | Error rcode ->
      let answer = Packet.raw_error buf rcode in
      Log.warn (fun m -> m "error %a while %a sent %a, answering with %a"
                   Rcode.pp rcode Ipaddr.V4.pp ip Cstruct.hexdump_pp buf
                   Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) answer) ;
      t, answer, [], None
    | Ok p ->
      let handle_inner keyname =
        let t, answer, out, notify =
          handle_packet t ts proto ip port p keyname
        in
        let answer = match answer with
          | Some answer ->
            let max_size, edns = Edns.reply p.edns in
            let answer = Packet.with_edns answer edns in
            (* be aware, this may be truncated... here's where AXFR is assembled! *)
            let r = Packet.encode ?max_size proto answer in
            Some (answer, r)
          | None -> None
        in
        t, answer, out, notify
      in
      let server, _, _ = t in
      match handle_tsig server now p buf with
      | Error (e, data) ->
        Log.err (fun m -> m "error %a while handling tsig" Tsig_op.pp_e e) ;
        t, data, [], None
      | Ok None ->
        let t, answer, out, notify = handle_inner None in
        let answer' = match answer with
          | None -> None
          | Some (_, (cs, _)) -> Some cs
        in
        (t, answer', out, notify)
      | Ok (Some (name, tsig, mac, key)) ->
        let n = function Some (`Notify n) -> Some (`Signed_notify n) | None -> None in
        let t', answer, out, notify = handle_inner (Some name) in
        let answer' = match answer with
          | None -> None
          | Some (answer, (buf, max_size)) ->
            match server.tsig_sign ~max_size ~mac name tsig ~key answer buf with
            | None ->
              Log.warn (fun m -> m "couldn't use %a to tsig sign" Domain_name.pp name);
              (* TODO - better send back unsigned answer? or an error? *)
              None
            | Some (buf, _) -> Some buf
        in
        (t', answer', out, n notify)

  let closed (t, l, ns) ip port =
    let l' = Notification.remove l ip port in
    (t, l', ns)

  let timer (t, l, ns) now =
    let ns', out = Notification.retransmit ns now in
    (t, l, ns'), out
end

module Secondary = struct

  type state =
    | Transferred of int64
    | Requested_soa of int64 * int * int * Cstruct.t
    | Requested_axfr of int64 * int * Cstruct.t

  let id = function
    | Transferred _ -> None
    | Requested_soa (_, id, _, _) -> Some id
    | Requested_axfr (_, id, _) -> Some id

  (* TODO undefined what happens if there are multiple transfer keys for zone x *)
  type s = t * (state * Ipaddr.V4.t * int * Domain_name.t) Domain_name.Map.t

  let data (t, _) = t.data

  let with_data (t, zones) data = ({ t with data }, zones)

  let create ?(a = []) ?primary ~tsig_verify ~tsig_sign ~rng keylist =
    (* two kinds of keys: aaa._key-management and ip1.ip2._transfer.zone *)
    let keys = Authentication.of_keys keylist in
    let zones =
      let f name _ zones =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name) ;
        match Authentication.primaries (keys, []) name with
        | [] -> begin match primary with
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
        | primaries ->
          List.fold_left (fun zones (keyname, ip) ->
              Log.app (fun m -> m "adding transfer key %a for zone %a"
                          Domain_name.pp keyname Domain_name.pp name) ;
              let v = Requested_soa (0L, 0, 0, Cstruct.empty), ip, 53, keyname in
              Domain_name.Map.add name v zones)
            zones primaries
      in
      Udns_trie.fold Rr_map.Soa keys f Domain_name.Map.empty
    in
    (create ~tsig_verify ~tsig_sign Udns_trie.empty (keys, a) rng, zones)

  let maybe_sign ?max_size t name signed original_id packet buf =
    match Authentication.find_key t.auth name with
    | Some key ->
      begin match Tsig.dnskey_to_tsig_algo key with
        | Ok algorithm ->
          begin match Tsig.tsig ~algorithm ~original_id ~signed () with
            | None -> Log.err (fun m -> m "creation of tsig failed") ; None
            | Some tsig -> match t.tsig_sign ?mac:None ?max_size name tsig ~key packet buf with
              | None -> Log.err (fun m -> m "signing failed") ; None
              | Some res -> Some res
          end
        | Error (`Msg msg) -> Log.err (fun m -> m "couldn't convert algorithm: %s" msg) ; None
      end
    | _ -> Log.err (fun m -> m "key %a not found (or multiple)" Domain_name.pp name) ; None

  let header rng () =
    let id = Randomconv.int ~bound:(1 lsl 16 - 1) rng in
    id, Packet.Flags.empty

  let axfr t proto now ts q_name name =
    let header = header t.rng ()
    and question = (q_name, `Axfr)
    in
    let p = Packet.create header question `Axfr_request in
    let buf, max_size = Packet.encode proto p in
    match maybe_sign ~max_size t name now (fst header) p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_axfr (ts, fst header, mac), buf)

  let query_soa ?(retry = 0) t proto now ts q_name name =
    let header = header t.rng ()
    and question = Packet.Question.create q_name Soa
    in
    let p = Packet.create header question `Query in
    let buf, max_size = Packet.encode proto p in
    match maybe_sign ~max_size t name now (fst header) p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_soa (ts, fst header, retry, mac), buf)

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

          match Udns_trie.lookup zone Rr_map.Soa t.data, st with
          | Ok soa, Transferred ts ->
            (* TODO: integer overflows (Int64.add) *)
            let r = Duration.of_sec (Int32.to_int soa.Soa.refresh) in
            maybe_out
              (if Int64.add ts r < now then
                 query_soa t `Tcp p_now now zone name
               else
                 None)
          | Ok soa, Requested_soa (ts, _, retry, _) ->
            let expiry = Duration.of_sec (Int32.to_int soa.Soa.expiry) in
            if Int64.add ts expiry < now then begin
              Log.warn (fun m -> m "expiry expired, dropping zone %a"
                           Domain_name.pp zone) ;
              let data = Udns_trie.remove_zone zone t.data in
              (({ t with data }, zones), acc)
            end else
              let retry = succ retry in
              let e = Duration.of_sec (retry * Int32.to_int soa.Soa.retry) in
              maybe_out
                (if Int64.add ts e < now then
                   query_soa ~retry t `Tcp p_now ts zone name
                 else
                   None)
          | Error _, Requested_soa (ts, _, retry, _) ->
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

  let handle_notify t zones now ts ip (zone, typ) _notify =
    match typ with
    | `K (Rr_map.K Soa) ->
      begin match Domain_name.Map.find zone zones with
        | None -> (* we don't know anything about the notified zone *)
          Log.warn (fun m -> m "ignoring notify for %a, no such zone"
                       Domain_name.pp zone) ;
          Error Rcode.Refused
        | Some (_, ip', port', name) when Ipaddr.V4.compare ip ip' = 0 ->
          Log.debug (fun m -> m "received notify for %a, replying and requesting SOA"
                        Domain_name.pp zone) ;
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
                       Domain_name.pp zone Ipaddr.V4.pp ip Ipaddr.V4.pp ip') ;
          Error Rcode.Refused
      end
    | _ ->
      Log.warn (fun m -> m "ignoring notify %a" Packet.Question.pp (zone, typ));
      Error Rcode.FormErr

  let authorise should is =
    let r = match is with
      | None -> false
      | Some x -> Domain_name.equal x should
    in
    if not r then
      Log.warn (fun m -> m "%a is not authorised (should %a)"
                   Fmt.(option ~none:(unit "no key") Domain_name.pp) is
                   Domain_name.pp should) ;
    r

  let authorise_zone zones keyname header zone =
    match Domain_name.Map.find zone zones with
    | None ->
      Log.warn (fun m -> m "ignoring %a, unknown zone" Domain_name.pp zone) ;
      Error Rcode.Refused
    | Some (st, ip, port, name) ->
      (* TODO use NotAuth instead of Refused here? *)
      guard (match id st with None -> true | Some id' -> fst header = id')
        Rcode.Refused >>= fun () ->
      guard (authorise name keyname) Rcode.Refused >>| fun () ->
      Log.debug (fun m -> m "authorized access to zone %a (with key %a)"
                    Domain_name.pp zone Domain_name.pp name) ;
      (st, ip, port, name)

  let handle_axfr t zones ts keyname header (zone, _) ((fresh_soa, fresh_zone) as axfr) =
    authorise_zone zones keyname header zone >>= fun (st, ip, port, name) ->
    match st with
    | Requested_axfr (_, _, _) ->
      (* TODO partial AXFR, but decoder already rejects them *)
      Log.info (fun m -> m "received authorised AXFR for %a: %a"
                   Domain_name.pp zone Packet.Axfr.pp axfr) ;
      (* SOA should be higher than ours! *)
      (match Udns_trie.lookup zone Soa t.data with
       | Error _ ->
         Log.info (fun m -> m "no soa for %a, maybe first axfr" Domain_name.pp zone) ;
         Ok ()
       | Ok soa ->
         if Soa.newer ~old:soa fresh_soa then
           Ok ()
         else begin
           Log.warn (fun m -> m "AXFR for %a (%a) is not newer than ours (%a)"
                        Domain_name.pp zone Soa.pp fresh_soa Soa.pp soa) ;
           (* TODO what is the right error here? *)
           Error Rcode.ServFail
         end) >>= fun () ->
      (* filter map to ensure that all entries are in the zone! *)
      let fresh_zone =
        Domain_name.Map.filter
          (fun name _ -> Domain_name.sub ~subdomain:name ~domain:zone)
          fresh_zone
      in
      let trie' =
        let trie = Udns_trie.remove_zone zone t.data in
        (* insert SOA explicitly - it's not part of entries (should it be?) *)
        let trie = Udns_trie.insert zone Rr_map.Soa fresh_soa trie in
        Udns_trie.insert_map fresh_zone trie
      in
      (* check new trie *)
      (match Udns_trie.check trie' with
        | Ok () ->
          Log.info (fun m -> m "zone %a transferred, and life %a"
                       Domain_name.pp zone Soa.pp fresh_soa)
        | Error err ->
          Log.warn (fun m -> m "check on transferred zone %a failed: %a"
                       Domain_name.pp zone Udns_trie.pp_zone_check err)) ;
      let zones = Domain_name.Map.add zone (Transferred ts, ip, port, name) zones in
      Ok ({ t with data = trie' }, zones, [])
    | _ ->
      Log.warn (fun m -> m "ignoring AXFR %a unmatched state" Domain_name.pp zone) ;
      Error Rcode.Refused

  let handle_answer t zones now ts keyname header (zone, typ) (answer, _) =
    authorise_zone zones keyname header zone >>= fun (st, ip, port, name) ->
    match st with
    | Requested_soa (_, _, retry, _) ->
      Log.debug (fun m -> m "received SOA after %d retries" retry) ;
      (* request AXFR now in case of serial is higher! *)
      begin match
          Udns_trie.lookup zone Rr_map.Soa t.data,
          Name_rr_map.find zone Soa answer
        with
        | _, None ->
          Log.err (fun m -> m "didn't receive SOA for %a from %a (answer %a)"
                      Domain_name.pp zone Ipaddr.V4.pp ip Name_rr_map.pp answer) ;
          Error Rcode.FormErr
        | Ok cached_soa, Some fresh ->
          (* TODO: > with wraparound in mind *)
          if Soa.newer ~old:cached_soa fresh then
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
                         Soa.pp fresh Domain_name.pp zone Soa.pp cached_soa) ;
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
      end
    | _ ->
      Log.warn (fun m -> m "ignoring question %a unmatched state"
                   Packet.Question.pp (zone, typ));
      Error Rcode.Refused

  let handle_packet (t, zones) now ts ip p keyname =
    match p.Packet.data with
    | `Query ->
      let flags, data, additional = match handle_question t p.question with
        | Ok (flags, data, additional) -> flags, `Answer data, additional
        | Error (rcode, data) -> err_flags rcode, `Rcode_error (rcode, Opcode.Query, data), None
      in
      let answer = Packet.create ?additional (fst p.header, flags) p.question data in
      (t, zones), Some answer, []
    | `Answer a ->
      let t, out =
        match handle_answer t zones now ts keyname p.header p.question a with
        | Ok (t, zones, out) -> (t, zones), out
        | Error rcode ->
          Log.warn (fun m -> m "error %a while processing answer %a" Rcode.pp rcode Packet.pp p);
          (t, zones), []
      in
      t, None, out
    | `Update _ ->
      (* we don't deal with updates *)
      let answer = Packet.create p.header p.question (`Rcode_error (Rcode.Refused, Opcode.Update, None)) in
      (t, zones), Some answer, []
    | `Axfr_request ->
      (* we don't reply to axfr requests *)
      let answer = Packet.create p.header p.question (`Rcode_error (Rcode.Refused, Opcode.Query, None)) in
      (t, zones), Some answer, []
    | `Axfr_reply data ->
      let r, out = match handle_axfr t zones ts keyname p.header p.question data with
        | Ok (t, zones, out) -> (t, zones), out
        | Error rcode ->
          Log.warn (fun m -> m "error %a while processing axfr %a" Rcode.pp rcode Packet.pp p);
          (t, zones), []
      in
      r, None, out
    | `Update_ack ->
      Log.warn (fun m -> m "ignoring update reply (we'll never send updates out)");
      (t, zones), None, []
    | `Notify n ->
      let zones, flags, answer, out = match handle_notify t zones now ts ip p.question n with
        | Ok (zones, out) -> zones, authoritative, `Notify_ack, out
        | Error rcode -> zones, err_flags rcode, `Rcode_error (rcode, Opcode.Notify, None), []
      in
      let answer = Packet.create (fst p.header, flags) p.question answer in
      (t, zones), Some answer, out
    | `Notify_ack ->
      Log.err (fun m -> m "ignoring notify response (we don't send notifications)") ;
      (t, zones), None, []
    | `Rcode_error (rc, op, data) ->
      Log.err (fun m -> m "ignoring rcode error %a for op %a data %a" Rcode.pp rc Opcode.pp op
                  Fmt.(option ~none:(unit "no") Packet.Query.pp) data);
      (t, zones), None, []

  let find_mac zones (name, _) =
    match Domain_name.Map.find name zones with
    | None -> None
    | Some (Requested_axfr (_, _, mac), _, _, _) -> Some mac
    | Some (Requested_soa (_, _, _, mac), _, _, _) -> Some mac
    | _ -> None

  let handle_buf t now ts proto ip buf =
    match
      safe_decode buf >>| fun res ->
      Log.debug (fun m -> m "received a packet from %a: %a" Ipaddr.V4.pp ip Packet.pp res) ;
      res
    with
    | Error rcode -> t, Packet.raw_error buf rcode, []
    | Ok p ->
      let handle_inner keyname =
        let t, answer, out = handle_packet t now ts ip p keyname in
        let answer = match answer with
          | Some answer ->
            let max_size, edns = Edns.reply p.edns in
            let answer = Packet.with_edns answer edns in
            let r = Packet.encode ?max_size proto answer in
            Some (answer, r)
          | None -> None
        in
        t, answer, out
      in
      let server, zones = t in
      let mac = find_mac zones p.question in
      match handle_tsig ?mac server now p buf with
      | Error (e, data) ->
        Logs.err (fun m -> m "error %a while handling tsig" Tsig_op.pp_e e) ;
        t, data, []
      | Ok None ->
        let t, answer, out = handle_inner None in
        let answer' = match answer with
          | None -> None
          | Some (_, (buf, _)) -> Some buf
        in
        t, answer', out
      | Ok (Some (name, tsig, mac, key)) ->
        let t, answer, out = handle_inner (Some name) in
        let answer' = match answer with
        | Some (p, (buf, max_size)) ->
          begin match server.tsig_sign ~max_size ~mac name tsig ~key p buf with
            | None ->
              (* TODO: output buf? *)
              Log.warn (fun m -> m "couldn't use %a to tsig sign"
                           Domain_name.pp name) ;
              None
            | Some (buf, _) -> Some buf
          end
        | None -> None
        in
        t, answer', out

  let closed (t, zones) now ts ip' port' =
    (* if this ip and port was registered for zone(s), we re-open connections to the remote servers*)
    let xs =
      Domain_name.Map.fold (fun zone (_, ip, port, keyname) acc ->
          if Ipaddr.V4.compare ip ip' = 0 && port = port' then
            match Authentication.find_zone_ips keyname with
            (* returns zone primary_ip secondary_ip -- for the hidden secondary the latter is None *)
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
