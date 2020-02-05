(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Rresult
open R.Infix
open Dns

let src = Logs.Src.create "dns_server" ~doc:"DNS server"
module Log = (val Logs.src_log src : Logs.LOG)

module IPM = struct
  include Map.Make(Ipaddr.V4)

  let union_append a b =
    let f _ a b = Some (a @ b) in
    union f a b

  let add_or_merge k v m =
    let tl = match find_opt k m with
      | None -> []
      | Some tl -> tl
    in
    add k (v :: tl) m
end

let guard p err = if p then Ok () else Error err

let guardf p err = if p then Ok () else Error (err ())

module Authentication = struct

  type operation = [
    | `Update
    | `Transfer
    | `Notify
  ]
  let all_ops = [ `Notify ; `Transfer ; `Update ]

  let access_granted ~required key = match required, key with
    | `Update, `Update -> true
    | `Transfer, (`Update | `Transfer) -> true
    | `Notify, (`Update | `Transfer | `Notify) -> true
    | _ -> false

  type t = Dns_trie.t

  let operation_to_string = function
    | `Update -> "_update"
    | `Transfer -> "_transfer"
    | `Notify -> "_notify"

  let find_zone_ips name =
    (* the name of a key is primaryip.secondaryip._transfer.zone
       e.g. 192.168.42.2.192.168.42.1._transfer.mirage
       alternative: <whatever>.primaryip._transfer.zone *)
    let is_transfer = Domain_name.equal_label (operation_to_string `Transfer) in
    match Domain_name.find_label ~rev:true name is_transfer with
    | None -> None
    | Some idx ->
      let amount = succ idx in
      let zone = Domain_name.drop_label_exn ~amount name in
      let len = Domain_name.count_labels name in
      let ip start =
        if start >= 0 && start + 4 < len then
          let a = Domain_name.get_label_exn name start
          and b = Domain_name.get_label_exn name (start + 1)
          and c = Domain_name.get_label_exn name (start + 2)
          and d = Domain_name.get_label_exn name (start + 3)
          in
          match Ipaddr.V4.of_string (String.concat "." [ a ; b ; c ; d ]) with
          | Error _ -> None
          | Ok ip -> Some ip
        else
          None
      in
      match ip (idx - 8), ip (idx - 4) with
      | _, None -> None
      | None, Some ip -> Some (zone, ip, None)
      | Some primary, Some secondary -> Some (zone, primary, Some secondary)

  let find_ns s trie zone =
    let accumulate name _ acc =
      let matches_zone z = Domain_name.(equal z root || equal z zone) in
      match find_zone_ips name, s with
      | None, _ -> acc
      | Some (z, prim, _), `P when matches_zone z-> (name, prim) :: acc
      | Some (z, _, Some sec), `S when matches_zone z -> (name, sec) :: acc
      | Some _, _ -> acc
    in
    Dns_trie.fold Rr_map.Dnskey trie accumulate []

  let secondaries t zone = find_ns `S t zone

  let primaries t zone = find_ns `P t zone

  let zone_and_operation name =
    let is_op lbl =
      List.exists
        (fun op -> Domain_name.equal_label lbl (operation_to_string op))
        all_ops
    in
    match Domain_name.find_label ~rev:true name is_op with
    | None -> None
    | Some idx ->
      let amount = succ idx in
      let dn = Domain_name.drop_label_exn ~amount name
      and op_str = Domain_name.get_label_exn name idx
      in
      let op =
        List.find
          (fun o -> Domain_name.equal_label (operation_to_string o) op_str)
          all_ops
      in
      match Domain_name.host dn with
      | Error _ -> None
      | Ok hn -> Some (hn, op)

  let soa name =
    let nameserver = Domain_name.prepend_label_exn name "ns"
    and hostmaster = Domain_name.prepend_label_exn name "hostmaster"
    in
    { Soa.nameserver ; hostmaster ; serial = 0l ; refresh = 16384l ;
      retry = 2048l ; expiry = 1048576l ; minimum = 300l }

  let add_keys trie name keys =
    match zone_and_operation name with
    | None -> Log.warn (fun m -> m "key without zone %a" Domain_name.pp name); trie
    | Some (zone, _) ->
      let soa =
        match Dns_trie.lookup zone Rr_map.Soa trie with
        | Ok soa -> { soa with Soa.serial = Int32.succ soa.Soa.serial }
        | Error _ -> soa zone
      in
      let keys' = match Dns_trie.lookup name Rr_map.Dnskey trie with
        | Error _ -> keys
        | Ok (_, dnskeys) ->
          Log.warn (fun m -> m "replacing Dnskeys (name %a, present %a, add %a)"
                       Domain_name.pp name
                       Fmt.(list ~sep:(unit ",") Dnskey.pp)
                       (Rr_map.Dnskey_set.elements dnskeys)
                       Fmt.(list ~sep:(unit ";") Dnskey.pp)
                       (Rr_map.Dnskey_set.elements keys) );
          keys
      in
      let trie' = Dns_trie.insert zone Rr_map.Soa soa trie in
      Dns_trie.insert name Rr_map.Dnskey (0l, keys') trie'

  let of_keys keys =
    List.fold_left (fun trie (name, key) ->
        add_keys trie name (Rr_map.Dnskey_set.singleton key))
      Dns_trie.empty keys

  let find_key t name =
    match Dns_trie.lookup name Rr_map.Dnskey t with
    | Ok (_, keys) ->
      if Rr_map.Dnskey_set.cardinal keys = 1 then
        Some (Rr_map.Dnskey_set.choose keys)
      else begin
        Log.warn (fun m -> m "found multiple (%d) keys for %a"
                     (Rr_map.Dnskey_set.cardinal keys)
                     Domain_name.pp name);
        None
      end
    | Error e ->
      Log.warn (fun m -> m "error %a while looking up key %a" Dns_trie.pp_e e
                   Domain_name.pp name);
      None

  let access ?key ~zone required =
    match key with
    | None -> false
    | Some keyname ->
      match zone_and_operation keyname with
      | None -> false
      | Some (key_zone, op) ->
        Domain_name.is_subdomain ~subdomain:zone ~domain:key_zone &&
        access_granted ~required op
end

let dns_rcode_stats name =
  let f = function
    | `Rcode_error (rc, _, _) -> Rcode.to_string rc
    | #Packet.reply -> "reply"
    | #Packet.request -> "request"
  in
  let src = Dns.counter_metrics ~f ("dns_server_stats_"^name) in
  (fun r -> Metrics.add src (fun x -> x) (fun d -> d r))

let tx_metrics = dns_rcode_stats "tx"
let rx_metrics = dns_rcode_stats "rx"

type t = {
  data : Dns_trie.t ;
  auth : Authentication.t ;
  unauthenticated_zone_transfer : bool ;
  rng : int -> Cstruct.t ;
  tsig_verify : Tsig_op.verify ;
  tsig_sign : Tsig_op.sign ;
}

let with_data t data = { t with data }

let text name data =
  match Dns_trie.entries name data with
  | Error e ->
    Error (`Msg (Fmt.strf "text: couldn't find zone %a: %a"
                   Domain_name.pp name Dns_trie.pp_e e))
  | Ok (soa, map) ->
    let buf = Buffer.create 1024 in
    let origin, default_ttl =
      Buffer.add_string buf
        ("$ORIGIN " ^ Domain_name.to_string ~trailing:true name ^ "\n");
      let ttl = soa.minimum in
      Buffer.add_string buf ("$TTL " ^ Int32.to_string ttl ^ "\n");
      name, ttl
    in
    Buffer.add_string buf (Rr_map.text ~origin ~default_ttl name Soa soa);
    Buffer.add_char buf '\n';
    let out map =
      Domain_name.Map.iter (fun name rrs ->
          Rr_map.iter (fun b ->
              Buffer.add_string buf (Rr_map.text_b ~origin ~default_ttl name b);
              Buffer.add_char buf '\n')
            rrs)
        map
    in
    let is_special name _ =
      match Domain_name.get_label name 0 with
      | Error _ -> false
      | Ok lbl -> String.get lbl 0 = '_'
    in
    let service, entries = Domain_name.Map.partition is_special map in
    out entries;
    Buffer.add_char buf '\n';
    out service;
    Ok (Buffer.contents buf)

let create ?(unauthenticated_zone_transfer = false) ?(tsig_verify = Tsig_op.no_verify) ?(tsig_sign = Tsig_op.no_sign)
    ?(auth = Dns_trie.empty) data rng =
  { data ; auth ; unauthenticated_zone_transfer ; rng ; tsig_verify ; tsig_sign }

let find_glue trie names =
  Domain_name.Host_set.fold (fun name map ->
      match
        match Dns_trie.lookup_glue name trie with
        | Some v4, Some v6 -> Some Rr_map.(add A v4 (singleton Aaaa v6))
        | Some v4, None -> Some (Rr_map.singleton A v4)
        | None, Some v6 -> Some (Rr_map.singleton Aaaa v6)
        | None, None -> None
      with
      | None -> map
      | Some rrs -> Domain_name.Map.add (Domain_name.raw name) rrs map)
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
    | `Any -> Dns_trie.lookup_any name trie
    | `K (Rr_map.K k) -> match Dns_trie.lookup_with_cname name k trie with
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
        Rr_map.(fold (fun (B (k, v)) s ->
            Domain_name.Host_set.union (names k v) s)
            an ns)
      in
      Name_rr_map.remove_sub
        (Name_rr_map.remove_sub (find_glue trie names) answer)
        authority
    in
    Ok (authoritative, (answer, authority), Some additional)
  | Error (`Delegation (name, (ttl, ns))) ->
    let authority = Name_rr_map.singleton name Ns (ttl, ns) in
    Ok (Packet.Flags.empty, (Name_rr_map.empty, authority),
        Some (find_glue trie ns))
  | Error (`EmptyNonTerminal (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Ok (authoritative, (Name_rr_map.empty, authority), None)
  | Error (`NotFound (zname, soa)) ->
    let authority = Name_rr_map.singleton zname Soa soa in
    Error (Rcode.NXDomain, Some (Name_rr_map.empty, authority))
  | Error `NotAuthoritative -> Error (Rcode.NotAuth, None)

let authorise_zone_transfer allow_unauthenticated proto key zone =
  guardf (proto = `Tcp) (fun () ->
      Log.err (fun m -> m "refusing zone transfer of %a via UDP"
                  Domain_name.pp zone);
      Rcode.Refused) >>= fun () ->
  guardf (allow_unauthenticated || Authentication.access `Transfer ?key ~zone) (fun () ->
      Log.err (fun m -> m "refusing unauthorised zone transfer of %a"
                  Domain_name.pp zone);
      Rcode.NotAuth)

let handle_axfr_request t proto key ((zone, _) as question) =
  authorise_zone_transfer t.unauthenticated_zone_transfer proto key zone >>= fun () ->
  match Dns_trie.entries zone t.data with
  | Ok (soa, entries) ->
    Log.info (fun m -> m "transfer key %a authorised for AXFR %a"
                 Fmt.(option ~none:(unit "none") Domain_name.pp) key
                 Packet.Question.pp question);
    Ok (soa, entries)
  | Error e ->
    Log.err (fun m -> m "AXFR attempted on %a, where we're not authoritative %a"
                Domain_name.pp zone Dns_trie.pp_e e);
    Error Rcode.NotAuth

module IM = Map.Make(Int32)

type trie_cache = Dns_trie.t IM.t Domain_name.Map.t

let find_trie m name serial =
  match Domain_name.Map.find name m with
  | None -> None
  | Some m' -> IM.find_opt serial m'

let handle_ixfr_request t m proto key ((zone, _) as question) soa =
  authorise_zone_transfer t.unauthenticated_zone_transfer proto key zone >>= fun () ->
  Log.info (fun m -> m "transfer key %a authorised for IXFR %a"
               Fmt.(option ~none:(unit "none") Domain_name.pp) key
               Packet.Question.pp question);
  let old = match find_trie m zone soa.Soa.serial with
    | None -> Dns_trie.empty
    | Some old -> old
  in
  match Dns_trie.diff zone soa ~old t.data with
  | Ok ixfr -> Ok ixfr
  | Error (`Msg msg) ->
    Log.err (fun m -> m "IXFR attempted on %a, where diff failed with %s"
                Domain_name.pp zone msg);
    Error Rcode.NotAuth

let safe_decode buf =
  match Packet.decode buf with
  | Error e ->
    Logs.err (fun m -> m "error %a while decoding, giving up" Packet.pp_err e);
    rx_metrics (`Rcode_error (Rcode.FormErr, Opcode.Query, None));
    Error Rcode.FormErr
(*  | Error `Partial ->
    Log.err (fun m -> m "partial frame (length %d)@.%a" (Cstruct.len buf) Cstruct.hexdump_pp buf);
    Packet.create <<no header>> <<no question>> Dns_enum.FormErr
  | Error (`Bad_edns_version i) ->
    Log.err (fun m -> m "bad edns version error %u while decoding@.%a"
                 i Cstruct.hexdump_pp buf);
    Error Dns_enum.BadVersOrSig
  | Error (`Not_implemented (off, msg)) ->
    Log.err (fun m -> m "not implemented at %d: %s while decoding@.%a"
                off msg Cstruct.hexdump_pp buf);
    Error Dns_enum.NotImp
  | Error e ->
    Log.err (fun m -> m "error %a while decoding@.%a"
                 Packet.pp_err e Cstruct.hexdump_pp buf);
    Error Dns_enum.FormErr *)
  | Ok v ->
    rx_metrics v.Packet.data;
    Ok v

let handle_question t (name, typ) =
  (* TODO white/blacklist of allowed qtypes? what about ANY and UDP? *)
  match typ with
  (* this won't happen, decoder constructs `Axfr *)
  | `Axfr | `Ixfr -> Error (Rcode.NotImp, None)
  | (`K _ | `Any) as k -> lookup t.data (name, k)
(*  | r ->
    Log.err (fun m -> m "refusing query type %a" Rr.pp r);
    Error (Rcode.Refused, None) *)

(* this implements RFC 2136 Section 2.4 + 3.2 *)
let handle_rr_prereq name trie = function
  | Packet.Update.Name_inuse ->
    begin match Dns_trie.lookup name A trie with
      | Ok _ | Error (`EmptyNonTerminal _) -> Ok ()
      | _ -> Error Rcode.NXDomain
    end
  | Packet.Update.Exists (K typ) ->
    begin match Dns_trie.lookup name typ trie with
      | Ok _ -> Ok ()
      | _ -> Error Rcode.NXRRSet
    end
  | Packet.Update.Not_name_inuse ->
    begin match Dns_trie.lookup name A trie with
      | Error (`NotFound _) -> Ok ()
      | _ -> Error Rcode.YXDomain
    end
  | Packet.Update.Not_exists (K typ) ->
    begin match Dns_trie.lookup name typ trie with
      | Error (`EmptyNonTerminal _ | `NotFound _) -> Ok ()
      | _ -> Error Rcode.YXRRSet
    end
  | Packet.Update.Exists_data Rr_map.(B (k, v)) ->
    match Dns_trie.lookup name k trie with
    | Ok v' when Rr_map.equal_rr k v v' -> Ok ()
    | _ -> Error Rcode.NXRRSet

(* RFC 2136 Section 2.5 + 3.4.2 *)
(* we partially ignore 3.4.2.3 and 3.4.2.4 by not special-handling of NS, SOA *)
let handle_rr_update name trie = function
  | Packet.Update.Remove (K typ) ->
    begin match typ with
      | Soa ->
        (* this does not follow 2136, but we want to be able to remove a zone *)
        Dns_trie.remove_zone name trie
      | _ -> Dns_trie.remove_ty name typ trie
    end
  | Packet.Update.Remove_all -> Dns_trie.remove_all name trie
  | Packet.Update.Remove_single Rr_map.(B (k, v)) ->
    Dns_trie.remove name k v trie
  | Packet.Update.Add Rr_map.(B (k, add)) ->
    (* turns out, RFC 2136, 3.4.2.2 says "SOA with smaller or equal serial is
       silently ignored" *)
    (* here we allow arbitrary, even out-of-zone updates.  this is
       crucial for the resolver operation as we have it right now:
       add . 300 NS resolver ; add resolver . 300 A 141.1.1.1 would
       otherwise fail (no SOA for . / delegation for resolver) *)
    Dns_trie.insert name k add trie

let sign_outgoing ~max_size server keyname signed packet buf =
  match Authentication.find_key server.auth keyname with
  | None ->
    Log.err (fun m -> m "key %a not found (or multiple)"
                Domain_name.pp keyname);
    None
  | Some key -> match Tsig.dnskey_to_tsig_algo key with
    | Error (`Msg msg) ->
      Log.err (fun m -> m "couldn't convert algorithm: %s" msg);
      None
    | Ok algorithm ->
      let original_id = fst packet.Packet.header in
      match Tsig.tsig ~algorithm ~original_id ~signed () with
      | None ->
        Log.err (fun m -> m "creation of tsig failed");
        None
      | Some tsig ->
        match server.tsig_sign ~max_size keyname tsig ~key packet buf with
        | Some res -> Some res
        | None ->
          Log.err (fun m -> m "signing failed");
          None

module Notification = struct
  (* passive secondaries (behind NAT etc.) such as let's encrypt, which
     initiated a signed! TCP session (the fd/flow are kept in the effectful
     layer) *)
  type connections =
   ([ `raw ] Domain_name.t * Ipaddr.V4.t) list Domain_name.Host_map.t

  let secondaries trie zone =
    match Dns_trie.lookup_with_cname zone Rr_map.Soa trie with
    | Ok (B (Soa, soa), (_, _, ns)) ->
      let secondaries =
        match Domain_name.host soa.Soa.nameserver with
        | Error _ -> ns
        | Ok prim -> Domain_name.Host_set.remove prim ns
      in
      Domain_name.Host_set.fold (fun ns acc ->
          match Dns_trie.lookup_glue ns trie with
          | Some (_, ips), _ -> Rr_map.Ipv4_set.union ips acc
          | _ ->
            Log.warn (fun m -> m "could not find an address record for the secondary %a (zone %a), it won't be notified"
                         Domain_name.pp ns Domain_name.pp zone);
            acc)
        secondaries Rr_map.Ipv4_set.empty
    | _ -> Rr_map.Ipv4_set.empty

  let to_notify conn ~data ~auth zone =
    (* for a given zone, compute the "ip -> key option" map of to-be-notiied
       secondaries uses data from 3 sources:
       - secondary NS of the zone as registered in data (ip only, take all NS
         and subtract the SOA nameserver)
       - keys of the form YY.secondary-ip._transfer.zone and
         YY.secondary-ip._transfer (root zone)
       - active connections (from the zone -> ip, key map above), used for
         let's encrypt etc. *)
    let secondaries =
      Rr_map.Ipv4_set.fold (fun ip m -> IPM.add ip None m)
        (secondaries data zone) IPM.empty
    in
    let of_list = List.fold_left (fun m (key, ip) -> IPM.add ip (Some key) m) in
    let secondaries_and_keys =
      of_list secondaries (Authentication.secondaries auth zone)
    in
    match Domain_name.Host_map.find zone conn with
    | None -> secondaries_and_keys
    | Some xs -> of_list secondaries_and_keys xs

  let insert ~data ~auth cs ~zone ~key ip =
    let cs' =
      let old =
        match Domain_name.Host_map.find zone cs with None -> [] | Some a -> a
      in
      Domain_name.Host_map.add zone ((key, ip) :: old) cs
    in
    match IPM.find_opt ip (to_notify cs ~data ~auth zone) with
    | None ->
      Log.info (fun m -> m "inserting notifications for %a key %a IP %a"
                   Domain_name.pp zone Domain_name.pp key Ipaddr.V4.pp ip);
      cs'
    | Some (Some k) ->
      if Domain_name.equal k key then begin
        Log.warn (fun m -> m "zone %a with key %a and IP %a already registered"
                     Domain_name.pp zone Domain_name.pp key Ipaddr.V4.pp ip);
        cs
      end else begin
        Log.warn (fun m -> m "replacing key zone %a oldkey %a IP %a, new key %a"
                     Domain_name.pp zone Domain_name.pp k Ipaddr.V4.pp ip
                     Domain_name.pp key);
        cs'
      end
    | Some None ->
      Log.info (fun m -> m "adding zone %a (key %a) IP %a (previously no key)"
                   Domain_name.pp zone Domain_name.pp key Ipaddr.V4.pp ip);
      cs'

  let remove conn ip =
    let is_not_it name (_, ip') =
      if Ipaddr.V4.compare ip ip' = 0 then begin
        Log.info (fun m -> m "removing notification for %a %a"
                     Domain_name.pp name Ipaddr.V4.pp ip);
        false
      end else true
    in
    Domain_name.Host_map.fold (fun name conns new_map ->
      match List.filter (is_not_it name) conns with
      | [] -> new_map
      | xs -> Domain_name.Host_map.add name xs new_map)
      conn Domain_name.Host_map.empty

  let encode_and_sign key_opt server now packet =
    tx_metrics packet.Packet.data;
    let buf, max_size = Packet.encode `Tcp packet in
    match key_opt with
    | None -> buf, None
    | Some key ->
      match sign_outgoing ~max_size server key now packet buf with
      | None -> buf, None
      | Some (out, mac) -> out, Some mac

  (* outstanding notifications in a map where keys are IP address, values is a
     map from zone to a quadruple consisting of timestamp, retry count, actual
     packet, an optional key name used for signing, and an optional mac (used
     for verifying the reply) *)
  type outstanding =
    (int64 * int * Packet.t * [ `raw ] Domain_name.t option * Cstruct.t option)
    Domain_name.Host_map.t IPM.t

  (* operations:
     - timer occured, retransmit outstanding or drop
     - send out notification for a given zone
     - a (signed?) notify response came in, drop it from outstanding *)
  let retransmit =
    Array.map Duration.of_sec
      [| 1 ; 1 ; 1 ; 4 ; 13 ; 20 ; 20 ; 120 ; 420 ; 900 ; 2100 ; 3600 * 23 |]

  let retransmit server ns now ts =
    let max = pred (Array.length retransmit) in
    IPM.fold (fun ip map (new_ns, out) ->
        let new_map, out' =
          Domain_name.Host_map.fold
            (fun name (oldts, count, packet, key, mac) (new_map, outs) ->
               if Int64.sub ts retransmit.(count) >= oldts then
                 let out, mac = encode_and_sign key server now packet in
                 (if count = max then begin
                     Log.warn (fun m -> m "retransmit notify to %a last time %a"
                                  Ipaddr.V4.pp ip Packet.pp packet);
                     new_map
                   end else
                    let v = ts, succ count, packet, key, mac in
                    Domain_name.Host_map.add name v new_map),
                 out :: outs
               else
                 let v = oldts, count, packet, key, mac in
                 Domain_name.Host_map.add name v new_map, outs)
            map (Domain_name.Host_map.empty, [])
        in
        (if Domain_name.Host_map.is_empty new_map then
           new_ns
         else
           IPM.add ip new_map new_ns),
        (match out' with [] -> out | _ -> (ip, out') :: out))
      ns (IPM.empty, [])

  let notify_one ns server now ts zone soa ip key =
    let packet =
      let question = Packet.Question.create zone Soa
      and header = Randomconv.int16 server.rng, authoritative
      in
      Packet.create header question (`Notify (Some soa))
    in
    let add_to_ns ns ip key mac =
      let data = ts, 0, packet, key, mac in
      let map = match IPM.find_opt ip ns with
        | None -> Domain_name.Host_map.empty
        | Some map -> map
      in
      let map' = Domain_name.Host_map.add zone data map in
      IPM.add ip map' ns
    in
    let out, mac = encode_and_sign key server now packet in
    let ns = add_to_ns ns ip key mac in
    (ns, out)

  let notify conn ns server now ts zone soa =
    let remotes = to_notify conn ~data:server.data ~auth:server.auth zone in
    Log.debug (fun m -> m "notifying %a: %a" Domain_name.pp zone
                  Fmt.(list ~sep:(unit ",@ ")
                         (pair ~sep:(unit ", key ") Ipaddr.V4.pp
                            (option ~none:(unit "none") Domain_name.pp)))
                  (IPM.bindings remotes));
    IPM.fold (fun ip key (ns, outs) ->
        let ns, out = notify_one ns server now ts zone soa ip key in
        ns, IPM.add ip [ out ] outs)
      remotes (ns, IPM.empty)

  let received_reply ns ip reply =
    match IPM.find_opt ip ns with
    | None -> ns
    | Some map ->
      match Domain_name.host (fst reply.Packet.question) with
      | Error _ ->
        Log.warn (fun m -> m "received notify reply for a non-hostname zone %a"
                     Domain_name.pp (fst reply.Packet.question));
        ns
      | Ok zone ->
        let map' = match Domain_name.Host_map.find zone map with
          | Some (_, _, request, _, _) ->
            begin match Packet.reply_matches_request ~request reply with
            | Ok r ->
              let map' = Domain_name.Host_map.remove zone map in
              (match r with
               | `Notify_ack -> ()
               | r -> Log.warn (fun m -> m "expected notify_ack, got %a"
                                   Packet.pp_reply r));
              map'
            | Error e ->
              Log.warn (fun m -> m "notify ack mismatched %a (req %a, rep %a)"
                           Packet.pp_mismatch e Packet.pp request
                           Packet.pp reply);
              map
          end
        | _ -> map
      in
      if Domain_name.Host_map.is_empty map' then
        IPM.remove ip ns
      else
        IPM.add ip map' ns

  let mac ns ip reply =
    match IPM.find_opt ip ns with
    | None -> None
    | Some map ->
      match Domain_name.host (fst reply.Packet.question) with
      | Error _ ->
        Log.warn (fun m -> m "mac for a non-hostname zone %a"
                     Domain_name.pp (fst reply.Packet.question));
        None
      | Ok zone -> match Domain_name.Host_map.find zone map with
        | Some (_, _, _, _, mac) -> mac
        | None -> None
end

let in_zone zone name = Domain_name.is_subdomain ~subdomain:name ~domain:zone

let update_data trie zone (prereq, update) =
  let in_zone = in_zone zone in
  Domain_name.Map.fold (fun name prereqs acc ->
      acc >>= fun () ->
      guard (in_zone name) Rcode.NotZone >>= fun () ->
      List.fold_left (fun acc prereq ->
          acc >>= fun () ->
          handle_rr_prereq name trie prereq)
        (Ok ()) prereqs)
    prereq (Ok ()) >>= fun () ->
  Domain_name.Map.fold (fun name updates acc ->
      acc >>= fun trie ->
      guard (in_zone name) Rcode.NotZone >>| fun () ->
      List.fold_left (handle_rr_update name) trie updates)
    update (Ok trie) >>= fun trie' ->
  (match Dns_trie.check trie' with
   | Ok () -> Ok ()
   | Error e ->
     Log.err (fun m -> m "check after update returned %a"
                 Dns_trie.pp_zone_check e);
     Error Rcode.YXRRSet) >>| fun () ->
  if Dns_trie.equal trie trie' then
    (* should this error out? - RFC 2136 3.4.2.7 says NoError at the end *)
    trie, []
  else
    let zones =
      (* figure out the zones where changes happened *)
      (* for each element in the map of updates (domain_name -> update list),
         figure out the zone of the domain_name. Since zone addition and
         removal is supported, this name may be present in both the old trie and
         the new trie' (update), only in the old trie (delete), only in the new
         trie (add). *)
      Domain_name.Map.fold (fun name _ acc ->
          match Dns_trie.zone name trie, Dns_trie.zone name trie' with
          | Ok (z, _), _ | _, Ok (z, _) -> Domain_name.Set.add z acc
          | Error e, Error _ ->
            Log.err (fun m -> m "couldn't find zone for %a in either trie: %a"
                        Domain_name.pp name Dns_trie.pp_e e);
            acc) update Domain_name.Set.empty
    in
    (* now, for each modified zone, ensure the serial in the SOA increased, and
       output the zone name and its zone. *)
    Domain_name.Set.fold (fun zone (trie', zones) ->
        match Dns_trie.lookup zone Soa trie, Dns_trie.lookup zone Soa trie' with
        | Ok oldsoa, Ok soa when Soa.newer ~old:oldsoa soa ->
          (* serial is already increased in trie', nothing to do *)
          trie', (zone, soa) :: zones
        | _, Ok soa ->
          (* serial was not increased, thus increase it now *)
          let soa = { soa with Soa.serial = Int32.succ soa.Soa.serial } in
          let trie'' = Dns_trie.insert zone Soa soa trie' in
          trie'', (zone, soa) :: zones
        | Ok oldsoa, Error _ ->
          (* zone was removed, output a fake soa with an increased serial to
             inform secondaries of this removal *)
          let serial = Int32.succ oldsoa.Soa.serial in
          trie', (zone, { oldsoa with Soa.serial }) :: zones
        | Error o, Error n ->
          (* the zone neither exists in the old trie nor in the new trie' *)
          Log.warn (fun m -> m "shouldn't happen: %a no soa in old %a and new %a"
                       Domain_name.pp zone Dns_trie.pp_e o Dns_trie.pp_e n);
          trie', zones)
      zones (trie', [])

let handle_update t _proto key (zone, _) u =
  if Authentication.access `Update ?key ~zone then begin
    Log.info (fun m -> m "update key %a authorised for update %a"
                 Fmt.(option ~none:(unit "none") Domain_name.pp) key
                 Packet.Update.pp u);
    match Domain_name.host zone with
    | Ok z -> update_data t.data z u
    | Error _ ->
      Log.warn (fun m -> m "update on a zone not a hostname %a"
                   Domain_name.pp zone);
      Error Rcode.FormErr
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
    let signed = Cstruct.sub buf 0 off in
    t.tsig_verify ?mac now p name ?key tsig signed >>= fun (tsig, mac, key) ->
    Ok (Some (name, tsig, mac, key))

module Primary = struct

  type s =
    t * Dns_trie.t IM.t Domain_name.Map.t * Notification.connections *
    Notification.outstanding

  let server (t, _, _, _) = t

  let data (t, _, _, _) = t.data

  let trie_cache (_, m, _, _) = m

  (* TODO: not entirely sure how many old ones to keep. This keeps for each
     zone the most recent 5 serials. It does _not_ remove removed zones.
     since it updates all zones with the new trie, there should be at most
     5 (well, 6) tries alive in memory *)
  (* TODO use LRU here! *)
  let update_trie_cache m trie =
    Dns_trie.fold Soa trie (fun name soa m ->
        let recorded = match Domain_name.Map.find name m with
          | None -> IM.empty
          | Some xs ->
            (* keep last 5 references around *)
            if IM.cardinal xs >= 5 then
              IM.remove (fst (IM.min_binding xs)) xs
            else
              xs
        in
        let im = IM.add soa.Soa.serial trie recorded in
        Domain_name.Map.add name im m)
        m

  let with_data (t, m, l, n) now ts data =
    (* need to notify secondaries of new, updated, and removed zones! *)
    let n', out =
      Dns_trie.fold Soa data
        (fun name soa (n, outs) ->
           match Domain_name.host name with
           | Error _ ->
             Log.warn (fun m -> m "zone not a hostname %a" Domain_name.pp name);
             (n, outs)
           | Ok zone ->
             match Dns_trie.lookup name Soa t.data with
             | Error _ ->
               (* a new zone appeared *)
               let n', outs' = Notification.notify l n t now ts zone soa in
               (n', IPM.union_append outs outs')
             | Ok old when Soa.newer ~old soa ->
               (* a zone was modified (its Soa increased) *)
               let n', outs' = Notification.notify l n t now ts zone soa in
               (n', IPM.union_append outs outs')
             | Ok _ -> (n, outs))
        (n, IPM.empty)
    in
    (* zone removal - present in t.data, absent in data *)
    let n'', out' =
      Dns_trie.fold Soa t.data (fun name soa (n, outs) ->
          match Domain_name.host name with
          | Error _ ->
            Log.warn (fun m -> m "zone not a hostname %a" Domain_name.pp name);
            (n, outs)
          | Ok zone ->
            match Dns_trie.lookup name Soa data with
            | Error _ ->
              let soa' = { soa with Soa.serial = Int32.succ soa.Soa.serial } in
              let n', outs' = Notification.notify l n t now ts zone soa' in
              (n', IPM.union_append outs outs')
            | Ok _ -> (n, outs))
        (n', out)
    in
    let m' = update_trie_cache m t.data in
    ({ t with data }, m', l, n''), IPM.bindings out'

  let with_keys (t, m, l, n) now ts keys =
    let auth = Authentication.of_keys keys in
    let old = t.auth in
    (* need to diff the old and new keys *)
    let added =
      Dns_trie.fold Rr_map.Dnskey auth (fun name _ acc ->
          match Dns_trie.lookup name Rr_map.Dnskey old with
          | Ok _ -> acc
          | Error _ -> Domain_name.Set.add name acc) Domain_name.Set.empty
    and removed =
      Dns_trie.fold Rr_map.Dnskey old (fun name _ acc ->
          match Dns_trie.lookup name Rr_map.Dnskey auth with
          | Ok _ -> acc
          | Error _ -> Domain_name.Set.add name acc) Domain_name.Set.empty
    in
    (* drop all removed keys from connections & notifications *)
    let not_removed (n, _) = not (Domain_name.Set.mem n removed) in
    let l' = Domain_name.Host_map.fold (fun name v acc ->
        match List.filter not_removed v with
        | [] -> acc
        | v' -> Domain_name.Host_map.add name v' acc)
        l Domain_name.Host_map.empty
    and n' = IPM.fold (fun ip m acc ->
        let m' = Domain_name.Host_map.fold (fun name v acc ->
            match v with
            | _, _, _, Some key, _ when Domain_name.Set.mem key removed -> acc
            | _ -> Domain_name.Host_map.add name v acc)
            m Domain_name.Host_map.empty
        in
        if Domain_name.Host_map.is_empty m' then acc else IPM.add ip m' acc)
        n IPM.empty
    in
    let t' = { t with auth } in
    (* for new transfer keys, send notifies out (with respective zone) *)
    let n'', outs =
      Domain_name.Set.fold (fun key (ns, out) ->
          match Authentication.find_zone_ips key with
          | Some (zone, _, Some sec) ->
            let notify =
              if Domain_name.(equal zone root) then
                Dns_trie.fold Soa t'.data (fun name soa n -> (name, soa)::n) []
              else
                match Dns_trie.lookup zone Rr_map.Soa t'.data with
                | Error _ -> []
                | Ok soa -> [zone, soa]
            in
            let ns, out_notifications =
              List.fold_left (fun (ns, outs) (name, soa) ->
                  match Domain_name.host name with
                  | Error (`Msg msg) ->
                    Log.warn (fun m -> m "non-hostname notification %a: %s"
                                 Domain_name.pp name msg);
                    ns, outs
                  | Ok host ->
                    let ns, out =
                      let key = Some key in
                      Notification.notify_one ns t' now ts host soa sec key
                    in
                    ns, out :: outs)
                (ns, []) notify
            in
            ns, (sec, out_notifications) :: out
          | _ -> ns, out)
        added (n', [])
    in
    (t', m, l', n''), outs

  let create ?(keys = []) ?unauthenticated_zone_transfer ?tsig_verify ?tsig_sign ~rng data =
    let auth = Authentication.of_keys keys in
    let t = create ?unauthenticated_zone_transfer ?tsig_verify ?tsig_sign ~auth data rng in
    let hm_empty = Domain_name.Host_map.empty in
    let notifications =
      let f name soa ns =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name);
        match Domain_name.host name with
        | Error _ ->
          Log.warn (fun m -> m "zone is not a valid hostname %a"
                       Domain_name.pp name);
          ns
        | Ok zone ->
          (* we drop notifications, the first call to timer will solve this :) *)
          fst (Notification.notify hm_empty ns t Ptime.epoch 0L zone soa)
      in
      Dns_trie.fold Rr_map.Soa data f IPM.empty
    in
    t, update_trie_cache Domain_name.Map.empty data, hm_empty, notifications

  let tcp_soa_query proto (name, typ) =
    match proto, typ with
    | `Tcp, `K (Rr_map.K Soa) ->
      begin match Domain_name.host name with
        | Ok h -> Ok h
        | Error _ -> Error ()
      end
    | _ -> Error ()

  let handle_packet (t, m, l, ns) now ts proto ip _port p key =
    let key = match key with
      | None -> None
      | Some k -> Some (Domain_name.raw k)
    in
    match p.Packet.data with
    | `Query ->
      (* if there was a (transfer-key) signed SOA, and tcp, we add to
         notification list! *)
      let l', ns', outs, keep = match tcp_soa_query proto p.question, key with
        | Ok zone, Some key when Authentication.access `Transfer ~key ~zone ->
          let zones, notify =
            if Domain_name.(equal root zone) then
              Dns_trie.fold Soa t.data (fun name soa (zs, n) ->
                  let zone = Domain_name.host_exn name in
                  Domain_name.Host_set.add zone zs, (zone, soa)::n)
                (Domain_name.Host_set.empty, [])
            else
              Domain_name.Host_set.singleton zone, []
          in
          let l' = Domain_name.Host_set.fold (fun zone l ->
              Notification.insert ~data:t.data ~auth:t.auth l ~zone ~key ip)
              zones l
          in
          let ns, outs =
            List.fold_left (fun (ns, outs) (name, soa) ->
                let ns, out =
                  Notification.notify_one ns t now ts name soa ip (Some key)
                in
                ns, out :: outs)
              (ns, []) notify
          in
          l', ns, [ ip, outs ], Some `Keep
        | _ -> l, ns, [], None
      in
      let answer =
        let flags, data, additional = match handle_question t p.question with
          | Ok (flags, data, additional) -> flags, `Answer data, additional
          | Error (rcode, data) ->
            err_flags rcode, `Rcode_error (rcode, Opcode.Query, data), None
        in
        Packet.create ?additional (fst p.header, flags) p.question data
      in
      (t, m, l', ns'), Some answer, outs, keep
    | `Update u ->
      let data, (flags, answer), stuff =
        match handle_update t proto key p.question u with
        | Ok (data, stuff) -> data, (authoritative, `Update_ack), stuff
        | Error rcode ->
          let err = `Rcode_error (rcode, Opcode.Update, None) in
          t.data, (err_flags rcode, err), []
      in
      let t' = { t with data }
      and m' = update_trie_cache m data
      in
      let ns, out =
        List.fold_left (fun (ns, outs) (zone, soa) ->
            match Domain_name.host zone with
            | Error _ ->
              Log.warn (fun m -> m "update zone %a is not a hostname, ignoring"
                           Domain_name.pp zone);
              (ns, outs)
            | Ok z ->
              let ns', outs' = Notification.notify l ns t' now ts z soa in
              (ns', IPM.union_append outs outs'))
          (ns, IPM.empty) stuff
      in
      let answer' = Packet.create (fst p.header, flags) p.question answer in
      (t', m', l, ns), Some answer', IPM.bindings out, None
    | `Axfr_request ->
      let flags, answer = match handle_axfr_request t proto key p.question with
        | Ok data -> authoritative, `Axfr_reply data
        | Error rcode ->
          err_flags rcode, `Rcode_error (rcode, Opcode.Query, None)
      in
      let answer = Packet.create (fst p.header, flags) p.question answer in
      (t, m, l, ns), Some answer, [], None
    | `Ixfr_request soa ->
      let flags, answer = match handle_ixfr_request t m proto key p.question soa with
        | Ok data -> authoritative, `Ixfr_reply data
        | Error rcode ->
          err_flags rcode, `Rcode_error (rcode, Opcode.Query, None)
      in
      let answer = Packet.create (fst p.header, flags) p.question answer in
      (t, m, l, ns), Some answer, [], None
    | `Notify_ack | `Rcode_error (_, Opcode.Notify, _) ->
      let ns' = Notification.received_reply ns ip p in
      (t, m, l, ns'), None, [], None
    | `Notify soa ->
      Log.warn (fun m -> m "unsolicited notify request %a (replying anyways)"
                   Fmt.(option ~none:(unit "no") Soa.pp) soa);
      let action =
        if Authentication.access `Notify ?key ~zone:(fst p.question) then
          Some (`Notify soa)
        else
          None
      and reply =
        Packet.create (fst p.header, authoritative) p.question `Notify_ack
      in
      (t, m, l, ns), Some reply, [], action
    | p ->
      Log.err (fun m -> m "ignoring unsolicited %a" Packet.pp_data p);
      (t, m, l, ns), None, [], None

  let handle_buf t now ts proto ip port buf =
    match
      safe_decode buf >>| fun res ->
      Log.debug (fun m -> m "from %a received:@[%a@]" Ipaddr.V4.pp ip
                   Packet.pp res);
      res
    with
    | Error rcode ->
      let answer = Packet.raw_error buf rcode in
      Log.warn (fun m -> m "error %a while %a sent %a, answering with %a"
                   Rcode.pp rcode Ipaddr.V4.pp ip Cstruct.hexdump_pp buf
                   Fmt.(option ~none:(unit "no") Cstruct.hexdump_pp) answer);
      tx_metrics (`Rcode_error (rcode, Opcode.Query, None));
      t, answer, [], None, None
    | Ok p ->
      let handle_inner keyname =
        let t, answer, out, notify =
          handle_packet t now ts proto ip port p keyname
        in
        let answer = match answer with
          | Some answer ->
            let max_size, edns = Edns.reply p.edns in
            let answer = Packet.with_edns answer edns in
            (* be aware, this may be truncated... here AXFR gets assembled! *)
            tx_metrics answer.Packet.data;
            let r = Packet.encode ?max_size proto answer in
            Some (answer, r)
          | None -> None
        in
        t, answer, out, notify
      in
      let server, _, _, ns = t in
      let mac = match p.Packet.data with
        | `Notify_ack | `Rcode_error _ -> Notification.mac ns ip p
        | _ -> None
      in
      match handle_tsig ?mac server now p buf with
      | Error (e, data) ->
        Log.err (fun m -> m "error %a while handling tsig" Tsig_op.pp_e e);
        t, data, [], None, None
      | Ok None ->
        let t, answer, out, notify = handle_inner None in
        let answer' = match answer with
          | None -> None
          | Some (_, (cs, _)) -> Some cs
        in
        t, answer', out, notify, None
      | Ok (Some (name, tsig, mac, key)) ->
        let n = function
          | Some (`Notify n) -> Some (`Signed_notify n)
          | Some `Keep -> Some `Keep
          | None -> None
        in
        let t', answer, out, notify = handle_inner (Some name) in
        let answer' = match answer with
          | None -> None
          | Some (answer, (buf, max_size)) ->
            match server.tsig_sign ~max_size ~mac name tsig ~key answer buf with
            | None ->
              Log.warn (fun m -> m "couldn't use %a to tsig sign"
                           Domain_name.pp name);
              (* TODO - better send back unsigned answer? or an error? *)
              None
            | Some (buf, _) -> Some buf
        in
        t', answer', out, n notify, Some name

  let closed (t, m, l, ns) ip =
    let l' = Notification.remove l ip in
    (t, m, l', ns)

  let timer (t, m, l, ns) now ts =
    let ns', out = Notification.retransmit t ns now ts in
    (t, m, l, ns'), out

  let to_be_notified (t, _, l, _) zone =
    IPM.bindings (Notification.to_notify l ~data:t.data ~auth:t.auth zone)
end

module Secondary = struct

  type state =
    | Transferred of int64
    | Requested_soa of int64 * int * int * Cstruct.t
    | Requested_axfr of int64 * int * Cstruct.t
    | Requested_ixfr of int64 * int * Soa.t * Cstruct.t

  let id = function
    | Transferred _ -> None
    | Requested_soa (_, id, _, _) -> Some id
    | Requested_axfr (_, id, _) -> Some id
    | Requested_ixfr (_, id, _, _) -> Some id

  (* undefined what happens if there are multiple transfer keys for zone *)
  type s =
    t * (state * Ipaddr.V4.t * [ `raw ] Domain_name.t) Domain_name.Host_map.t

  let data (t, _) = t.data

  let with_data (t, zones) data = ({ t with data }, zones)

  let create ?primary ~tsig_verify ~tsig_sign ~rng keylist =
    let auth = Authentication.of_keys keylist in
    let zones =
      let f name _ zones =
        Log.debug (fun m -> m "soa found for %a" Domain_name.pp name);
        match Domain_name.host name with
        | Error _ ->
          Log.warn (fun m -> m "zone %a not a hostname" Domain_name.pp name);
          zones
        | Ok zone ->
          match Authentication.primaries auth name with
          | [] -> begin match primary with
              | None ->
                Log.warn (fun m -> m "no nameserver found for %a"
                             Domain_name.pp name);
                zones
              | Some ip ->
                List.fold_left (fun zones (keyname, _) ->
                    let keyname = Domain_name.raw keyname in
                    if
                      Authentication.access `Transfer ~key:keyname ~zone:name
                    then begin
                      Log.app (fun m -> m "adding zone %a with key %a and ip %a"
                                  Domain_name.pp name Domain_name.pp keyname
                                  Ipaddr.V4.pp ip);
                      let v =
                        Requested_soa (0L, 0, 0, Cstruct.empty), ip, keyname
                      in
                      Domain_name.Host_map.add zone v zones
                    end else begin
                      Log.warn (fun m -> m "no transfer key found for %a"
                                   Domain_name.pp name);
                      zones
                    end) zones keylist
            end
          | primaries ->
            List.fold_left (fun zones (keyname, ip) ->
                Log.app (fun m -> m "adding transfer key %a for zone %a"
                            Domain_name.pp keyname Domain_name.pp name);
                let v = Requested_soa (0L, 0, 0, Cstruct.empty), ip, keyname in
                Domain_name.Host_map.add zone v zones)
              zones primaries
      in
      Dns_trie.fold Rr_map.Soa auth f Domain_name.Host_map.empty
    in
    (create ~tsig_verify ~tsig_sign Dns_trie.empty ~auth rng, zones)

  let header rng () = Randomconv.int16 rng, Packet.Flags.empty

  let axfr t now ts q_name name =
    let header = header t.rng ()
    and question = (Domain_name.raw q_name, `Axfr)
    in
    let p = Packet.create header question `Axfr_request in
    tx_metrics `Axfr_request;
    let buf, max_size = Packet.encode `Tcp p in
    match sign_outgoing ~max_size t name now p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_axfr (ts, fst header, mac), buf)

  let ixfr t now ts q_name soa name =
    let header = header t.rng ()
    and question = (Domain_name.raw q_name, `Ixfr)
    in
    let p = Packet.create header question (`Ixfr_request soa) in
    tx_metrics (`Ixfr_request soa);
    let buf, max_size = Packet.encode `Tcp p in
    match sign_outgoing ~max_size t name now p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_ixfr (ts, fst header, soa, mac), buf)

  let query_soa ?(retry = 0) t now ts q_name name =
    let header = header t.rng ()
    and question = Packet.Question.create q_name Soa
    in
    let p = Packet.create header question `Query in
    tx_metrics `Query;
    let buf, max_size = Packet.encode `Tcp p in
    match sign_outgoing ~max_size t name now p buf with
    | None -> None
    | Some (buf, mac) -> Some (Requested_soa (ts, fst header, retry, mac), buf)

  let timer (t, zones) p_now now =
    (* what is there to be done?
       - request SOA on every soa.refresh interval
       - if the primary server is not reachable, try every time after soa.retry
       - once soa.expiry is over (from the initial SOA request), don't serve
          the zone anymore

       - axfr (once soa is through and we know we have stale data) is retried
          every 3 seconds
       - if we don't have a soa yet for the zone, retry every 3 seconds as well
       - TODO exponential backoff for that
    *)
    Log.debug (fun m -> m "secondary timer");
    let three_sec = Duration.of_sec 3 in
    let t, out =
      Domain_name.Host_map.fold (fun zone (st, ip, name) ((t, zones), map) ->
          Log.debug (fun m -> m "secondary timer zone %a ip %a name %a"
                        Domain_name.pp zone Ipaddr.V4.pp ip Domain_name.pp name);
          let maybe_out data =
            let st, out = match data with
              | None -> st, map
              | Some (st, out) -> st, IPM.add_or_merge ip out map
            in
            ((t, Domain_name.Host_map.add zone (st, ip, name) zones), out)
          in
          match Dns_trie.lookup zone Rr_map.Soa t.data, st with
          | Ok soa, Transferred ts ->
            let r = Duration.of_sec (Int32.to_int soa.Soa.refresh) in
            maybe_out
              (if Int64.sub now r >= ts then
                 query_soa t p_now now zone name
               else
                 None)
          | Ok soa, Requested_soa (ts, _, retry, _) ->
            let expiry = Duration.of_sec (Int32.to_int soa.Soa.expiry) in
            if Int64.sub now expiry >= ts then begin
              Log.warn (fun m -> m "expiry expired, dropping zone %a"
                           Domain_name.pp zone);
              let data = Dns_trie.remove_zone zone t.data in
              (({ t with data }, zones), map)
            end else
              let retry = succ retry in
              let e = Duration.of_sec (retry * Int32.to_int soa.Soa.retry) in
              maybe_out
                (if Int64.sub now e >= ts then
                   query_soa ~retry t p_now now zone name
                 else
                   None)
          | Error _, Requested_soa (ts, _, retry, _) ->
            maybe_out
              (if Int64.sub now three_sec >= ts then
                 query_soa ~retry:(succ retry) t p_now now zone name
               else
                 None)
          | _, Requested_axfr (ts, _, _) ->
            maybe_out
              (if Int64.sub now three_sec >= ts then
                 axfr t p_now now zone name
               else
                 None)
          | _, Requested_ixfr (ts, _, soa, _) ->
            maybe_out
              (if Int64.sub now three_sec >= ts then
                 ixfr t p_now now zone soa name
               else
                 None)
          | Error e, _ ->
            Log.err (fun m -> m "ended up here zone %a error %a looking for soa"
                        Domain_name.pp zone Dns_trie.pp_e e);
            maybe_out None)
        zones ((t, Domain_name.Host_map.empty), IPM.empty)
    in
    t, IPM.bindings out

  let handle_notify t zones now ts ip zone typ notify keyname =
    match typ with
    | `K (Rr_map.K Soa) ->
      begin match Domain_name.Host_map.find zone zones, keyname with
        | None, None ->
          (* we don't know anything about the notified zone *)
          Log.warn (fun m -> m "ignoring notify for %a, no such zone"
                       Domain_name.pp zone);
          Error Rcode.Refused
        | None, Some kname ->
          if Authentication.access `Notify ~key:kname ~zone then
            let r = match axfr t now ts zone kname with
              | None ->
                Log.warn (fun m -> m "new zone %a, couldn't AXFR"
                             Domain_name.pp zone);
                zones, None
              | Some (st, buf) ->
                Domain_name.Host_map.add zone (st, ip, kname) zones,
                Some (ip, buf)
            in
            Ok r
          else begin
            Log.warn (fun m -> m "ignoring notify %a (key %a) not authorised"
                         Domain_name.pp zone Domain_name.pp kname);
            Error Rcode.Refused
          end
        | Some (Transferred _, ip', name), None ->
          if Ipaddr.V4.compare ip ip' = 0 then begin
            Log.debug (fun m -> m "received notify %a, requesting SOA"
                          Domain_name.pp zone);
            let zones, out =
              match query_soa t now ts zone name with
              | None -> zones, None
              | Some (st, buf) ->
                Domain_name.Host_map.add zone (st, ip, name) zones,
                Some (ip, buf)
            in
            Ok (zones, out)
          end else begin
            Log.warn (fun m -> m "ignoring notify %a from %a (%a is primary)"
                         Domain_name.pp zone Ipaddr.V4.pp ip Ipaddr.V4.pp ip');
            Error Rcode.Refused
          end
        | Some _, None ->
          Log.warn (fun m -> m "received unsigned notify %a already in progress"
                       Domain_name.pp zone);
          Ok (zones, None)
        | Some (st, ip', name), Some _ ->
          if Ipaddr.V4.compare ip ip' = 0 then begin
            (* we received a signed notify! check if SOA present, and act *)
            match st, notify, Dns_trie.lookup zone Rr_map.Soa t.data with
            | Transferred _, None, _ ->
              begin match query_soa t now ts zone name with
                | None ->
                  Log.warn (fun m -> m "signed notify %a, couldn't sign soa?"
                               Domain_name.pp zone);
                  Ok (zones, None)
                | Some (st, buf) ->
                  Ok (Domain_name.Host_map.add zone (st, ip, name) zones,
                      Some (ip, buf))
              end
            | _, None, _ ->
              Log.warn (fun m -> m "signed notify %a no SOA already in progress"
                           Domain_name.pp zone);
              Ok (zones, None)
            | _, Some soa, Error _ ->
              Log.info (fun m -> m "signed notify %a soa %a no local SOA"
                           Domain_name.pp zone Soa.pp soa);
              begin match axfr t now ts zone name with
                | None ->
                  Log.warn (fun m -> m "signed notify for %a couldn't sign axfr"
                               Domain_name.pp zone);
                  Ok (zones, None)
                | Some (st, buf) ->
                  Ok (Domain_name.Host_map.add zone (st, ip, name) zones,
                      Some (ip, buf))
              end
            | _, Some soa, Ok old ->
              if Soa.newer ~old soa then
                match ixfr t now ts zone old name with
                  | None ->
                    Log.warn (fun m -> m "signed notify %a couldn't sign ixfr"
                                 Domain_name.pp zone);
                    Ok (zones, None)
                  | Some (st, buf) ->
                    Log.info (fun m -> m "signed notify %a, ixfr"
                                 Domain_name.pp zone);
                    Ok (Domain_name.Host_map.add zone (st, ip, name) zones,
                        Some (ip, buf))
              else begin
                Log.warn (fun m -> m "signed notify %a with SOA %a not newer %a"
                             Domain_name.pp zone Soa.pp soa Soa.pp old);
                let st = Transferred ts, ip, name in
                Ok (Domain_name.Host_map.add zone st zones, None)
              end
          end else begin
            Log.warn (fun m -> m "ignoring notify %a from %a (%a is primary)"
                         Domain_name.pp zone Ipaddr.V4.pp ip Ipaddr.V4.pp ip');
            Error Rcode.Refused
          end
      end
    | _ ->
      Log.warn (fun m -> m "ignoring notify %a"
                   Packet.Question.pp (Domain_name.raw zone, typ));
      Error Rcode.FormErr

  let authorise_zone zones keyname header zone =
    match Domain_name.Host_map.find zone zones with
    | None ->
      Log.warn (fun m -> m "ignoring %a, unknown zone" Domain_name.pp zone);
      Error Rcode.Refused
    | Some (st, ip, name) ->
      (* TODO use NotAuth instead of Refused here? *)
      guard (match id st with None -> true | Some id' -> fst header = id')
        Rcode.Refused >>= fun () ->
      guard (Authentication.access `Transfer ?key:keyname ~zone)
        Rcode.Refused >>| fun () ->
      Log.debug (fun m -> m "authorized access to zone %a (with key %a)"
                    Domain_name.pp zone Domain_name.pp name);
      (st, ip, name)

  let rrs_in_zone zone rr_map =
    Domain_name.Map.filter
      (fun name _ -> Domain_name.is_subdomain ~subdomain:name ~domain:zone)
      rr_map

  let handle_axfr t zones ts keyname header zone (fresh_soa, fresh_zone) =
    authorise_zone zones keyname header zone >>= fun (st, ip, name) ->
    match st with
    | Requested_axfr (_, _, _) ->
      (* TODO partial AXFR, but decoder already rejects them *)
      Log.info (fun m -> m "received authorised AXFR for %a: %a"
                   Domain_name.pp zone Packet.Axfr.pp (fresh_soa, fresh_zone));
      (* SOA should be higher than ours! *)
      (match Dns_trie.lookup zone Soa t.data with
       | Error _ ->
         Log.info (fun m -> m "no soa for %a, maybe first axfr"
                      Domain_name.pp zone);
         Ok ()
       | Ok soa ->
         if Soa.newer ~old:soa fresh_soa then
           Ok ()
         else begin
           Log.warn (fun m -> m "AXFR for %a (%a) is not newer than ours (%a)"
                        Domain_name.pp zone Soa.pp fresh_soa Soa.pp soa);
           (* TODO what is the right error here? *)
           Error Rcode.ServFail
         end) >>= fun () ->
      (* filter map to ensure that all entries are in the zone! *)
      let fresh_zone = rrs_in_zone zone fresh_zone in
      let trie' =
        let trie = Dns_trie.remove_zone zone t.data in
        (* insert SOA explicitly - it's not part of entries (should it be?) *)
        let trie = Dns_trie.insert zone Rr_map.Soa fresh_soa trie in
        Dns_trie.insert_map fresh_zone trie
      in
      (* check new trie *)
      (match Dns_trie.check trie' with
        | Ok () ->
          Log.info (fun m -> m "zone %a transferred, and life %a"
                       Domain_name.pp zone Soa.pp fresh_soa)
        | Error err ->
          Log.warn (fun m -> m "check on transferred zone %a failed: %a"
                       Domain_name.pp zone Dns_trie.pp_zone_check err));
      let zones =
        Domain_name.Host_map.add zone (Transferred ts, ip, name) zones
      in
      Ok ({ t with data = trie' }, zones)
    | _ ->
      Log.warn (fun m -> m "ignoring AXFR %a unmatched state"
                   Domain_name.pp zone);
      Error Rcode.Refused

  let handle_ixfr t zones ts keyname header zone (fresh_soa, data) =
    authorise_zone zones keyname header zone >>= fun (st, ip, name) ->
    match st with
    | Requested_ixfr (_, _, soa, _) ->
      if Soa.newer ~old:soa fresh_soa then
        let trie' = match data with
          | `Empty -> t.data
          | `Full entries ->
            let fresh_zone = rrs_in_zone zone entries in
            let trie = Dns_trie.remove_zone zone t.data in
            Dns_trie.insert_map fresh_zone trie
          | `Difference (_, del, add) ->
            let del = rrs_in_zone zone del
            and add = rrs_in_zone zone add
            in
            Dns_trie.insert_map add (Dns_trie.remove_map del t.data)
        in
        let trie' = Dns_trie.insert zone Rr_map.Soa fresh_soa trie' in
        (match Dns_trie.check trie' with
         | Ok () ->
           Log.info (fun m -> m "zone %a transferred, and life %a"
                        Domain_name.pp zone Soa.pp fresh_soa)
         | Error err ->
           Log.warn (fun m -> m "check on IXFR zone %a failed: %a"
                        Domain_name.pp zone Dns_trie.pp_zone_check err));
        let zones =
          Domain_name.Host_map.add zone (Transferred ts, ip, name) zones
        in
        Ok ({ t with data = trie' }, zones)
      else begin
        Log.warn (fun m -> m "requested zone %a soa %a, got %a as fresh soa"
                     Domain_name.pp zone Soa.pp soa Soa.pp fresh_soa);
        Error Rcode.ServFail
      end
    | _ ->
      Log.warn (fun m -> m "ignoring IXFR %a unmatched state"
                   Domain_name.pp zone);
      Error Rcode.Refused

  let handle_answer t zones now ts keyname header zone typ (answer, _) =
    authorise_zone zones keyname header zone >>= fun (st, ip, name) ->
    match st with
    | Requested_soa (_, _, retry, _) ->
      Log.debug (fun m -> m "received SOA after %d retries" retry);
      (* request AXFR now in case of serial is higher! *)
      begin
        match
          Dns_trie.lookup zone Rr_map.Soa t.data,
          Name_rr_map.find (Domain_name.raw zone) Soa answer
        with
        | _, None ->
          Log.err (fun m -> m "didn't receive SOA for %a from %a (answer %a)"
                      Domain_name.pp zone Ipaddr.V4.pp ip Name_rr_map.pp answer);
          Error Rcode.FormErr
        | Ok cached_soa, Some fresh ->
          if Soa.newer ~old:cached_soa fresh then
            match ixfr t now ts zone cached_soa name with
            | None ->
              Log.warn (fun m -> m "trouble creating ixfr for %a (using %a)"
                           Domain_name.pp zone Domain_name.pp name);
              (* TODO: reset state? *)
              Ok (t, zones, None)
            | Some (st, buf) ->
              Log.debug (fun m -> m "requesting IXFR for %a now!"
                            Domain_name.pp zone);
              let zones = Domain_name.Host_map.add zone (st, ip, name) zones in
              Ok (t, zones, Some (ip, buf))
          else begin
            Log.info (fun m -> m "received soa %a %a is not newer than %a"
                         Soa.pp fresh Domain_name.pp zone Soa.pp cached_soa);
            let zones =
              Domain_name.Host_map.add zone (Transferred ts, ip, name) zones
            in
            Ok (t, zones, None)
          end
        | Error _, _ ->
          Log.info (fun m -> m "couldn't find soa, requesting AXFR");
          begin match axfr t now ts zone name with
            | None ->
              Log.warn (fun m -> m "trouble building axfr");
              Ok (t, zones, None)
            | Some (st, buf) ->
              Log.debug (fun m -> m "requesting AXFR for %a now!"
                            Domain_name.pp zone);
              let zones = Domain_name.Host_map.add zone (st, ip, name) zones in
              Ok (t, zones, Some (ip, buf))
          end
      end
    | _ ->
      Log.warn (fun m -> m "ignoring question %a unmatched state"
                   Packet.Question.pp (Domain_name.raw zone, typ));
      Error Rcode.Refused

  let handle_packet (t, zones) now ts ip p keyname =
    let keyname = match keyname with
      | None -> None
      | Some k -> Some (Domain_name.raw k)
    in
    match p.Packet.data with
    | `Query ->
      let flags, data, additional = match handle_question t p.question with
        | Ok (flags, data, additional) -> flags, `Answer data, additional
        | Error (rcode, data) ->
          err_flags rcode, `Rcode_error (rcode, Opcode.Query, data), None
      in
      let answer =
        Packet.create ?additional (fst p.header, flags) p.question data
      in
      (t, zones), Some answer, None
    | `Answer a ->
      begin match Domain_name.host (fst p.question) with
        | Error _ ->
          Log.warn (fun m -> m "answer for a non-hostname zone %a"
                       Domain_name.pp (fst p.question));
          (t, zones), None, None
        | Ok zone ->
          let t, out =
            let typ = snd p.question in
            match handle_answer t zones now ts keyname p.header zone typ a with
            | Ok (t, zones, out) -> (t, zones), out
            | Error rcode ->
              Log.warn (fun m -> m "error %a while processing answer %a"
                           Rcode.pp rcode Packet.pp p);
              (t, zones), None
          in
          t, None, out
      end
    | `Update _ ->
      (* we don't deal with updates *)
      let pkt = `Rcode_error (Rcode.Refused, Opcode.Update, None) in
      let answer = Packet.create p.header p.question pkt in
      (t, zones), Some answer, None
    | `Axfr_request | `Ixfr_request _ ->
      (* we don't reply to axfr/ixfr requests *)
      let pkt = `Rcode_error (Rcode.Refused, Opcode.Query, None) in
      let answer = Packet.create p.header p.question pkt in
      (t, zones), Some answer, None
    | `Rcode_error (Rcode.NotAuth, Opcode.Query, _) ->
      (* notauth axfr and SOA replies (and drop the resp. zone) *)
      begin match Domain_name.host (fst p.Packet.question) with
        | Error _ ->
          Log.warn (fun m -> m "rcode error with a non-hostname zone %a"
                       Domain_name.pp (fst p.Packet.question));
          (t, zones), None, None
        | Ok zone ->
          match authorise_zone zones keyname p.Packet.header zone with
          | Ok (Requested_axfr (_, _, _), _, _
               | Requested_ixfr (_, _, _, _), _, _
               | Requested_soa (_, _, _, _), _, _) ->
            Log.warn (fun m -> m "notauth reply, dropping zone %a"
                         Domain_name.pp zone);
            let trie = Dns_trie.remove_zone zone t.data in
            let zones' = Domain_name.Host_map.remove zone zones in
            ({ t with data = trie }, zones'), None, None
          | _ ->
            Log.warn (fun m -> m "ignoring unsolicited notauth error");
            (t, zones), None, None
      end
    | `Rcode_error (rc, Opcode.Query, _) ->
      (* errors with IXFR: try AXFR *)
      begin match Domain_name.host (fst p.Packet.question) with
        | Error _ ->
          Log.warn (fun m -> m "rcode error with non-hostname zone %a"
                       Domain_name.pp (fst p.Packet.question));
          (t, zones), None, None
        | Ok zone ->
          match authorise_zone zones keyname p.Packet.header zone with
          | Ok (Requested_ixfr (_, _, _, _), _, name) ->
            Log.warn (fun m -> m "received %a reply for %a (req IXFR, now AXFR)"
                         Rcode.pp rc Domain_name.pp zone);
            begin match axfr t now ts zone name with
              | None ->
                Log.err (fun m -> m "failed to construct AXFR");
                (t, zones), None, None
              | Some (st, buf) ->
                Log.debug (fun m -> m "requesting AXFR for %a now!"
                              Domain_name.pp zone);
                let zones' =
                  Domain_name.Host_map.add zone (st, ip, name) zones
                in
                (t, zones'), None, Some (ip, buf)
            end
          | _ ->
            Log.warn (fun m -> m "ignoring unsolicited notauth error");
            (t, zones), None, None
      end
    | `Axfr_reply data ->
      begin match Domain_name.host (fst p.question) with
        | Error _ ->
          Log.warn (fun m -> m "axfr reply with non-hostname zone %a"
                       Domain_name.pp (fst p.question));
          (t, zones), None, None
        | Ok zone ->
          let r =
            match handle_axfr t zones ts keyname p.header zone data with
            | Ok (t, zones) -> t, zones
            | Error rcode ->
              Log.warn (fun m -> m "error %a while processing axfr %a"
                           Rcode.pp rcode Packet.pp p);
              t, zones
          in
          r, None, None
      end
    | `Ixfr_reply data ->
      begin match Domain_name.host (fst p.question) with
        | Error _ ->
          Log.warn (fun m -> m "ixfr where zone is not a hostname %a"
                       Domain_name.pp (fst p.question));
          (t, zones), None, None
        | Ok zone ->
          let r =
            match handle_ixfr t zones ts keyname p.header zone data with
            | Ok (t, zones) -> t, zones
            | Error rcode ->
              Log.warn (fun m -> m "error %a while processing axfr %a"
                           Rcode.pp rcode Packet.pp p);
              t, zones
          in
          r, None, None
      end
    | `Update_ack ->
      Log.warn (fun m -> m "ignoring update reply (never sending updates)");
      (t, zones), None, None
    | `Notify n ->
      begin match Domain_name.host (fst p.question) with
        | Error _ ->
          Log.warn (fun m -> m "notify for non-hostname zone %a" Domain_name.pp
                       (fst p.question));
          (t, zones), None, None
        | Ok zone ->
          let zones, flags, answer, out =
            let typ = snd p.question in
            match handle_notify t zones now ts ip zone typ n keyname with
            | Ok (zones, out) -> zones, authoritative, `Notify_ack, out
            | Error rcode ->
              let pkt = `Rcode_error (rcode, Opcode.Notify, None) in
              zones, err_flags rcode, pkt, None
          in
          let answer = Packet.create (fst p.header, flags) p.question answer in
          (t, zones), Some answer, out
      end
    | `Notify_ack ->
      Log.err (fun m -> m "ignoring notify ack (never sending notifications)");
      (t, zones), None, None
    | `Rcode_error (rc, op, data) ->
      Log.err (fun m -> m "ignoring rcode error %a for op %a data %a"
                  Rcode.pp rc Opcode.pp op
                  Fmt.(option ~none:(unit "no") Packet.Answer.pp) data);
      (t, zones), None, None

  let find_mac zones p =
    match p.Packet.data with
    | #Packet.request -> None
    | #Packet.reply ->
      match Domain_name.host (fst p.question) with
      | Error _ -> None
      | Ok zone ->
        match Domain_name.Host_map.find zone zones with
        | None -> None
        | Some (Requested_axfr (_, _, mac), _, _) -> Some mac
        | Some (Requested_ixfr (_, _, _, mac), _, _) -> Some mac
        | Some (Requested_soa (_, _, _, mac), _, _) -> Some mac
        | _ -> None

  let handle_buf t now ts proto ip buf =
    match
      safe_decode buf >>| fun res ->
      Log.debug (fun m -> m "received a packet from %a: %a" Ipaddr.V4.pp ip
                    Packet.pp res);
      res
    with
    | Error rcode ->
      tx_metrics (`Rcode_error (rcode, Query, None));
      t, Packet.raw_error buf rcode, None
    | Ok p ->
      let handle_inner keyname =
        let t, answer, out = handle_packet t now ts ip p keyname in
        let answer = match answer with
          | Some answer ->
            let max_size, edns = Edns.reply p.edns in
            let answer = Packet.with_edns answer edns in
            tx_metrics answer.Packet.data;
            let r = Packet.encode ?max_size proto answer in
            Some (answer, r)
          | None -> None
        in
        t, answer, out
      in
      let server, zones = t in
      let mac = find_mac zones p in
      match handle_tsig ?mac server now p buf with
      | Error (e, data) ->
        Logs.err (fun m -> m "error %a while handling tsig" Tsig_op.pp_e e);
        t, data, None
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
        | None -> None
        | Some (p, (buf, max_size)) ->
          match server.tsig_sign ~max_size ~mac name tsig ~key p buf with
          | None ->
            (* TODO: output buf? *)
            Log.warn (fun m -> m "couldn't use %a to tsig sign"
                         Domain_name.pp name);
            None
          | Some (buf, _) -> Some buf
        in
        t, answer', out

  let closed (t, zones) now ts ip' =
    (* if ip, port was registered for zone(s), re-open connections to remotes *)
    let zones', out =
      Domain_name.Host_map.fold (fun zone (_, ip, keyname) (zones', out) ->
          if Ipaddr.V4.compare ip ip' = 0 then
            match Authentication.find_zone_ips keyname with
            (* hidden secondary has latter = None *)
            | Some (_, _, None) ->
              begin match query_soa t now ts zone keyname with
                | None -> zones', out
                | Some (st, data) ->
                  (zone, (st, ip, keyname)) :: zones',
                  data :: out
              end
            | _ -> zones', out
          else
            zones', out)
        zones ([], [])
    in
    let zones'' = List.fold_left (fun z (zone, v) ->
        Domain_name.Host_map.add zone v z) zones zones'
    in
    (t, zones''), out
end
