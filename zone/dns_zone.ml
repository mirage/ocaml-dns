(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
 * Copyright (c) 2017 Hannes Mehnert <hannes@mehnert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * dnsserver.ml -- an authoritative DNS server
 *
 *)

let parse buf =
  Dns_zone_state.reset ();
  try
    (* TODO end-of-file handling? insert a newline at the end before lexing? *)
    let lexbuf = Lexing.from_string buf in
    Ok (Dns_zone_parser.zfile Dns_zone_lexer.token lexbuf)
  with
    | Parsing.Parse_error -> Error (`Msg (Fmt.str "zone parse error at line %d" Dns_zone_state.(state.lineno)))
    | Dns_zone_state.Zone_parse_problem s -> Error (`Msg (Fmt.str "zone parse problem at line %d: %s" Dns_zone_state.(state.lineno) s))
    | exn -> Error (`Msg (Printexc.to_string exn))

let src = Logs.Src.create "dns_zone" ~doc:"DNS zone parse"
module Log = (val Logs.src_log src : Logs.LOG)

let decode_zone trie zone data =
  match parse data with
  | Error `Msg msg ->
    Log.warn (fun m -> m "ignoring zone %a: %s (data %s)"
                 Domain_name.pp zone msg data);
    trie, Dns.Name_rr_map.empty
  | Ok rrs ->
    (* we take all resource records within the zone *)
    let in_zone subdomain = Domain_name.is_subdomain ~domain:zone ~subdomain in
    let zone_rrs, other_rrs =
      Domain_name.Map.partition (fun name _ -> in_zone name) rrs
    in
    let trie' = Dns_trie.insert_map zone_rrs trie in
    match Dns_trie.lookup zone Dns.Rr_map.Soa trie', Dns_trie.check trie' with
    | Error _, _ ->
      Log.warn (fun m -> m "ignoring %a: no SOA" Domain_name.pp zone);
      trie, Dns.Name_rr_map.empty
    | _, Error ze ->
      Log.warn (fun m -> m "ignoring %a: zone check failed %a"
                   Domain_name.pp zone Dns_trie.pp_zone_check ze);
      trie, Dns.Name_rr_map.empty
    | Ok _, Ok () -> trie', other_rrs

let add_additional_glue trie (zone, other_rrs) =
  (* collect potential glue:
     - find NS entries for zone
     - find A and AAAA records for name servers in other rrs
       (Dns_trie.check ensures that the NS in zone have an address record)
     - only if the other names are not in zones, they are picked from
       this zone file *)
  match Dns_trie.lookup zone Dns.Rr_map.Ns trie with
  | Error _ ->
    Log.warn (fun m -> m "no NS entries for %a" Domain_name.pp zone);
    trie
  | Ok (_, name_servers) ->
    let not_authoritative nameserver =
      match Dns_trie.lookup nameserver Dns.Rr_map.A trie with
      | Error (`NotAuthoritative | `Delegation _) -> true
      | _ -> false
    in
    let need_glue =
      Domain_name.Host_set.filter not_authoritative name_servers
    in
    let raw_need_glue =
      Domain_name.Host_set.fold (fun ns acc ->
          Domain_name.Set.add (Domain_name.raw ns) acc)
        need_glue Domain_name.Set.empty
    in
    let trie =
      Domain_name.Host_set.fold (fun ns trie ->
          let dn = Domain_name.raw ns in
          match
            Dns.Name_rr_map.find dn Dns.Rr_map.A other_rrs,
            Dns.Name_rr_map.find dn Dns.Rr_map.Aaaa other_rrs
          with
          | Some v4, Some v6 ->
            let trie = Dns_trie.insert ns Dns.Rr_map.A v4 trie in
            Dns_trie.insert ns Dns.Rr_map.Aaaa v6 trie
          | Some v4, None -> Dns_trie.insert ns Dns.Rr_map.A v4 trie
          | None, Some v6 -> Dns_trie.insert ns Dns.Rr_map.Aaaa v6 trie
          | None, None ->
            Logs.info (fun m -> m "unknown IP for NS %a (used in zone %a)"
                          Domain_name.pp ns Domain_name.pp zone);
            trie)
        need_glue trie
    in
    Domain_name.Map.iter (fun name value ->
        let leftover =
          if Domain_name.Set.mem name raw_need_glue then
            Dns.Rr_map.remove A (Dns.Rr_map.remove Aaaa value)
          else
            value
        in
        if Dns.Rr_map.is_empty leftover then
          ()
        else begin
          Log.warn (fun m -> m "ignoring %d entries in zone file %a"
                       (Dns.Rr_map.cardinal leftover) Domain_name.pp zone);
          Dns.Rr_map.iter (fun b ->
              Log.warn (fun m -> m "%s" (Dns.Rr_map.text_b name b)))
            leftover
        end)
      other_rrs;
    trie

let decode_keys zone keys =
  match parse keys with
  | Error `Msg msg ->
    Log.warn (fun m -> m "ignoring keys for %a: %s (data: %s)"
                 Domain_name.pp zone msg keys);
    Domain_name.Map.empty
  | Ok rrs ->
    let tst subdomain = Domain_name.is_subdomain ~domain:zone ~subdomain in
    Domain_name.Map.fold (fun n data acc ->
        if not (tst n) then begin
          Log.warn (fun m -> m "ignoring key %a (not in zone %a)"
                       Domain_name.pp n Domain_name.pp zone);
          acc
        end else
          match Dns.Rr_map.(find Dnskey data) with
          | None ->
            Log.warn (fun m -> m "no dnskey found %a" Domain_name.pp n);
            acc
          | Some (_, keys) ->
            match Dns.Rr_map.Dnskey_set.elements keys with
            | [ x ] -> Domain_name.Map.add n x acc
            | xs ->
              Log.warn (fun m -> m "ignoring %d dnskeys for %a (only one supported)"
                           (List.length xs) Domain_name.pp n);
              acc)
      rrs Domain_name.Map.empty

let decode_zones bindings =
  let trie, zones, glue =
    List.fold_left (fun (trie, zones, glues) (name, data) ->
        match Domain_name.of_string name with
        | Error `Msg msg ->
          Log.warn (fun m -> m "ignoring %s, not a domain name %s" name msg);
          trie, zones, glues
        | Ok name ->
          let trie, glue = decode_zone trie name data in
          trie, Domain_name.Set.add name zones, (name, glue) :: glues)
      (Dns_trie.empty, Domain_name.Set.empty, [])
      bindings
  in
  let trie = List.fold_left add_additional_glue trie glue in
  zones, trie

let decode_zones_keys bindings =
  let key_domain = Domain_name.of_string_exn "_keys" in
  let trie, keys, zones, glue =
    List.fold_left (fun (trie, keys, zones, glues) (name, data) ->
        match Domain_name.of_string name with
        | Error `Msg msg ->
          Log.warn (fun m -> m "ignoring %s, not a domain name %s" name msg);
          trie, keys, zones, glues
        | Ok name ->
          if Domain_name.is_subdomain ~domain:key_domain ~subdomain:name then
            let domain = Domain_name.drop_label_exn ~rev:true name in
            let keys' = decode_keys domain data in
            let f key a _b =
              Log.warn (fun m -> m "encountered key %a also in %a"
                           Domain_name.pp key Domain_name.pp domain);
              Some a
            in
            trie, Domain_name.Map.union f keys keys', zones, glues
          else
            let trie, glue = decode_zone trie name data in
            trie, keys, Domain_name.Set.add name zones, (name, glue) :: glues)
      (Dns_trie.empty, Domain_name.Map.empty, Domain_name.Set.empty, [])
      bindings
  in
  let trie = List.fold_left add_additional_glue trie glue in
  zones, trie, Domain_name.Map.bindings keys
