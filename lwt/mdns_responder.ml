(*
 * Copyright (c) 2015 Luke Dunstan <LukeDunstan81@gmail.com>
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
 *)

open Lwt

module DR = Dns.RR
module DP = Dns.Packet
module DS = Dns.Protocol.Server
module DQ = Dns.Query
module H = Dns.Hashcons

type ip_endpoint = Ipaddr.V4.t * int

module type TRANSPORT = sig
  val alloc : unit -> Dns.Buf.t
  val write : ip_endpoint -> Dns.Buf.t -> unit Lwt.t
  val sleep : float -> unit Lwt.t
end

let label str =
  MProf.Trace.label str

let multicast_ip = Ipaddr.V4.of_string_exn "224.0.0.251"

let sentinel = DR.Unknown (0, [])

let filter_out_known rr known =
  match (rr, known) with

  | (DR.A l, DP.A k) ->
    let lf = List.filter (fun ip -> k <> ip) l
    in
    if lf <> [] then DR.A lf else sentinel

  | (DR.AAAA l, DP.AAAA k) ->
    let lf = List.filter (fun ip -> k <> ip) l
    in
    if lf <> [] then DR.AAAA lf else sentinel

  | (DR.CNAME l, DP.CNAME k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.CNAME lf else sentinel

  | (DR.MB l, DP.MB k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.MB lf else sentinel

  | (DR.MG l, DP.MB k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.MG lf else sentinel

  | (DR.MR l, DP.MR k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.MR lf else sentinel

  | (DR.NS l, DP.NS k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.NS lf else sentinel

  (* SOA not relevant *)
  | (DR.WKS l, DP.WKS (ka, kp, kb)) ->
    let lf = List.filter (fun (address, protocol, bitmap) ->
        address <> ka || protocol <> kp || bitmap.H.node <> kb) l
    in
    if lf <> [] then DR.WKS lf else sentinel

  | (DR.PTR l, DP.PTR k) ->
    let lf = List.filter (fun d -> d.DR.owner.H.node <> k) l
    in
    if lf <> [] then DR.PTR lf else sentinel

  | (DR.HINFO l, DP.HINFO (kcpu, kos)) ->
    let lf = List.filter (fun (cpu, os) -> cpu.H.node <> kcpu || os.H.node <> kos) l
    in
    if lf <> [] then DR.HINFO lf else sentinel

  | (DR.MINFO l, DP.MINFO (krm, kem)) ->
    let lf = List.filter (fun (rm, em) -> rm.DR.owner.H.node <> krm || em.DR.owner.H.node <> kem) l
    in
    if lf <> [] then DR.MINFO lf else sentinel

  | (DR.MX l, DP.MX (kp, kn)) ->
    let lf = List.filter (fun (preference, d) -> preference <> kp || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.MX lf else sentinel

  | (DR.TXT ll, DP.TXT kl) ->
    sentinel  (* TODO *)

  | (DR.RP l, DP.RP (kmbox, ktxt)) ->
    let lf = List.filter (fun (mbox, txt) -> mbox.DR.owner.H.node <> kmbox || txt.DR.owner.H.node <> ktxt) l
    in
    if lf <> [] then DR.RP lf else sentinel

  | (DR.AFSDB l, DP.AFSDB (kt, kn)) ->
    let lf = List.filter (fun (t, d) -> t <> kt || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.AFSDB lf else sentinel

  | (DR.X25 l, DP.X25 k) ->
    let lf = List.filter (fun s -> s.H.node <> k) l
    in
    if lf <> [] then DR.X25 lf else sentinel

  | (DR.ISDN l, DP.ISDN (ka, ksa)) ->
    let lf = List.filter (fun (a, sa) ->
        let sa = match sa with None -> None | Some sa -> Some sa.H.node in
        a.H.node <> ka || sa <> ksa) l
    in
    if lf <> [] then DR.ISDN lf else sentinel

  | (DR.RT l, DP.RT (kp, kn)) ->
    let lf = List.filter (fun (preference, d) -> preference <> kp || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.RT lf else sentinel

  | (DR.SRV l, DP.SRV (kprio, kw, kport, kn)) ->
    let lf = List.filter (fun (priority, weight, port, d) ->
        priority <> kprio || weight <> kw || port <> kport || d.DR.owner.H.node <> kn) l
    in
    if lf <> [] then DR.SRV lf else sentinel

  | (DR.DS l, DP.DS (kt, ka, kd, kn)) ->
    let lf = List.filter (fun (tag, alg, digest, k) ->
        tag <> kt || alg <> ka || digest <> kd || k.H.node <> kn) l
    in
    if lf <> [] then DR.DS lf else sentinel

  | (DR.DNSKEY l, DP.DNSKEY (kfl, ktt, kk)) ->
    let lf = List.filter (fun (fl, t, k) ->
        let tt = DP.int_to_dnssec_alg t in
        match tt with
        | None -> false
        | Some tt -> fl <> kfl || tt <> ktt || k.H.node <> kk
      ) l
    in
    if lf <> [] then DR.DNSKEY lf else sentinel

  | (DR.RRSIG l, DP.RRSIG (ktyp, kalg, klbl, kttl, kexp_ts, kinc_ts, ktag, kname, ksign)) ->
    let lf = List.filter DR.(fun {
        rrsig_type = typ;
        rrsig_alg = alg;
        rrsig_labels = lbl;
        rrsig_ttl = ttl;
        rrsig_expiry = exp_ts;
        rrsig_incept = inc_ts;
        rrsig_keytag = tag;
        rrsig_name = name;
        rrsig_sig = sign;
      } ->
        typ <> ktyp || alg <> kalg || lbl <> klbl || ttl <> kttl ||
        exp_ts <> kexp_ts || inc_ts <> kinc_ts || tag <> ktag ||
        name <> kname || sign <> ksign
      ) l
    in
    if lf <> [] then DR.RRSIG lf else sentinel

  | (DR.Unknown _, _) -> sentinel

  | _, _ -> rr

let rec filter_known_list rr knownl =
  match knownl with
  | [] -> rr
  | known::tl ->
    begin
      let frr = filter_out_known rr known.DP.rdata in
      match frr with DR.Unknown _ -> frr | _ -> filter_known_list frr tl
    end


module Make (Transport : TRANSPORT) = struct
  type timestamp = int

  (* RFC 6762 section 10.2 implies that uniqueness is based on name/rrtype/rrclass,
     but section 8.1 implies that a domain name is enough. *)
  type unique_key = Dns.Name.t
  type unique_state = PreProbe | Probing | Confirmed
  type unique_assoc = unique_key * unique_state

  type t = {
    db : Dns.Loader.db;
    dnstrie : Dns.Trie.dnstrie;
    probe_condition : unit Lwt_condition.t;
    unique : (unique_key, unique_state) Hashtbl.t;
    mutable probe_forever : unit Lwt.t;
    mutable probe_restart : bool;
    mutable probe_tiebreak : bool;
    mutable probe_end : bool;
    mutable probe_rrs : DP.rr list;
  }


  let of_db db =
    let dnstrie = db.Dns.Loader.trie in
    {
      db; dnstrie;
      probe_condition = Lwt_condition.create ();
      unique = Hashtbl.create 10;
      probe_forever=return_unit;
      probe_restart=false; probe_tiebreak=false; probe_end=false;
      probe_rrs=[];
    }

  let of_zonebufs zonebufs =
    let db = List.fold_left (fun db -> Dns.Zone.load ~db []) 
        (Dns.Loader.new_db ()) zonebufs in
    of_db db

  let of_zonebuf zonebuf = of_zonebufs [zonebuf]


  let add_unique_hostname t name ?(ttl=120l) ip =
    (* TODO: support IPv6 with AAAA *)
    (* Add it to the trie *)
    Dns.Loader.add_a_rr ip ttl name t.db;
    (* Add an entry to our own table of unique records *)
    Hashtbl.add t.unique name PreProbe


  let unique_of_key t name =
    try
      let state = Hashtbl.find t.unique name in
      Some state
    with
    | Not_found -> None

  (* This predicate controls the cache-flush bit *)
  let is_confirmed_unique t owner rdata =
    (* FIXME: O(N) *)
    match unique_of_key t owner with
    | Some state -> state = Confirmed
    | None -> false


  let prepare_probe t =
    (* Build a list of names that need to be probed *)
    let names = Hashtbl.fold (
      fun name state l ->
        if state <> Confirmed then begin
          name :: l
        end else
          l
      ) t.unique []
    in
    (* Mark the names as state Probing *)
    List.iter (fun name -> Hashtbl.replace t.unique name Probing) names;
    (* Build a list of questions *)
    let questions = List.map (fun name -> DP.({
        q_name = name;
        q_type = Q_ANY_TYP;
        q_class = Q_IN;
        q_unicast = Q_mDNS_Unicast;  (* request unicast response as per RFC 6762 section 8.1 para 6 *)
      })) names
    in
    (* Reuse Query.answer_multiple to get the records that we need for the authority section *)
    let answer = DQ.answer_multiple ~dnssec:false ~mdns:true questions t.dnstrie in
    let authorities = List.filter (fun answer -> Hashtbl.mem t.unique answer.DP.name) answer.DQ.answer in
    if authorities = [] then
      (* There are no unique records to probe for *)
      None
    else
      (* I don't know whether the cache flush bit needs to be set in the authority RRs, but seems logical *)
      let authorities = List.map (fun rr -> { rr with DP.flush = true }) authorities in
      let detail = DP.({ qr=Query; opcode=Standard; aa=false; tc=false; rd=false; ra=false; rcode=NoError; }) in
      let query = DP.({ id=0; detail; questions; answers=[]; authorities; additionals=[]; }) in
      let obuf = DP.marshal (Transport.alloc ()) query in
      Some obuf


  exception RestartProbe

  let probe_restart t =
    t.probe_restart <- true;
    Lwt_condition.signal t.probe_condition ()

  let check_probe_restart t =
    if t.probe_restart then
      raise RestartProbe

  let sleep t f =
    Transport.sleep f >>= fun () ->
    return_unit

  let wait_cond t =
    Lwt_condition.wait t.probe_condition >>= fun () ->
    return_unit

  let probe_cycle t packet =
    let delay f =
      check_probe_restart t;
      Lwt.pick [
        sleep t f;
        wait_cond t
      ] >>= fun () ->
      check_probe_restart t;
      return_unit
    in
    (* First probe *)
    let dest = (multicast_ip,5353) in
    label "probe.w1";
    Transport.write dest packet >>= fun () ->
    (* Fixed delay of 250 ms *)
    label "probe.d1";
    delay 0.25 >>= fun () ->
    (* Second probe *)
    label "probe.w2";
    Transport.write dest packet >>= fun () ->
    (* Fixed delay of 250 ms *)
    label "probe.d2";
    delay 0.25 >>= fun () ->
    (* Third probe *)
    label "probe.w3";
    Transport.write dest packet >>= fun () ->
    (* Fixed delay of 250 ms *)
    label "probe.d3";
    delay 0.25 >>= fun () ->
    (* Build a list of names that have probed successfully *)
    let names = Hashtbl.fold (
      fun name state l ->
        if state = Probing then begin
          name :: l
        end else begin
          l
        end
      ) t.unique []
    in
    (* Mark them as confirmed *)
    List.iter (fun name -> Hashtbl.replace t.unique name Confirmed) names;
    return_unit

  let try_probe t =
    (* TODO: probes should be per-link if there are multiple NICs *)
    t.probe_restart <- false;
    match prepare_probe t with
    | None ->
      return false
    | Some packet ->
      probe_cycle t packet >>= fun () ->
      return true

  let rec probe_forever t first first_wakener =
    begin
      try_lwt
        (* If we lose a simultaneous probe tie-break then we have to delay 1 second *)
        (* TODO: if there are more than 15 conflicts in 10 seconds then we are
           supposed to wait 5 seconds *)
        (if t.probe_tiebreak then
          Transport.sleep 1.0
        else
          return_unit) >>= fun () ->
        try_probe t >>= fun done_probe ->
        (* We will only reach this point if the probe cycle has completed *)
        if !first then begin
          (* Only once, because a thread can only be woken once *)
          first := false;
          Lwt.wakeup first_wakener ()
        end;
        if done_probe then
          return_unit
        else begin
          (* If there is nothing to do, block until we get a signal *)
          label "probe_idle";
          Lwt_condition.wait t.probe_condition
        end
      with
      | RestartProbe -> return_unit
      | _ -> return_unit
    end >>= fun () ->
    if t.probe_end then begin
      return_unit
    end else begin
      probe_forever t first first_wakener
    end

  let first_probe t =
    label "first_probe";
    (* Random delay of 0-250 ms *)
    Transport.sleep (Random.float 0.25) >>= fun () ->
    let first = ref true in
    let first_wait, first_wakener = Lwt.wait () in
    t.probe_forever <- probe_forever t first first_wakener;
    (* The caller may wait for the first complete probe cycle *)
    first_wait

  let announce t ~repeat =
    label "announce";
    let questions = ref [] in
    let build_questions node =
      let q = DP.({
        q_name = node.DR.owner.H.node;
        q_type = Q_ANY_TYP;
        q_class = Q_IN;
        q_unicast = Q_Normal;
      }) in
      questions := q :: !questions
    in
    let dedup_answer answer =
      (* Delete duplicate RRs from the response *)
      (* FIXME: O(N*N) *)
      (* TODO: Dns.Query shouldn't generate duplicate RRs *)
      let rr_eq rr1 rr2 =
        rr1.DP.name = rr2.DP.name &&
        DP.compare_rdata rr1.DP.rdata rr2.DP.rdata = 0
      in
      let rec dedup l =
        match l with
        | [] -> l
        | hd::tl -> if List.exists (rr_eq hd) tl
          then tl
          else hd :: dedup tl
      in
      { answer with DQ.answer = dedup answer.DQ.answer; DQ.additional = [] }
    in
    let rec write_repeat dest obuf repeat sleept =
      (* RFC 6762 section 11 - TODO: send with IP TTL = 255 *)
      Transport.write dest obuf >>= fun () ->
      if repeat = 1 then
        return_unit
      else
        Transport.sleep sleept >>= fun () ->
        write_repeat dest obuf (repeat - 1) (sleept *. 2.0)
    in
    Dns.Trie.iter build_questions t.dnstrie;
    (* TODO: if the data for a shared record has changed, we should send 'goodbye'.
       See RFC 6762 section 8.4 *)
    let answer = DQ.answer_multiple ~dnssec:false ~mdns:true ~flush:(is_confirmed_unique t) !questions t.dnstrie in
    let answer = dedup_answer answer in
    let dest_host = multicast_ip in
    let dest_port = 5353 in
    (* TODO: refactor Dns.Query to avoid the need for this fake query *)
    let fake_detail = DP.({ qr=Query; opcode=Standard; aa=false; tc=false; rd=false; ra=false; rcode=NoError}) in
    let fake_query = DP.({
        id=0;
        detail=fake_detail;
        questions= !questions; answers=[]; authorities=[]; additionals=[];
    }) in
    let response = DQ.response_of_answer ~mdns:true fake_query answer in
    if response.DP.answers = [] then
      return_unit
    else
      (* TODO: limit the response packet size *)
      let obuf = Transport.alloc () in
      match DS.marshal obuf fake_query response with
      | None -> return_unit
      | Some obuf -> write_repeat (dest_host,dest_port) obuf repeat 1.0


  let get_answer t query =
    let filter name rrset =
      (* RFC 6762 section 7.1 - Known Answer Suppression *)
      (* First match on owner name and check TTL *)
      let relevant_known = List.filter (fun known ->
          (name = known.DP.name) && (known.DP.ttl >= Int32.div rrset.DR.ttl 2l)
        ) query.DP.answers
      in
      (* Now suppress known records based on RR type *)
      let rdata = filter_known_list rrset.DR.rdata relevant_known in
      {
        DR.ttl = (match rdata with DR.Unknown _ -> 0l | _ -> rrset.DR.ttl);
        DR.rdata = rdata;
      }
    in
    (* DNSSEC disabled for testing *)
    DQ.answer_multiple ~dnssec:false ~mdns:true ~filter ~flush:(is_confirmed_unique t) query.DP.questions t.dnstrie

  let process_query t src dst query =
    let check_unique query response =
      (* A "simultaneous probe conflict" occurs if we see a (probe) request
         that contains a question matching one of our unique records,
         and the authority section contains different data. *)
      (* let unique_qs = List.filter (fun q -> Hashtbl.mem t.unique q.DP.q_name) query.DP.questions in *)
      let theirs = List.filter (fun rr -> Hashtbl.mem t.unique rr.DP.name) query.DP.authorities in
      List.iter (fun auth ->
          let state = Hashtbl.find t.unique auth.DP.name in
          (* For this step we only care aboue records that are part of the current probe cycle. *)
          if state = Probing then
            try
              let ours = List.find (fun rr -> Hashtbl.mem t.unique rr.DP.name) response.DP.answers in
              (* TODO: proper lexicographical comparison *)
              let compare = DP.compare_rdata ours.DP.rdata auth.DP.rdata in
              if compare < 0 then begin
                (* Our data is less than the requester's data, so restart the probe sequence *)
                Hashtbl.replace t.unique auth.DP.name PreProbe;
                t.probe_tiebreak <- true;
                probe_restart t
              end
            (* else if compare > 0 then the requester will restart its own probe sequence *)
            (* else if compare = 0 then there is no conflict *)
            (* TODO: if compare = 0 and the peer is sending a TTL less than half of our record
               then we are supposed to announce our record to avoid premature expiry *)
            with
            | Not_found -> ()
        ) theirs;
      (* Now filter out answers that are unique but unconfirmed *)
      let answers = List.filter (fun rr ->
          match unique_of_key t rr.DP.name with
          | Some state -> state = Confirmed  (* Exclude if unconfirmed *)
          | None -> true  (* OK, not unique *)
        ) response.DP.answers in
      { response with DP.answers = answers }
    in
    let get_delay legacy response =
      if legacy then
        (* No delay for legacy mode *)
        return_unit
      else if List.exists (fun a -> a.DP.flush) response.DP.answers then
        (* No delay for records that have been verified as unique *)
        (* TODO: send separate unique and non-unique responses if applicable *)
        return_unit
      else
        (* Delay response for 20-120 ms *)
        Transport.sleep (0.02 +. Random.float 0.1)
    in
    match Dns.Protocol.contain_exc "answer" (fun () -> get_answer t query) with
    | None -> return_unit
    | Some answer when answer.DQ.answer = [] -> return_unit
    | Some answer ->
      let src_host, src_port = src in
      let legacy = (src_port != 5353) in
      let unicast =
        (* True if all of the questions have the unicast response bit set *)
        (* TODO: split into separate unicast and multicast responses if applicable *)
        if legacy then
          false
        else
          List.for_all (fun q -> q.DP.q_unicast = DP.Q_mDNS_Unicast) query.DP.questions
      in
      let reply_host = if legacy || unicast then src_host else multicast_ip in
      let reply_port = src_port in
      (* RFC 6762 section 18.5 - TODO: check tc bit *)
      label "post delay";
      (* NOTE: echoing of questions is still required for legacy mode *)
      let response = DQ.response_of_answer ~mdns:(not legacy) query answer in
      let response = check_unique query response in
      if response.DP.answers = [] then
        return_unit
      else
        begin
          (* Possible delay before responding *)
          get_delay legacy response >>= fun () ->
          (* TODO: limit the response packet size *)
          let obuf = Transport.alloc () in
          match DS.marshal obuf query response with
          | None -> return_unit
          | Some obuf ->
            (* RFC 6762 section 11 - TODO: send with IP TTL = 255 *)
            Transport.write (reply_host,reply_port) obuf
        end


  let rename_unique t old_name state =
    let increment_name name = match Dns.Name.to_string_list name with
      | head :: tail ->
        let re = Re_str.regexp "\\(.*\\)\\([0-9]+\\)" in
        let new_head = if Re_str.string_match re head 0 then begin
          let num = int_of_string (Re_str.matched_group 2 head) in
          (Re_str.matched_group 1 head) ^ (string_of_int (num + 1))
        end else
          head ^ "2"
        in
        Dns.Name.of_string_list (new_head :: tail)
      | [] -> failwith "can't offer the DNS root"
    in
    (* Find the old RR from the trie *)
    let rrsets = match Dns.Trie.simple_lookup (Dns.Name.to_key old_name) t.dnstrie with
      | None -> failwith "rename_unique: old not not found"
      | Some node ->
        let rrsets = node.DR.rrsets in
        (* Remove the rrsets from the old node *)
        (* TODO: remove the node itself *)
        node.DR.rrsets <- [];
        rrsets
    in
    (* Create a new name *)
    let new_name = increment_name old_name in
    (* Add the new RR to the trie *)
    (* TODO: Dns.Loader doesn't support a simple rename operation *)
    List.iter (fun rrset -> match rrset.DR.rdata with
        | DR.A l -> List.iter (fun ip -> Dns.Loader.add_a_rr ip rrset.DR.ttl new_name t.db) l
        | _ -> failwith "Only A records are supported") rrsets;
    (* Remove the old entry from the hash table and add the new one *)
    Hashtbl.remove t.unique old_name;
    Hashtbl.replace t.unique new_name state

  let process_response t response =
    let conflict_exists l =
      List.exists (fun rr ->
          let name = rr.DP.name in
          match unique_of_key t name with
          | None -> false
          | Some state ->
            let exists = List.exists (fun our ->
                our.DP.name = name && DP.compare_rdata rr.DP.rdata our.DP.rdata = 0
              ) t.probe_rrs in
            if not exists then begin
              (* If we are currently probing then we must defer to the existing host *)
              (* In any case we must then re-probe *)
              if state = Probing then begin
                rename_unique t name PreProbe;
              end else begin
                Hashtbl.replace t.unique name PreProbe
              end;
              true
            end else
              (* if compare = 0 then there is no conflict *)
              false
        ) l
    in
    (* Check for conflicts with our unique records *)
    (* RFC 6762 section 9 - need to check all sections *)
    if conflict_exists response.DP.answers || conflict_exists response.DP.authorities || conflict_exists response.DP.additionals then
      probe_restart t;
    (* RFC 6762 section 10.5 - TODO: passive observation of failures *)
    return_unit


  let process t ~src ~dst ibuf =
    label "mDNS process";
    let open DP in
    match DS.parse ibuf with
    | None -> return_unit
    | Some dp when dp.detail.opcode != Standard ->
      (* RFC 6762 section 18.3 *)
      return_unit
    | Some dp when dp.detail.rcode != NoError ->
      (* RFC 6762 section 18.11 *)
      return_unit
    | Some dp when dp.detail.qr = Query -> process_query t src dst dp
    | Some dp -> process_response t dp

  let stop_probe t =
    (* TODO: send 'goodbye' for all names *)
    t.probe_end <- true;
    Lwt_condition.signal t.probe_condition ();
    t.probe_forever

  let trie t = t.dnstrie

end
