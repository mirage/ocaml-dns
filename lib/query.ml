(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
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
 * dnsquery.ml -- map DNS query-response mechanism onto trie database
 *
 *)

open Cstruct
open Operators
open RR
open Trie
open Name
open Printf

module H = Hashcons

(* We answer a query with RCODE, AA, ANSWERS, AUTHORITY and ADDITIONAL *)

type query_answer = {
  rcode : Packet.rcode;
  aa: bool;
  answer: Packet.rr list;
  authority: Packet.rr list;
  additional: Packet.rr list;
} 

let answer_query qname qtype trie = 

  let aa_flag = ref true in
  let ans_rrs = ref [] in
  let auth_rrs = ref [] in
  let add_rrs = ref [] in
  let addqueue = ref [] in
  let rrlog = ref [] in 

  (* We must avoid repeating RRSets in the response.  To do this, we
     keep two lists: one of RRSets that are already included, and one of
     RRSets we plan to put in the additional records section.  When we
     add an RRSet to the answer or authority section we strip it from
     the additionals queue, and when we enqueue an additional RRSet we
     make sure it's not already been included.  
     N.B. (1) We only log those types that might turn up more than once. 
     N.B. (2) We can use "==" and "!=" because owners are unique:
     they are either the owner field of a dnsnode from the 
     trie, or they are the qname, which only happens if it 
     does not have any RRSets of its own and matched a wildcard.*)
  let log_rrset owner rrtype =
    addqueue := List.filter 
	  (fun (n, t) -> rrtype != t || owner != n.owner.H.node) !addqueue;
    rrlog := (owner, rrtype) :: !rrlog
  in
  
  let in_log owner rrtype = 
    List.exists (fun (o, t) -> o == owner && t == rrtype) !rrlog
  in
  
  let enqueue_additional dnsnode rrtype = 
    if not (in_log dnsnode.owner.H.node rrtype) 
    then addqueue := (dnsnode, rrtype) :: !addqueue 
  in

  let add_rrset owner ttl rdata section = 
    let addrr ?(rrclass = Some Packet.RR_IN) rr = 
      let rrclass = match rrclass with
        | Some x -> x
        | None   -> failwith "unknown rrclass"
      in
      let rr = Packet.({ name = owner; 
                         cls = rrclass; 
                         ttl = ttl; 
                         rdata = rr }) 
      in
      match section with 
        | `Answer     -> ans_rrs  := rr :: !ans_rrs 
        | `Authority  -> auth_rrs := rr :: !auth_rrs 
        | `Additional -> add_rrs  := rr :: !add_rrs 
    in
    
    (* having extracted record from trie, partially marshal it *)
    match rdata with 
      | RR.A l -> 
          log_rrset owner Packet.RR_A; 
          List.iter (fun ip -> addrr (Packet.A ip)) l
            
      | RR.NS l -> 
          log_rrset owner Packet.RR_NS;
	      List.iter (fun d -> 
	        enqueue_additional d Packet.RR_A; 
            enqueue_additional d Packet.RR_AAAA;
            addrr (Packet.NS d.owner.H.node)
          ) l 
            
      | RR.CNAME l -> 
          List.iter (fun d -> addrr (Packet.CNAME d.owner.H.node)) l
            
      | RR.SOA l -> log_rrset owner Packet.RR_SOA;
	      List.iter (fun (prim,admin,serial,refresh,retry,expiry,minttl) ->
            addrr (Packet.SOA (prim.owner.H.node,
		                       admin.owner.H.node, 
                               serial, refresh, retry, expiry, minttl))) l
            
      | RR.MB l -> 
	      List.iter (fun d -> 
	        enqueue_additional d Packet.RR_A; 
            enqueue_additional d Packet.RR_AAAA;
	        addrr (Packet.MB d.owner.H.node)) l
            
      | RR.MG l -> 
	      List.iter (fun d -> addrr (Packet.MG d.owner.H.node)) l
            
      | RR.MR l -> 
	      List.iter (fun d -> addrr (Packet.MR d.owner.H.node)) l
            
      | RR.WKS l -> 
	      List.iter (fun (address, protocol, bitmap) -> 
	        addrr (Packet.WKS (address, protocol, bitmap.H.node))) l

      | RR.PTR l -> 
	      List.iter (fun d -> addrr (Packet.PTR d.owner.H.node)) l
            
      | RR.HINFO l -> 
	      List.iter (fun (cpu, os) -> 
	        addrr (Packet.HINFO (cpu.H.node, os.H.node))) l
            
      | RR.MINFO l -> 
	      List.iter (fun (rm, em) -> 
	        addrr (Packet.MINFO (rm.owner.H.node, em.owner.H.node))) l
            
      | RR.MX l -> 
	      List.iter (fun (preference, d) -> 
	        enqueue_additional d Packet.RR_A;
	        enqueue_additional d Packet.RR_AAAA;
	        addrr (Packet.MX (preference, d.owner.H.node))) l
            
      | RR.TXT l ->
	      List.iter (fun sl -> (* XXX handle multiple TXT cstrings properly *)
	        let data = List.map (fun x -> x.H.node) sl in 
            addrr (Packet.TXT data)) l
            
      | RR.RP l -> 
	      List.iter (fun (mbox, txt) -> 
	        addrr (Packet.RP (mbox.owner.H.node, txt.owner.H.node))) l
            
      | RR.AFSDB l ->
	      List.iter (fun (t, d) -> 
	        enqueue_additional d Packet.RR_A;
	        enqueue_additional d Packet.RR_AAAA;
	        addrr (Packet.AFSDB (t, d.owner.H.node))) l
            
      | RR.X25 l -> 
          log_rrset owner Packet.RR_X25;
	      List.iter (fun s -> addrr (Packet.X25 s.H.node)) l
            
      | RR.ISDN l -> 
          log_rrset owner Packet.RR_ISDN;
	      List.iter (fun (a, sa) ->
            let sa = match sa with None -> None | Some sa -> Some sa.H.node in
            addrr (Packet.ISDN (a.H.node, sa))) l

      (*
        (function (* XXX handle multiple cstrings properly *)
        | (addr, None) 
        -> addrr (`ISDN addr.H.node)
        | (addr, Some sa) (* XXX Handle multiple charstrings properly *)
        -> addrr (`ISDN (addr.H.node ^ sa.H.node))) l
      *)
            
      | RR.RT l -> 
	      List.iter (fun (preference, d) -> 
	        enqueue_additional d Packet.RR_A;
	        enqueue_additional d Packet.RR_AAAA;
	        enqueue_additional d Packet.RR_X25;
	        enqueue_additional d Packet.RR_ISDN;
	        addrr (Packet.RT (preference, d.owner.H.node))) l
            
      | RR.AAAA l -> 
          log_rrset owner Packet.RR_AAAA;
	      List.iter (fun i -> addrr (Packet.AAAA i.H.node)) l 
            
      | RR.SRV l -> 
          List.iter (fun (priority, weight, port, d) -> 
	        enqueue_additional d Packet.RR_A;
	        enqueue_additional d Packet.RR_AAAA;
	        addrr (Packet.SRV (priority, weight, port, d.owner.H.node))) l
            
      (* | RR.UNSPEC l ->  *)
      (*     List.iter (fun s -> addrr (Packet.UNSPEC s.H.node)) l *)

      | RR.DNSKEY l -> 
          List.iter (fun  (fl, t, k) ->
            let tt = Packet.int_to_dnssec_alg t in
            match tt with
              | None -> failwith (sprintf "bad dnssec alg type t:%d" t)
              | Some tt -> addrr (Packet.DNSKEY (fl, tt, k.H.node))
          ) l

      | RR.Unknown (t,l) -> 
          let s = l ||> (fun x -> x.H.node) |> String.concat "" in 
           addrr (Packet.UNKNOWN (t, s))

      | _ -> failwith "unknown rr"
  in
  
  (* Extract relevant RRSets given a query type, a list of RRSets and a flag to
     say whether to return Cnames too *)
  let get_rrsets qtype sets cnames_ok = 
    let match_rrset qtype set =
      (* eprintf "MATCH q:%s r:%s\n%!"  *)
      (*   (Packet.q_type_to_string qtype) (RR.rdata_to_string set.rdata); *)
      match (qtype, set.rdata) with 
        | (Packet.Q_A, A _) -> true
        | (Packet.Q_NS, NS _) -> true
        | (Packet.Q_CNAME, CNAME _) -> true
        | (Packet.Q_SOA, SOA _) -> true
        | (Packet.Q_MB, MB _) -> true
        | (Packet.Q_MG, MG _) -> true
        | (Packet.Q_MR, MR _) -> true
        | (Packet.Q_WKS, WKS _) -> true
        | (Packet.Q_PTR, PTR _) -> true
        | (Packet.Q_HINFO, HINFO _) -> true
        | (Packet.Q_MINFO, MINFO _) -> true
        | (Packet.Q_MX, MX _) -> true
        | (Packet.Q_TXT, TXT _) -> true
        | (Packet.Q_RP, RP _) -> true
        | (Packet.Q_AFSDB, AFSDB _) -> true
        | (Packet.Q_X25, X25 _) -> true
        | (Packet.Q_ISDN, ISDN _) -> true
        | (Packet.Q_RT, RT _) -> true
        | (Packet.Q_SRV, SRV _) -> true
        | (Packet.Q_AAAA, AAAA _) -> true
        | (Packet.Q_DNSKEY, DNSKEY _) -> true
        (* | (Packet.Q_UNSPEC, UNSPEC _) -> true *)
        | (Packet.Q_MAILB, MB _) -> true
        | (Packet.Q_MAILB, MG _) -> true
        | (Packet.Q_MAILB, MR _) -> true
        | (Packet.Q_ANY_TYP, _) -> true
        | (_, CNAME _) -> cnames_ok
        | (_, _) -> false 
    in List.filter (match_rrset qtype) sets
  in

  (* Get an RRSet, which may not exist *)
  let add_opt_rrset node qtype rrtype section = 
    if not (in_log node.owner.H.node rrtype)
    then
      let a = get_rrsets qtype node.rrsets false in
      List.iter (fun s -> 
        add_rrset node.owner.H.node s.ttl s.rdata section) a 
  in

  (* Get an RRSet, which must exist *)
  let add_req_rrset node qtype rrtype section = 
    if not (in_log node.owner.H.node rrtype)
    then
      let a = get_rrsets qtype node.rrsets false in
      if a = [] then raise TrieCorrupt; 
      List.iter (fun s -> 
        add_rrset node.owner.H.node s.ttl s.rdata section) a
  in

  (* Get the SOA RRSet for a negative response *)
  let add_negative_soa_rrset node = 
    (* Don't need to check if it's already there *)
    let a = get_rrsets Packet.Q_SOA node.rrsets false in
    if a = [] then raise TrieCorrupt;
    (* RFC 2308: The TTL of the SOA RRset in a negative response must be set
       to the minimum of its own TTL and the "minimum" field of the SOA
       itself *)
    List.iter (fun s -> 
      match s.rdata with
	      SOA ((_, _, _, _, _, _, ttl) :: _) -> 
	        add_rrset node.owner.H.node (min s.ttl ttl) s.rdata `Authority
        | _ -> raise TrieCorrupt ) a
  in

  (* Fill in the ANSWER section *)
  let rec add_answer_rrsets owner ?(lc = 5) rrsets qtype = 
    let add_answer_rrset s = 
      match s with 
	      { rdata = CNAME (d::_) } -> 
            (* Only follow the first CNAME in a set *)
	        if not (lc < 1 || qtype = Packet.Q_CNAME ) then begin 
              add_answer_rrsets d.owner.H.node ~lc:(lc - 1) d.rrsets qtype 
            end;
	        add_rrset owner s.ttl s.rdata `Answer;
        | _ -> add_rrset owner s.ttl s.rdata `Answer
    in
    let a = get_rrsets qtype rrsets true in
    List.iter add_answer_rrset a
  in

  (* Call the trie lookup and assemble the RRs for a response *)
  let main_lookup qname qtype trie = 
    let key = canon2key qname in
    match lookup key trie with
      | `Found (sec, node, zonehead) -> (* Name has RRs, and we own it. *)
          add_answer_rrsets node.owner.H.node node.rrsets qtype;
	      add_opt_rrset zonehead Packet.Q_NS Packet.RR_NS `Authority;
	      Packet.NoError
	        
      | `NoError (zonehead) ->          (* Name "exists", but has no RRs. *)
	      add_negative_soa_rrset zonehead;
	      Packet.NoError

      | `NoErrorNSEC (zonehead, nsec) ->
	      add_negative_soa_rrset zonehead;
	      (* add_opt_rrset nsec `NSEC `Authority; *)
	      Packet.NoError
	        
      | `Delegated (sec, cutpoint) ->   (* Name is delegated. *)
	      add_req_rrset cutpoint Packet.Q_NS Packet.RR_NS `Authority; 
	      aa_flag := false; 
	      (* DNSSEC child zone keys *)
	      Packet.NoError

      | `Wildcard (source, zonehead) -> (* Name is matched by a wildcard. *)
	      add_answer_rrsets qname source.rrsets qtype; 
	      add_opt_rrset zonehead Packet.Q_NS Packet.RR_NS `Authority;
	      Packet.NoError

      | `WildcardNSEC (source, zonehead, nsec) -> 
	      add_answer_rrsets qname source.rrsets qtype; 
	      add_opt_rrset zonehead Packet.Q_NS Packet.RR_NS `Authority;
	      (* add_opt_rrset nsec `NSEC `Authority; *)
	      Packet.NoError

      | `NXDomain (zonehead) ->         (* Name doesn't exist. *)
	      add_negative_soa_rrset zonehead;
	      Packet.NXDomain

      | `NXDomainNSEC (zonehead, nsec1, nsec2) ->
	      add_negative_soa_rrset zonehead;
	      (* add_opt_rrset nsec1 `NSEC `Authority; *)
	      (* add_opt_rrset nsec2 `NSEC `Authority; *)
	      Packet.NXDomain
  in
  
  try 
    let rc = main_lookup qname qtype trie in	
    List.iter (fun (o, t) -> 
      add_opt_rrset o Packet.Q_ANY_TYP t `Additional) !addqueue;
    { rcode = rc; aa = !aa_flag; 
      answer = !ans_rrs; authority = !auth_rrs; additional = !add_rrs }
  with 
      BadDomainName _ -> { rcode = Packet.FormErr; aa = false; 
			               answer = []; authority = []; additional=[] }
    | TrieCorrupt ->  { rcode = Packet.ServFail; aa = false;
		                answer = []; authority = []; additional=[] }
