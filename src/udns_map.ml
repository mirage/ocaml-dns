(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

let int_compare : int -> int -> int = fun a b -> compare a b

module MxSet = Set.Make (struct
    type t = int * Domain_name.t
    let compare (pri, name) (pri', name') =
      match int_compare pri pri' with
      | 0 -> Domain_name.compare name name'
      | x -> x
  end)

module TxtSet = Set.Make (struct
    type t = string list
    let compare a b =
      match int_compare (List.length a) (List.length b) with
      | 0 ->
        List.fold_left2
          (fun r a b -> if r = 0 then String.compare a b else r)
          0 a b
      | x -> x
  end)

module Ipv4Set = Set.Make (Ipaddr.V4)

module Ipv6Set = Set.Make (Ipaddr.V6)

module SrvSet = Set.Make (struct
    type t = Udns_packet.srv
    let compare = Udns_packet.compare_srv
  end)

module DnskeySet = Set.Make (struct
    type t = Udns_packet.dnskey
    let compare = Udns_packet.compare_dnskey
  end)

module CaaSet = Set.Make (struct
    type t = Udns_packet.caa
    let compare = Udns_packet.compare_caa
  end)

module TlsaSet = Set.Make (struct
    type t = Udns_packet.tlsa
    let compare = Udns_packet.compare_tlsa
  end)

module SshfpSet = Set.Make (struct
    type t = Udns_packet.sshfp
    let compare = Udns_packet.compare_sshfp
  end)

type _ k =
  | Any : Udns_packet.rr list k
  | Cname : (int32 * Domain_name.t) k
  | Mx : (int32 * MxSet.t) k
  | Ns : (int32 * Domain_name.Set.t) k
  | Ptr : (int32 * Domain_name.t) k
  | Soa : (int32 * Udns_packet.soa) k
  | Txt : (int32 * TxtSet.t) k
  | A : (int32 * Ipv4Set.t) k
  | Aaaa : (int32 * Ipv6Set.t) k
  | Srv : (int32 * SrvSet.t) k
  | Dnskey : DnskeySet.t k
  | Caa : (int32 * CaaSet.t) k
  | Tlsa : (int32 * TlsaSet.t) k
  | Sshfp : (int32 * SshfpSet.t) k

module K = struct
  type 'a t = 'a k

  let compare : type a b. a t -> b t -> (a, b) Gmap.Order.t = fun t t' ->
    let open Gmap.Order in
    match t, t' with
    | Soa, Soa -> Eq | Soa, _ -> Lt | _, Soa -> Gt
    | Ns, Ns -> Eq | Ns, _ -> Lt | _, Ns -> Gt
    | Mx, Mx -> Eq | Mx, _ -> Lt | _, Mx -> Gt
    | Cname, Cname -> Eq | Cname, _ -> Lt | _, Cname -> Gt
    | A, A -> Eq | A, _ -> Lt | _, A -> Gt
    | Aaaa, Aaaa -> Eq | Aaaa, _ -> Lt | _, Aaaa -> Gt
    | Ptr, Ptr -> Eq | Ptr, _ -> Lt | _, Ptr -> Gt
    | Srv, Srv -> Eq | Srv, _ -> Lt | _, Srv -> Gt
    | Dnskey, Dnskey -> Eq | Dnskey, _ -> Lt | _, Dnskey -> Gt
    | Caa, Caa -> Eq | Caa, _ -> Lt | _, Caa -> Gt
    | Tlsa, Tlsa -> Eq | Tlsa, _ -> Lt | _, Tlsa -> Gt
    | Sshfp, Sshfp -> Eq | Sshfp, _ -> Lt | _, Sshfp -> Gt
    | Txt, Txt -> Eq | Txt, _ -> Lt | _, Txt -> Gt
    | Any, Any -> Eq (* | Any, _ -> Lt | _, Any -> Gt *)

  let pp : type a. Format.formatter -> a t -> a -> unit = fun ppf t v ->
    match t, v with
    | Any, entries ->
      Fmt.pf ppf "any %a" Udns_packet.pp_rrs entries
    | Cname, (ttl, alias) -> Fmt.pf ppf "cname ttl %lu %a" ttl Domain_name.pp alias
    | Mx, (ttl, mxs) ->
      Fmt.pf ppf "mx ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") (pair ~sep:(unit " ") int Domain_name.pp))
        (MxSet.elements mxs)
    | Ns, (ttl, names) ->
      Fmt.pf ppf "ns ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Domain_name.pp)
        (Domain_name.Set.elements names)
    | Ptr, (ttl, name) -> Fmt.pf ppf "ptr ttl %lu %a" ttl Domain_name.pp name
    | Soa, (ttl, soa) -> Fmt.pf ppf "soa ttl %lu %a" ttl Udns_packet.pp_soa soa
    | Txt, (ttl, txts) ->
      Fmt.pf ppf "txt ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") (list ~sep:(unit " ") string))
        (TxtSet.elements txts)
    | A, (ttl, a) ->
      Fmt.pf ppf "a ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Ipaddr.V4.pp) (Ipv4Set.elements a)
    | Aaaa, (ttl, aaaas) ->
      Fmt.pf ppf "aaaa ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Ipaddr.V6.pp) (Ipv6Set.elements aaaas)
    | Srv, (ttl, srvs) ->
      Fmt.pf ppf "srv ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Udns_packet.pp_srv) (SrvSet.elements srvs)
    | Dnskey, keys ->
      Fmt.pf ppf "dnskey %a"
        Fmt.(list ~sep:(unit ";@,") Udns_packet.pp_dnskey)
        (DnskeySet.elements keys)
    | Caa, (ttl, caas) ->
      Fmt.pf ppf "caa ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Udns_packet.pp_caa) (CaaSet.elements caas)
    | Tlsa, (ttl, tlsas) ->
      Fmt.pf ppf "tlsa ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Udns_packet.pp_tlsa) (TlsaSet.elements tlsas)
    | Sshfp, (ttl, sshfps) ->
      Fmt.pf ppf "sshfp ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Udns_packet.pp_sshfp)
        (SshfpSet.elements sshfps)

  let text : type a. Domain_name.t -> a t -> a -> string = fun n t v ->
    let hex cs =
      let buf = Bytes.create (Cstruct.len cs * 2) in
      for i = 0 to pred (Cstruct.len cs) do
        let byte = Cstruct.get_uint8 cs i in
        let up, low = byte lsr 4, byte land 0x0F in
        let to_hex_char v = char_of_int (if v < 10 then 0x30 + v else 0x37 + v) in
        Bytes.set buf (i * 2) (to_hex_char up) ;
        Bytes.set buf (i * 2 + 1) (to_hex_char low)
      done;
      Bytes.unsafe_to_string buf
    in
    let name n = Domain_name.to_string ~trailing:true n in
    let str_name = name n in
    let strs =
      match t, v with
      | Any, _ -> (* no *) []
      | Cname, (ttl, alias) ->
        [ Fmt.strf "%s\t%lu\tCNAME\t%s" str_name ttl (name alias) ]
      | Mx, (ttl, mxs) ->
        List.map (fun (prio, mx) ->
            Fmt.strf "%s\t%lu\tMX\t%u\t%s" str_name ttl prio (name mx))
          (MxSet.elements mxs)
      | Ns, (ttl, ns) ->
        Domain_name.Set.fold (fun ns acc ->
            Fmt.strf "%s\t%lu\tNS\t%s" str_name ttl (name ns) :: acc)
          ns []
      | Ptr, (ttl, ptr) ->
        [ Fmt.strf "%s\t%lu\tPTR\t%s" str_name ttl (name ptr) ]
      | Soa, (ttl, soa) ->
        [ Fmt.strf "%s\t%lu\tSOA\t%s\t%s\t%lu\t%lu\t%lu\t%lu\t%lu" str_name ttl
            (name soa.Udns_packet.nameserver)
            (name soa.Udns_packet.hostmaster)
            soa.Udns_packet.serial soa.Udns_packet.refresh soa.Udns_packet.retry
            soa.Udns_packet.expiry soa.Udns_packet.minimum ]
      | Txt, (ttl, txts) ->
        List.map (fun txt ->
            Fmt.strf "%s\t%lu\tTXT\t%s" str_name ttl (String.concat "" txt))
          (TxtSet.elements txts)
      | A, (ttl, a) ->
        List.map (fun ip ->
          Fmt.strf "%s\t%lu\tA\t%s" str_name ttl (Ipaddr.V4.to_string ip))
          (Ipv4Set.elements a)
      | Aaaa, (ttl, aaaa) ->
        List.map (fun ip ->
            Fmt.strf "%s\t%lu\tAAAA\t%s" str_name ttl (Ipaddr.V6.to_string ip))
          (Ipv6Set.elements aaaa)
      | Srv, (ttl, srvs) ->
        List.map (fun srv ->
            Fmt.strf "%s\t%lu\tSRV\t%u\t%u\t%u\t%s"
              str_name ttl srv.Udns_packet.priority srv.Udns_packet.weight
              srv.Udns_packet.port (name srv.Udns_packet.target))
          (SrvSet.elements srvs)
      | Dnskey, keys ->
        List.map (fun key ->
            Fmt.strf "%s\t300\tDNSKEY\t%u\t3\t%d\t%s"
              str_name key.Udns_packet.flags
              (Udns_enum.dnskey_to_int key.Udns_packet.key_algorithm)
              (hex key.Udns_packet.key))
          (DnskeySet.elements keys)
      | Caa, (ttl, caas) ->
        List.map (fun caa ->
            Fmt.strf "%s\t%lu\tCAA\t%s\t%s\t%s"
              str_name ttl (if caa.Udns_packet.critical then "128" else "0")
              caa.Udns_packet.tag (String.concat ";" caa.Udns_packet.value))
          (CaaSet.elements caas)
      | Tlsa, (ttl, tlsas) ->
        List.map (fun tlsa ->
            Fmt.strf "%s\t%lu\tTLSA\t%u\t%u\t%u\t%s"
              str_name ttl
              (Udns_enum.tlsa_cert_usage_to_int tlsa.Udns_packet.tlsa_cert_usage)
              (Udns_enum.tlsa_selector_to_int tlsa.Udns_packet.tlsa_selector)
              (Udns_enum.tlsa_matching_type_to_int tlsa.Udns_packet.tlsa_matching_type)
              (hex tlsa.Udns_packet.tlsa_data))
          (TlsaSet.elements tlsas)
      | Sshfp, (ttl, sshfps) ->
        List.map (fun sshfp ->
            Fmt.strf "%s\t%lu\tSSHFP\t%u\t%u\t%s" str_name ttl
              (Udns_enum.sshfp_algorithm_to_int sshfp.Udns_packet.sshfp_algorithm)
              (Udns_enum.sshfp_type_to_int sshfp.Udns_packet.sshfp_type)
              (hex sshfp.Udns_packet.sshfp_fingerprint))
          (SshfpSet.elements sshfps)
    in
    String.concat "\n" strs
end

include Gmap.Make(K)

let pp_b ppf (B (k, v)) = K.pp ppf k v

let equal_b b b' = match b, b' with
  | B (Any, entries), B (Any, entries') ->
    List.length entries = List.length entries' &&
    List.for_all (fun e ->
        List.exists (fun e' -> Udns_packet.rr_equal e e') entries')
      entries
  | B (Cname, (_, alias)), B (Cname, (_, alias')) ->
    Domain_name.equal alias alias'
  | B (Mx, (_, mxs)), B (Mx, (_, mxs')) ->
    MxSet.equal mxs mxs'
  | B (Ns, (_, ns)), B (Ns, (_, ns')) ->
    Domain_name.Set.equal ns ns'
  | B (Ptr, (_, name)), B (Ptr, (_, name')) ->
    Domain_name.equal name name'
  | B (Soa, (_, soa)), B (Soa, (_, soa')) ->
    Udns_packet.compare_soa soa soa' = 0
  | B (Txt, (_, txts)), B (Txt, (_, txts')) ->
    TxtSet.equal txts txts'
  | B (A, (_, aas)), B (A, (_, aas')) ->
    Ipv4Set.equal aas aas'
  | B (Aaaa, (_, aaaas)), B (Aaaa, (_, aaaas')) ->
    Ipv6Set.equal aaaas aaaas'
  | B (Srv, (_, srvs)), B (Srv, (_, srvs')) ->
    SrvSet.equal srvs srvs'
  | B (Dnskey, keys), B (Dnskey, keys') ->
    DnskeySet.equal keys keys'
  | B (Caa, (_, caas)), B (Caa, (_, caas')) ->
    CaaSet.equal caas caas'
  | B (Tlsa, (_, tlsas)), B (Tlsa, (_, tlsas')) ->
    TlsaSet.equal tlsas tlsas'
  | B (Sshfp, (_, sshfps)), B (Sshfp, (_, sshfps')) ->
    SshfpSet.equal sshfps sshfps'
  | _, _ -> false

let glue map =
  Domain_name.Map.fold (fun name ((ttla, a), (ttlaaaa, aaaa)) acc ->
      (List.map (fun a ->
           { Udns_packet.name ; ttl = ttla ; rdata = Udns_packet.A a })
          a @
       List.map (fun aaaa ->
           { Udns_packet.name ; ttl = ttlaaaa ; rdata = Udns_packet.AAAA aaaa })
          aaaa) @ acc)
    map []

let k_to_rr_typ : type a. a key -> Udns_enum.rr_typ = function
  | Any -> Udns_enum.ANY
  | Cname -> Udns_enum.CNAME
  | Mx -> Udns_enum.MX
  | Ns -> Udns_enum.NS
  | Ptr -> Udns_enum.PTR
  | Soa -> Udns_enum.SOA
  | Txt -> Udns_enum.TXT
  | A -> Udns_enum.A
  | Aaaa -> Udns_enum.AAAA
  | Srv -> Udns_enum.SRV
  | Dnskey -> Udns_enum.DNSKEY
  | Caa -> Udns_enum.CAA
  | Tlsa -> Udns_enum.TLSA
  | Sshfp -> Udns_enum.SSHFP

let to_rr_typ : b -> Udns_enum.rr_typ = fun (B (k, _)) ->
  k_to_rr_typ k

let to_rdata : b -> int32 * Udns_packet.rdata list = fun (B (k, v)) ->
  match k, v with
  | Cname, (ttl, alias) -> ttl, [ Udns_packet.CNAME alias ]
  | Mx, (ttl, mxs) ->
    ttl, MxSet.fold (fun (pri, mx) acc -> Udns_packet.MX (pri, mx) :: acc) mxs []
  | Ns, (ttl, names) ->
    ttl, Domain_name.Set.fold (fun ns acc -> Udns_packet.NS ns :: acc) names []
  | Ptr, (ttl, ptrname) ->
    ttl, [ Udns_packet.PTR ptrname ]
  | Soa, (ttl, soa) ->
    ttl, [ Udns_packet.SOA soa ]
  | Txt, (ttl, txts) ->
    ttl, TxtSet.fold (fun txt acc -> Udns_packet.TXT txt :: acc) txts []
  | A, (ttl, aas) ->
    ttl, Ipv4Set.fold (fun a acc -> Udns_packet.A a :: acc) aas []
  | Aaaa, (ttl, aaaas) ->
    ttl, Ipv6Set.fold (fun aaaa acc -> Udns_packet.AAAA aaaa :: acc) aaaas []
  | Srv, (ttl, srvs) ->
    ttl, SrvSet.fold (fun srv acc -> Udns_packet.SRV srv :: acc) srvs []
  | Dnskey, dnskeys ->
    0l, DnskeySet.fold (fun key acc -> Udns_packet.DNSKEY key :: acc) dnskeys []
  | Caa, (ttl, caas) ->
    ttl, CaaSet.fold (fun caa acc -> Udns_packet.CAA caa :: acc) caas []
  | Tlsa, (ttl, tlsas) ->
    ttl, TlsaSet.fold (fun tlsa acc -> Udns_packet.TLSA tlsa :: acc) tlsas []
  | Sshfp, (ttl, sshfps) ->
    ttl, SshfpSet.fold (fun fp acc -> Udns_packet.SSHFP fp :: acc) sshfps []
  | Any, _ -> assert false

let to_rr : Domain_name.t -> b -> Udns_packet.rr list = fun name b ->
  match b with
  | B (Any, entries) -> entries
  | _ ->
    let ttl, rdatas = to_rdata b in
    List.map (fun rdata -> { Udns_packet.name ; ttl ; rdata }) rdatas

let names = function
  | B (Any, rrs) -> Udns_packet.rr_names rrs
  | B (Mx, (_, mxs)) ->
    MxSet.fold (fun (_, name) acc -> Domain_name.Set.add name acc)
      mxs Domain_name.Set.empty
  | B (Ns, (_, names)) -> names
  | B (Srv, (_, srvs)) ->
    SrvSet.fold (fun x acc -> Domain_name.Set.add x.Udns_packet.target acc)
      srvs Domain_name.Set.empty
  | _ -> Domain_name.Set.empty

let of_rdata : int32 -> Udns_packet.rdata -> b option = fun ttl rd ->
  match rd with
  | Udns_packet.CNAME alias ->
    Some (B (Cname, (ttl, alias)))
  | Udns_packet.MX (pri, name) ->
    Some (B (Mx, (ttl, MxSet.singleton (pri, name))))
  | Udns_packet.NS ns ->
    Some (B (Ns, (ttl, Domain_name.Set.singleton ns)))
  | Udns_packet.PTR ptr ->
    Some (B (Ptr, (ttl, ptr)))
  | Udns_packet.SOA soa ->
    Some (B (Soa, (ttl, soa)))
  | Udns_packet.TXT txt ->
    Some (B (Txt, (ttl, TxtSet.singleton txt)))
  | Udns_packet.A ip ->
    Some (B (A, (ttl, Ipv4Set.singleton ip)))
  | Udns_packet.AAAA ip ->
    Some (B (Aaaa, (ttl, Ipv6Set.singleton ip)))
  | Udns_packet.SRV srv ->
    Some (B (Srv, (ttl, SrvSet.singleton srv)))
  | Udns_packet.DNSKEY key ->
    Some (B (Dnskey, DnskeySet.singleton key))
  | Udns_packet.CAA caa ->
    Some (B (Caa, (ttl, CaaSet.singleton caa)))
  | Udns_packet.TLSA tlsa ->
    Some (B (Tlsa, (ttl, TlsaSet.singleton tlsa)))
  | Udns_packet.SSHFP sshfp ->
    Some (B (Sshfp, (ttl, SshfpSet.singleton sshfp)))
  | _ -> None

let add_rdata : b -> Udns_packet.rdata -> b option = fun v rdata ->
  match v, rdata with
  | B (Mx, (ttl, mxs)), Udns_packet.MX (pri, name) ->
    Some (B (Mx, (ttl, MxSet.add (pri, name) mxs)))
  | B (Ns, (ttl, nss)), Udns_packet.NS ns ->
    Some (B (Ns, (ttl, Domain_name.Set.add ns nss)))
  | B (Txt, (ttl, txts)), Udns_packet.TXT txt ->
    Some (B (Txt, (ttl, TxtSet.add txt txts)))
  | B (A, (ttl, ips)), Udns_packet.A ip ->
    Some (B (A, (ttl, Ipv4Set.add ip ips)))
  | B (Aaaa, (ttl, ips)), Udns_packet.AAAA ip ->
    Some (B (Aaaa, (ttl, Ipv6Set.add ip ips)))
  | B (Srv, (ttl, srvs)), Udns_packet.SRV srv ->
    Some (B (Srv, (ttl, SrvSet.add srv srvs)))
  | B (Dnskey, keys), Udns_packet.DNSKEY key ->
    Some (B (Dnskey, DnskeySet.add key keys))
  | B (Caa, (ttl, caas)), Udns_packet.CAA caa ->
    Some (B (Caa, (ttl, CaaSet.add caa caas)))
  | B (Tlsa, (ttl, tlsas)), Udns_packet.TLSA tlsa ->
    Some (B (Tlsa, (ttl, TlsaSet.add tlsa tlsas)))
  | B (Sshfp, (ttl, sshfps)), Udns_packet.SSHFP sshfp ->
    Some (B (Sshfp, (ttl, SshfpSet.add sshfp sshfps)))
  | _ -> None

let remove_rdata : b -> Udns_packet.rdata -> b option = fun v rdata ->
  match v, rdata with
  | B (Mx, (ttl, mxs)), Udns_packet.MX (prio, name) ->
    let mxs' = MxSet.remove (prio, name) mxs in
    if MxSet.is_empty mxs' then None else Some (B (Mx, (ttl, mxs')))
  | B (Ns, (ttl, nss)), Udns_packet.NS ns ->
    let nss' = Domain_name.Set.remove ns nss in
    if Domain_name.Set.is_empty nss' then None else Some (B (Ns, (ttl, nss')))
  | B (Txt, (ttl, txts)), Udns_packet.TXT txt ->
    let txts' = TxtSet.remove txt txts in
    if TxtSet.is_empty txts' then None else Some (B (Txt, (ttl, txts')))
  | B (A, (ttl, ips)), Udns_packet.A ip ->
    let ips' = Ipv4Set.remove ip ips in
    if Ipv4Set.is_empty ips' then None else Some (B (A, (ttl, ips')))
  | B (Aaaa, (ttl, ips)), Udns_packet.AAAA ip ->
    let ips' = Ipv6Set.remove ip ips in
    if Ipv6Set.is_empty ips' then None else Some (B (Aaaa, (ttl, ips')))
  | B (Srv, (ttl, srvs)), Udns_packet.SRV srv ->
    let srvs' = SrvSet.remove srv srvs in
    if SrvSet.is_empty srvs' then None else Some (B (Srv, (ttl, srvs')))
  | B (Dnskey, keys), Udns_packet.DNSKEY key ->
    let keys' = DnskeySet.remove key keys in
    if DnskeySet.is_empty keys' then None else Some (B (Dnskey, keys'))
  | B (Caa, (ttl, caas)), Udns_packet.CAA caa ->
    let caas' = CaaSet.remove caa caas in
    if CaaSet.is_empty caas' then None else Some (B (Caa, (ttl, caas')))
  | B (Tlsa, (ttl, tlsas)), Udns_packet.TLSA tlsa ->
    let tlsas' = TlsaSet.remove tlsa tlsas in
    if TlsaSet.is_empty tlsas' then None else Some (B (Tlsa, (ttl, tlsas')))
  | B (Sshfp, (ttl, sshfps)), Udns_packet.SSHFP sshfp ->
    let sshfps' = SshfpSet.remove sshfp sshfps in
    if SshfpSet.is_empty sshfps' then None else Some (B (Sshfp, (ttl, sshfps')))
  | _ -> None

let lookup_rr : Udns_enum.rr_typ -> t -> b option = fun rr t ->
  match rr with
  | Udns_enum.MX -> findb Mx t
  | Udns_enum.NS -> findb Ns t
  | Udns_enum.PTR -> findb Ptr t
  | Udns_enum.SOA -> findb Soa t
  | Udns_enum.TXT -> findb Txt t
  | Udns_enum.A -> findb A t
  | Udns_enum.AAAA -> findb Aaaa t
  | Udns_enum.SRV -> findb Srv t
  | Udns_enum.DNSKEY -> findb Dnskey t
  | Udns_enum.CAA -> findb Caa t
  | Udns_enum.TLSA -> findb Tlsa t
  | Udns_enum.SSHFP -> findb Sshfp t
  | _ -> None

let remove_rr : Udns_enum.rr_typ -> t -> t = fun rr t ->
  match rr with
  | Udns_enum.MX -> remove Mx t
  | Udns_enum.NS -> remove Ns t
  | Udns_enum.PTR -> remove Ptr t
  | Udns_enum.SOA -> remove Soa t
  | Udns_enum.TXT -> remove Txt t
  | Udns_enum.A -> remove A t
  | Udns_enum.AAAA -> remove Aaaa t
  | Udns_enum.SRV -> remove Srv t
  | Udns_enum.DNSKEY -> remove Dnskey t
  | Udns_enum.CAA -> remove Caa t
  | Udns_enum.TLSA -> remove Tlsa t
  | Udns_enum.SSHFP -> remove Sshfp t
  | _ -> t

let of_rrs rrs =
  List.fold_left (fun map rr ->
      let m = match Domain_name.Map.find rr.Udns_packet.name map with
        | None -> empty
        | Some map -> map
      in
      let v = match lookup_rr (Udns_packet.rdata_to_rr_typ rr.Udns_packet.rdata) m with
        | None -> of_rdata rr.Udns_packet.ttl rr.Udns_packet.rdata
        | Some v -> add_rdata v rr.Udns_packet.rdata
      in
      let m' = match v with
        | None ->
          Logs.warn (fun m -> m "failed to insert rr %a" Udns_packet.pp_rr rr) ;
          m
        | Some v -> addb v m
      in
      Domain_name.Map.add rr.Udns_packet.name m' map)
    Domain_name.Map.empty rrs

let text name (B (key, v)) = K.text name key v
