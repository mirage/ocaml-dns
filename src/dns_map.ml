(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* still feels wrong, maybe more explicit? *)
type _ k =
  | Any : (Dns_packet.rr list * Domain_name.Set.t) k
  | Cname : (int32 * Domain_name.t) k
  | Mx : (int32 * (int * Domain_name.t) list) k
  | Ns : (int32 * Domain_name.Set.t) k
  | Ptr : (int32 * Domain_name.t) k
  | Soa : (int32 * Dns_packet.soa) k
  | Txt : (int32 * string list list) k
  | A : (int32 * Ipaddr.V4.t list) k
  | Aaaa : (int32 * Ipaddr.V6.t list) k
  | Srv : (int32 * Dns_packet.srv list) k
  | Dnskey : Dns_packet.dnskey list k
  | Caa : (int32 * Dns_packet.caa list) k
  | Tlsa : (int32 * Dns_packet.tlsa list) k
  | Sshfp : (int32 * Dns_packet.sshfp list) k

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
    | Any, (entries, names) ->
      Fmt.pf ppf "any %a %a" Dns_packet.pp_rrs entries
        Fmt.(list ~sep:(unit ";@,") Domain_name.pp) (Domain_name.Set.elements names)
    | Cname, (ttl, alias) -> Fmt.pf ppf "cname ttl %lu %a" ttl Domain_name.pp alias
    | Mx, (ttl, mxs) ->
      Fmt.pf ppf "mx ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") (pair ~sep:(unit " ") int Domain_name.pp)) mxs
    | Ns, (ttl, names) ->
      Fmt.pf ppf "ns ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Domain_name.pp) (Domain_name.Set.elements names)
    | Ptr, (ttl, name) -> Fmt.pf ppf "ptr ttl %lu %a" ttl Domain_name.pp name
    | Soa, (ttl, soa) -> Fmt.pf ppf "soa ttl %lu %a" ttl Dns_packet.pp_soa soa
    | Txt, (ttl, txts) ->
      Fmt.pf ppf "txt ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") (list ~sep:(unit " ") string)) txts
    | A, (ttl, a) ->
      Fmt.pf ppf "a ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Ipaddr.V4.pp_hum) a
    | Aaaa, (ttl, aaaa) ->
      Fmt.pf ppf "a ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Ipaddr.V6.pp_hum) aaaa
    | Srv, (ttl, srvs) ->
      Fmt.pf ppf "srv ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Dns_packet.pp_srv) srvs
    | Dnskey, keys ->
      Fmt.pf ppf "dnskey %a"
        Fmt.(list ~sep:(unit ";@,") Dns_packet.pp_dnskey) keys
    | Caa, (ttl, caas) ->
      Fmt.pf ppf "caa ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Dns_packet.pp_caa) caas
    | Tlsa, (ttl, tlsas) ->
      Fmt.pf ppf "tlsa ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Dns_packet.pp_tlsa) tlsas
    | Sshfp, (ttl, sshfps) ->
      Fmt.pf ppf "sshfp ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Dns_packet.pp_sshfp) sshfps


  let text : type a. Domain_name.t -> a t -> a -> string = fun n t v ->
    let name n = Domain_name.to_string n ^ "." in
    let str_name = name n in
    let strs =
      match t, v with
      | Any, _ -> (* no *) []
      | Cname, (ttl, alias) ->
        [ Printf.sprintf "%s\t%lu\tCNAME\t%s" str_name ttl (name alias) ]
      | Mx, (ttl, mxs) ->
        List.map (fun (prio, mx) ->
            Printf.sprintf "%s\t%lu\tMX\t%u\t%s" str_name ttl prio (name mx))
          mxs
      | Ns, (ttl, ns) ->
        Domain_name.Set.fold (fun ns acc ->
            Printf.sprintf "%s\t%lu\tNS\t%s" str_name ttl (name ns) :: acc)
          ns []
      | Ptr, (ttl, ptr) ->
        [ Printf.sprintf "%s\t%lu\tPTR\t%s" str_name ttl (name ptr) ]
      | Soa, (ttl, soa) ->
        [ Printf.sprintf "%s\t%lu\tSOA\t%s\t%s\t%lu\t%lu\t%lu\t%lu\t%lu" str_name ttl
            (name soa.Dns_packet.nameserver)
            (name soa.Dns_packet.hostmaster)
            soa.Dns_packet.serial soa.Dns_packet.refresh soa.Dns_packet.retry
            soa.Dns_packet.expiry soa.Dns_packet.minimum ]
      | Txt, (ttl, txts) ->
        List.map (fun txt ->
            Printf.sprintf "%s\t%lu\tTXT\t%s" str_name ttl
              (String.concat "" txt))
          txts
      | A, (ttl, a) ->
        List.map (fun ip ->
          Printf.sprintf "%s\t%lu\tA\t%s" str_name ttl
            (Ipaddr.V4.to_string ip))
          a
      | Aaaa, (ttl, aaaa) ->
        List.map (fun ip ->
            Printf.sprintf "%s\t%lu\tAAAA\t%s" str_name ttl
              (Ipaddr.V6.to_string ip))
          aaaa
      | Srv, (ttl, srvs) ->
        List.map (fun srv ->
            Printf.sprintf "%s\t%lu\tSRV\t%u\t%u\t%u\t%s"
              str_name ttl srv.Dns_packet.priority srv.Dns_packet.weight
              srv.Dns_packet.port (name srv.Dns_packet.target))
          srvs
      | Dnskey, keys ->
        List.map (fun key ->
            let `Hex hex = Hex.of_cstruct key.Dns_packet.key in
            Printf.sprintf "%s\t300\tDNSKEY\t%u\t3\t%d\t%s"
              str_name key.Dns_packet.flags
              (Dns_enum.dnskey_to_int key.Dns_packet.key_algorithm)
              hex)
          keys
      | Caa, (ttl, caas) ->
        List.map (fun caa ->
            Printf.sprintf "%s\t%lu\tCAA\t%s\t%s\t%s"
              str_name ttl (if caa.Dns_packet.critical then "128" else "0")
              caa.Dns_packet.tag (String.concat ";" caa.Dns_packet.value))
          caas
      | Tlsa, (ttl, tlsas) ->
        List.map (fun tlsa ->
            let `Hex hex = Hex.of_cstruct tlsa.Dns_packet.tlsa_data in
            Printf.sprintf "%s\t%lu\tTLSA\t%u\t%u\t%u\t%s"
              str_name ttl
              (Dns_enum.tlsa_cert_usage_to_int tlsa.Dns_packet.tlsa_cert_usage)
              (Dns_enum.tlsa_selector_to_int tlsa.Dns_packet.tlsa_selector)
              (Dns_enum.tlsa_matching_type_to_int tlsa.Dns_packet.tlsa_matching_type)
              hex)
          tlsas
      | Sshfp, (ttl, sshfps) ->
        List.map (fun sshfp ->
            let `Hex hex = Hex.of_cstruct sshfp.Dns_packet.sshfp_fingerprint in
            Printf.sprintf "%s\t%lu\tSSHFP\t%u\t%u\t%s" str_name ttl
              (Dns_enum.sshfp_algorithm_to_int sshfp.Dns_packet.sshfp_algorithm)
              (Dns_enum.sshfp_type_to_int sshfp.Dns_packet.sshfp_type)
              hex)
          sshfps
    in
    String.concat "\n" strs
end

include Gmap.Make(K)

let pp_b ppf (B (k, v)) = K.pp ppf k v

let equal_b b b' = match b, b' with
  | B (Any, (entries, names)), B (Any, (entries', names')) ->
    List.length entries = List.length entries' &&
    List.for_all (fun e ->
        List.exists (fun e' -> Dns_packet.rr_equal e e') entries')
      entries &&
    Domain_name.Set.equal names names'
  | B (Cname, (_, alias)), B (Cname, (_, alias')) ->
    Domain_name.equal alias alias'
  | B (Mx, (_, mxs)), B (Mx, (_, mxs')) ->
    List.length mxs = List.length mxs' &&
    List.for_all (fun (prio, name) ->
        List.exists (fun (prio', name') ->
            prio = prio' && Domain_name.equal name name')
          mxs')
      mxs
  | B (Ns, (_, ns)), B (Ns, (_, ns')) ->
    Domain_name.Set.equal ns ns'
  | B (Ptr, (_, name)), B (Ptr, (_, name')) ->
    Domain_name.equal name name'
  | B (Soa, (_, soa)), B (Soa, (_, soa')) ->
    Dns_packet.compare_soa soa soa' = 0
  | B (Txt, (_, txts)), B (Txt, (_, txts')) ->
    List.length txts = List.length txts &&
    List.for_all (fun txt ->
        List.exists (fun txt' ->
            List.length txt = List.length txt' &&
            List.for_all2 String.equal txt txt')
          txts')
      txts
  | B (A, (_, aas)), B (A, (_, aas')) ->
    List.length aas = List.length aas' &&
    List.for_all (fun a ->
        List.exists (fun a' -> Ipaddr.V4.compare a a' = 0) aas')
      aas
  | B (Aaaa, (_, aaaas)), B (Aaaa, (_, aaaas')) ->
    List.length aaaas = List.length aaaas' &&
    List.for_all (fun aaaa ->
        List.exists (fun aaaa' -> Ipaddr.V6.compare aaaa aaaa' = 0) aaaas')
      aaaas
  | B (Srv, (_, srvs)), B (Srv, (_, srvs')) ->
    List.length srvs = List.length srvs' &&
    List.for_all (fun srv ->
        List.exists (fun srv' -> Dns_packet.compare_srv srv srv' = 0) srvs')
      srvs
  | B (Dnskey, keys), B (Dnskey, keys') ->
    List.length keys = List.length keys' &&
    List.for_all (fun key ->
        List.exists (fun key' -> Dns_packet.compare_dnskey key key' = 0) keys')
      keys
  | B (Caa, (_, caas)), B (Caa, (_, caas')) ->
    List.length caas = List.length caas' &&
    List.for_all (fun caa ->
        List.exists (fun caa' -> Dns_packet.compare_caa caa caa' = 0) caas')
      caas
  | B (Tlsa, (_, tlsas)), B (Tlsa, (_, tlsas')) ->
    List.length tlsas = List.length tlsas' &&
    List.for_all (fun tlsa ->
        List.exists (fun tlsa' -> Dns_packet.compare_tlsa tlsa tlsa' = 0) tlsas')
      tlsas
  | B (Sshfp, (_, sshfps)), B (Sshfp, (_, sshfps')) ->
    List.length sshfps = List.length sshfps' &&
    List.for_all (fun sshfp ->
        List.exists (fun sshfp' -> Dns_packet.compare_sshfp sshfp sshfp' = 0) sshfps')
      sshfps
  | _, _ -> false

let glue map =
  Domain_name.Map.fold (fun name ((ttla, a), (ttlaaaa, aaaa)) acc ->
      (List.map (fun a ->
           { Dns_packet.name ; ttl = ttla ; rdata = Dns_packet.A a })
          a @
       List.map (fun aaaa ->
           { Dns_packet.name ; ttl = ttlaaaa ; rdata = Dns_packet.AAAA aaaa })
          aaaa) @ acc)
    map []

let k_to_rr_typ : type a. a key -> Dns_enum.rr_typ = function
  | Any -> Dns_enum.ANY
  | Cname -> Dns_enum.CNAME
  | Mx -> Dns_enum.MX
  | Ns -> Dns_enum.NS
  | Ptr -> Dns_enum.PTR
  | Soa -> Dns_enum.SOA
  | Txt -> Dns_enum.TXT
  | A -> Dns_enum.A
  | Aaaa -> Dns_enum.AAAA
  | Srv -> Dns_enum.SRV
  | Dnskey -> Dns_enum.DNSKEY
  | Caa -> Dns_enum.CAA
  | Tlsa -> Dns_enum.TLSA
  | Sshfp -> Dns_enum.SSHFP

let to_rr_typ : b -> Dns_enum.rr_typ = fun (B (k, _)) ->
   k_to_rr_typ k

let to_rr : Domain_name.t -> b -> Dns_packet.rr list = fun name (B (k, v)) ->
  match k, v with
  | Any, (entries, _) -> entries
  | Cname, (ttl, alias) ->
    [ { Dns_packet.name ; ttl ; rdata = Dns_packet.CNAME alias } ]
  | Mx, (ttl, mxs) ->
    List.map (fun (prio, mx) ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.MX (prio, mx) })
      mxs
  | Ns, (ttl, names) ->
    Domain_name.Set.fold (fun ns acc ->
      { Dns_packet.name ; ttl ; rdata = Dns_packet.NS ns } :: acc)
      names []
  | Ptr, (ttl, ptrname) ->
    [ { Dns_packet.name ; ttl ; rdata = Dns_packet.PTR ptrname } ]
  | Soa, (ttl, soa) ->
    [ { Dns_packet.name ; ttl ; rdata = Dns_packet.SOA soa } ]
  | Txt, (ttl, txts) ->
    List.map (fun txt ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.TXT txt })
      txts
  | A, (ttl, aas) ->
    List.map (fun a ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.A a })
      aas
  | Aaaa, (ttl, aaaas) ->
    List.map (fun aaaa ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.AAAA aaaa })
      aaaas
  | Srv, (ttl, srvs) ->
    List.map (fun srv ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.SRV srv })
      srvs
  | Dnskey, dnskeys ->
    List.map (fun key ->
        { Dns_packet.name ; ttl = 0l ; rdata = Dns_packet.DNSKEY key })
      dnskeys
  | Caa, (ttl, caas) ->
    List.map (fun caa ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.CAA caa })
      caas
  | Tlsa, (ttl, tlsas) ->
    List.map (fun tlsa ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.TLSA tlsa })
      tlsas
  | Sshfp, (ttl, sshfps) ->
    List.map (fun sshfp ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.SSHFP sshfp })
      sshfps

let names = function
  | B (Any, (_, names)) -> names
  | B (Mx, (_, mxs)) -> Domain_name.Set.of_list (snd (List.split mxs))
  | B (Ns, (_, names)) -> names
  | B (Srv, (_, srvs)) ->
    Domain_name.Set.of_list (List.map (fun x -> x.Dns_packet.target) srvs)
  | _ -> Domain_name.Set.empty

let of_rdata : int32 -> Dns_packet.rdata -> b option = fun ttl rd ->
  match rd with
  | Dns_packet.CNAME alias -> Some (B (Cname, (ttl, alias)))
  | Dns_packet.MX (prio, name) -> Some (B (Mx, (ttl, [ (prio, name) ])))
  | Dns_packet.NS ns -> Some (B (Ns, (ttl, Domain_name.Set.singleton ns)))
  | Dns_packet.PTR ptr -> Some (B (Ptr, (ttl, ptr)))
  | Dns_packet.SOA soa -> Some (B (Soa, (ttl, soa)))
  | Dns_packet.TXT txt -> Some (B (Txt, (ttl, [ txt ])))
  | Dns_packet.A ip -> Some (B (A, (ttl, [ ip ])))
  | Dns_packet.AAAA ip -> Some (B (Aaaa, (ttl, [ ip ])))
  | Dns_packet.SRV srv -> Some (B (Srv, (ttl, [ srv ])))
  | Dns_packet.DNSKEY key -> Some (B (Dnskey, [ key ]))
  | Dns_packet.CAA caa -> Some (B (Caa, (ttl, [ caa ])))
  | Dns_packet.TLSA tlsa -> Some (B (Tlsa, (ttl, [ tlsa ])))
  | Dns_packet.SSHFP sshfp -> Some (B (Sshfp, (ttl, [ sshfp ])))
  | _ -> None

let add_rdata : b -> Dns_packet.rdata -> b option = fun v rdata ->
  let add n xs = if List.mem n xs then xs else n :: xs in
  match v, rdata with
  | B (Mx, (ttl, mxs)), Dns_packet.MX (prio, name) ->
    Some (B (Mx, (ttl, add (prio, name) mxs)))
  | B (Ns, (ttl, nss)), Dns_packet.NS ns ->
    Some (B (Ns, (ttl, Domain_name.Set.add ns nss)))
  | B (Txt, (ttl, txts)), Dns_packet.TXT txt ->
    Some (B (Txt, (ttl, add txt txts)))
  | B (A, (ttl, ips)), Dns_packet.A ip ->
    Some (B (A, (ttl, add ip ips)))
  | B (Aaaa, (ttl, ips)), Dns_packet.AAAA ip ->
    Some (B (Aaaa, (ttl, add ip ips)))
  | B (Srv, (ttl, srvs)), Dns_packet.SRV srv ->
    Some (B (Srv, (ttl, add srv srvs)))
  | B (Dnskey, keys), Dns_packet.DNSKEY key ->
    Some (B (Dnskey, add key keys))
  | B (Caa, (ttl, caas)), Dns_packet.CAA caa ->
    Some (B (Caa, (ttl, add caa caas)))
  | B (Tlsa, (ttl, tlsas)), Dns_packet.TLSA tlsa ->
    Some (B (Tlsa, (ttl, add tlsa tlsas)))
  | B (Sshfp, (ttl, sshfps)), Dns_packet.SSHFP sshfp ->
    Some (B (Sshfp, (ttl, add sshfp sshfps)))
  | _ -> None

let remove_rdata : b -> Dns_packet.rdata -> b option = fun v rdata ->
  let rm n xs = List.filter (fun x -> compare x n <> 0) xs in
  match v, rdata with
  | B (Mx, (ttl, mxs)), Dns_packet.MX (prio, name) ->
    begin match rm (prio, name) mxs with
      | [] -> None
      | mxs -> Some (B (Mx, (ttl, mxs)))
    end
  | B (Ns, (ttl, nss)), Dns_packet.NS ns ->
    let left = Domain_name.Set.remove ns nss in
    if left = Domain_name.Set.empty then
      None
    else
      Some (B (Ns, (ttl, left)))
  | B (Txt, (ttl, txts)), Dns_packet.TXT txt ->
    begin match rm txt txts with
      | [] -> None
      | txts -> Some (B (Txt, (ttl, txts)))
    end
  | B (A, (ttl, ips)), Dns_packet.A ip ->
    begin match rm ip ips with
      | [] -> None
      | ips -> Some (B (A, (ttl, ips)))
    end
  | B (Aaaa, (ttl, ips)), Dns_packet.AAAA ip ->
    begin match rm ip ips with
      | [] -> None
      | ips -> Some (B (Aaaa, (ttl, ips)))
    end
  | B (Srv, (ttl, srvs)), Dns_packet.SRV srv ->
    begin match rm srv srvs with
      | [] -> None
      | srvs -> Some (B (Srv, (ttl, srvs)))
    end
  | B (Dnskey, keys), Dns_packet.DNSKEY key ->
    begin match rm key keys with
      | [] -> None
      | keys -> Some (B (Dnskey, keys))
    end
  | B (Caa, (ttl, caas)), Dns_packet.CAA caa ->
    begin match rm caa caas with
      | [] -> None
      | caas -> Some (B (Caa, (ttl, caas)))
    end
  | B (Tlsa, (ttl, tlsas)), Dns_packet.TLSA tlsa ->
    begin match rm tlsa tlsas with
      | [] -> None
      | tlsas -> Some (B (Tlsa, (ttl, tlsas)))
    end
  | B (Sshfp, (ttl, sshfps)), Dns_packet.SSHFP sshfp ->
    begin match rm sshfp sshfps with
      | [] -> None
      | sshfps -> Some (B (Sshfp, (ttl, sshfps)))
    end
  | _ -> None

let lookup_rr : Dns_enum.rr_typ -> t -> b option = fun rr t ->
  match rr with
  | Dns_enum.MX -> findb Mx t
  | Dns_enum.NS -> findb Ns t
  | Dns_enum.PTR -> findb Ptr t
  | Dns_enum.SOA -> findb Soa t
  | Dns_enum.TXT -> findb Txt t
  | Dns_enum.A -> findb A t
  | Dns_enum.AAAA -> findb Aaaa t
  | Dns_enum.SRV -> findb Srv t
  | Dns_enum.DNSKEY -> findb Dnskey t
  | Dns_enum.CAA -> findb Caa t
  | Dns_enum.TLSA -> findb Tlsa t
  | Dns_enum.SSHFP -> findb Sshfp t
  | _ -> None

let remove_rr : Dns_enum.rr_typ -> t -> t = fun rr t ->
  match rr with
  | Dns_enum.MX -> remove Mx t
  | Dns_enum.NS -> remove Ns t
  | Dns_enum.PTR -> remove Ptr t
  | Dns_enum.SOA -> remove Soa t
  | Dns_enum.TXT -> remove Txt t
  | Dns_enum.A -> remove A t
  | Dns_enum.AAAA -> remove Aaaa t
  | Dns_enum.SRV -> remove Srv t
  | Dns_enum.DNSKEY -> remove Dnskey t
  | Dns_enum.CAA -> remove Caa t
  | Dns_enum.TLSA -> remove Tlsa t
  | Dns_enum.SSHFP -> remove Sshfp t
  | _ -> t

let of_rrs rrs =
  List.fold_left (fun map rr ->
      let m = match Domain_name.Map.find rr.Dns_packet.name map with
        | None -> empty
        | Some map -> map
      in
      let v = match lookup_rr (Dns_packet.rdata_to_rr_typ rr.Dns_packet.rdata) m with
        | None -> of_rdata rr.Dns_packet.ttl rr.Dns_packet.rdata
        | Some v -> add_rdata v rr.Dns_packet.rdata
      in
      let m' = match v with
        | None ->
          Logs.warn (fun m -> m "failed to insert rr %a" Dns_packet.pp_rr rr) ;
          m
        | Some v -> addb v m
      in
      Domain_name.Map.add rr.Dns_packet.name m' map)
    Domain_name.Map.empty rrs

let text name (B (key, v)) = K.text name key v
