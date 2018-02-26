(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

(* this code wouldn't exist without Justus Matthiesen, thanks for the help! *)

module Order = struct
  type (_,_) t =
    | Lt : ('a, 'b) t
    | Eq : ('a, 'a) t
    | Gt : ('a, 'b) t
end

module type KEY = sig
  type _ t
  val compare : 'a t -> 'b t -> ('a, 'b) Order.t
  val pp : Format.formatter -> 'a t -> 'a -> unit
end

module type S = sig
  type 'a key
  type t
  type v = V : 'a key * 'a -> v

  val empty : t
  val is_empty : t -> bool
  val mem : 'a key -> t -> bool
  val addv : v -> t -> t
  val add : 'a key -> 'a -> t -> t
  val singleton : 'a key -> 'a -> t
  val remove : 'a key -> t -> t
  val getv : 'a key -> t -> v
  val get : 'a key -> t -> 'a
  val findv : 'a key -> t -> v option
  val find : 'a key -> t -> 'a option
  val min_binding : t -> v
  val max_binding : t -> v
  val bindings : t -> v list
  val cardinal : t -> int
  val choose :  t -> v
  val iter : (v -> unit) -> t -> unit
  val fold : (v -> 'a -> 'a) -> t -> 'a -> 'a
  val for_all : (v -> bool) -> t -> bool
  val exists : (v -> bool) -> t -> bool
  val filter : (v -> bool) -> t -> t
  val pp : Format.formatter -> t -> unit
  val equal : (v -> v -> bool) -> t -> t -> bool
end

module Make (Key : KEY) : S with type 'a key = 'a Key.t = struct
  type 'a key = 'a Key.t
  type k = K : 'a key -> k
  type v = V : 'a key * 'a -> v

  module M = Map.Make(struct
      type t = k
      let compare (K a) (K b) = match Key.compare a b with
        | Order.Lt -> -1
        | Order.Eq -> 0
        | Order.Gt -> 1
    end)

  type t = v M.t

  let empty = M.empty
  let is_empty = M.is_empty
  let mem k m = M.mem (K k) m
  let addv (V (k, _) as v) m = M.add (K k) v m
  let add k v m = M.add (K k) (V (k, v)) m
  let singleton k v = M.singleton (K k) (V (k, v))
  let remove k m = M.remove (K k) m
  let getv : type a. a Key.t -> t -> v = fun k t ->
    match M.find (K k) t with
    | V (k', v) ->
      match Key.compare k k' with
      | Order.Eq -> V (k, v)
      | _ -> assert false
  let get : type a. a Key.t -> t -> a = fun k t ->
    match M.find (K k) t with
    | V (k', v) ->
      match Key.compare k k' with
      | Order.Eq -> v
      | _ -> assert false
  let findv : type a. a Key.t -> t -> v option = fun k t ->
    try Some (getv k t) with Not_found -> None
  let find : type a. a Key.t -> t -> a option = fun k t ->
    try Some (get k t) with Not_found -> None

  let min_binding t = snd (M.min_binding t)
  (* min_binding_opt (since 4.05) *)
  let max_binding t = snd (M.max_binding t)
  (* max_binding_opt (since 4.05) *)
  let bindings t = snd (List.split (M.bindings t))
  let cardinal t = M.cardinal t

  let choose t = snd (M.choose t)
  (* choose_opt since 4.05 *)
  (* find_first / find_first_opt / find_last / find_last_opt *)
  let iter f t = M.iter (fun _ b -> f b) t
  let fold f t acc = M.fold (fun _ b acc -> f b acc) t acc
  let for_all f t = M.for_all (fun _ b -> f b) t
  let exists f t = M.exists (fun _ b -> f b) t
  let filter f t = M.filter (fun _ b -> f b) t

  let pp ppf t =
    let pp ppf = function
      | V (k, v) -> Key.pp ppf k v
    in
    Fmt.(list ~sep:(unit "@.") pp) ppf (bindings t)

  let equal cmp a b = M.equal cmp a b

  (*
    val merge :
      (key -> 'a option -> 'b option -> 'c option) -> 'a t -> 'b t -> 'c t
    val union : (key -> 'a -> 'a -> 'a option) -> 'a t -> 'a t -> 'a t
    val compare : ('a -> 'a -> int) -> 'a t -> 'a t -> int
    val equal : ('a -> 'a -> bool) -> 'a t -> 'a t -> bool
    val partition : (key -> 'a -> bool) -> 'a t -> 'a t * 'a t
    val split : key -> 'a t -> 'a t * 'a option * 'a t
    let map f t = M.map (fun _ b -> f b) t
    val mapi : (key -> 'a -> 'b) -> 'a t -> 'b t
*)
end


module K = struct
  (* still feels wrong, maybe more explicit? *)
  type _ t =
    | Any : (Dns_packet.rr list * Dns_name.DomSet.t) t
    | Cname : (int32 * Dns_name.t) t
    | Mx : (int32 * (int * Dns_name.t) list) t
    | Ns : (int32 * Dns_name.DomSet.t) t
    | Ptr : (int32 * Dns_name.t) t
    | Soa : (int32 * Dns_packet.soa) t
    | Txt : (int32 * string list list) t
    | A : (int32 * Ipaddr.V4.t list) t
    | Aaaa : (int32 * Ipaddr.V6.t list) t
    | Srv : (int32 * Dns_packet.srv list) t
    | Dnskey : Dns_packet.dnskey list t
    | Caa : (int32 * Dns_packet.caa list) t
    | Tlsa : (int32 * Dns_packet.tlsa list) t
    | Sshfp : (int32 * Dns_packet.sshfp list) t

  let compare : type a b. a t -> b t -> (a, b) Order.t = fun t t' ->
    let open Order in
    match t, t' with
    | Any, Any -> Eq | Any, _ -> Lt | _, Any -> Gt
    | Cname, Cname -> Eq | Cname, _ -> Lt | _, Cname -> Gt
    | Mx, Mx -> Eq | Mx, _ -> Lt | _, Mx -> Gt
    | Ns, Ns -> Eq | Ns, _ -> Lt | _, Ns -> Gt
    | Ptr, Ptr -> Eq | Ptr, _ -> Lt | _, Ptr -> Gt
    | Soa, Soa -> Eq | Soa, _ -> Lt | _, Soa -> Gt
    | Txt, Txt -> Eq | Txt, _ -> Lt | _, Txt -> Gt
    | A, A -> Eq | A, _ -> Lt | _, A -> Gt
    | Aaaa, Aaaa -> Eq | Aaaa, _ -> Lt | _, Aaaa -> Gt
    | Srv, Srv -> Eq | Srv, _ -> Lt | _, Srv -> Gt
    | Dnskey, Dnskey -> Eq | Dnskey, _ -> Lt | _, Dnskey -> Gt
    | Caa, Caa -> Eq | Caa, _ -> Lt | _, Caa -> Gt
    | Tlsa, Tlsa -> Eq | Tlsa, _ -> Lt | _, Tlsa -> Gt
    | Sshfp, Sshfp -> Eq (* | Sshfp, _ -> Lt | _, Sshfp -> Gt *)

  let pp : type a. Format.formatter -> a t -> a -> unit = fun ppf t v ->
    match t, v with
    | Any, (entries, names) ->
      Fmt.pf ppf "any %a %a" Dns_packet.pp_rrs entries
        Fmt.(list ~sep:(unit ";@,") Dns_name.pp) (Dns_name.DomSet.elements names)
    | Cname, (ttl, alias) -> Fmt.pf ppf "cname ttl %lu %a" ttl Dns_name.pp alias
    | Mx, (ttl, mxs) ->
      Fmt.pf ppf "mx ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") (pair ~sep:(unit " ") int Dns_name.pp)) mxs
    | Ns, (ttl, names) ->
      Fmt.pf ppf "ns ttl %lu %a" ttl
        Fmt.(list ~sep:(unit ";@,") Dns_name.pp) (Dns_name.DomSet.elements names)
    | Ptr, (ttl, name) -> Fmt.pf ppf "ptr ttl %lu %a" ttl Dns_name.pp name
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
end

include Make(K)

let pp_v ppf (V (k, v)) = K.pp ppf k v

let equal_v v v' = match v, v' with
  | V (K.Any, (entries, names)), V (K.Any, (entries', names')) ->
    List.length entries = List.length entries' &&
    List.for_all (fun e ->
        List.exists (fun e' -> Dns_packet.rr_equal e e') entries')
      entries &&
    Dns_name.DomSet.equal names names'
  | V (K.Cname, (_, alias)), V (K.Cname, (_, alias')) ->
    Dns_name.equal alias alias'
  | V (K.Mx, (_, mxs)), V (K.Mx, (_, mxs')) ->
    List.length mxs = List.length mxs' &&
    List.for_all (fun (prio, name) ->
        List.exists (fun (prio', name') ->
            prio = prio' && Dns_name.equal name name')
          mxs')
      mxs
  | V (K.Ns, (_, ns)), V (K.Ns, (_, ns')) ->
    Dns_name.DomSet.equal ns ns'
  | V (K.Ptr, (_, name)), V (K.Ptr, (_, name')) ->
    Dns_name.equal name name'
  | V (K.Soa, (_, soa)), V (K.Soa, (_, soa')) ->
    Dns_packet.compare_soa soa soa' = 0
  | V (K.Txt, (_, txts)), V (K.Txt, (_, txts')) ->
    List.length txts = List.length txts &&
    List.for_all (fun txt ->
        List.exists (fun txt' ->
            List.length txt = List.length txt' &&
            List.for_all2 String.equal txt txt')
          txts')
      txts
  | V (K.A, (_, aas)), V (K.A, (_, aas')) ->
    List.length aas = List.length aas' &&
    List.for_all (fun a ->
        List.exists (fun a' -> Ipaddr.V4.compare a a' = 0) aas')
      aas
  | V (K.Aaaa, (_, aaaas)), V (K.Aaaa, (_, aaaas')) ->
    List.length aaaas = List.length aaaas' &&
    List.for_all (fun aaaa ->
        List.exists (fun aaaa' -> Ipaddr.V6.compare aaaa aaaa' = 0) aaaas')
      aaaas
  | V (K.Srv, (_, srvs)), V (K.Srv, (_, srvs')) ->
    List.length srvs = List.length srvs' &&
    List.for_all (fun srv ->
        List.exists (fun srv' -> Dns_packet.compare_srv srv srv' = 0) srvs')
      srvs
  | V (K.Dnskey, keys), V (K.Dnskey, keys') ->
    List.length keys = List.length keys' &&
    List.for_all (fun key ->
        List.exists (fun key' -> Dns_packet.compare_dnskey key key' = 0) keys')
      keys
  | V (K.Caa, (_, caas)), V (K.Caa, (_, caas')) ->
    List.length caas = List.length caas' &&
    List.for_all (fun caa ->
        List.exists (fun caa' -> Dns_packet.compare_caa caa caa' = 0) caas')
      caas
  | V (K.Tlsa, (_, tlsas)), V (K.Tlsa, (_, tlsas')) ->
    List.length tlsas = List.length tlsas' &&
    List.for_all (fun tlsa ->
        List.exists (fun tlsa' -> Dns_packet.compare_tlsa tlsa tlsa' = 0) tlsas')
      tlsas
  | V (K.Sshfp, (_, sshfps)), V (K.Sshfp, (_, sshfps')) ->
    List.length sshfps = List.length sshfps' &&
    List.for_all (fun sshfp ->
        List.exists (fun sshfp' -> Dns_packet.compare_sshfp sshfp sshfp' = 0) sshfps')
      sshfps
  | _, _ -> false

let glue map =
  Dns_name.DomMap.fold (fun name ((ttla, a), (ttlaaaa, aaaa)) acc ->
      (List.map (fun a ->
           { Dns_packet.name ; ttl = ttla ; rdata = Dns_packet.A a })
          a @
       List.map (fun aaaa ->
           { Dns_packet.name ; ttl = ttlaaaa ; rdata = Dns_packet.AAAA aaaa })
          aaaa) @ acc)
    map []

let to_rr_typ : v -> Dns_enum.rr_typ = fun (V (k, _)) ->
  match k with
  | K.Any -> Dns_enum.ANY
  | K.Cname -> Dns_enum.CNAME
  | K.Mx -> Dns_enum.MX
  | K.Ns -> Dns_enum.NS
  | K.Ptr -> Dns_enum.PTR
  | K.Soa -> Dns_enum.SOA
  | K.Txt -> Dns_enum.TXT
  | K.A -> Dns_enum.A
  | K.Aaaa -> Dns_enum.AAAA
  | K.Srv -> Dns_enum.SRV
  | K.Dnskey -> Dns_enum.DNSKEY
  | K.Caa -> Dns_enum.CAA
  | K.Tlsa -> Dns_enum.TLSA
  | K.Sshfp -> Dns_enum.SSHFP

let to_rr : Dns_name.t -> v -> Dns_packet.rr list = fun name (V (k, v)) ->
  match k, v with
  | K.Any, (entries, _) -> entries
  | K.Cname, (ttl, alias) ->
    [ { Dns_packet.name ; ttl ; rdata = Dns_packet.CNAME alias } ]
  | K.Mx, (ttl, mxs) ->
    List.map (fun (prio, mx) ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.MX (prio, mx) })
      mxs
  | K.Ns, (ttl, names) ->
    Dns_name.DomSet.fold (fun ns acc ->
      { Dns_packet.name ; ttl ; rdata = Dns_packet.NS ns } :: acc)
      names []
  | K.Ptr, (ttl, name) ->
    [ { Dns_packet.name ; ttl ; rdata = Dns_packet.PTR name } ]
  | K.Soa, (ttl, soa) ->
    [ { Dns_packet.name ; ttl ; rdata = Dns_packet.SOA soa } ]
  | K.Txt, (ttl, txts) ->
    List.map (fun txt ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.TXT txt })
      txts
  | K.A, (ttl, aas) ->
    List.map (fun a ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.A a })
      aas
  | K.Aaaa, (ttl, aaaas) ->
    List.map (fun aaaa ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.AAAA aaaa })
      aaaas
  | K.Srv, (ttl, srvs) ->
    List.map (fun srv ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.SRV srv })
      srvs
  | K.Dnskey, dnskeys ->
    List.map (fun key ->
        { Dns_packet.name ; ttl = 0l ; rdata = Dns_packet.DNSKEY key })
      dnskeys
  | K.Caa, (ttl, caas) ->
    List.map (fun caa ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.CAA caa })
      caas
  | K.Tlsa, (ttl, tlsas) ->
    List.map (fun tlsa ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.TLSA tlsa })
      tlsas
  | K.Sshfp, (ttl, sshfps) ->
    List.map (fun sshfp ->
        { Dns_packet.name ; ttl ; rdata = Dns_packet.SSHFP sshfp })
      sshfps

let names = function
  | V (K.Any, (_, names)) -> names
  | V (K.Mx, (_, mxs)) -> Dns_name.DomSet.of_list (snd (List.split mxs))
  | V (K.Ns, (_, names)) -> names
  | V (K.Srv, (_, srvs)) ->
    Dns_name.DomSet.of_list (List.map (fun x -> x.Dns_packet.target) srvs)
  | _ -> Dns_name.DomSet.empty

let of_rdata : int32 -> Dns_packet.rdata -> v option = fun ttl rd ->
  match rd with
  | Dns_packet.MX (prio, name) -> Some (V (K.Mx, (ttl, [ (prio, name) ])))
  | Dns_packet.NS ns -> Some (V (K.Ns, (ttl, Dns_name.DomSet.singleton ns)))
  | Dns_packet.PTR ptr -> Some (V (K.Ptr, (ttl, ptr)))
  | Dns_packet.SOA soa -> Some (V (K.Soa, (ttl, soa)))
  | Dns_packet.TXT txt -> Some (V (K.Txt, (ttl, [ txt ])))
  | Dns_packet.A ip -> Some (V (K.A, (ttl, [ ip ])))
  | Dns_packet.AAAA ip -> Some (V (K.Aaaa, (ttl, [ ip ])))
  | Dns_packet.SRV srv -> Some (V (K.Srv, (ttl, [ srv ])))
  | Dns_packet.DNSKEY key -> Some (V (K.Dnskey, [ key ]))
  | Dns_packet.CAA caa -> Some (V (K.Caa, (ttl, [ caa ])))
  | Dns_packet.TLSA tlsa -> Some (V (K.Tlsa, (ttl, [ tlsa ])))
  | Dns_packet.SSHFP sshfp -> Some (V (K.Sshfp, (ttl, [ sshfp ])))
  | _ -> None

let add_rdata : v -> Dns_packet.rdata -> v option = fun v rdata ->
  let add n xs = if List.mem n xs then xs else n :: xs in
  match v, rdata with
  | V (K.Mx, (ttl, mxs)), Dns_packet.MX (prio, name) ->
    Some (V (K.Mx, (ttl, add (prio, name) mxs)))
  | V (K.Ns, (ttl, nss)), Dns_packet.NS ns ->
    Some (V (K.Ns, (ttl, Dns_name.DomSet.add ns nss)))
  | V (K.Txt, (ttl, txts)), Dns_packet.TXT txt ->
    Some (V (K.Txt, (ttl, add txt txts)))
  | V (K.A, (ttl, ips)), Dns_packet.A ip ->
    Some (V (K.A, (ttl, add ip ips)))
  | V (K.Aaaa, (ttl, ips)), Dns_packet.AAAA ip ->
    Some (V (K.Aaaa, (ttl, add ip ips)))
  | V (K.Srv, (ttl, srvs)), Dns_packet.SRV srv ->
    Some (V (K.Srv, (ttl, add srv srvs)))
  | V (K.Dnskey, keys), Dns_packet.DNSKEY key ->
    Some (V (K.Dnskey, add key keys))
  | V (K.Caa, (ttl, caas)), Dns_packet.CAA caa ->
    Some (V (K.Caa, (ttl, add caa caas)))
  | V (K.Tlsa, (ttl, tlsas)), Dns_packet.TLSA tlsa ->
    Some (V (K.Tlsa, (ttl, add tlsa tlsas)))
  | V (K.Sshfp, (ttl, sshfps)), Dns_packet.SSHFP sshfp ->
    Some (V (K.Sshfp, (ttl, add sshfp sshfps)))
  | _ -> None

let remove_rdata : v -> Dns_packet.rdata -> v option = fun v rdata ->
  let rm n xs = List.filter (fun x -> compare x n <> 0) xs in
  match v, rdata with
  | V (K.Mx, (ttl, mxs)), Dns_packet.MX (prio, name) ->
    begin match rm (prio, name) mxs with
      | [] -> None
      | mxs -> Some (V (K.Mx, (ttl, mxs)))
    end
  | V (K.Ns, (ttl, nss)), Dns_packet.NS ns ->
    let left = Dns_name.DomSet.remove ns nss in
    if left = Dns_name.DomSet.empty then
      None
    else
      Some (V (K.Ns, (ttl, left)))
  | V (K.Txt, (ttl, txts)), Dns_packet.TXT txt ->
    begin match rm txt txts with
      | [] -> None
      | txts -> Some (V (K.Txt, (ttl, txts)))
    end
  | V (K.A, (ttl, ips)), Dns_packet.A ip ->
    begin match rm ip ips with
      | [] -> None
      | ips -> Some (V (K.A, (ttl, ips)))
    end
  | V (K.Aaaa, (ttl, ips)), Dns_packet.AAAA ip ->
    begin match rm ip ips with
      | [] -> None
      | ips -> Some (V (K.Aaaa, (ttl, ips)))
    end
  | V (K.Srv, (ttl, srvs)), Dns_packet.SRV srv ->
    begin match rm srv srvs with
      | [] -> None
      | srvs -> Some (V (K.Srv, (ttl, srvs)))
    end
  | V (K.Dnskey, keys), Dns_packet.DNSKEY key ->
    begin match rm key keys with
      | [] -> None
      | keys -> Some (V (K.Dnskey, keys))
    end
  | V (K.Caa, (ttl, caas)), Dns_packet.CAA caa ->
    begin match rm caa caas with
      | [] -> None
      | caas -> Some (V (K.Caa, (ttl, caas)))
    end
  | V (K.Tlsa, (ttl, tlsas)), Dns_packet.TLSA tlsa ->
    begin match rm tlsa tlsas with
      | [] -> None
      | tlsas -> Some (V (K.Tlsa, (ttl, tlsas)))
    end
  | V (K.Sshfp, (ttl, sshfps)), Dns_packet.SSHFP sshfp ->
    begin match rm sshfp sshfps with
      | [] -> None
      | sshfps -> Some (V (K.Sshfp, (ttl, sshfps)))
    end
  | _ -> None

let lookup_rr : Dns_enum.rr_typ -> t -> v option = fun rr t ->
  match rr with
  | Dns_enum.MX -> findv K.Mx t
  | Dns_enum.NS -> findv K.Ns t
  | Dns_enum.PTR -> findv K.Ptr t
  | Dns_enum.SOA -> findv K.Soa t
  | Dns_enum.TXT -> findv K.Txt t
  | Dns_enum.A -> findv K.A t
  | Dns_enum.AAAA -> findv K.Aaaa t
  | Dns_enum.SRV -> findv K.Srv t
  | Dns_enum.DNSKEY -> findv K.Dnskey t
  | Dns_enum.CAA -> findv K.Caa t
  | Dns_enum.TLSA -> findv K.Tlsa t
  | Dns_enum.SSHFP -> findv K.Sshfp t
  | _ -> None

let remove_rr : Dns_enum.rr_typ -> t -> t = fun rr t ->
  match rr with
  | Dns_enum.MX -> remove K.Mx t
  | Dns_enum.NS -> remove K.Ns t
  | Dns_enum.PTR -> remove K.Ptr t
  | Dns_enum.SOA -> remove K.Soa t
  | Dns_enum.TXT -> remove K.Txt t
  | Dns_enum.A -> remove K.A t
  | Dns_enum.AAAA -> remove K.Aaaa t
  | Dns_enum.SRV -> remove K.Srv t
  | Dns_enum.DNSKEY -> remove K.Dnskey t
  | Dns_enum.CAA -> remove K.Caa t
  | Dns_enum.TLSA -> remove K.Tlsa t
  | Dns_enum.SSHFP -> remove K.Sshfp t
  | _ -> t

let of_rrs rrs =
  List.fold_left (fun map rr ->
      let m = match Dns_name.DomMap.find rr.Dns_packet.name map with
        | exception Not_found -> empty
        | map -> map
      in
      let v = match lookup_rr (Dns_packet.rdata_to_rr_typ rr.Dns_packet.rdata) m with
        | None -> of_rdata rr.Dns_packet.ttl rr.Dns_packet.rdata
        | Some v -> add_rdata v rr.Dns_packet.rdata
      in
      let m' = match v with
        | None -> (* warn? *) m
        | Some v -> addv v m
      in
      Dns_name.DomMap.add rr.Dns_packet.name m' map)
    Dns_name.DomMap.empty rrs
