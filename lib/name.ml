open Wire
open Operators

type label =              
  | L of string * int (* string *)
  | P of int * int (* pointer *)
  | Z of int (* zero; terminator *)

let parse_label base bits = 
  let cur = offset_of_bitstring bits in
  let offset = (cur-base)/8 in
  bitmatch bits with
    | { length: 8: check(length != 0 && length < 64); 
        name: (length*8): string; bits: -1: bitstring }
      -> (L (name, offset), bits)
    
    | { 0b0_11: 2; ptr: 14; bits: -1: bitstring } 
      -> (P (ptr, offset), bits)
    
    | { 0: 8; bits: -1: bitstring } 
      -> (Z offset, bits)

type domain_name = string list
let domain_name (sl:string list) : domain_name = sl
let empty_domain_name = []
let domain_name_to_string dn = join "." dn
let parse_name names base bits = 
  (* what. a. mess. *)
  let rec aux offsets name bits = 
    match parse_label base bits with
      | (L (n, o) as label, data) 
        -> Hashtbl.add names o label;
          offsets |> List.iter (fun off -> (Hashtbl.add names off label));
          aux (o :: offsets) (n :: name) data 
      | (P (p, _), data) 
        -> let ns = (Hashtbl.find_all names p
                        |> List.filter (function L _ -> true | _ -> false)
                        |> List.rev)
           in
           offsets |> List.iter (fun off ->
             ns |> List.iter (fun n -> Hashtbl.add names off n)
           );
           ((ns |> List.rev ||> (
             function
               | L (nm,_) -> nm
               | _ -> raise (Unparsable ("parse_name", bits)))
            ) @ name), data
      | (Z o as zero, data) -> Hashtbl.add names o zero; (name, data)
  in 
  let name, bits = aux [] [] bits in
  (List.rev name, bits)

(* Hash-consing: character strings *)
module CSH = Hashcons.Make (struct 
  type t = string 
  let equal a b = (a = b)
  let hash s = Hashtbl.hash s
end)
let cstr_hash = ref (CSH.create 101)
let hashcons_charstring s = CSH.hashcons !cstr_hash s

(* 
   Hash-consing: domain names (string lists).  This requires a little
   more subtlety than the Hashcons module gives us directly: we want to 
   merge common suffixes, and we're downcasing everything. 
   N.B. RFC 4343 says we shouldn't do this downcasing.
*)
module DNH = Hashcons.Make (struct 
  type t = domain_name
  let equal a b = (a = b)
  let hash s = Hashtbl.hash s
end)
let dn_hash = ref (DNH.create 101)
let rec hashcons_domainname (x:domain_name) = match x with
  | [] -> DNH.hashcons !dn_hash empty_domain_name
  | h :: t -> 
      let th = hashcons_domainname t 
      in DNH.hashcons !dn_hash 
	(((hashcons_charstring (String.lowercase h)).Hashcons.node) 
	 :: (th.Hashcons.node))

let clear_cons_tables () = 
  DNH.clear !dn_hash;
  CSH.clear !cstr_hash;
  dn_hash := DNH.create 1;
  cstr_hash := CSH.create 1

exception BadDomainName of string

type key = string

let canon2key domain_name = 
  let labelize s = 
    if String.contains s '\000' then 
      raise (BadDomainName "contains null character");
    if String.length s = 0 then 
      raise (BadDomainName "zero-length label");
    if String.length s > 63 then 
      raise (BadDomainName ("label too long: " ^ s));
    s 
  in List.fold_left (fun s l -> (labelize l) ^ "\000" ^ s) "" domain_name










