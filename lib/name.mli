type label
type domain_name = string list
val parse_name : 
  (int, label) Hashtbl.t -> int -> Bitstring.t -> domain_name * Bitstring.t
val domain_name_to_string : domain_name -> string

(** Construct a {! Hashcons} character-string from a string. *)
val hashcons_charstring : string -> string Hashcons.hash_consed

(** Construct a {! Hashcons} domain name (list of labels) from a {!
    domain_name}. *)
val hashcons_domainname : domain_name -> domain_name Hashcons.hash_consed

(** Clear the {! Hashcons} table. *)
val clear_cons_tables : unit -> unit

(** Malformed input to {! canon2key}. *)
exception BadDomainName of string

(** Lookup key for the {! Trie}. *)
type key = string

(** Convert a canonical [[ "www"; "example"; "com" ]] domain name into a key.
    N.B. Requires that the input is already lower-case!  
*)
val canon2key : domain_name -> key

val label_set : domain_name -> string list list
val domain_name_to_string_list : domain_name -> string list




















