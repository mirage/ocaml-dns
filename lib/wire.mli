val offset_of_bitstring : Bitstring.t -> int

(** For bit manipulation. *)
type int16 = int
(** Convert {! int } to {! byte }; useful in pipelines. *)
val int16 : int -> int16
(* val int16_to_int : int16 -> int *)

(** Single octet, for bit manipulation. *)
type byte
(** Convert {! int } to {! byte }; useful in pipelines. *)
val byte : int -> byte
(** Convert {! byte } to {! int }. *)
val byte_to_int : byte -> int
(** Convert {! byte } to {! Int32 }. *)
val byte_to_int32 : byte -> int32

(** *)
type bytes
val bytes : string -> bytes 
val bits_to_bytes : Bitstring.t -> bytes
val bytes_to_string : bytes -> string
val bytes_to_ipv4 : bytes -> Uri_IP.ipv4

(** Received some unparsable bits. *)
exception Unparsable of string * Bitstring.t

