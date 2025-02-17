(* (c) 2017-2019 Hannes Mehnert, all rights reserved *)

type proto = [ `Tcp | `Udp ]

let max_rdata_length =
  (* The maximum length of a single resource record data must be limited, such
     a resource record needs to fit into a DNS message together with some more
     data (namely question, header, and TSIG). The size of a DNS message is
     limited by EDNS, which uses the class field (2 byte) for the indication,
     and the TCP transport requires a 2 byte length prefix.

     so in total it may not exceed 65535 bytes, including:
     - DNS header
     - 1 QUESTION
     - 1 RR
     - 1 TSIG

     being conservative (name compression = off):
     - header: ID (2 byte) OP+FLAGS (2 byte), 4 * 2 byte count of question, answer, authority, additional = 12 byte
     - question: name (max 255 bytes), typ (2 byte), class (2 byte) = 259
     - RR: name, typ, class, ttl (4 byte), rdlength (2 byte), rdata (this is the size we are interested in) = 265 + x
     - TSIG being key name, typ, class, ttl, rdlength, 16 bytes (base TSIG struct), algorithm name (atm 13 bytes "hmac-sha512"), mac (64 bytes, sha512) = 358
     --> 65535 - 894 = 64641 bytes
  *)
  64641

let andThen v f = match v with 0 -> f | x -> x
let opt_eq f a b = match a, b with
  | Some a, Some b -> f a b
  | None, None -> true
  | _ -> false

let guard p err = if p then Ok () else Error err

let src = Logs.Src.create "dns" ~doc:"DNS core"
module Log = (val Logs.src_log src : Logs.LOG)

module Ptime_extra = struct
  (* this is here because I don't like float, and rather convert Ptime.t to int64 *)
  let s_in_d = 86_400L
  let ps_in_s = 1_000_000_000_000L

  let span_to_int64 ts =
    let d_min, d_max = Int64.(div min_int s_in_d, div max_int s_in_d) in
    let d, ps = Ptime.Span.to_d_ps ts in
    let d = Int64.of_int d in
    if d < d_min || d > d_max then
      None
    else
      let s = Int64.mul d s_in_d in
      let s' = Int64.(add s (div ps ps_in_s)) in
      if s' < s then
        None
      else
        Some s'

  let to_int64 t = span_to_int64 (Ptime.to_span t)

  let of_int64 ?(off = 0) s =
    let d, ps = Int64.(div s s_in_d, mul (rem s s_in_d) ps_in_s) in
    if d < Int64.of_int min_int || d > Int64.of_int max_int then
      Error (`Malformed (off, Fmt.str "timestamp does not fit in time range %Ld" s))
    else
      match Ptime.Span.of_d_ps (Int64.to_int d, ps) with
      | Some span ->
        begin match Ptime.of_span span with
          | Some ts -> Ok ts
          | None -> Error (`Malformed (off, Fmt.str "span does not fit into timestamp %Ld" s))
        end
      | None -> Error (`Malformed (off, Fmt.str "timestamp does not fit %Ld" s))
end

module Class = struct
  (* 16 bit *)
  type t =
    (* Reserved0 [@id 0] RFC6895 *)
    | IN (* RFC1035 *)
    (* 2 Uassigned *)
    | CHAOS (* D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981. *)
    | HESIOD (* Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987. *)
    | NONE (* RFC2136 *)
    | ANY_CLASS (* RFC1035 *)
  (* 256-65279 Unassigned *)
  (* 65280-65534 Reserved for Private Use [RFC6895] *)
  (* ReservedFFFF [@id 65535] *)

  let to_int = function
    | IN -> 1
    | CHAOS -> 3
    | HESIOD -> 4
    | NONE -> 254
    | ANY_CLASS -> 255

  let _compare a b = Int.compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 1 -> Ok IN
    | 3 -> Ok CHAOS
    | 4 -> Ok HESIOD
    | 254 -> Ok NONE
    | 255 -> Ok ANY_CLASS
    | c -> Error (`Not_implemented (off, Fmt.str "class %X" c))

  let to_string = function
    | IN -> "IN"
    | CHAOS -> "CHAOS"
    | HESIOD -> "HESIOD"
    | NONE -> "NONE"
    | ANY_CLASS -> "ANY_CLASS"

  let _pp ppf c = Fmt.string ppf (to_string c)
end

module Opcode = struct
  (* 4 bit *)
  type t =
    | Query (* RFC1035 *)
    | IQuery (* Inverse Query, OBSOLETE) [RFC3425] *)
    | Status (* RFC1035 *)
    (* 3 Unassigned *)
    | Notify (* RFC1996 *)
    | Update (* RFC2136 *)
  (* 6-15 Unassigned *)

  let to_int = function
    | Query -> 0
    | IQuery -> 1
    | Status -> 2
    | Notify -> 4
    | Update -> 5

  let compare a b = Int.compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 0 -> Ok Query
    | 1 -> Ok IQuery
    | 2 -> Ok Status
    | 4 -> Ok Notify
    | 5 -> Ok Update
    | x -> Error (`Not_implemented (off, Fmt.str "opcode 0x%X" x))

  let to_string = function
    | Query -> "Query"
    | IQuery -> "IQuery"
    | Status -> "Status"
    | Notify -> "Notify"
    | Update -> "Update"

  let pp ppf t = Fmt.string ppf (to_string t)
end

module Rcode = struct
  (* 4 bit + 16 in EDNS/TSIG*)
  type t =
    | NoError (* No Error,[RFC1035] *)
    | FormErr (* Format Error,[RFC1035] *)
    | ServFail (* Server Failure,[RFC1035] *)
    | NXDomain (* Non-Existent Domain,[RFC1035] *)
    | NotImp (* Not Implemented,[RFC1035] *)
    | Refused (* Query Refused,[RFC1035] *)
    | YXDomain (* Name Exists when it should not,[RFC2136][RFC6672] *)
    | YXRRSet (* RR Set Exists when it should not,[RFC2136] *)
    | NXRRSet (* RR Set that should exist does not,[RFC2136] *)
    | NotAuth (* Server Not Authoritative for zone,[RFC2136]
                 9,NotAuth,Not Authorized,[RFC2845] *)
    | NotZone (* Name not contained in zone,[RFC2136] *)
    (* 11-15,Unassigned *)
    | BadVersOrSig (* 16,BADVERS,Bad OPT Version,[RFC6891]
                      16,BADSIG,TSIG Signature Failure,[RFC2845] *)
    | BadKey (* Key not recognized,[RFC2845] *)
    | BadTime (* Signature out of time window,[RFC2845] *)
    | BadMode (* BADMODE,Bad TKEY Mode,[RFC2930] *)
    | BadName (* BADNAME,Duplicate key name,[RFC2930] *)
    | BadAlg (* BADALG,Algorithm not supported,[RFC2930] *)
    | BadTrunc (* BADTRUNC,Bad Truncation,[RFC4635] *)
    | BadCookie (* BADCOOKIE,Bad/missing Server Cookie,[RFC7873] *)
  (* 24-3840,Unassigned *)
  (* 3841-4095,Reserved for Private Use,,[RFC6895] *)
  (* 4096-65534,Unassigned *)
  (* 65535,"Reserved, can be allocated by Standards Action",,[RFC6895] *)

  let to_int = function
    | NoError -> 0 | FormErr -> 1 | ServFail -> 2 | NXDomain -> 3
    | NotImp -> 4 | Refused -> 5 | YXDomain -> 6 | YXRRSet -> 7
    | NXRRSet -> 8 | NotAuth -> 9 | NotZone -> 10 | BadVersOrSig -> 16
    | BadKey -> 17 | BadTime -> 18 | BadMode -> 19 | BadName -> 20
    | BadAlg -> 21 | BadTrunc -> 22 | BadCookie -> 23
  let compare a b = Int.compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 0 -> Ok NoError | 1 -> Ok FormErr | 2 -> Ok ServFail
    | 3 -> Ok NXDomain | 4 -> Ok NotImp | 5 -> Ok Refused
    | 6 -> Ok YXDomain | 7 -> Ok YXRRSet | 8 -> Ok NXRRSet
    | 9 -> Ok NotAuth | 10 -> Ok NotZone | 16 -> Ok BadVersOrSig
    | 17 -> Ok BadKey | 18 -> Ok BadTime | 19 -> Ok BadMode
    | 20 -> Ok BadName | 21 -> Ok BadAlg | 22 -> Ok BadTrunc
    | 23 -> Ok BadCookie
    | x -> Error (`Not_implemented (off, Fmt.str "rcode 0x%04X" x))
  let to_string = function
    | NoError -> "no error" | FormErr -> "form error"
    | ServFail -> "server failure" | NXDomain -> "no such domain"
    | NotImp -> "not implemented" | Refused -> "refused"
    | YXDomain -> "name exists when it should not"
    | YXRRSet -> "resource record set exists when it should not"
    | NXRRSet -> "resource record set that should exist does not"
    | NotAuth -> "server not authoritative for zone or not authorized"
    | NotZone -> "name not contained in zone"
    | BadVersOrSig -> "bad version or signature"
    | BadKey -> "bad TSIG key" | BadTime -> "signature time out of window"
    | BadMode -> "bad TKEY mode" | BadName -> "duplicate key name"
    | BadAlg -> "unsupported algorithm"  | BadTrunc -> "bad truncation"
    | BadCookie -> "bad cookie"

  let pp ppf r = Fmt.string ppf (to_string r)
end

let ( let* ) = Result.bind

module Name = struct
  module Int_map = Map.Make(struct
      type t = int
      let compare = Int.compare
    end)
  type name_offset_map = int Domain_name.Map.t

  let ptr_tag = 0xC0 (* = 1100 0000 *)

  let decode names buf ~off =
    (* first collect all the labels (and their offsets) *)
    let rec aux offsets off =
      match String.get_uint8 buf off with
      | 0 -> Ok ((`Z, off), offsets, succ off)
      | i when i >= ptr_tag ->
        let ptr = (i - ptr_tag) lsl 8 + String.get_uint8 buf (succ off) in
        Ok ((`P ptr, off), offsets, off + 2)
      | i when i >= 64 -> Error (`Malformed (off, Fmt.str "label tag 0x%x" i)) (* bit patterns starting with 10 or 01 *)
      | i -> (* this is clearly < 64! *)
        let name = String.sub buf (succ off) i in
        aux ((name, off) :: offsets) (succ off + i)
    in
    (* Cstruct.xxx can raise, and we'll have a partial parse then *)
    let* l, offs, foff = (try aux [] off with Invalid_argument _ -> Error `Partial) in
    (* treat last element special -- either Z or P *)
    let* off, name, size =
      match l with
      | `Z, off -> Ok (off, Domain_name.root, 1)
      | `P p, off -> match Int_map.find p names with
        | exception Not_found ->
          Error (`Malformed (off, "bad label offset: " ^ string_of_int p))
        | (exp, size) -> Ok (off, exp, size)
    in
    (* insert last label into names Map*)
    let names = Int_map.add off (name, size) names in
    (* fold over offs, insert into names Map, and reassemble the actual name *)
    let t = Array.(append (Domain_name.to_array name) (make (List.length offs) "")) in
    let names, _, size =
      List.fold_left (fun (names, idx, size) (label, off) ->
          let s = succ size + String.length label in
          Array.set t idx label ;
          let sub = Domain_name.of_array (Array.sub t 0 (succ idx)) in
          Int_map.add off (sub, s) names, succ idx, s)
        (names, Array.length (Domain_name.to_array name), size) offs
    in
    let t = Domain_name.of_array t in
    if size > 255 then
      Error (`Malformed (off, "name too long"))
    else
      Ok (t, names, foff)

  let encode : ?compress:bool -> 'a Domain_name.t -> int Domain_name.Map.t ->
    bytes -> int -> int Domain_name.Map.t * int =
    fun ?(compress = true) name names buf off ->
    let name = Domain_name.raw name in
    let encode_lbl lbl off =
      let l = String.length lbl in
      Bytes.set_uint8 buf off l ;
      Bytes.blit_string lbl 0 buf (succ off) l ;
      off + succ l
    and z off =
      Bytes.set_uint8 buf off 0 ;
      succ off
    in
    let maybe_insert_label name off names =
      (* do not add label to our map if it'd overflow the pointer (14 bit) *)
      if off < 1 lsl 14 then
        Domain_name.Map.add name off names
      else
        names
    and name_remainder arr l off =
      let last = Array.get arr (pred l)
      and rem = Array.sub arr 0 (pred l)
      in
      let l = encode_lbl last off in
      l, Domain_name.of_array rem
    in
    let names, off =
      if compress then
        let rec one names off name =
          let arr = Domain_name.to_array name in
          let l = Array.length arr in
          if l = 0 then
            names, z off
          else
            match Domain_name.Map.find name names with
            | None ->
              let l, rem = name_remainder arr l off in
              one (maybe_insert_label name off names) l rem
            | Some ptr ->
              let data = ptr_tag lsl 8 + ptr in
              Bytes.set_uint16_be buf off data ;
              names, off + 2
        in
        one names off name
      else
        let rec one names off name =
          let arr = Domain_name.to_array name in
          let l = Array.length arr in
          if l = 0 then
            names, z off
          else
            let l, rem = name_remainder arr l off in
            one (maybe_insert_label name off names) l rem
        in
        one names off name
    in
    names, off

  let host off name =
    Result.map_error (function `Msg m ->
        `Malformed (off, Fmt.str "invalid hostname %a: %s" Domain_name.pp name m))
      (Domain_name.host name)

  (*
  (* enable once https://github.com/ocaml/dune/issues/897 is resolved *)
  let%expect_test "decode_name" =
    let test ?(map = Int_map.empty) ?(off = 0) data rmap roff =
      match decode map data ~off with
      | Error _ -> Format.printf "decode error"
      | Ok (name, omap, ooff) ->
        begin match Int_map.equal (fun (n, off) (n', off') ->
            Domain_name.equal n n' && off = off') rmap omap, roff = ooff
          with
          | true, true -> Format.printf "%a" Domain_name.pp name
          | false, _ -> Format.printf "map mismatch"
          | _, false -> Format.printf "offset mismatch"
        end
    in
    let test_err ?(map = Int_map.empty) ?(off = 0) data =
      match decode map data ~off with
      | Error _ -> Format.printf "error (as expected)"
      | Ok _ -> Format.printf "expected error, got ok"
    in
    let n_of_s = Domain_name.of_string_exn in
    let map =
      Int_map.add 0 (n_of_s "foo.com", 9)
        (Int_map.add 4 (n_of_s "com", 5)
           (Int_map.add 8 (Domain_name.root, 1) Int_map.empty))
    in
    test "\003foo\003com\000" map 9;
    [%expect {|foo.com|}];
    test ~map ~off:9 "\003foo\003com\000\xC0\000" (Int_map.add 9 (n_of_s "foo.com", 9) map) 11;
    [%expect {|foo.com|}];
    let map' =
      Int_map.add 13 (n_of_s "foo.com", 9)
        (Int_map.add 9 (n_of_s "bar.foo.com", 13) map)
    in
    test ~map ~off:9 "\003foo\003com\000\003bar\xC0\000" map' 15;
    [%expect {|bar.foo.com|}];
    let map' =
      Int_map.add 14 (n_of_s "foo.com", 9)
        (Int_map.add 9 (n_of_s "bar-.foo.com", 14) map)
    in
    test ~map ~off:9 "\003foo\003com\000\004bar-\xC0\000" map' 16;
    [%expect {|bar-.foo.com|}];
    let map' =
      Int_map.add 0 (n_of_s "f23", 5) Int_map.(add 4 (Domain_name.root, 1) empty)
    in
    test "\003f23\000" map' 5;
    [%expect {|f23|}];
    let map' =
      Int_map.add 0 (n_of_s "23", 4)
        (Int_map.add 3 (Domain_name.root, 1) Int_map.empty)
    in
    test "\00223\000" map' 4;
    [%expect {|23|}];
    test_err "\003bar"; (* incomplete label *)
    [%expect {|error (as expected)|}];
    test_err "\xC0"; (* incomplete ptr *)
    [%expect {|error (as expected)|}];
    test_err "\005foo"; (* incomplete label *)
    [%expect {|error (as expected)|}];
    test_err "\xC0\x0A"; (* bad pointer *)
    [%expect {|error (as expected)|}];
    test_err "\xC0\x00"; (* cyclic pointer *)
    [%expect {|error (as expected)|}];
    test_err "\xC0\x01"; (* pointer to middle of pointer *)
    [%expect {|error (as expected)|}];
    test_err "\x40"; (* bad tag 0x40 *)
    [%expect {|error (as expected)|}];
    test_err "\x80"; (* bad tag 0x80 *)
    [%expect {|error (as expected)|}];
    let map' =
      Int_map.add 0 (n_of_s "-", 3)
        (Int_map.add 2 (Domain_name.root, 1) Int_map.empty)
    in
    test "\001-\000" map' 3; (* "-" at start of label *)
    [%expect {|-|}];
    let map' =
      Int_map.add 0 (n_of_s "foo-+", 7)
        (Int_map.add 6 (Domain_name.root, 1) Int_map.empty)
    in
    test "\005foo-+\000" map' 7; (* content foo-+ in label *)
    [%expect {|foo-+|}];
    let map' =
      Int_map.add 0 (n_of_s "23", 4)
        (Int_map.add 3 (Domain_name.root, 1) Int_map.empty)
    in
    test "\00223\000" map' 4; (* content 23 in label *)
    [%expect {|23|}];
    (* longest allowed domain name *)
    let max = "s23456789012345678901234567890123456789012345678901234567890123" in
    let lst = String.sub max 0 61 in
    let full = n_of_s (String.concat "." [ max ; max ; max ; lst ]) in
    let map' =
      Int_map.add 0 (full, 255)
        (Int_map.add 64 (n_of_s (String.concat "." [ max ; max ; lst ]), 191)
           (Int_map.add 128 (n_of_s (String.concat "." [ max ; lst ]), 127)
              (Int_map.add 192 (n_of_s lst, 63)
                 (Int_map.add 254 (Domain_name.root, 1) Int_map.empty))))
    in
    test ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3D" ^ lst ^ "\000")
      map' 255 ;
    [%expect {|s23456789012345678901234567890123456789012345678901234567890123.s23456789012345678901234567890123456789012345678901234567890123.s23456789012345678901234567890123456789012345678901234567890123.s234567890123456789012345678901234567890123456789012345678901|}];
    test_err ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3E" ^ lst ^ "1\000"); (* name too long *)
    [%expect {|error (as expected)|}];
    test_err ("\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\x3F" ^ max ^ "\000"); (* domain name really too long *)
    [%expect {|error (as expected)|}]

  let%expect_test "encode_name" =
    let buf = Bytes.create 30 in
    let test_buf ?(off = 0) len =
      Format.printf "%a" Ohex.pp (String.sub (Bytes.unsafe_to_string buf) off len)
    in
    let test ?compress ?(map = Domain_name.Map.empty) ?(off = 0) name rmap roff =
      let omap, ooff = encode ?compress name map buf off in
      if Domain_name.Map.equal (fun a b -> Int.compare a b = 0) rmap omap && roff = ooff then
        Format.printf "ok"
      else
        Format.printf "error"
    in
    let n_of_s = Domain_name.of_string_exn in
    test Domain_name.root Domain_name.Map.empty 1; (* compressed encode of root is good *)
    [%expect {|ok|}];
    test_buf 1;
    [%expect {|00|}];
    test ~compress:false Domain_name.root Domain_name.Map.empty 1;
    [%expect {|ok|}];
    test_buf 1;
    [%expect {|00|}];
    let map =
      Domain_name.Map.add (n_of_s "foo.bar") 0
        (Domain_name.Map.add (n_of_s "bar") 4 Domain_name.Map.empty)
    in
    test (n_of_s "foo.bar") map 9; (* encode of foo.bar is good *)
    [%expect {|ok|}];
    test_buf 9;
    [%expect {|0366 6f6f 0362 6172  00|}];
    test ~compress:false (n_of_s "foo.bar") map 9; (* uncompressed foo.bar is good *)
    [%expect {|ok|}];
    test_buf 9;
    [%expect {|0366 6f6f 0362 6172  00|}];
    let emap = Domain_name.Map.add (n_of_s "baz.foo.bar") 9 map in
    test ~map ~off:9 (n_of_s "baz.foo.bar") emap 15; (* encode of baz.foo.bar is good *)
    [%expect {|ok|}];
    test_buf 15;
    [%expect {|0366 6f6f 0362 6172  0003 6261 7ac0 00|}];
    let map' =
      Domain_name.Map.add (n_of_s "baz.foo.bar") 9
        (Domain_name.Map.add (n_of_s "foo.bar") 13
           (Domain_name.Map.add (n_of_s "bar") 17 Domain_name.Map.empty))
    in
    test ~compress:false ~map ~off:9 (n_of_s "baz.foo.bar") map' 22;
    [%expect {|ok|}];
    test_buf 22;
    [%expect {|
0366 6f6f 0362 6172  0003 6261 7a03 666f  6f03 6261 7200|}]
    *)
end

(* start of authority *)
module Soa = struct
  type t = {
    nameserver : [ `raw ] Domain_name.t ;
    hostmaster : [ `raw ] Domain_name.t ;
    serial : int32 ;
    refresh : int32 ;
    retry : int32 ;
    expiry : int32 ;
    minimum : int32 ;
  }

  let default_refresh = 86400l (* 24 hours *)
  let default_retry = 7200l (* 2 hours *)
  let default_expiry = 3600000l (* 1000 hours *)
  let default_minimum = 3600l (* 1 hour *)

  let create ?(serial = 0l) ?(refresh = default_refresh) ?(retry = default_retry)
      ?(expiry = default_expiry) ?(minimum = default_minimum) ?hostmaster nameserver =
    let nameserver = Domain_name.raw nameserver in
    let hostmaster = match hostmaster with
      | None -> Domain_name.(prepend_label_exn (drop_label_exn nameserver) "hostmaster")
      | Some x -> Domain_name.raw x
    in
    { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }

  let canonical t =
    { t with nameserver = Domain_name.canonical t.nameserver ;
             hostmaster = Domain_name.canonical t.hostmaster }

  let pp ppf soa =
    Fmt.pf ppf "SOA %a %a %lu %lu %lu %lu %lu"
      Domain_name.pp soa.nameserver Domain_name.pp soa.hostmaster
      soa.serial soa.refresh soa.retry soa.expiry soa.minimum

  let compare soa soa' =
    andThen (Int32.compare soa.serial soa'.serial)
      (andThen (Domain_name.compare soa.nameserver soa'.nameserver)
         (andThen (Domain_name.compare soa.hostmaster soa'.hostmaster)
            (andThen (Int32.compare soa.refresh soa'.refresh)
               (andThen (Int32.compare soa.retry soa'.retry)
                  (andThen (Int32.compare soa.expiry soa'.expiry)
                     (Int32.compare soa.minimum soa'.minimum))))))

  let newer ~old soa = Int32.sub soa.serial old.serial > 0l

  let decode_exn names buf ~off ~len:_ =
    let* nameserver, names, off = Name.decode names buf ~off in
    let* hostmaster, names, off = Name.decode names buf ~off in
    let serial = String.get_int32_be buf off in
    let refresh = String.get_int32_be buf (off + 4) in
    let retry = String.get_int32_be buf (off + 8) in
    let expiry = String.get_int32_be buf (off + 12) in
    let minimum = String.get_int32_be buf (off + 16) in
    let soa =
      { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }
    in
    Ok (soa, names, off + 20)

  let encode ?compress soa names buf off =
    let names, off = Name.encode ?compress soa.nameserver names buf off in
    let names, off = Name.encode ?compress soa.hostmaster names buf off in
    Bytes.set_int32_be buf off soa.serial ;
    Bytes.set_int32_be buf (off + 4) soa.refresh ;
    Bytes.set_int32_be buf (off + 8) soa.retry ;
    Bytes.set_int32_be buf (off + 12) soa.expiry ;
    Bytes.set_int32_be buf (off + 16) soa.minimum ;
    names, off + 20
end

(* name server *)
module Ns = struct
  type t = [ `host ] Domain_name.t

  let canonical t = Domain_name.canonical t

  let pp ppf ns = Fmt.pf ppf "NS %a" Domain_name.pp ns

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ =
    let* name, names, off' = Name.decode names buf ~off in
    let* host = Name.host off name in
    Ok (host, names, off')

  let encode = Name.encode
end

(* mail exchange *)
module Mx = struct
  type t = {
    preference : int ;
    mail_exchange : [ `host ] Domain_name.t ;
  }

  let canonical t =
    { t with mail_exchange = Domain_name.canonical t.mail_exchange }

  let pp ppf { preference ; mail_exchange } =
    Fmt.pf ppf "MX %u %a" preference Domain_name.pp mail_exchange

  let compare mx mx' =
    andThen (Int.compare mx.preference mx'.preference)
      (Domain_name.compare mx.mail_exchange mx'.mail_exchange)

  let decode_exn names buf ~off ~len:_ =
    let preference = String.get_uint16_be buf off in
    let off = off + 2 in
    let* mx, names, off' = Name.decode names buf ~off in
    let* mail_exchange = Name.host off mx in
    Ok ({ preference ; mail_exchange }, names, off')

  let encode ?compress { preference ; mail_exchange } names buf off =
    Bytes.set_uint16_be buf off preference ;
    Name.encode ?compress mail_exchange names buf (off + 2)
end

(* canonical name *)
module Cname = struct
  type t = [ `raw ] Domain_name.t

  let canonical t = Domain_name.canonical t

  let pp ppf alias = Fmt.pf ppf "CNAME %a" Domain_name.pp alias

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ = Name.decode names buf ~off

  let encode = Name.encode
end

(* address record *)
module A = struct
  type t = Ipaddr.V4.t

  let pp ppf address = Fmt.pf ppf "A %a" Ipaddr.V4.pp address

  let compare = Ipaddr.V4.compare

  let decode_exn names buf ~off ~len:_ =
    let ip = String.get_int32_be buf off in
    Ok (Ipaddr.V4.of_int32 ip, names, off + 4)

  let encode ip names buf off =
    let ip = Ipaddr.V4.to_int32 ip in
    Bytes.set_int32_be buf off ip ;
    names, off + 4
end

(* quad-a record *)
module Aaaa = struct
  type t = Ipaddr.V6.t

  let pp ppf address = Fmt.pf ppf "AAAA %a" Ipaddr.V6.pp address

  let compare = Ipaddr.V6.compare

  let decode_exn names buf ~off ~len:_ =
    let iph = String.get_int64_be buf off
    and ipl = String.get_int64_be buf (off + 8)
    in
    Ok (Ipaddr.V6.of_int64 (iph, ipl), names, off + 16)

  let encode ip names buf off =
    let iph, ipl = Ipaddr.V6.to_int64 ip in
    Bytes.set_int64_be buf off iph ;
    Bytes.set_int64_be buf (off + 8) ipl ;
    names, off + 16
end

(* domain name pointer - reverse entries *)
module Ptr = struct
  type t = [ `host ] Domain_name.t

  let canonical t = Domain_name.canonical t

  let pp ppf rev = Fmt.pf ppf "PTR %a" Domain_name.pp rev

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ =
    let* rname, names, off' = Name.decode names buf ~off in
    let* ptr = Name.host off rname in
    Ok (ptr, names, off')

  let encode = Name.encode
end

(* service record *)
module Srv = struct
  type t = {
    priority : int ;
    weight : int ;
    port : int ;
    target : [ `host ] Domain_name.t
  }

  let canonical t =
    { t with target = Domain_name.canonical t.target }

  let pp ppf t =
    Fmt.pf ppf
      "SRV priority %d weight %d port %d target %a"
      t.priority t.weight t.port Domain_name.pp t.target

  let compare a b =
    andThen (Int.compare a.priority b.priority)
      (andThen (Int.compare a.weight b.weight)
         (andThen (Int.compare a.port b.port)
            (Domain_name.compare a.target b.target)))

  let decode_exn names buf ~off ~len:_ =
    let priority = String.get_int16_be buf off
    and weight = String.get_int16_be buf (off + 2)
    and port = String.get_int16_be buf (off + 4)
    in
    let off = off + 6 in
    let* target, names, off' = Name.decode names buf ~off in
    let* target = Name.host off target in
    Ok ({ priority ; weight ; port ; target }, names, off')

  let encode t names buf off =
    Bytes.set_uint16_be buf off t.priority ;
    Bytes.set_uint16_be buf (off + 2) t.weight ;
    Bytes.set_uint16_be buf (off + 4) t.port ;
    (* as of rfc2782, no name compression for target! rfc2052 required it *)
    Name.encode ~compress:false t.target names buf (off + 6)
end

(* DNS key *)
module Dnskey = struct

  (* 8 bit *)
  type algorithm =
    | RSA_SHA1 | RSASHA1_NSEC3_SHA1 | RSA_SHA256 | RSA_SHA512
    | P256_SHA256 | P384_SHA384 | ED25519
    | MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | Unknown of int

  let algorithm_to_int = function
    | RSA_SHA1 -> 5
    | RSASHA1_NSEC3_SHA1 -> 7
    | RSA_SHA256 -> 8
    | RSA_SHA512 -> 10
    | P256_SHA256 -> 13
    | P384_SHA384 -> 14
    | ED25519 -> 15
    | MD5 -> 157
    | SHA1 -> 161
    | SHA224 -> 162
    | SHA256 -> 163
    | SHA384 -> 164
    | SHA512 -> 165
    | Unknown x -> x
  let int_to_algorithm = function
    | 5 -> RSA_SHA1
    | 7 -> RSASHA1_NSEC3_SHA1
    | 8 -> RSA_SHA256
    | 10 -> RSA_SHA512
    | 13 -> P256_SHA256
    | 14 -> P384_SHA384
    | 15 -> ED25519
    | 157 -> MD5
    | 161 -> SHA1
    | 162 -> SHA224
    | 163 -> SHA256
    | 164 -> SHA384
    | 165 -> SHA512
    | x ->
      if x >= 0 && x < 256 then
        Unknown x
      else
        invalid_arg ("invalid DNSKEY algorithm " ^ string_of_int x)
  let algorithm_to_string = function
    | RSA_SHA1 -> "RSASHA1"
    | RSASHA1_NSEC3_SHA1 -> "RSASHA1NSEC3SHA1"
    | RSA_SHA256 -> "RSASHA256"
    | RSA_SHA512 -> "RSASHA512"
    | P256_SHA256 -> "ECDSAP256SHA256"
    | P384_SHA384 -> "ECDSAP384SHA384"
    | ED25519 -> "ED25519"
    | MD5 -> "MD5"
    | SHA1 -> "SHA1"
    | SHA224 -> "SHA224"
    | SHA256 -> "SHA256"
    | SHA384 -> "SHA384"
    | SHA512 -> "SHA512"
    | Unknown x -> string_of_int x
  let string_to_algorithm = function
    | "RSASHA1" -> Ok RSA_SHA1
    | "RSASHA1NSEC3SHA1" -> Ok RSASHA1_NSEC3_SHA1
    | "RSASHA256" -> Ok RSA_SHA256
    | "RSASHA512" -> Ok RSA_SHA512
    | "ECDSAP256SHA256" -> Ok P256_SHA256
    | "ECDSAP384SHA384" -> Ok P384_SHA384
    | "ED25519" -> Ok ED25519
    | "MD5" -> Ok MD5
    | "SHA1" -> Ok SHA1
    | "SHA224" -> Ok SHA224
    | "SHA256" -> Ok SHA256
    | "SHA384" -> Ok SHA384
    | "SHA512" -> Ok SHA512
    | x -> try Ok (Unknown (int_of_string x)) with
        Failure _ -> Error (`Msg ("DNSKEY algorithm not implemented " ^ x))

  let pp_algorithm ppf k = Fmt.string ppf (algorithm_to_string k)

  let compare_algorithm a b =
    Int.compare (algorithm_to_int a) (algorithm_to_int b)

  type flag = [ `Zone | `Revoke | `Secure_entry_point ]

  let bit = function
    | `Zone -> 7
    | `Revoke -> 8
    | `Secure_entry_point -> 15

  let all = [ `Zone ; `Revoke ; `Secure_entry_point ]

  let compare_flag a b = match a, b with
    | `Zone, `Zone -> 0 | `Zone, _ -> 1 | _, `Zone -> -1
    | `Revoke, `Revoke -> 0 | `Revoke, _ -> 1 | _, `Revoke -> -1
    | `Secure_entry_point, `Secure_entry_point -> 0

  module F = Set.Make(struct type t = flag let compare = compare_flag end)

  let pp_flag ppf = function
    | `Zone -> Fmt.string ppf "zone"
    | `Revoke -> Fmt.string ppf "revoke"
    | `Secure_entry_point -> Fmt.string ppf "secure entry point"

  let number f = 1 lsl (15 - bit f)

  let decode_flags i =
    List.fold_left (fun flags f ->
        if number f land i > 0 then F.add f flags else flags)
      F.empty all

  let encode_flags f =
    F.fold (fun f acc -> acc + number f) f 0

  type t = {
    flags : F.t ;
    algorithm : algorithm ; (* u_int8_t *)
    key : string ;
  }

  let compare a b =
    andThen (F.compare a.flags b.flags)
      (andThen (compare_algorithm a.algorithm b.algorithm)
         (String.compare a.key b.key))

  let decode_exn names buf ~off ~len =
    let flags = String.get_uint16_be buf off
    and proto = String.get_uint8 buf (off + 2)
    and algo = String.get_uint8 buf (off + 3)
    in
    let* () =
      guard (proto = 3)
        (`Not_implemented (off + 2, Fmt.str "dnskey protocol 0x%x" proto))
    in
    let algorithm = int_to_algorithm algo in
    let key = String.sub buf (off + 4) (len - 4) in
    let flags = decode_flags flags in
    Ok ({ flags ; algorithm ; key }, names, off + len)

  let encode t names buf off =
    let flags = encode_flags t.flags in
    Bytes.set_uint16_be buf off flags ;
    Bytes.set_uint8 buf (off + 2) 3 ;
    Bytes.set_uint8 buf (off + 3) (algorithm_to_int t.algorithm) ;
    let kl = String.length t.key in
    Bytes.blit_string t.key 0 buf (off + 4) kl ;
    names, off + 4 + kl

  let key_tag t =
    let data = Bytes.create (4 + String.length t.key) in
    let _names, _off = encode t Domain_name.Map.empty data 0 in
    let rec go idx ac =
      if idx >= Bytes.length data then
        (ac + (ac lsr 16) land 0xFFFF) land 0xFFFF
      else
        let b = Bytes.get_uint8 data idx in
        let lowest_bit_set = idx land 1 <> 0 in
        let ac = ac + if lowest_bit_set then b else b lsl 8 in
        go (succ idx) ac
    in
    go 0 0

  let pp ppf t =
    Fmt.pf ppf "DNSKEY flags %a algo %a key_tag %d key %a"
      Fmt.(list ~sep:(any ", ") pp_flag) (F.elements t.flags)
      pp_algorithm t.algorithm
      (key_tag t)
      (Ohex.pp_hexdump ()) t.key

  let digest_prep owner t =
    let kl = String.length t.key in
    let buf = Bytes.create (kl + 255 + 4) in (* key length + max name + 4 *)
    let names = Domain_name.Map.empty in
    let _, off = Name.encode ~compress:false owner names buf 0 in
    let _, off' = encode t names buf off in
    String.sub (Bytes.unsafe_to_string buf) 0 off'

  let of_string key =
    let parse algo key =
      let* algorithm = string_to_algorithm algo in
      Ok { flags = F.empty ; algorithm ; key }
    in
    match String.split_on_char ':' key with
    | [ algo ; key ] -> parse algo key
    | _ -> Error (`Msg ("invalid DNSKEY string " ^ key))

  let to_string key =
    let algo = algorithm_to_string key.algorithm in
    algo ^ ":" ^ key.key

  let name_key_of_string str =
    match String.split_on_char ':' str with
    | name :: key ->
      let* name = Domain_name.of_string name in
      let* dnskey = of_string (String.concat ":" key) in
      Ok (name, dnskey)
    | [] -> Error (`Msg ("couldn't parse name:key in " ^ str))

  let name_key_to_string (name, key) =
    Domain_name.to_string name ^ ":" ^ to_string key
end

(** RRSIG *)
module Rrsig = struct

  type t = {
    type_covered : int ;
    algorithm : Dnskey.algorithm ;
    label_count : int ;
    original_ttl : int32 ;
    signature_expiration : Ptime.t ;
    signature_inception : Ptime.t ;
    key_tag : int ;
    signer_name : [ `raw ] Domain_name.t ;
    signature : string
  }

  let canonical t =
    { t with signer_name = Domain_name.canonical t.signer_name }

  let pp ppf t =
    Fmt.pf ppf "RRSIG type covered %u algo %a labels %u original ttl %lu signature expiration %a signature inception %a key tag %u signer name %a signature %a"
      t.type_covered
      Dnskey.pp_algorithm t.algorithm
      t.label_count t.original_ttl
      (Ptime.pp_rfc3339 ()) t.signature_expiration
      (Ptime.pp_rfc3339 ()) t.signature_inception
      t.key_tag Domain_name.pp t.signer_name
      (Ohex.pp_hexdump ()) t.signature

  let compare a b =
    andThen (Int.compare a.type_covered b.type_covered)
      (andThen (Dnskey.compare_algorithm a.algorithm b.algorithm)
         (andThen (Int.compare a.label_count b.label_count)
            (andThen (Int32.compare a.original_ttl b.original_ttl)
               (andThen (Ptime.compare a.signature_expiration b.signature_expiration)
                  (andThen (Ptime.compare a.signature_inception b.signature_inception)
                     (andThen (Int.compare a.key_tag b.key_tag)
                        (andThen (Domain_name.compare a.signer_name b.signer_name)
                           (String.compare a.signature b.signature))))))))

  let decode_exn names buf ~off ~len =
    let type_covered = String.get_uint16_be buf off
    and algo = String.get_uint8 buf (off + 2)
    and label_count = String.get_uint8 buf (off + 3)
    and original_ttl = String.get_int32_be buf (off + 4)
    and sig_exp = String.get_int32_be buf (off + 8)
    and sig_inc = String.get_int32_be buf (off + 12)
    and key_tag = String.get_uint16_be buf (off + 16)
    in
    let* signer_name, names, off' = Name.decode names buf ~off:(off + 18) in
    let signature = String.sub buf off' (len - (off' - off)) in
    let algorithm = Dnskey.int_to_algorithm algo in
    (* sig_exp and sig_inc are supposed seconds since UNIX epoch (1970-01-01),
       TODO but may only be +68years and -68years in respect to current timestamp *)
    let* signature_expiration =
      Ptime_extra.of_int64 ~off:(off + 8) (Int64.of_int32 sig_exp)
    in
    let* signature_inception =
      Ptime_extra.of_int64 ~off:(off + 12) (Int64.of_int32 sig_inc)
    in
    Ok ({ type_covered ; algorithm ; label_count ; original_ttl ;
          signature_expiration ; signature_inception ; key_tag ; signer_name ;
          signature },
        names, off + len)

  let encode t names buf off =
    Bytes.set_uint16_be buf off t.type_covered ;
    Bytes.set_uint8 buf (off + 2) (Dnskey.algorithm_to_int t.algorithm) ;
    Bytes.set_uint8 buf (off + 3) t.label_count ;
    Bytes.set_int32_be buf (off + 4) t.original_ttl ;
    (* TODO +-68 years in respect to current timestamp *)
    let int_s ts =
      match Ptime_extra.to_int64 ts with
      | None -> 0l
      | Some s ->
        if Int64.(s > of_int32 Int32.min_int && s < of_int32 Int32.max_int) then
          Int64.to_int32 s
        else
          0l
    in
    Bytes.set_int32_be buf (off + 8) (int_s t.signature_expiration) ;
    Bytes.set_int32_be buf (off + 12) (int_s t.signature_inception) ;
    Bytes.set_uint16_be buf (off + 16) t.key_tag ;
    let names, off = Name.encode ~compress:false t.signer_name names buf (off + 18) in
    let slen = String.length t.signature in
    Bytes.blit_string t.signature 0 buf off slen ;
    names, off + slen

  (* RFC 4035 section 5.3.2 *)
  (* RFC 4034 section 6.2 point 4 *)
  let used_name rrsig name =
    let rrsig_labels = rrsig.label_count
    and fqdn_labels = Domain_name.count_labels name
    in
    if rrsig_labels = fqdn_labels then
      Ok name
    else if rrsig_labels < fqdn_labels then
      let amount = fqdn_labels - rrsig_labels in
      Ok Domain_name.(prepend_label_exn (drop_label_exn ~amount name) "*")
    else (* rrsig_labels > fqdn_labels *)
      Error (`Msg "rrsig_labels is greater than fqdn_labels: name is too short")

  let prep_rrsig rrsig =
    (* from RFC 4034 section 3.1.8.1 *)
    (* this buffer may be too small... *)
    let tbs = Bytes.create 4096 in
    let rrsig_raw = canonical { rrsig with signature = "" } in
    let _, off = encode rrsig_raw Domain_name.Map.empty tbs 0 in
    tbs, off
end

module Ds = struct
  type digest_type =
    | SHA1
    | SHA256
    | SHA384
    | Unknown of int

  let digest_type_to_int = function
    | SHA1 -> 1
    | SHA256 -> 2
    | SHA384 -> 4
    | Unknown i -> i
  let int_to_digest_type = function
    | 1 -> SHA1
    | 2 -> SHA256
    | 4 -> SHA384
    | x ->
      if x >= 0 && x < 256 then
        Unknown x
      else
        invalid_arg ("invalid DS digest type " ^ string_of_int x)
  let digest_type_to_string = function
    | SHA1 -> "SHA1"
    | SHA256 -> "SHA256"
    | SHA384 -> "SHA384"
    | Unknown i -> string_of_int i

  let pp_digest_type ppf k = Fmt.string ppf (digest_type_to_string k)

  let compare_digest_type a b =
    Int.compare (digest_type_to_int a) (digest_type_to_int b)

  type t = {
    key_tag : int ;
    algorithm : Dnskey.algorithm ;
    digest_type : digest_type ;
    digest : string
  }

  let pp ppf t =
    Fmt.pf ppf "DS key_tag %u algo %a digest type %a digest %a"
      t.key_tag
      Dnskey.pp_algorithm t.algorithm
      pp_digest_type t.digest_type
      (Ohex.pp_hexdump ()) t.digest

  let compare a b =
    andThen (Int.compare a.key_tag b.key_tag)
      (andThen (Dnskey.compare_algorithm a.algorithm b.algorithm)
         (andThen (compare_digest_type a.digest_type b.digest_type)
            (String.compare a.digest b.digest)))

  let decode_exn names buf ~off ~len =
    let key_tag = String.get_uint16_be buf off
    and algo = String.get_uint8 buf (off + 2)
    and dt = String.get_uint8 buf (off + 3)
    and digest = String.sub buf (off + 4) (len - 4)
    in
    let algorithm = Dnskey.int_to_algorithm algo
    and digest_type = int_to_digest_type dt
    in
    Ok ({ key_tag ; algorithm ; digest_type ; digest }, names, off + len)

  let encode t names buf off =
    Bytes.set_uint16_be buf off t.key_tag ;
    Bytes.set_uint8 buf (off + 2) (Dnskey.algorithm_to_int t.algorithm) ;
    Bytes.set_uint8 buf (off + 3) (digest_type_to_int t.digest_type) ;
    Bytes.blit_string t.digest 0 buf (off + 4) (String.length t.digest) ;
    names, off + String.length t.digest + 4
end

module Bit_map = struct
  include Set.Make
        (struct type t = int let compare = Int.compare end)

  let byte_to_bits byte =
    let rec more v =
      if v = 0 then
        []
      else if v >= 0x80 then
        0 :: more (v - 0x80)
      else if v >= 0x40 then
        1 :: more (v - 0x40)
      else if v >= 0x20 then
        2 :: more (v - 0x20)
      else if v >= 0x10 then
        3 :: more (v - 0x10)
      else if v >= 0x08 then
        4 :: more (v - 0x08)
      else if v >= 0x04 then
        5 :: more (v - 0x04)
      else if v >= 0x02 then
        6 :: more (v - 0x02)
      else (* if v >= 0x01 then *)
        7 :: more (v - 0x01)
    in
    List.sort Int.compare (more byte)

  let decode_exn buf ~off ~len =
    let rec decode_bit_map_field last_block idx acc =
      if idx - off = len then
        Ok acc
      else
        let block = String.get_uint8 buf idx in
        if block <= last_block then
          Error (`Malformed (off + idx, "block number not increasing"))
        else
          let length = String.get_uint8 buf (idx + 1) in
          let s = idx + 2 in
          let rec octet idx =
            let b = String.get_uint8 buf (s + idx) in
            let bits = byte_to_bits b in
            let more = if idx = 0 then empty else octet (idx - 1) in
            List.fold_left (fun acc b' -> add (idx * 8 + b') acc) more bits
          in
          let bits = octet (length - 1) in
          decode_bit_map_field block (s + length)
            (union (map (fun b -> b + block * 256) bits) acc)
    in
    decode_bit_map_field (-1) off empty

  let bits_to_byte data =
    let rec more b = function
      | [] -> b
      | 0 :: rt -> more (0x80 + b) rt
      | 1 :: rt -> more (0x40 + b) rt
      | 2 :: rt -> more (0x20 + b) rt
      | 3 :: rt -> more (0x10 + b) rt
      | 4 :: rt -> more (0x08 + b) rt
      | 5 :: rt -> more (0x04 + b) rt
      | 6 :: rt -> more (0x02 + b) rt
      | 7 :: rt -> more (0x01 + b) rt
      | _ -> assert false
    in
    more 0 data

  let encode buf off data =
    let encode_block off block data =
      Bytes.set_uint8 buf off block;
      let bytes = (max_elt data + 1 + 7) / 8 in
      Bytes.set_uint8 buf (off + 1) bytes;
      let rec enc_octet idx data =
        if is_empty data then
          ()
        else
          let data, rest = partition (fun i -> i < (idx + 1) * 8) data in
          let d = map (fun i -> i mod 8) data in
          let byte = bits_to_byte (elements d) in
          Bytes.set_uint8 buf (idx + off + 2) byte;
          enc_octet (idx + 1) rest
      in
      enc_octet 0 data;
      off + 2 + bytes
    in
    let rec encode_types off i =
      if is_empty i then
        off
      else
        let next = min_elt i in
        let block = next / 256 in
        let block_end = block * 256 + 255 in
        let this, rest = partition (fun i -> i <= block_end) i in
        let to_enc = map (fun i -> i mod 256) this in
        let off = encode_block off block to_enc in
        encode_types off rest
    in
    encode_types off data
end

module Nsec = struct
  type t = {
    next_domain : [`raw] Domain_name.t;
    types : Bit_map.t;
  }

  let pp ppf { next_domain ; types } =
    Fmt.pf ppf "NSEC %a: %a" Domain_name.pp next_domain
      Fmt.(list ~sep:(any " ") int) (Bit_map.elements types)

  let compare a b =
    andThen (Domain_name.compare a.next_domain b.next_domain)
      (Bit_map.compare a.types b.types)

  let decode_exn names buf ~off ~len =
    let* next_domain, names, off' = Name.decode names buf ~off in
    let len' = len - (off' - off) in
    let* types = Bit_map.decode_exn buf ~off:off' ~len:len' in
    Ok ({ next_domain ; types }, names, off + len)

  let encode t names buf off =
    let names, off = Name.encode ~compress:false t.next_domain names buf off in
    names, Bit_map.encode buf off t.types

  let canonical t =
    { t with next_domain = Domain_name.canonical t.next_domain }
end

module Nsec3 = struct
  type f = [ `Opt_out | `Unknown of int ]

  let compare_flags a b = match a, b with
    | None, None | Some `Opt_out, Some `Opt_out -> 0
    | _, Some `Opt_out -> -1
    | Some `Opt_out, _ -> 1
    | Some `Unknown a, Some `Unknown b -> Int.compare a b
    | None, Some `Unknown _ -> -1
    | Some `Unknown _, None -> 1

  let flags_of_int b =
    match b with
    | 0x01 -> Some `Opt_out
    | 0x00 -> None
    | x ->
      Log.warn (fun m -> m "NSEC3 record with unknown flag %02X" x);
      Some (`Unknown x)

  let flags_to_int = function
    | Some `Opt_out -> 0x01
    | Some `Unknown x -> x
    | None -> 0x00

  type t = {
    (* hash - but only SHA1 is supported *)
    flags : f option ;
    iterations : int ;
    salt : string ;
    next_owner_hashed : string ;
    types : Bit_map.t ;
  }

  let hash = 1

  let pp ppf { flags ; iterations ; salt ; next_owner_hashed ; types } =
    Fmt.pf ppf "NSEC3 %s%d iterations, salt: %a, next owner %a types %a"
      (match flags with
       | None -> ""
       | Some `Opt_out -> "opt-out "
       | Some `Unknown x -> "unknown " ^ string_of_int x ^ " ")
      iterations (Ohex.pp_hexdump ()) salt
      (Ohex.pp_hexdump ()) next_owner_hashed
      Fmt.(list ~sep:(any " ") int) (Bit_map.elements types)

  let compare a b =
    andThen (compare_flags a.flags b.flags)
      (andThen (Int.compare a.iterations b.iterations)
         (andThen (String.compare a.salt b.salt)
            (andThen (String.compare a.next_owner_hashed b.next_owner_hashed)
               (Bit_map.compare a.types b.types))))

  let decode_exn names buf ~off ~len =
    let hash_algo = String.get_uint8 buf off in
    let* () =
      guard (hash_algo = hash)
        (`Not_implemented (off, "NSEC3 hash only SHA-1 supported"))
    in
    let flags = flags_of_int (String.get_uint8 buf (off + 1)) in
    let iterations = String.get_uint16_be buf (off + 2) in
    let slen = String.get_uint8 buf (off + 4) in
    let salt = String.sub buf (off + 5) slen in
    let hlen = String.get_uint8 buf (off + 5 + slen) in
    let next_owner_hashed = String.sub buf (off + 6 + slen) hlen in
    let off' = off + 6 + slen + hlen in
    let len' = len - (off' - off) in
    let* types = Bit_map.decode_exn buf ~off:off' ~len:len' in
    Ok ({ flags ; iterations ; salt ; next_owner_hashed ; types }, names, off + len)

  let encode t names buf off =
    Bytes.set_uint8 buf off hash;
    Bytes.set_uint8 buf (off + 1) (flags_to_int t.flags);
    Bytes.set_uint16_be buf (off + 2) t.iterations;
    let slen = String.length t.salt in
    Bytes.set_uint8 buf (off + 4) slen;
    Bytes.blit_string t.salt 0 buf (off + 5) slen;
    let off' = off + 5 + slen in
    let hlen = String.length t.next_owner_hashed in
    Bytes.set_uint8 buf off' hlen;
    Bytes.blit_string t.next_owner_hashed 0 buf (off' + 1) hlen;
    let off' = off' + 1 + hlen in
    let off = Bit_map.encode buf off' t.types in
    names, off
end

module Loc = struct
  type t = {
    latitude : int32;
    longitude : int32;
    altitude : int32;
    size : int;
    horiz_pre : int;
    vert_pre : int;
  }

  let lat_long_parse ((deg, min, sec), dir) =
    let ( * ), (+) = Int32.mul, Int32.add in
    let arcsecs = (Int32.shift_left 1l 31) + (
      (((deg * 60l) + min) * 60l) * 1000l + sec
    ) in
    match dir with
      | `North | `East -> arcsecs
      | `South | `West -> -1l * arcsecs

  let alt_parse alt =
    let (+) = Int64.add in
    Int64.to_int32 (10000000L + alt)

  let rec pow10 e =
    if e = 0 then 1L else
    let ( * ) = Int64.mul in
    pow10 (e - 1) * 10L

  let precision_parse (size, horiz_pre, vert_pre) =
    let encode = fun p ->
      let exponent =
        let rec r = fun p e ->
          if e >= 9 then 9 else
          if p < (pow10 (e + 1)) then e else
          r p (e + 1)
        in
        r p 0
      in
      let mantissa =
        let ( / ) = Int64.div in
        let m = p / (pow10 exponent) in
        if m > 9L then 9 else Int64.to_int m
      in
      (Int.shift_left mantissa 4) lor exponent
    in
    (encode size, encode horiz_pre, encode vert_pre)

  (* RFC 1876 Appendix A *)
  let parse ~latitude ~longitude ~altitude ~precision =
    let latitude = lat_long_parse latitude in
    let longitude = lat_long_parse longitude in
    let altitude = alt_parse altitude in
    let size, horiz_pre, vert_pre = precision_parse precision in
    { latitude ; longitude ; altitude ; size ; horiz_pre ; vert_pre}

  let arcsecs_print lat_long =
    let ( * ), (-), (/) = Int32.mul, Int32.sub, Int32.div in
    let lat_long = (Int32.shift_left 1l 31) - lat_long in
    let dir = lat_long <= 0l in
    let lat_long = Int32.abs lat_long in
    let sec =
      let decimal = Int32.rem lat_long (60l * 1000l) in
      let integer = decimal / 1000l in
      let decimal = Int32.rem decimal 1000l in
      (integer, decimal)
    in
    let min = Int32.rem (lat_long / (1000l * 60l)) 60l in
    let deg = lat_long / (1000l * 60l * 60l) in
    (deg, min, sec), dir

  let lat_print lat =
    let arcsecs, dir = arcsecs_print lat in
    let dir = if dir then "N" else "S" in
    (arcsecs, dir)

  let long_print long =
    let arcsecs, dir = arcsecs_print long in
    let dir = if dir then "E" else "W" in
    (arcsecs, dir)

  let alt_print alt =
    let (+), (-), (/) = Int64.add, Int64.sub, Int64.div in
    (* convert a uint32 alt to an int64 *)
    let alt = if alt < 0l then
        Int64.of_int32 alt + Int64.shift_left 1L 32
      else Int64.of_int32 alt
    in
    let alt = alt - 10000000L in
    (alt / 100L, Int64.rem alt 100L)

  let precision_print prec =
    let mantissa = ((Int.shift_right prec 4) land 0x0f) mod 10 in
    let exponent = ((Int.shift_right prec 0) land 0x0f) mod 10 in
    let (/), ( * ) = Int64.div, Int64.mul in
    let p = Int64.of_int mantissa * pow10 exponent in
    (p / 100L, Int64.rem p 100L)

  let to_string loc =
    let decimal_string (integer, decimal) decimal_digits =
      let (/), ( * ) = Int64.div, Int64.mul in
      let integer_string = Int64.to_string integer in
      if decimal = 0L then
        integer_string
      else
      let decimal_string =
        let rec trim_trailing_zeros decimal num_trimmed =
          if (decimal / 10L) * 10L = decimal then
            trim_trailing_zeros (decimal / 10L) (num_trimmed + 1)
          else
            decimal, num_trimmed
        in
        (* remove trailing zero from decimal *)
        let decimal, num_trimmed = trim_trailing_zeros decimal 0 in
        (* left pad zeros *)
        let decimal = Int64.to_string decimal in
        String.make (decimal_digits - String.length decimal - num_trimmed) '0' ^ decimal
      in
      integer_string ^ "." ^ decimal_string
    in
    let lat_long_to_string deg min sec dir =
      let sec_string =
        let integer, decimal = sec in
        decimal_string (Int64.of_int32 integer, Int64.of_int32 decimal) 3
      in
      String.concat " " ((List.map (Int32.to_string) [deg; min]) @ [sec_string ; dir])
    in
    let lat_string =
      let (lat_deg, lat_min, lat_sec), lat_dir = lat_print loc.latitude in
      lat_long_to_string lat_deg lat_min lat_sec lat_dir
    in
    let long_string =
      let (long_deg, long_min, long_sec), long_dir = long_print loc.longitude in
      lat_long_to_string long_deg long_min long_sec long_dir
    in
    let meter_values =
      List.map (fun m -> decimal_string m 2 ^ "m") (
        [alt_print loc.altitude] @ (List.map precision_print [loc.size; loc.horiz_pre; loc.vert_pre])
      )
    in
    String.concat " " ([lat_string; long_string;] @ meter_values)

  let pp ppf loc = Fmt.pf ppf "LOC %s" (to_string loc)

  let compare a b =
    List.fold_right andThen [
      Int32.compare a.latitude b.latitude ;
      Int32.compare a.longitude b.longitude ;
      Int32.compare a.altitude b.altitude ;
      Int.compare a.size b.size ;
      Int.compare a.horiz_pre b.horiz_pre ;
      Int.compare a.vert_pre b.vert_pre ;
    ] 0

  let decode_exn names buf ~off ~len =
    let size = String.get_uint8 buf (off + 1) in
    let horiz_pre = String.get_uint8 buf (off + 2) in
    let vert_pre = String.get_uint8 buf (off + 3) in
    let latitude = String.get_int32_be buf (off + 4) in
    let longitude = String.get_int32_be buf (off + 8) in
    let altitude = String.get_int32_be buf (off + 12) in
    Ok ({ latitude ; longitude ; altitude ; size ; horiz_pre; vert_pre }, names, off + len)

  let encode loc names buf off =
    Bytes.set_uint8 buf off 0;
    Bytes.set_uint8 buf (off + 1) loc.size;
    Bytes.set_uint8 buf (off + 2) loc.horiz_pre;
    Bytes.set_uint8 buf (off + 3) loc.vert_pre;
    Bytes.set_int32_be buf (off + 4) loc.latitude;
    Bytes.set_int32_be buf (off + 8) loc.longitude;
    Bytes.set_int32_be buf (off + 12) loc.altitude;
    names, off + 16

end

(* Null record *)
module Null = struct
  type t = string

  let pp ppf null = Fmt.pf ppf "NULL %a" (Ohex.pp_hexdump ()) null

  let compare = String.compare

  let decode names buf ~off ~len =
    let sub = String.sub buf off len in
    Ok (sub, names, off + len)

  let encode null names buf off =
    let max_len = 65535 in
    let len = min max_len (String.length null) in
    Bytes.blit_string null 0 buf off len ;
    names, off + len
end

(* certificate authority authorization *)
module Caa = struct
  type t = {
    critical : bool ;
    tag : string ;
    value : string list ;
  }

  let pp ppf t =
    Fmt.pf ppf "CAA critical %b tag %s value %a"
      t.critical t.tag Fmt.(list ~sep:(any "; ") string) t.value

  let compare a b =
    andThen (Bool.compare a.critical b.critical)
      (andThen (String.compare a.tag b.tag)
         (List.fold_left2
            (fun r a b -> match r with 0 -> String.compare a b | x -> x)
            0 a.value b.value))

  let decode_exn names buf ~off ~len =
    let critical = String.get_uint8 buf off = 0x80
    and tl = String.get_uint8 buf (succ off)
    in
    let* () =
      guard (tl > 0 && tl < 16)
        (`Not_implemented (succ off, Fmt.str "caa tag 0x%x" tl))
    in
    let tag = String.sub buf (off + 2) tl in
    let vs = 2 + tl in
    let value = String.sub buf (off + vs) (len - vs) in
    let value = String.split_on_char ';' value in
    Ok ({ critical ; tag ; value }, names, off + len)

  let encode t names buf off =
    Bytes.set_uint8 buf off (if t.critical then 0x80 else 0x0) ;
    let tl = String.length t.tag in
    Bytes.set_uint8 buf (succ off) tl ;
    Bytes.unsafe_blit_string t.tag 0 buf (off + 2) tl ;
    let value = String.concat ";" t.value in
    let vl = String.length value in
    Bytes.blit_string value 0 buf (off + 2 + tl) vl ;
    names, off + tl + 2 + vl
end

(* transport layer security A *)
module Tlsa = struct

  (* 8 bit *)
  type cert_usage =
    | CA_constraint
    | Service_certificate_constraint
    | Trust_anchor_assertion
    | Domain_issued_certificate
    | Unknown of int

  let cert_usage_to_int = function
    | CA_constraint -> 0
    | Service_certificate_constraint -> 1
    | Trust_anchor_assertion -> 2
    | Domain_issued_certificate -> 3
    | Unknown x -> x
  let int_to_cert_usage = function
    | 0 -> CA_constraint
    | 1 -> Service_certificate_constraint
    | 2 -> Trust_anchor_assertion
    | 3 -> Domain_issued_certificate
    | x ->
      if x >= 0 && x < 256 then
        Unknown x
      else
        invalid_arg ("Bad certificate usage " ^ string_of_int x)
  let cert_usage_to_string = function
    | CA_constraint -> "CA constraint"
    | Service_certificate_constraint -> "service certificate constraint"
    | Trust_anchor_assertion -> "trust anchor assertion"
    | Domain_issued_certificate -> "domain issued certificate"
    | Unknown x -> "unknown " ^ string_of_int x

  let pp_cert_usage ppf k = Fmt.string ppf (cert_usage_to_string k)

  let compare_cert_usage a b =
    Int.compare (cert_usage_to_int a) (cert_usage_to_int b)

  (* 8 bit *)
  type selector =
    | Full_certificate
    | Subject_public_key_info
    | Private
    | Unknown of int

  let selector_to_int = function
    | Full_certificate -> 0
    | Subject_public_key_info -> 1
    | Private -> 255
    | Unknown x -> x
  let int_to_selector = function
    | 0 -> Full_certificate
    | 1 -> Subject_public_key_info
    | 255 -> Private
    | x ->
      if x >= 0 && x < 256 then
        Unknown x
      else
        invalid_arg ("Bad selector " ^ string_of_int x)
  let selector_to_string = function
    | Full_certificate -> "full certificate"
    | Subject_public_key_info -> "subject public key info"
    | Private -> "private"
    | Unknown x -> "unknown " ^ string_of_int x

  let pp_selector ppf k = Fmt.string ppf (selector_to_string k)

  let compare_selector a b =
    Int.compare (selector_to_int a) (selector_to_int b)

  (* 8 bit *)
  type matching_type =
    | No_hash
    | SHA256
    | SHA512
    | Unknown of int

  let matching_type_to_int = function
    | No_hash -> 0
    | SHA256 -> 1
    | SHA512 -> 2
    | Unknown x -> x
  let int_to_matching_type = function
    | 0 -> No_hash
    | 1 -> SHA256
    | 2 -> SHA512
    | x ->
      if x >= 0 && x < 256 then
        Unknown x
      else
        invalid_arg ("Bad matching type " ^ string_of_int x)
  let matching_type_to_string = function
    | No_hash -> "no hash"
    | SHA256 -> "SHA256"
    | SHA512 -> "SHA512"
    | Unknown x -> "unknown " ^ string_of_int x

  let pp_matching_type ppf k = Fmt.string ppf (matching_type_to_string k)

  let compare_matching_type a b =
    Int.compare (matching_type_to_int a) (matching_type_to_int b)

  type t = {
    cert_usage : cert_usage ;
    selector : selector ;
    matching_type : matching_type ;
    data : string ;
  }

  let pp ppf tlsa =
    Fmt.pf ppf "TLSA @[<v>%a %a %a@ %a@]"
      pp_cert_usage tlsa.cert_usage
      pp_selector tlsa.selector
      pp_matching_type tlsa.matching_type
      (Ohex.pp_hexdump ()) tlsa.data

  let compare t1 t2 =
    andThen (compare_cert_usage t1.cert_usage t2.cert_usage)
      (andThen (compare_selector t1.selector t2.selector)
         (andThen (compare_matching_type t1.matching_type t2.matching_type)
            (String.compare t1.data t2.data)))

  let decode_exn names buf ~off ~len =
    let usage, selector, matching_type =
      String.get_uint8 buf off,
      String.get_uint8 buf (off + 1),
      String.get_uint8 buf (off + 2)
    in
    let data = String.sub buf (off + 3) (len - 3) in
    let cert_usage = int_to_cert_usage usage in
    let selector = int_to_selector selector in
    let matching_type = int_to_matching_type matching_type in
    let tlsa = { cert_usage ; selector ; matching_type ; data } in
    Ok (tlsa, names, off + len)

  let encode tlsa names buf off =
    Bytes.set_uint8 buf off (cert_usage_to_int tlsa.cert_usage) ;
    Bytes.set_uint8 buf (off + 1) (selector_to_int tlsa.selector) ;
    Bytes.set_uint8 buf (off + 2) (matching_type_to_int tlsa.matching_type) ;
    let l = String.length tlsa.data in
    Bytes.blit_string tlsa.data 0 buf (off + 3) l ;
    names, off + 3 + l
end

(* secure shell fingerprint *)
module Sshfp = struct

  (* 8 bit *)
  type algorithm =
    | Rsa
    | Dsa
    | Ecdsa
    | Ed25519
    | Unknown of int

  let algorithm_to_int = function
    | Rsa -> 1
    | Dsa -> 2
    | Ecdsa -> 3
    | Ed25519 -> 4
    | Unknown x -> x

  let int_to_algorithm = function
    | 1 -> Rsa
    | 2 -> Dsa
    | 3 -> Ecdsa
    | 4 -> Ed25519
    | x ->
      if x >= 0 && x < 256 then
        Unknown x
      else
        invalid_arg ("Bad SSHFP algorithm " ^ string_of_int x)

  let algorithm_to_string = function
    | Rsa -> "RSA"
    | Dsa -> "DSA"
    | Ecdsa -> "ECDSA"
    | Ed25519 -> "ED25519"
    | Unknown x -> "unknown " ^ string_of_int x

  let pp_algorithm ppf k = Fmt.string ppf (algorithm_to_string k)

  let compare_algorithm a b =
    Int.compare (algorithm_to_int a) (algorithm_to_int b)

  (* 8 bit *)
  type typ =
    | SHA1
    | SHA256
    | Unknown of int

  let typ_to_int = function
    | SHA1 -> 1
    | SHA256 -> 2
    | Unknown x -> x

  let int_to_typ = function
    | 1 -> SHA1
    | 2 -> SHA256
    | x ->
      if x >= 0 && x < 256 then
        Unknown x
      else
        invalid_arg ("Bad SSHFP typ " ^ string_of_int x)

  let typ_to_string = function
    | SHA1 -> "SHA1"
    | SHA256 -> "SHA256"
    | Unknown x -> "unknown " ^ string_of_int x

  let pp_typ ppf k = Fmt.string ppf (typ_to_string k)

  let compare_typ a b =
    Int.compare (typ_to_int a) (typ_to_int b)

  type t = {
    algorithm : algorithm ;
    typ : typ ;
    fingerprint : string ;
  }

  let pp ppf sshfp =
    Fmt.pf ppf "SSHFP %a %a %a"
      pp_algorithm sshfp.algorithm
      pp_typ sshfp.typ
      (Ohex.pp_hexdump ()) sshfp.fingerprint

  let compare s1 s2 =
    andThen (compare_algorithm s1.algorithm s2.algorithm)
      (andThen (compare_typ s1.typ s2.typ)
         (String.compare s1.fingerprint s2.fingerprint))

  let decode_exn names buf ~off ~len =
    let algo, typ = String.get_uint8 buf off, String.get_uint8 buf (succ off) in
    let fingerprint = String.sub buf (off + 2) (len - 2) in
    let algorithm = int_to_algorithm algo in
    let typ = int_to_typ typ in
    let sshfp = { algorithm ; typ ; fingerprint } in
    Ok (sshfp, names, off + len)

  let encode sshfp names buf off =
    Bytes.set_uint8 buf off (algorithm_to_int sshfp.algorithm) ;
    Bytes.set_uint8 buf (succ off) (typ_to_int sshfp.typ) ;
    let l = String.length sshfp.fingerprint in
    Bytes.blit_string sshfp.fingerprint 0 buf (off + 2) l ;
    names, off + l + 2
end

(* Text record *)
module Txt = struct
  type t = string

  let pp ppf txt = Fmt.pf ppf "TXT %s" txt

  let compare = String.compare

  let decode_exn names buf ~off ~len =
    let decode_character_str buf off =
      let len = String.get_uint8 buf off in
      let data = String.sub buf (succ off) len in
      (data, off + len + 1)
    in
    let sub = String.sub buf off len in
    let rec more acc off =
      if len = off then
        List.rev acc
      else
        let d, off = decode_character_str sub off in
        more (d::acc) off
    in
    let txts = more [] 0 in
    Ok (String.concat "" txts, names, off + len)

  let encode txt names buf off =
    let max_len = 255 in
    let rec more off txt =
      if txt = "" then
        off
      else
        let len = String.length txt in
        let len, rest =
          if len > max_len then
            max_len, String.(sub txt max_len (len - max_len))
          else
            len, ""
        in
        Bytes.set_uint8 buf off len ;
        Bytes.blit_string txt 0 buf (succ off) len ;
        more (off + len + 1) rest
    in
    let off = more off txt in
    names, off
end

module Tsig = struct
  type algorithm =
    | SHA1
    | SHA224
    | SHA256
    | SHA384
    | SHA512

  type t = {
    algorithm : algorithm ;
    signed : Ptime.t ;
    fudge : Ptime.Span.t ;
    mac : string ;
    original_id : int ; (* again 16 bit *)
    error : Rcode.t ;
    other : Ptime.t option
  }

  let rtyp = 250

  let equal a b =
    a.algorithm = b.algorithm &&
    Ptime.equal a.signed b.signed &&
    Ptime.Span.equal a.fudge b.fudge &&
    String.equal a.mac b.mac &&
    a.original_id = b.original_id &&
    a.error = b.error &&
    opt_eq Ptime.equal a.other b.other

  let algorithm_to_name, algorithm_of_name =
    let of_s s = Domain_name.(host_exn (of_string_exn s)) in
    let map =
      [ (* of_s "HMAC-MD5.SIG-ALG.REG.INT", MD5 ; *)
        of_s "hmac-sha1", SHA1 ;
        of_s "hmac-sha224", SHA224 ;
        of_s "hmac-sha256", SHA256 ;
        of_s "hmac-sha384", SHA384 ;
        of_s "hmac-sha512", SHA512 ]
    in
    (fun a -> fst (List.find (fun (_, t) -> t = a) map)),
    (fun ?(off = 0) (b : [ `host ] Domain_name.t) ->
       try Ok (snd (List.find (fun (n, _) -> Domain_name.equal b n) map))
       with Not_found ->
         let m = Fmt.str "algorithm name %a" Domain_name.pp b in
         Error (`Not_implemented (off, m)))

  let pp_algorithm ppf a = Domain_name.pp ppf (algorithm_to_name a)

  let valid_time now tsig =
    let ts = tsig.signed
    and fudge = tsig.fudge
    in
    match Ptime.add_span now fudge, Ptime.sub_span now fudge with
    | None, _ -> false
    | _, None -> false
    | Some late, Some early ->
      Ptime.is_earlier ts ~than:late && Ptime.is_later ts ~than:early

  let ptime_to_bits ts =
    match Ptime_extra.to_int64 ts with
    | None -> None
    | Some x ->
      if Int64.logand 0xffff_0000_0000_0000L x = 0L then Some x else None

  let tsig ~algorithm ~signed ?(fudge = Ptime.Span.of_int_s 300)
      ?(mac = "") ?(original_id = 0) ?(error = Rcode.NoError)
      ?other () =
    match ptime_to_bits signed, Ptime_extra.span_to_int64 fudge with
    | None, _ | _, None -> None
    | Some _, Some fu ->
      if Int64.logand 0xffff_ffff_ffff_0000L fu = 0L then
        Some { algorithm ; signed ; fudge ; mac ; original_id ; error ; other }
      else
        None

  let with_mac tsig mac = { tsig with mac }

  let with_error tsig error = { tsig with error }

  let with_signed tsig signed =
    match ptime_to_bits signed with
    | Some _ -> Some { tsig with signed }
    | None -> None

  let with_other tsig other =
    match other with
    | None -> Some { tsig with other }
    | Some ts ->
      match ptime_to_bits ts with
      | Some _ -> Some { tsig with other }
      | None -> None

  let pp ppf t =
    Fmt.pf ppf
      "TSIG %a signed %a fudge %a mac %a original id %04X err %a other %a"
      pp_algorithm t.algorithm
      (Ptime.pp_rfc3339 ()) t.signed Ptime.Span.pp t.fudge
      (Ohex.pp_hexdump ()) t.mac t.original_id Rcode.pp t.error
      Fmt.(option ~none:(any "none") (Ptime.pp_rfc3339 ())) t.other

  let decode_48bit_time buf off =
    let a = String.get_uint16_be buf off
    and b = String.get_uint16_be buf (off + 2)
    and c = String.get_uint16_be buf (off + 4)
    in
    Int64.(add
             (add (shift_left (of_int a) 32) (shift_left (of_int b) 16))
             (of_int c))

  let decode_exn names buf ~off =
    let ttl = String.get_int32_be buf off in
    let* () =
      guard (ttl = 0l) (`Malformed (off, Fmt.str "tsig ttl is not zero %lu" ttl))
    in
    let len = String.get_uint16_be buf (off + 4) in
    let rdata_start = off + 6 in
    let* (algorithm, names, off') = Name.decode names buf ~off:rdata_start in
    let* algorithm = Name.host rdata_start algorithm in
    let signed = decode_48bit_time buf off'
    and fudge = String.get_uint16_be buf (off' + 6)
    and mac_len = String.get_uint16_be buf (off' + 8)
    in
    let mac = String.sub buf (off' + 10) mac_len
    and original_id = String.get_uint16_be buf (off' + 10 + mac_len)
    and error = String.get_uint16_be buf (off' + 12 + mac_len)
    and other_len = String.get_uint16_be buf (off' + 14 + mac_len)
    in
    let rdata_end = off' + 10 + mac_len + 6 + other_len in
    let* () =
      guard (rdata_end - rdata_start = len)
        (`Leftover (rdata_end, "more bytes in tsig"))
    in
    let* () = guard (String.length buf >= rdata_end) `Partial in
    let* () =
      guard (other_len = 0 || other_len = 6)
        (`Malformed (off' + 14 + mac_len, "other timestamp should be 0 or 6 bytes!"))
    in
    let* algorithm = algorithm_of_name ~off:rdata_start algorithm in
    let* signed = Ptime_extra.of_int64 ~off:off' signed in
    let* error = Rcode.of_int ~off:(off' + 12 + mac_len) error in
    let* other =
      if other_len = 0 then
        Ok None
      else
        let other = decode_48bit_time buf (off' + 16 + mac_len) in
        let* x = Ptime_extra.of_int64 ~off:(off' + 14 + mac_len + 2) other in
        Ok (Some x)
    in
    let fudge = Ptime.Span.of_int_s fudge in
    Ok ({ algorithm ; signed ; fudge ; mac ; original_id ; error ; other },
        names,
        off' + 16 + mac_len + other_len)

  let encode_48bit_time buf ?(off = 0) ts =
    match ptime_to_bits ts with
    | None ->
      Log.warn (fun m -> m "couldn't convert (to_span %a) to int64" Ptime.pp ts)
    | Some secs ->
      let a, b, c =
        let f s = Int64.(to_int (logand 0xffffL (shift_right secs s))) in
        f 32, f 16, f 0
      in
      Bytes.set_uint16_be buf off a ;
      Bytes.set_uint16_be buf (off + 2) b ;
      Bytes.set_uint16_be buf (off + 4) c

  let encode_16bit_time buf ?(off = 0) ts =
    match Ptime_extra.span_to_int64 ts with
    | None ->
      Log.warn (fun m -> m "couldn't convert span %a to int64" Ptime.Span.pp ts)
    | Some secs ->
      if Int64.logand secs 0xffff_ffff_ffff_0000L > 0L then
        Log.warn (fun m -> m "secs %Lu > 16 bit" secs)
      else
        let a = Int64.(to_int (logand 0xffffL secs)) in
        Bytes.set_uint16_be buf off a

  (* TODO unused -- why? *)
  let _encode t names buf off =
    let algo = algorithm_to_name t.algorithm in
    let names, off = Name.encode ~compress:false algo names buf off in
    encode_48bit_time buf ~off t.signed ;
    encode_16bit_time buf ~off:(off + 6) t.fudge ;
    let mac_len = String.length t.mac in
    Bytes.set_uint16_be buf (off + 8) mac_len ;
    Bytes.blit_string t.mac 0 buf (off + 10) mac_len ;
    Bytes.set_uint16_be buf (off + 10 + mac_len) t.original_id ;
    Bytes.set_uint16_be buf (off + 12 + mac_len) (Rcode.to_int t.error) ;
    let other_len = match t.other with None -> 0 | Some _ -> 6 in
    Bytes.set_uint16_be buf (off + 14 + mac_len) other_len ;
    (match t.other with
     | None -> ()
     | Some t -> encode_48bit_time buf ~off:(off + 16 + mac_len) t) ;
    names, off + 16 + mac_len + other_len

  let name_to_buf name =
    let buf = Bytes.make 255 '\000'
    and emp = Domain_name.Map.empty
    in
    let _, off = Name.encode ~compress:false name emp buf 0 in
    String.sub (Bytes.unsafe_to_string buf) 0 off

  let encode_raw_tsig_base name t =
    let name = name_to_buf (Domain_name.canonical name)
    and aname = name_to_buf (algorithm_to_name t.algorithm)
    in
    let clttl = Bytes.create 6 in
    Bytes.set_uint16_be clttl 0 Class.(to_int ANY_CLASS) ;
    Bytes.set_int32_be clttl 2 0l ;
    let time = Bytes.create 8 in
    encode_48bit_time time t.signed ;
    encode_16bit_time time ~off:6 t.fudge ;
    let other =
      let buf = match t.other with
        | None ->
          let buf = Bytes.create 4 in
          Bytes.set_uint16_be buf 2 0 ;
          buf
        | Some t ->
          let buf = Bytes.make 10 '\000' in
          Bytes.set_uint16_be buf 2 6 ;
          encode_48bit_time buf ~off:4 t ;
          buf
      in
      Bytes.set_uint16_be buf 0 (Rcode.to_int t.error) ;
      Bytes.unsafe_to_string buf
    in
    name, Bytes.unsafe_to_string clttl, [ aname ; Bytes.unsafe_to_string time ], other

  let encode_raw name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    String.concat "" (name :: clttl :: mid @ [ fin ])

  let encode_full name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    let typ =
      let typ = Bytes.create 2 in
      Bytes.set_uint16_be typ 0 rtyp ;
      Bytes.unsafe_to_string typ
    and mac =
      let len = String.length t.mac in
      let l = Bytes.create 2 in
      Bytes.set_uint16_be l 0 len ;
      let orig = Bytes.create 2 in
      Bytes.set_uint16_be orig 0 t.original_id ;
      [ Bytes.unsafe_to_string l ; t.mac ; Bytes.unsafe_to_string orig ]
    in
    let rdata = String.concat "" (mid @ mac @ [ fin ]) in
    let len =
      let buf = Bytes.make 2 '\000' in
      Bytes.set_uint16_be buf 0 (String.length rdata) ;
      Bytes.unsafe_to_string buf
    in
    String.concat "" [ name ; typ ; clttl ; len ; rdata ]

  let dnskey_to_tsig_algo key =
    match key.Dnskey.algorithm with
    | Dnskey.RSA_SHA1 | Dnskey.RSASHA1_NSEC3_SHA1 | Dnskey.RSA_SHA256 | Dnskey.RSA_SHA512 -> Error (`Msg "TSIG with RSA is not supported")
    | Dnskey.P256_SHA256 | Dnskey.P384_SHA384 | Dnskey.ED25519 -> Error (`Msg "TSIG with EC is not supported")
    | Dnskey.MD5 -> Error (`Msg "TSIG algorithm MD5 is not supported")
    | Dnskey.SHA1 -> Ok SHA1
    | Dnskey.SHA224 -> Ok SHA224
    | Dnskey.SHA256 -> Ok SHA256
    | Dnskey.SHA384 -> Ok SHA384
    | Dnskey.SHA512 -> Ok SHA512
    | Dnskey.Unknown x -> Error (`Msg ("Unknown DNSKEY algorithm " ^ string_of_int x))
end

module Edns = struct

  type extension =
    | Nsid of string
    | Cookie of string
    | Tcp_keepalive of int option
    | Padding of int
    | Extension of int * string

  let pp_extension ppf = function
    | Nsid cs -> Fmt.pf ppf "nsid %a" (Ohex.pp_hexdump ()) cs
    | Cookie cs -> Fmt.pf ppf "cookie %a" (Ohex.pp_hexdump ()) cs
    | Tcp_keepalive i -> Fmt.pf ppf "keepalive %a" Fmt.(option ~none:(any "none") int) i
    | Padding i -> Fmt.pf ppf "padding %d" i
    | Extension (t, v) -> Fmt.pf ppf "unknown option %d: %a" t (Ohex.pp_hexdump ()) v

  let compare_extension a b = match a, b with
    | Nsid a, Nsid b -> String.compare a b
    | Nsid _, _ -> 1 | _, Nsid _ -> -1
    | Cookie a, Cookie b -> String.compare a b
    | Cookie _, _ -> 1 | _, Cookie _ -> -1
    | Tcp_keepalive a, Tcp_keepalive b ->
      begin match a, b with
        | None, None -> 0
        | None, Some _ -> -1
        | Some _, None -> 1
        | Some a, Some b -> Int.compare a b
      end
    | Tcp_keepalive _, _ -> 1 | _, Tcp_keepalive _ -> -1
    | Padding a, Padding b -> Int.compare a b
    | Padding _, _ -> 1 | _, Padding _ -> -1
    | Extension (t, v), Extension (t', v') ->
      andThen (Int.compare t t') (String.compare v v')

  (* tag is 16 bit, we don't support many *)
  let extension_to_int = function
    | Nsid _ -> 3
    | Cookie _ -> 10
    | Tcp_keepalive _ -> 11
    | Padding _ -> 12
    | Extension (tag, _) -> tag

  let int_to_extension = function
    | 3 -> Some `nsid
    | 10 -> Some `cookie
    | 11 -> Some `tcp_keepalive
    | 12 -> Some `padding
    | _ -> None

  let extension_payload = function
    | Nsid cs -> cs
    | Cookie cs -> cs
    | Tcp_keepalive i ->
      (match i with
       | None -> ""
       | Some i ->
         let buf = Bytes.create 2 in
         Bytes.set_uint16_be buf 0 i ;
         Bytes.unsafe_to_string buf)
    | Padding i -> String.make i '\x00'
    | Extension (_, v) -> v

  let encode_extension t buf off =
    let code = extension_to_int t in
    let v = extension_payload t in
    let l = String.length v in
    Bytes.set_uint16_be buf off code ;
    Bytes.set_uint16_be buf (off + 2) l ;
    Bytes.blit_string v 0 buf (off + 4) l ;
    off + 4 + l

  let decode_extension buf ~off =
    let code = String.get_uint16_be buf off
    and tl = String.get_uint16_be buf (off + 2)
    in
    let v = String.sub buf (off + 4) tl in
    let len = tl + 4 in
    match int_to_extension code with
    | Some `nsid -> Ok (Nsid v, len)
    | Some `cookie -> Ok (Cookie v, len)
    | Some `tcp_keepalive ->
      let* i =
        match tl with
        | 0 -> Ok None
        | 2 -> Ok (Some (String.get_uint16_be v 0))
        | _ -> Error (`Not_implemented (off, Fmt.str "edns keepalive 0x%x" tl))
      in
      Ok (Tcp_keepalive i, len)
    | Some `padding -> Ok (Padding tl, len)
    | None -> Ok (Extension (code, v), len)

  type t = {
    extended_rcode : int ;
    version : int ;
    dnssec_ok : bool ;
    payload_size : int ;
    extensions : extension list ;
  }

  let rtyp = 41

  let min_payload_size = 512 (* from RFC 6891 Section 6.2.3 *)

  let create ?(extended_rcode = 0) ?(version = 0) ?(dnssec_ok = false)
      ?(payload_size = min_payload_size) ?(extensions = []) () =
    let payload_size =
      if payload_size < min_payload_size then begin
        Log.warn (fun m -> m "requested payload size %d is too small, using %d"
                      payload_size min_payload_size);
        min_payload_size
      end else
        payload_size
    in
    { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions }

  (* once we handle cookies, dnssec, or other extensions, need to adjust *)
  let reply = function
    | None -> None, None
    | Some opt ->
      let payload_size = opt.payload_size in
      Some payload_size, Some (create ~payload_size ())

  let compare a b =
    andThen (Int.compare a.extended_rcode b.extended_rcode)
      (andThen (Int.compare a.version b.version)
         (andThen (Bool.compare a.dnssec_ok b.dnssec_ok)
            (andThen (Int.compare a.payload_size b.payload_size)
               (List.fold_left2
                  (fun r a b -> if r = 0 then compare_extension a b else r)
                  (Int.compare (List.length a.extensions) (List.length b.extensions))
                  a.extensions b.extensions))))

  let pp ppf opt =
    Fmt.(pf ppf "EDNS rcode %u version %u dnssec_ok %b payload_size %u extensions %a"
           opt.extended_rcode opt.version opt.dnssec_ok opt.payload_size
           (list ~sep:(any ", ") pp_extension) opt.extensions)

  let decode_extensions buf ~len =
    let rec one acc pos =
      if len = pos then
        Ok (List.rev acc)
      else
        let* opt, len = decode_extension buf ~off:pos in
        one (opt :: acc) (pos + len)
    in
    one [] 0

  let decode_exn buf ~off =
    (* EDNS is special -- the incoming off points to before name type clas *)
    (* name must be the root, typ is OPT, class is used for length *)
    let* () = guard (String.get_uint8 buf off = 0) (`Malformed (off, "bad edns (must be 0)")) in
    (* crazyness: payload_size is encoded in class *)
    let payload_size = String.get_uint16_be buf (off + 3)
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    and extended_rcode = String.get_uint8 buf (off + 5)
    and version = String.get_uint8 buf (off + 6)
    and flags = String.get_uint16_be buf (off + 7)
    and len = String.get_uint16_be buf (off + 9)
    in
    let off = off + 11 in
    let dnssec_ok = flags land 0x8000 = 0x8000 in
    let* () = guard (version = 0) (`Bad_edns_version version) in
    let payload_size =
      if payload_size < min_payload_size then begin
        Log.warn (fun m -> m "EDNS payload size is too small %d, using %d"
                     payload_size min_payload_size);
        min_payload_size
      end else
        payload_size
    in
    let exts_buf = String.sub buf off len in
    let* extensions = decode_extensions exts_buf ~len in
    let opt = { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions } in
    Ok (opt, off + len)

  let encode_extensions t buf off =
    List.fold_left (fun off opt -> encode_extension opt buf off) off t

  let encode t buf off =
    (* name is . *)
    Bytes.set_uint8 buf off 0 ;
    (* type *)
    Bytes.set_uint16_be buf (off + 1) rtyp ;
    (* class is payload size! *)
    Bytes.set_uint16_be buf (off + 3) t.payload_size ;
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    Bytes.set_uint8 buf (off + 5) t.extended_rcode ;
    Bytes.set_uint8 buf (off + 6) t.version ;
    Bytes.set_uint16_be buf (off + 7) (if t.dnssec_ok then 0x8000 else 0) ;
    let ext_start = off + 11 in
    let ext_end = encode_extensions t.extensions buf ext_start in
    Bytes.set_uint16_be buf (off + 9) (ext_end - ext_start) ;
    ext_end

  let allocate_and_encode edns =
    (* this is unwise! *)
    let buf = Bytes.create 128 in
    let off = encode edns buf 0 in
    String.sub (Bytes.unsafe_to_string buf) 0 off
end

(* resource record map *)
module Rr_map = struct
  module Mx_set = Set.Make(Mx)
  module Txt_set = Set.Make(Txt)
  module Srv_set = Set.Make(Srv)
  module Dnskey_set = Set.Make(Dnskey)
  module Caa_set = Set.Make(Caa)
  module Tlsa_set = Set.Make(Tlsa)
  module Sshfp_set = Set.Make(Sshfp)
  module Ds_set = Set.Make(Ds)
  module Rrsig_set = Set.Make(Rrsig)
  module Loc_set = Set.Make(Loc)
  module Null_set = Set.Make(Null)

  module I : sig
    type t
    val of_int : ?off:int -> int -> (t, [> `Malformed of int * string ]) result
    val to_int : t -> int
    val compare : t -> t -> int
  end = struct
    type t = int
    let of_int ?(off = 0) i = match i with
      | 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 33 | 41 | 43 | 44 | 46 | 47 | 48 | 50 | 52 | 250 | 251 | 252 | 255 | 257 ->
        Error (`Malformed (off, "reserved and supported RTYPE not Unknown"))
      | x -> if x >= 0 && x < 1 lsl 16 then Ok x else Error (`Malformed (off, "RTYPE exceeds 16 bit"))
    let to_int t = t
    let compare = Int.compare
  end

  type 'a with_ttl = int32 * 'a

  type _ rr =
    | Soa : Soa.t rr
    | Ns : Domain_name.Host_set.t with_ttl rr
    | Mx : Mx_set.t with_ttl rr
    | Cname : Cname.t with_ttl rr
    | A : Ipaddr.V4.Set.t with_ttl rr
    | Aaaa : Ipaddr.V6.Set.t with_ttl rr
    | Ptr : Ptr.t with_ttl rr
    | Srv : Srv_set.t with_ttl rr
    | Dnskey : Dnskey_set.t with_ttl rr
    | Caa : Caa_set.t with_ttl rr
    | Tlsa : Tlsa_set.t with_ttl rr
    | Sshfp : Sshfp_set.t with_ttl rr
    | Txt : Txt_set.t with_ttl rr
    | Ds : Ds_set.t with_ttl rr
    | Rrsig : Rrsig_set.t with_ttl rr
    | Nsec : Nsec.t with_ttl rr
    | Nsec3 : Nsec3.t with_ttl rr
    | Loc : Loc_set.t with_ttl rr
    | Null : Null_set.t with_ttl rr
    | Unknown : I.t -> Txt_set.t with_ttl rr

  module K = struct
    type 'a t = 'a rr

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
      | Ds, Ds -> Eq | Ds, _ -> Lt | _, Ds -> Gt
      | Rrsig, Rrsig -> Eq | Rrsig, _ -> Lt | _, Rrsig -> Gt
      | Nsec, Nsec -> Eq | Nsec, _ -> Lt | _, Nsec -> Gt
      | Nsec3, Nsec3 -> Eq | Nsec3, _ -> Lt | _, Nsec3 -> Gt
      | Loc, Loc -> Eq | Loc, _ -> Lt | _, Loc -> Gt
      | Null, Null -> Eq | Null, _ -> Lt | _, Null -> Gt
      | Unknown a, Unknown b ->
        let r = I.compare a b in
        if r = 0 then Eq else if r < 0 then Lt else Gt
  end

  include Gmap.Make(K)

  type k = K : 'a key -> k

  let comparek (K k) (K k') = match K.compare k k' with
    | Gmap.Order.Eq -> 0 | Gmap.Order.Gt -> 1 | Gmap.Order.Lt -> -1

  let equal_rr : type a. a key -> a -> a -> bool = fun k v v' ->
    match k, v, v' with
    | Cname, (_, alias), (_, alias') -> Domain_name.equal alias alias'
    | Mx, (_, mxs), (_, mxs') -> Mx_set.equal mxs mxs'
    | Ns, (_, ns), (_, ns') -> Domain_name.Host_set.equal ns ns'
    | Ptr, (_, name), (_, name') -> Domain_name.equal name name'
    | Soa, soa, soa' -> Soa.compare soa soa' = 0
    | Txt, (_, txts), (_, txts') -> Txt_set.equal txts txts'
    | A, (_, aas), (_, aas') -> Ipaddr.V4.Set.equal aas aas'
    | Aaaa, (_, aaaas), (_, aaaas') -> Ipaddr.V6.Set.equal aaaas aaaas'
    | Srv, (_, srvs), (_, srvs') -> Srv_set.equal srvs srvs'
    | Dnskey, (_, keys), (_, keys') -> Dnskey_set.equal keys keys'
    | Caa, (_, caas), (_, caas') -> Caa_set.equal caas caas'
    | Tlsa, (_, tlsas), (_, tlsas') -> Tlsa_set.equal tlsas tlsas'
    | Sshfp, (_, sshfps), (_, sshfps') -> Sshfp_set.equal sshfps sshfps'
    | Ds, (_, ds), (_, ds') -> Ds_set.equal ds ds'
    | Rrsig, (_, rrs), (_, rrs') -> Rrsig_set.equal rrs rrs'
    | Nsec, (_, ns), (_, ns') -> Nsec.compare ns ns' = 0
    | Nsec3, (_, ns), (_, ns') -> Nsec3.compare ns ns' = 0
    | Loc, (_, loc), (_, loc') -> Loc_set.equal loc loc'
    | Null, (_, null), (_, null') -> Null_set.equal null null'
    | Unknown _, (_, data), (_, data') -> Txt_set.equal data data'

  let equalb (B (k, v)) (B (k', v')) = match K.compare k k' with
    | Gmap.Order.Eq -> equal_rr k v v'
    | _ -> false

  let to_int : type a. a key -> int = function
    | A -> 1 | Ns -> 2 | Cname -> 5 | Soa -> 6 | Null -> 10 | Ptr -> 12 | Mx -> 15
    | Txt -> 16 | Aaaa -> 28  | Loc -> 29 | Srv -> 33 | Ds -> 43
    | Sshfp -> 44 | Rrsig -> 46 | Nsec -> 47 | Dnskey -> 48 | Nsec3 -> 50
    | Tlsa -> 52 | Caa -> 257
    | Unknown x -> I.to_int x

  let any_rtyp = 255 and axfr_rtyp = 252 and ixfr_rtyp = 251

  let of_int ?(off = 0) = function
    | 1 -> Ok (K A) | 2 -> Ok (K Ns) | 5 -> Ok (K Cname) | 6 -> Ok (K Soa) | 10 -> Ok (K Null)
    | 12 -> Ok (K Ptr) | 15 -> Ok (K Mx) | 16 -> Ok (K Txt) | 28 -> Ok (K Aaaa)
    | 29 -> Ok (K Loc) | 33 -> Ok (K Srv) | 43 -> Ok (K Ds) | 44 -> Ok (K Sshfp)
    | 46 -> Ok (K Rrsig) | 47 -> Ok (K Nsec) | 48 -> Ok (K Dnskey)
    | 50 -> Ok (K Nsec3) | 52 -> Ok (K Tlsa) | 257 -> Ok (K Caa)
    | x ->
      let* i = I.of_int ~off x in
      Ok (K (Unknown i))

  let ppk ppf (K k) = match k with
    | Cname -> Fmt.string ppf "CNAME"
    | Mx -> Fmt.string ppf "MX"
    | Ns -> Fmt.string ppf "NS"
    | Ptr -> Fmt.string ppf "PTR"
    | Soa -> Fmt.string ppf "SOA"
    | Txt -> Fmt.string ppf "TXT"
    | A -> Fmt.string ppf "A"
    | Aaaa -> Fmt.string ppf "AAAA"
    | Srv -> Fmt.string ppf "SRV"
    | Dnskey -> Fmt.string ppf "DNSKEY"
    | Caa -> Fmt.string ppf "CAA"
    | Tlsa -> Fmt.string ppf "TLSA"
    | Sshfp -> Fmt.string ppf "SSHFP"
    | Ds -> Fmt.string ppf "DS"
    | Rrsig -> Fmt.string ppf "RRSIG"
    | Nsec -> Fmt.string ppf "NSEC"
    | Nsec3 -> Fmt.string ppf "NSEC3"
    | Loc -> Fmt.string ppf "LOC"
    | Null -> Fmt.string ppf "NULL"
    | Unknown x -> Fmt.pf ppf "TYPE%d" (I.to_int x)

  let of_string = function
    | "CNAME" -> Ok (K Cname)
    | "MX" -> Ok (K Mx)
    | "NS" -> Ok (K Ns)
    | "PTR" -> Ok (K Ptr)
    | "SOA" -> Ok (K Soa)
    | "TXT" -> Ok (K Txt)
    | "A" -> Ok (K A)
    | "AAAA" -> Ok (K Aaaa)
    | "SRV" -> Ok (K Srv)
    | "DNSKEY" -> Ok (K Dnskey)
    | "CAA" -> Ok (K Caa)
    | "TLSA" -> Ok (K Tlsa)
    | "SSHFP" -> Ok (K Sshfp)
    | "DS" -> Ok (K Ds)
    | "RRSIG" -> Ok (K Rrsig)
    | "NSEC" -> Ok (K Nsec)
    | "NSEC3" -> Ok (K Nsec3)
    | "LOC" -> Ok (K Loc)
    | "NULL" -> Ok (K Null)
    | x when String.length x > 4 && String.(equal "TYPE" (sub x 0 4)) ->
      Result.map_error
        (function `Malformed (_, m) -> `Msg m | `Msg m -> `Msg m)
        (try
           let i = int_of_string String.(sub x 4 (String.length x - 4)) in
           of_int i
         with
         | Failure _ ->
           Error (`Msg ("Bad RR type " ^ x ^ ": couldn't decode number")))
    | x -> Error (`Msg ("Bad RR type: couldn't decode " ^ x))

  type rrtyp = [ `Any | `Tsig | `Edns | `Ixfr | `Axfr | `K of k ]

  let pp_rr ppf = function
    | `Any -> Fmt.string ppf "ANY"
    | `Tsig -> Fmt.string ppf "TSIG"
    | `Edns -> Fmt.string ppf "EDNS"
    | `Ixfr -> Fmt.string ppf "IXFR"
    | `Axfr -> Fmt.string ppf "AXFR"
    | `K k -> ppk ppf k

  let rr_to_int : rrtyp -> int = function
    | `Any -> any_rtyp
    | `Tsig -> Tsig.rtyp
    | `Edns -> Edns.rtyp
    | `Ixfr -> ixfr_rtyp
    | `Axfr -> axfr_rtyp
    | `K (K k) -> to_int k

  let encode_ntc ?compress names buf off (n, t, c) =
    let names, off = Name.encode ?compress n names buf off in
    Bytes.set_uint16_be buf off (rr_to_int t) ;
    Bytes.set_uint16_be buf (off + 2) c ;
    names, off + 4

  let encode : type a. ?clas:Class.t -> [ `raw ] Domain_name.t -> a key -> a -> Name.name_offset_map -> bytes -> int ->
    (Name.name_offset_map * int) * int = fun ?(clas = Class.IN) name k v names buf off ->
    let clas = Class.to_int clas in
    let rr names f off ttl =
      let names, off' = encode_ntc names buf off (name, `K (K k), clas) in
      (* leave 6 bytes space for TTL and length *)
      let rdata_start = off' + 6 in
      let names, rdata_end = f names buf rdata_start in
      let rdata_len = rdata_end - rdata_start in
      Bytes.set_int32_be buf off' ttl ;
      Bytes.set_uint16_be buf (off' + 4) rdata_len ;
      names, rdata_end
    in
    match k, v with
    | Soa, soa -> rr names (Soa.encode soa) off soa.minimum, 1
    | Ns, (ttl, ns) ->
      Domain_name.Host_set.fold (fun name ((names, off), count) ->
          rr names (Ns.encode name) off ttl, succ count)
        ns ((names, off), 0)
    | Mx, (ttl, mx) ->
      Mx_set.fold (fun mx ((names, off), count) ->
          rr names (Mx.encode mx) off ttl, succ count)
        mx ((names, off), 0)
    | Cname, (ttl, alias) -> rr names (Cname.encode alias) off ttl, 1
    | A, (ttl, addresses) ->
      Ipaddr.V4.Set.fold (fun address ((names, off), count) ->
        rr names (A.encode address) off ttl, succ count)
        addresses ((names, off), 0)
    | Aaaa, (ttl, aaaas) ->
      Ipaddr.V6.Set.fold (fun address ((names, off), count) ->
          rr names (Aaaa.encode address) off ttl, succ count)
        aaaas ((names, off), 0)
    | Ptr, (ttl, rev) -> rr names (Ptr.encode rev) off ttl, 1
    | Srv, (ttl, srvs) ->
      Srv_set.fold (fun srv ((names, off), count) ->
          rr names (Srv.encode srv) off ttl, succ count)
        srvs ((names, off), 0)
    | Dnskey, (ttl, dnskeys) ->
      Dnskey_set.fold (fun dnskey ((names, off), count) ->
        rr names (Dnskey.encode dnskey) off ttl, succ count)
        dnskeys ((names, off), 0)
    | Caa, (ttl, caas) ->
      Caa_set.fold (fun caa ((names, off), count) ->
          rr names (Caa.encode caa) off ttl, succ count)
        caas ((names, off), 0)
    | Tlsa, (ttl, tlsas) ->
      Tlsa_set.fold (fun tlsa ((names, off), count) ->
          rr names (Tlsa.encode tlsa) off ttl, succ count)
        tlsas ((names, off), 0)
    | Sshfp, (ttl, sshfps) ->
      Sshfp_set.fold (fun sshfp ((names, off), count) ->
          rr names (Sshfp.encode sshfp) off ttl, succ count)
        sshfps ((names, off), 0)
    | Txt, (ttl, txts) ->
      Txt_set.fold (fun txt ((names, off), count) ->
          rr names (Txt.encode txt) off ttl, succ count)
        txts ((names, off), 0)
    | Ds, (ttl, ds) ->
      Ds_set.fold (fun ds ((names, off), count) ->
          rr names (Ds.encode ds) off ttl, succ count)
        ds ((names, off), 0)
    | Rrsig, (ttl, rrs) ->
      Rrsig_set.fold (fun rrsig ((names, off), count) ->
          rr names (Rrsig.encode rrsig) off ttl, succ count)
        rrs ((names, off), 0)
    | Nsec, (ttl, nsec) ->
      rr names (Nsec.encode nsec) off ttl, 1
    | Nsec3, (ttl, nsec) ->
      rr names (Nsec3.encode nsec) off ttl, 1
    | Loc, (ttl, locs) ->
      Loc_set.fold (fun loc ((names, off), count) ->
          rr names (Loc.encode loc) off ttl, succ count)
        locs ((names, off), 0)
    | Null, (ttl, nulls) ->
      Null_set.fold (fun null ((names, off), count) ->
          rr names (Null.encode null) off ttl, succ count)
        nulls ((names, off), 0)
    | Unknown _, (ttl, datas) ->
      let encode data names buf off =
        let l = String.length data in
        Bytes.blit_string data 0 buf off l;
        names, off + l
      in
      Txt_set.fold (fun data ((names, off), count) ->
          rr names (encode data) off ttl, succ count)
        datas ((names, off), 0)

  let encode_dnssec : type a. ttl:int32 -> ?clas:Class.t -> [ `raw ] Domain_name.t -> a key -> a ->
    (int * string) list = fun ~ttl ?(clas = Class.IN) name k v ->
    let clas = Class.to_int clas in
    let compress = false in
    let names = Domain_name.Map.empty in
    let rr f =
      let buf = Bytes.create 4096 in
      let _names, off' = encode_ntc ~compress names buf 0 (name, `K (K k), clas) in
      (* leave 6 bytes space for TTL and length *)
      let rdata_start = off' + 6 in
      let _names, rdata_end = f names buf rdata_start in
      let rdata_len = rdata_end - rdata_start in
      Bytes.set_int32_be buf off' ttl ;
      Bytes.set_uint16_be buf (off' + 4) rdata_len ;
      rdata_start, String.sub (Bytes.unsafe_to_string buf) 0 rdata_end
    in
    match k, v with
    | Soa, soa -> [ rr (Soa.encode ~compress soa) ]
    | Ns, (_ttl, ns) ->
      Domain_name.Host_set.fold (fun name acc ->
          rr (Ns.encode ~compress name) :: acc)
        ns []
    | Mx, (_ttl, mx) ->
      Mx_set.fold (fun mx acc ->
          rr (Mx.encode ~compress mx) :: acc)
        mx []
    | Cname, (_ttl, alias) -> [ rr (Cname.encode ~compress alias) ]
    | A, (_ttl, addresses) ->
      Ipaddr.V4.Set.fold (fun address acc -> rr (A.encode address) :: acc)
        addresses []
    | Aaaa, (_ttl, aaaas) ->
      Ipaddr.V6.Set.fold (fun address acc ->
          rr (Aaaa.encode address) :: acc)
        aaaas []
    | Ptr, (_ttl, rev) -> [ rr (Ptr.encode ~compress rev) ]
    | Srv, (_ttl, srvs) ->
      Srv_set.fold (fun srv acc ->
          rr (Srv.encode srv) :: acc)
        srvs []
    | Dnskey, (_ttl, dnskeys) ->
      Dnskey_set.fold (fun dnskey acc ->
          rr (Dnskey.encode dnskey) :: acc)
        dnskeys []
    | Caa, (_ttl, caas) ->
      Caa_set.fold (fun caa acc ->
          rr (Caa.encode caa) :: acc)
        caas []
    | Tlsa, (_ttl, tlsas) ->
      Tlsa_set.fold (fun tlsa acc ->
          rr (Tlsa.encode tlsa) :: acc)
        tlsas []
    | Sshfp, (_ttl, sshfps) ->
      Sshfp_set.fold (fun sshfp acc ->
          rr (Sshfp.encode sshfp) :: acc)
        sshfps []
    | Txt, (_ttl, txts) ->
      Txt_set.fold (fun txt acc ->
          rr (Txt.encode txt) :: acc)
        txts []
    | Ds, (_ttl, ds) ->
      Ds_set.fold (fun ds acc ->
          rr (Ds.encode ds) :: acc)
        ds []
    | Rrsig, (_ttl, rrs) ->
      Rrsig_set.fold (fun rrsig acc ->
          rr (Rrsig.encode rrsig) :: acc)
        rrs []
    | Nsec, (_ttl, ns) ->
      [ rr (Nsec.encode ns) ]
    | Nsec3, (_ttl, ns) ->
      [ rr (Nsec3.encode ns) ]
    | Loc, (_ttl, locs) ->
      Loc_set.fold (fun loc acc ->
          rr (Loc.encode loc) :: acc)
        locs []
    | Null, (_ttl, nulls) ->
      Null_set.fold (fun null acc ->
          rr (Null.encode null) :: acc)
        nulls []
    | Unknown _, (_ttl, datas) ->
      let encode data names buf off =
        let l = String.length data in
        Bytes.blit_string data 0 buf off l;
        names, off + l
      in
      Txt_set.fold (fun data acc ->
          rr (encode data) :: acc)
        datas []

  (* RFC 4034, Section 6.2 point 3 *)
  let canonical : type a. a key -> a -> a = fun k v ->
    match k, v with
    | Soa, s -> Soa.canonical s
    | Ns, (ttl, ns) -> ttl, Domain_name.Host_set.map Ns.canonical ns
    | Mx, (ttl, mx) -> ttl, Mx_set.map Mx.canonical mx
    | Cname, (ttl, cn) -> ttl, Cname.canonical cn
    | Ptr, (ttl, ptr) -> ttl, Ptr.canonical ptr
    | Srv, (ttl, srv) -> ttl, Srv_set.map Srv.canonical srv
    | Rrsig, (ttl, rrsig) -> ttl, Rrsig_set.map Rrsig.canonical rrsig
    | Nsec, (ttl, nsec) -> ttl, Nsec.canonical nsec
    | _, v -> v

  (* ordering, according to RFC 4034, section 6.3 *)
  let canonical_order str str_off str' str'_off =
    let str_l = String.length str - str_off and str'_l = String.length str' - str'_off in
    let rec c idx =
      if str_l = str'_l && str_l = idx then 0
      else if str_l = idx then 1
      else if str'_l = idx then -1
      else
        match Int.compare (String.get_uint8 str (str_off + idx)) (String.get_uint8 str' (str'_off + idx)) with
        | 0 -> c (succ idx)
        | x -> x
    in
    c 0

  (* RFC 4034, section 3.1.8.1 *)
  let prep_for_sig : type a . [`raw] Domain_name.t -> Rrsig.t -> a key -> a ->
    ([`raw] Domain_name.t * string, [> `Msg of string ]) result =
      fun name rrsig typ value ->
    let buf, off = Rrsig.prep_rrsig rrsig in
    let rrsig_cs = String.sub (Bytes.unsafe_to_string buf) 0 off in
    Log.debug (fun m -> m "using rrsig %a" (Ohex.pp_hexdump ()) rrsig_cs);
    let* name =
      let* used_name = Rrsig.used_name rrsig name in
      Ok (Domain_name.canonical used_name)
    in
    let* (K covered_typ) =
      Result.map_error
        (function `Malformed (_, txt) -> `Msg txt)
        (of_int rrsig.Rrsig.type_covered)
    in
    let* () = guard (K covered_typ <> K Rrsig) (`Msg "RRSIG records are never signed") in
    let* () = guard (K covered_typ = K typ) (`Msg "RRSIG type_covered does not match typ") in
    let value = canonical typ value in
    (* RFC 4034 section 6.2 point 5 *)
    let ttl = rrsig.Rrsig.original_ttl in
    let cs = encode_dnssec ~ttl name typ value in
    let order (off, cs) (off', cs') =
      canonical_order cs off cs' off'
    in
    let sorted_cs = List.map snd (List.sort order cs) in
    Ok (name, String.concat "" (rrsig_cs :: sorted_cs))

  let canonical_encoded_name name =
    let buf = Bytes.make 512 '\000' in
    let _, s =
      Name.encode ~compress:false (Domain_name.canonical name)
        Domain_name.Map.empty buf 0
    in
    String.sub (Bytes.unsafe_to_string buf) 0 s

  let union_rr : type a. a key -> a -> a -> a = fun k l r ->
    match k, l, r with
    | Cname, _, cname -> cname
    | Mx, (_, mxs), (ttl, mxs') -> (ttl, Mx_set.union mxs mxs')
    | Ns, (_, ns), (ttl, ns') -> (ttl, Domain_name.Host_set.union ns ns')
    | Ptr, _, ptr -> ptr
    | Soa, _, soa -> soa
    | Txt, (_, txts), (ttl, txts') -> (ttl, Txt_set.union txts txts')
    | A, (_, ips), (ttl, ips') -> (ttl, Ipaddr.V4.Set.union ips ips')
    | Aaaa, (_, ips), (ttl, ips') -> (ttl, Ipaddr.V6.Set.union ips ips')
    | Srv, (_, srvs), (ttl, srvs') -> (ttl, Srv_set.union srvs srvs')
    | Dnskey, (_, keys), (ttl, keys') -> (ttl, Dnskey_set.union keys keys')
    | Caa, (_, caas), (ttl, caas') -> (ttl, Caa_set.union caas caas')
    | Tlsa, (_, tlsas), (ttl, tlsas') -> (ttl, Tlsa_set.union tlsas tlsas')
    | Sshfp, (_, sshfps), (ttl, sshfps') -> (ttl, Sshfp_set.union sshfps sshfps')
    | Ds, (_, ds), (ttl, ds') -> (ttl, Ds_set.union ds ds')
    | Rrsig, (_, rrs), (ttl, rrs') -> (ttl, Rrsig_set.union rrs rrs')
    | Nsec, _, nsec -> nsec
    | Nsec3, _, nsec -> nsec
    | Loc, _, loc -> loc
    | Null, _, null -> null
    | Unknown _, (_, data), (ttl, data') -> (ttl, Txt_set.union data data')

  let unionee : type a. a key -> a -> a -> a option =
    fun k v v' -> Some (union_rr k v v')

  let combine_opt : type a. a key -> a -> a option -> a option = fun k l r ->
    match r with
    | None -> Some l
    | Some r -> Some (union_rr k l r)

  let remove_rr : type a. a key -> a -> a -> a option = fun k v rem ->
    match k, v, rem with
    | Cname, _, _ -> None
    | Mx, (ttl, mxs), (_, rm) ->
      let s = Mx_set.diff mxs rm in
      if Mx_set.is_empty s then None else Some (ttl, s)
    | Ns, (ttl, ns), (_, rm) ->
      let s = Domain_name.Host_set.diff ns rm in
      if Domain_name.Host_set.is_empty s then None else Some (ttl, s)
    | Ptr, _, _ -> None
    | Soa, _, _ -> None
    | Txt, (ttl, txts), (_, rm) ->
      let s = Txt_set.diff txts rm in
      if Txt_set.is_empty s then None else Some (ttl, s)
    | A, (ttl, ips), (_, rm) ->
      let s = Ipaddr.V4.Set.diff ips rm in
      if Ipaddr.V4.Set.is_empty s then None else Some (ttl, s)
    | Aaaa, (ttl, ips), (_, rm) ->
      let s = Ipaddr.V6.Set.diff ips rm in
      if Ipaddr.V6.Set.is_empty s then None else Some (ttl, s)
    | Srv, (ttl, srvs), (_, rm) ->
      let s = Srv_set.diff srvs rm in
      if Srv_set.is_empty s then None else Some (ttl, s)
    | Dnskey, (ttl, keys), (_, rm) ->
      let s = Dnskey_set.diff keys rm in
      if Dnskey_set.is_empty s then None else Some (ttl, s)
    | Caa, (ttl, caas), (_, rm) ->
      let s = Caa_set.diff caas rm in
      if Caa_set.is_empty s then None else Some (ttl, s)
    | Tlsa, (ttl, tlsas), (_, rm) ->
      let s = Tlsa_set.diff tlsas rm in
      if Tlsa_set.is_empty s then None else Some (ttl, s)
    | Sshfp, (ttl, sshfps), (_, rm) ->
      let s = Sshfp_set.diff sshfps rm in
      if Sshfp_set.is_empty s then None else Some (ttl, s)
    | Ds, (ttl, ds), (_, rm) ->
      let s = Ds_set.diff ds rm in
      if Ds_set.is_empty s then None else Some (ttl, s)
    | Rrsig, (ttl, rrs), (_, rm) ->
      let s = Rrsig_set.diff rrs rm in
      if Rrsig_set.is_empty s then None else Some (ttl, s)
    | Nsec, _, _ -> None
    | Nsec3, _, _ -> None
    | Loc, (ttl, locs), (_, rm) ->
      let s = Loc_set.diff locs rm in
      if Loc_set.is_empty s then None else Some (ttl, s)
    | Null, (ttl, nulls), (_, rm) ->
      let s = Null_set.diff nulls rm in
      if Null_set.is_empty s then None else Some (ttl, s)
    | Unknown _, (ttl, datas), (_, rm) ->
      let data = Txt_set.diff datas rm in
      if Txt_set.is_empty data then None else Some (ttl, data)

  let diff ~old map =
    let deleted, added = ref empty, ref empty in
    let merger : type a . a key -> a option -> a option -> a option =
      fun k a b ->
        (match k, a, b with
         | Soa, _, _ -> () (* SOA is special anyways *)
         | _, None, Some data -> added := add k data !added
         | _, Some data, None -> deleted := add k data !deleted
         | _, None, None -> ()
         | _, Some old, Some n ->
           (* TODO should handle TTL-only changes as well! *)
           (match remove_rr k old n with
            | None -> (* there isn't any change *) ()
            | Some tbr -> deleted := add k tbr !deleted);
           match remove_rr k n old with
           | None -> (* there's nothing more *) ()
           | Some tba -> added := add k tba !added);
        None
    in
    ignore (merge { f = merger } old map);
    (if is_empty !deleted then None else Some !deleted),
    (if is_empty !added then None else Some !added)

  let text : type c. ?origin:'a Domain_name.t -> ?default_ttl:int32 ->
    'b Domain_name.t -> c key -> c -> string = fun ?origin ?default_ttl n t v ->
    let rec ws_after_56 s =
      let pos = 56 in
      let l = String.length s in
      if l < pos then s
      else String.sub s 0 pos ^ " " ^ ws_after_56 (String.sub s pos (l - pos))
    in
    let hex cs =
      let buf = Bytes.create (String.length cs * 2) in
      for i = 0 to pred (String.length cs) do
        let byte = String.get_uint8 cs i in
        let up, low = byte lsr 4, byte land 0x0F in
        let to_hex_char v = char_of_int (if v < 10 then 0x30 + v else 0x37 + v) in
        Bytes.set buf (i * 2) (to_hex_char up) ;
        Bytes.set buf (i * 2 + 1) (to_hex_char low)
      done;
      Bytes.unsafe_to_string buf |> ws_after_56
    and b64 cs =
      Base64.encode_string cs |> ws_after_56
    in
    let origin = match origin with
      | None -> None
      | Some n -> Some (n, Array.length (Domain_name.to_array n))
    in
    let name : type a . a Domain_name.t -> string = fun n ->
      let n = Domain_name.raw n in
      match origin with
      | Some (domain, amount) when Domain_name.is_subdomain ~subdomain:n ~domain ->
        let n' = Domain_name.drop_label_exn ~rev:true ~amount n in
        if Domain_name.equal n' Domain_name.root then
          "@"
        else
          Domain_name.to_string n'
      | _ -> Domain_name.to_string ~trailing:true n
    in
    let ttl_opt ttl = match default_ttl with
      | Some d when Int32.compare ttl d = 0 -> None
      | _ -> Some ttl
    in
    let ttl_fmt = Fmt.(option (append uint32 (any "\t"))) in
    let str_name = name n in
    let strs =
      match t, v with
      | Cname, (ttl, alias) ->
        [ Fmt.str "%s\t%aCNAME\t%s" str_name ttl_fmt (ttl_opt ttl) (name alias) ]
      | Mx, (ttl, mxs) ->
        Mx_set.fold (fun { preference ; mail_exchange } acc ->
            Fmt.str "%s\t%aMX\t%u\t%s" str_name ttl_fmt (ttl_opt ttl) preference (name mail_exchange) :: acc)
          mxs []
      | Ns, (ttl, ns) ->
        Domain_name.Host_set.fold (fun ns acc ->
            Fmt.str "%s\t%aNS\t%s" str_name ttl_fmt (ttl_opt ttl) (name ns) :: acc)
          ns []
      | Ptr, (ttl, ptr) ->
        [ Fmt.str "%s\t%aPTR\t%s" str_name ttl_fmt (ttl_opt ttl) (name ptr) ]
      | Soa, soa ->
        [ Fmt.str "%s\t%aSOA\t%s\t%s\t%lu\t%lu\t%lu\t%lu\t%lu" str_name
            ttl_fmt (ttl_opt soa.minimum)
            (name soa.nameserver)
            (name soa.hostmaster)
            soa.serial soa.refresh soa.retry
            soa.expiry soa.minimum ]
      | Txt, (ttl, txts) ->
        Txt_set.fold (fun txt acc ->
            Fmt.str "%s\t%aTXT\t\"%s\"" str_name ttl_fmt (ttl_opt ttl) txt :: acc)
          txts []
      | A, (ttl, a) ->
        Ipaddr.V4.Set.fold (fun ip acc ->
          Fmt.str "%s\t%aA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V4.to_string ip) :: acc)
          a []
      | Aaaa, (ttl, aaaa) ->
        Ipaddr.V6.Set.fold (fun ip acc ->
            Fmt.str "%s\t%aAAAA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V6.to_string ip) :: acc)
          aaaa []
      | Srv, (ttl, srvs) ->
        Srv_set.fold (fun srv acc ->
            Fmt.str "%s\t%aSRV\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              srv.priority srv.weight srv.port
              (name srv.target) :: acc)
          srvs []
      | Dnskey, (ttl, keys) ->
        Dnskey_set.fold (fun key acc ->
            Fmt.str "%s%a\tDNSKEY\t%u\t3\t%d\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              (Dnskey.encode_flags key.flags)
              (Dnskey.algorithm_to_int key.algorithm)
              (b64 key.key) :: acc)
          keys []
      | Caa, (ttl, caas) ->
        Caa_set.fold (fun caa acc ->
            Fmt.str "%s\t%aCAA\t%s\t%s\t\"%s\""
              str_name ttl_fmt (ttl_opt ttl)
              (if caa.critical then "128" else "0")
              caa.tag (String.concat ";" caa.value) :: acc)
          caas []
      | Tlsa, (ttl, tlsas) ->
        Tlsa_set.fold (fun tlsa acc ->
            Fmt.str "%s\t%aTLSA\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              (Tlsa.cert_usage_to_int tlsa.cert_usage)
              (Tlsa.selector_to_int tlsa.selector)
              (Tlsa.matching_type_to_int tlsa.matching_type)
              (hex tlsa.data) :: acc)
          tlsas []
      | Sshfp, (ttl, sshfps) ->
        Sshfp_set.fold (fun sshfp acc ->
            Fmt.str "%s\t%aSSHFP\t%u\t%u\t%s" str_name ttl_fmt (ttl_opt ttl)
              (Sshfp.algorithm_to_int sshfp.algorithm)
              (Sshfp.typ_to_int sshfp.typ)
              (hex sshfp.fingerprint) :: acc)
          sshfps []
      | Ds, (ttl, ds) ->
        Ds_set.fold (fun ds acc ->
            Fmt.str "%s\t%aDS\t%u\t%u\t%u\t%s" str_name ttl_fmt (ttl_opt ttl)
              ds.Ds.key_tag
              (Dnskey.algorithm_to_int ds.algorithm)
              (Ds.digest_type_to_int ds.digest_type)
              (hex ds.digest) :: acc)
          ds []
      | Rrsig, (ttl, rrs) ->
        Rrsig_set.fold (fun rrsig acc ->
            let typ = match of_int rrsig.type_covered with
              | Ok k -> Fmt.to_to_string ppk k
              | Error _ -> "TYPE" ^ string_of_int rrsig.type_covered
            in
            let pp_ts ppf ts =
              let (year, month, day), ((hour, minute, second), _) = Ptime.to_date_time ts in
              Fmt.pf ppf "%04d%02d%02d%02d%02d%02d" year month day hour minute second
            in
            Fmt.str "%s\t%aRRSIG\t%s\t%u\t%u\t%lu\t%a\t%a\t%u\t%s\t%s" str_name ttl_fmt (ttl_opt ttl)
              typ (Dnskey.algorithm_to_int rrsig.algorithm)
              rrsig.label_count rrsig.original_ttl
              pp_ts rrsig.signature_expiration pp_ts rrsig.signature_inception
              rrsig.key_tag (name rrsig.signer_name)
              (b64 rrsig.signature) :: acc)
          rrs []
      | Nsec, (ttl, ns) ->
        let types =
          Bit_map.fold (fun i acc ->
              match of_int i with
              | Ok k -> k :: acc
              | Error _ -> assert false)
            ns.Nsec.types [] |> List.rev
        in
        [ Fmt.str "%s\t%aNSEC\t%s\t(%a)" str_name ttl_fmt (ttl_opt ttl)
            (name ns.Nsec.next_domain) Fmt.(list ~sep:(any " ") ppk) types ]
      | Nsec3, (ttl, ns) ->
        let types =
          Bit_map.fold (fun i acc ->
              match of_int i with
              | Ok k -> k :: acc
              | Error _ -> assert false)
            ns.Nsec3.types [] |> List.rev
        in
        [ Fmt.str "%s\t%aNSEC3\t%d\t%d\t%d\t%s\t%s\t%a" str_name
            ttl_fmt (ttl_opt ttl) Nsec3.hash (Nsec3.flags_to_int ns.Nsec3.flags)
            ns.Nsec3.iterations
            (if String.length ns.Nsec3.salt = 0 then "-" else hex ns.Nsec3.salt)
            (hex (* TODO base32 *) ns.Nsec3.next_owner_hashed)
            Fmt.(list ~sep:(any " ") ppk) types ]
      | Loc, (ttl, locs) ->
        Loc_set.fold (fun loc acc ->
            Fmt.str "%s\t%aLOC\t%s" str_name ttl_fmt (ttl_opt ttl) (Loc.to_string loc) :: acc)
          locs []
      | Null, (ttl, nulls) ->
        Null_set.fold (fun null acc ->
            Fmt.str "%s\t%aNULL\t%a" str_name ttl_fmt (ttl_opt ttl) Ohex.pp null :: acc)
          nulls []
      | Unknown x, (ttl, datas) ->
        Txt_set.fold (fun data acc ->
            Fmt.str "%s\t%aTYPE%d\t\\# %d %s" str_name ttl_fmt (ttl_opt ttl)
              (I.to_int x) (String.length data) (hex data) :: acc)
          datas []
    in
    String.concat "\n" strs

  let ttl : type a. a key -> a -> int32 = fun k v ->
    match k, v with
    | Cname, (ttl, _) -> ttl
    | Mx, (ttl, _) -> ttl
    | Ns, (ttl, _) -> ttl
    | Ptr, (ttl, _) -> ttl
    | Soa, soa -> soa.minimum
    | Txt, (ttl, _) -> ttl
    | A, (ttl, _) -> ttl
    | Aaaa, (ttl, _) -> ttl
    | Srv, (ttl, _) -> ttl
    | Dnskey, (ttl, _) -> ttl
    | Caa, (ttl, _) -> ttl
    | Tlsa, (ttl, _) -> ttl
    | Sshfp, (ttl, _) -> ttl
    | Ds, (ttl, _) -> ttl
    | Rrsig, (ttl, _) -> ttl
    | Nsec, (ttl, _) -> ttl
    | Nsec3, (ttl, _) -> ttl
    | Loc, (ttl, _) -> ttl
    | Null, (ttl, _) -> ttl
    | Unknown _, (ttl, _) -> ttl

  let with_ttl : type a. a key -> a -> int32 -> a = fun k v ttl ->
    match k, v with
    | Cname, (_, cname) -> ttl, cname
    | Mx, (_, mxs) -> ttl, mxs
    | Ns, (_, ns) -> ttl, ns
    | Ptr, (_, ptr) -> ttl, ptr
    | Soa, soa -> soa
    | Txt, (_, txts) -> ttl, txts
    | A, (_, ips) -> ttl, ips
    | Aaaa, (_, ips) -> ttl, ips
    | Srv, (_, srvs) -> ttl, srvs
    | Dnskey, keys -> keys
    | Caa, (_, caas) -> ttl, caas
    | Tlsa, (_, tlsas) -> ttl, tlsas
    | Sshfp, (_, sshfps) -> ttl, sshfps
    | Ds, (_, ds) -> ttl, ds
    | Rrsig, (_, rrs) -> ttl, rrs
    | Nsec, (_, ns) -> ttl, ns
    | Nsec3, (_, ns) -> ttl, ns
    | Loc, (_, loc) -> ttl, loc
    | Null, (_, null) -> ttl, null
    | Unknown _, (_, datas) -> ttl, datas

  let split : type a. a key -> a -> a * a option = fun k v ->
    match k, v with
    | Cname, (ttl, cname) ->
      (ttl, cname), None
    | Mx, (ttl, mxs) ->
      let one = Mx_set.choose mxs in
      let rest = Mx_set.remove one mxs in
      let rest' =
        if Mx_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Mx_set.singleton one), rest'
    | Ns, (ttl, ns) ->
      let one = Domain_name.Host_set.choose ns in
      let rest = Domain_name.Host_set.remove one ns in
      let rest' =
        if Domain_name.Host_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Domain_name.Host_set.singleton one), rest'
    | Ptr, (ttl, ptr) -> (ttl, ptr), None
    | Soa, soa -> soa, None
    | Txt, (ttl, txts) ->
      let one = Txt_set.choose txts in
      let rest = Txt_set.remove one txts in
      let rest' =
        if Txt_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Txt_set.singleton one), rest'
    | A, (ttl, ips) ->
      let one = Ipaddr.V4.Set.choose ips in
      let rest = Ipaddr.V4.Set.remove one ips in
      let rest' =
        if Ipaddr.V4.Set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Ipaddr.V4.Set.singleton one), rest'
    | Aaaa, (ttl, ips) ->
      let one = Ipaddr.V6.Set.choose ips in
      let rest = Ipaddr.V6.Set.remove one ips in
      let rest' =
        if Ipaddr.V6.Set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Ipaddr.V6.Set.singleton one), rest'
    | Srv, (ttl, srvs) ->
      let one = Srv_set.choose srvs in
      let rest = Srv_set.remove one srvs in
      let rest' =
        if Srv_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Srv_set.singleton one), rest'
    | Dnskey, (ttl, keys) ->
      let one = Dnskey_set.choose keys in
      let rest = Dnskey_set.remove one keys in
      let rest' =
        if Dnskey_set.is_empty keys then None else Some (ttl, rest)
      in
      (ttl, Dnskey_set.singleton one), rest'
    | Caa, (ttl, caas) ->
      let one = Caa_set.choose caas in
      let rest = Caa_set.remove one caas in
      let rest' =
        if Caa_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Caa_set.singleton one), rest'
    | Tlsa, (ttl, tlsas) ->
      let one = Tlsa_set.choose tlsas in
      let rest = Tlsa_set.remove one tlsas in
      let rest' =
        if Tlsa_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Tlsa_set.singleton one), rest'
    | Sshfp, (ttl, sshfps) ->
      let one = Sshfp_set.choose sshfps in
      let rest = Sshfp_set.remove one sshfps in
      let rest' =
        if Sshfp_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Sshfp_set.singleton one), rest'
    | Ds, (ttl, ds) ->
      let one = Ds_set.choose ds in
      let rest = Ds_set.remove one ds in
      let rest' =
        if Ds_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Ds_set.singleton one), rest'
    | Rrsig, (ttl, rrs) ->
      let one = Rrsig_set.choose rrs in
      let rest = Rrsig_set.remove one rrs in
      let rest' =
        if Rrsig_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Rrsig_set.singleton one), rest'
    | Nsec, (ttl, rr) -> (ttl, rr), None
    | Nsec3, (ttl, rr) -> (ttl, rr), None
    | Loc, (ttl, locs) ->
      let one = Loc_set.choose locs in
      let rest = Loc_set.remove one locs in
      let rest' =
        if Loc_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Loc_set.singleton one), rest'
    | Null, (ttl, nulls) ->
      let one = Null_set.choose nulls in
      let rest = Null_set.remove one nulls in
      let rest' =
        if Null_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Null_set.singleton one), rest'
    | Unknown _, (ttl, datas) ->
      let one = Txt_set.choose datas in
      let rest = Txt_set.remove one datas in
      let rest' =
        if Txt_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Txt_set.singleton one), rest'

  let pp_b ppf (B (k, v)) =
    let txt = text Domain_name.root k v in
    Fmt.string ppf txt

  let names : type a. a key -> a -> Domain_name.Host_set.t = fun k v ->
    match k, v with
    | Cname, (_, alias) ->
      begin match Domain_name.host alias with
        | Error _ -> Domain_name.Host_set.empty
        | Ok a -> Domain_name.Host_set.singleton a
      end
    | Mx, (_, mxs) ->
      Mx_set.fold (fun { mail_exchange ; _} acc ->
          Domain_name.Host_set.add mail_exchange acc)
        mxs Domain_name.Host_set.empty
    | Ns, (_, names) -> names
    | Srv, (_, srvs) ->
      Srv_set.fold (fun x acc -> Domain_name.Host_set.add x.target acc)
        srvs Domain_name.Host_set.empty
    | _ -> Domain_name.Host_set.empty

  let decode names buf off (K typ) =
    let* () = guard (String.length buf - off >= 6) `Partial in
    let ttl = String.get_int32_be buf off
    and len = String.get_uint16_be buf (off + 4)
    and rdata_start = off + 6
    in
    let* () =
      guard (Int32.logand ttl 0x8000_0000l = 0l)
        (`Malformed (off, Fmt.str "bad TTL (high bit set) %lu" ttl))
    in
    let* () = guard (String.length buf - rdata_start >= len) `Partial in
    let* () =
      guard (len <= max_rdata_length)
        (`Malformed (off + 4, Fmt.str "length %d exceeds maximum rdata size" len))
    in
    let* b, names, rdata_end =
      try
        let buf = String.sub buf 0 (rdata_start + len)
        and off = rdata_start
        in
        begin match typ with
          | Soa ->
            let* soa, names, off = Soa.decode_exn names buf ~off ~len in
            Ok (B (Soa, soa), names, off)
          | Ns ->
            let* ns, names, off = Ns.decode names buf ~off ~len in
            Ok (B (Ns, (ttl, Domain_name.Host_set.singleton ns)), names, off)
          | Mx ->
            let* mx, names, off = Mx.decode_exn names buf ~off ~len in
            Ok (B (Mx, (ttl, Mx_set.singleton mx)), names, off)
          | Cname ->
            let* alias, names, off = Cname.decode names buf ~off ~len in
            Ok (B (Cname, (ttl, alias)), names, off)
          | A ->
            let* address, names, off = A.decode_exn names buf ~off ~len in
            Ok (B (A, (ttl, Ipaddr.V4.Set.singleton address)), names, off)
          | Aaaa ->
            let* address, names, off = Aaaa.decode_exn names buf ~off ~len in
            Ok (B (Aaaa, (ttl, Ipaddr.V6.Set.singleton address)), names, off)
          | Ptr ->
            let* rev, names, off = Ptr.decode names buf ~off ~len in
            Ok (B (Ptr, (ttl, rev)), names, off)
          | Srv ->
            let* srv, names, off = Srv.decode_exn names buf ~off ~len in
            Ok (B (Srv, (ttl, Srv_set.singleton srv)), names, off)
          | Dnskey ->
            let* dnskey, names, off = Dnskey.decode_exn names buf ~off ~len in
            Ok (B (Dnskey, (ttl, Dnskey_set.singleton dnskey)), names, off)
          | Caa ->
            let* caa, names, off = Caa.decode_exn names buf ~off ~len in
            Ok (B (Caa, (ttl, Caa_set.singleton caa)), names, off)
          | Tlsa ->
            let* tlsa, names, off = Tlsa.decode_exn names buf ~off ~len in
            Ok (B (Tlsa, (ttl, Tlsa_set.singleton tlsa)), names, off)
          | Sshfp ->
            let* sshfp, names, off = Sshfp.decode_exn names buf ~off ~len in
            Ok (B (Sshfp, (ttl, Sshfp_set.singleton sshfp)), names, off)
          | Txt ->
            let* txt, names, off = Txt.decode_exn names buf ~off ~len in
            Ok (B (Txt, (ttl, Txt_set.singleton txt)), names, off)
          | Ds ->
            let* ds, names, off = Ds.decode_exn names buf ~off ~len in
            Ok (B (Ds, (ttl, Ds_set.singleton ds)), names, off)
          | Rrsig ->
            let* rrs, names, off = Rrsig.decode_exn names buf ~off ~len in
            Ok (B (Rrsig, (ttl, Rrsig_set.singleton rrs)), names, off)
          | Nsec ->
            let* rr, names, off = Nsec.decode_exn names buf ~off ~len in
            Ok (B (Nsec, (ttl, rr)), names, off)
          | Nsec3 ->
            let* rr, names, off = Nsec3.decode_exn names buf ~off ~len in
            Ok (B (Nsec3, (ttl, rr)), names, off)
          | Loc ->
            let* loc, names, off = Loc.decode_exn names buf ~off ~len in
            Ok (B (Loc, (ttl, Loc_set.singleton loc)), names, off)
          | Null ->
            let* null, names, off = Null.decode names buf ~off ~len in
            Ok (B (Null, (ttl, Null_set.singleton null)), names, off)
          | Unknown x ->
            let data = String.sub buf off len in
            Ok (B (Unknown x, (ttl, Txt_set.singleton data)), names, rdata_start + len)
        end with
        | Invalid_argument _ -> Error `Partial
    in
    let* () =
      guard (len = rdata_end - rdata_start) (`Leftover (rdata_end, "rdata"))
    in
    Ok (b, names, rdata_end)

  let text_b ?origin ?default_ttl name (B (key, v)) =
    text ?origin ?default_ttl name key v
end

module Name_rr_map = struct
  type t = Rr_map.t Domain_name.Map.t

  let empty = Domain_name.Map.empty

  let equal a b =
    Domain_name.Map.equal (Rr_map.equal { f = Rr_map.equal_rr }) a b

  let pp ppf map =
    Fmt.(list ~sep:(any "@."))
      (fun ppf (name, rr_map) ->
         Fmt.(list ~sep:(any "@.") string) ppf
           (List.map (Rr_map.text_b name) (Rr_map.bindings rr_map)))
      ppf
      (Domain_name.Map.bindings map)

  let add name k v dmap =
    let m = match Domain_name.Map.find name dmap with
      | None -> Rr_map.empty
      | Some map -> map
    in
    let m' = Rr_map.update k (Rr_map.combine_opt k v) m in
    Domain_name.Map.add name m' dmap

  let find : type a . [ `raw ] Domain_name.t -> a Rr_map.rr -> t -> a option =
    fun name k dmap ->
    match Domain_name.Map.find name dmap with
    | None -> None
    | Some rrmap -> Rr_map.find k rrmap

  let remove_sub map sub =
    (* remove all entries which are in sub from map *)
    (* we don't compare values, just do it based on rrtype! *)
    Domain_name.Map.fold (fun name rrmap map ->
        match Domain_name.Map.find name map with
        | None -> map
        | Some rrs ->
          let rrs' = Rr_map.fold (fun (B (k, _)) map -> Rr_map.remove k map) rrmap rrs in
          if Rr_map.is_empty rrs'
          then Domain_name.Map.remove name map
          else Domain_name.Map.add name rrs' map)
      sub map

  let singleton name k v =
    Domain_name.Map.singleton name (Rr_map.singleton k v)

  let union t t' =
    Domain_name.Map.union (fun _ rr rr' ->
        Some (Rr_map.union { f = Rr_map.unionee } rr rr'))
      t t'
end

module Packet = struct

  module Flag = struct
    type t = [
      | `Authoritative
      | `Truncation
      | `Recursion_desired
      | `Recursion_available
      | `Authentic_data
      | `Checking_disabled
    ]

    let all = [
      `Authoritative ; `Truncation ; `Recursion_desired ;
      `Recursion_available ; `Authentic_data ; `Checking_disabled
    ]

    let compare a b = match a, b with
      | `Authoritative, `Authoritative -> 0
      | `Authoritative, _ -> 1 | _, `Authoritative -> -1
      | `Truncation, `Truncation -> 0
      | `Truncation, _ -> 1 | _, `Truncation -> -1
      | `Recursion_desired, `Recursion_desired -> 0
      | `Recursion_desired, _ -> 1 | _, `Recursion_desired -> -1
      | `Recursion_available, `Recursion_available -> 0
      | `Recursion_available, _ -> 1 | _, `Recursion_available -> -1
      | `Authentic_data, `Authentic_data -> 0
      | `Authentic_data, _ -> 1 | _, `Authentic_data -> -1
      | `Checking_disabled, `Checking_disabled -> 0
    (* | `Checking_disabled, _ -> 1 | _, `Checking_disabled -> -1 *)

    let pp ppf = function
      | `Authoritative -> Fmt.string ppf "authoritative"
      | `Truncation -> Fmt.string ppf "truncation"
      | `Recursion_desired -> Fmt.string ppf "recursion desired"
      | `Recursion_available -> Fmt.string ppf "recursion available"
      | `Authentic_data -> Fmt.string ppf "authentic data"
      | `Checking_disabled -> Fmt.string ppf "checking disabled"

    let pp_short ppf = function
      | `Authoritative -> Fmt.string ppf "AA"
      | `Truncation -> Fmt.string ppf "TC"
      | `Recursion_desired -> Fmt.string ppf "RD"
      | `Recursion_available -> Fmt.string ppf "RA"
      | `Authentic_data -> Fmt.string ppf "AD"
      | `Checking_disabled -> Fmt.string ppf "CD"

    let bit = function
      | `Authoritative -> 5
      | `Truncation -> 6
      | `Recursion_desired -> 7
      | `Recursion_available -> 8
      | `Authentic_data -> 10
      | `Checking_disabled -> 11

    let number f = 1 lsl (15 - bit f)
  end

  module Flags = Set.Make(Flag)

  module Header = struct

    type t = int * Flags.t

    let compare_id (id, _) (id', _) = Int.compare id id'

    let compare (id, flags) (id', flags') =
      andThen (Int.compare id id') (Flags.compare flags flags')

    let pp ppf ((id, flags), query, operation, rcode) =
      Fmt.pf ppf "%04X (%s) operation %a rcode @[%a@] flags: @[%a@]"
        id (if query then "query" else "response")
        Opcode.pp operation
        Rcode.pp rcode
        Fmt.(list ~sep:(any ", ") Flag.pp) (Flags.elements flags)

    let len = 12

    (* header is:
       0  QR - 0 for query, 1 for response
       1-4   operation
       5  AA Authoritative Answer [RFC1035]                             \
       6  TC Truncated Response   [RFC1035]                             |
       7  RD Recursion Desired    [RFC1035]                             |
       8  RA Recursion Available  [RFC1035]                             |-> flags
       9     Reserved                                                   |
       10 AD Authentic Data       [RFC4035][RFC6840][RFC Errata 4924]   |
       11 CD Checking Disabled    [RFC4035][RFC6840][RFC Errata 4927]   /
       12-15 rcode *)

    let decode_flags hdr =
      List.fold_left (fun flags flag ->
          if Flag.number flag land hdr > 0 then Flags.add flag flags else flags)
        Flags.empty Flag.all

    let decode buf =
      (* we only access the first 4 bytes, but anything <12 is a bad DNS frame *)
      let* () = guard (String.length buf >= len) `Partial in
      let hdr = String.get_uint16_be buf 2 in
      let op = (hdr land 0x7800) lsr 11
      and rc = hdr land 0x000F
      in
      let* operation = Opcode.of_int ~off:2 op in
      let* rcode = Rcode.of_int ~off:3 rc in
      let id = String.get_uint16_be buf 0
      and query = hdr lsr 15 = 0
      and flags = decode_flags hdr
      in
      Ok ((id, flags), query, operation, rcode)

    let encode_flags flags =
      Flags.fold (fun f acc -> acc + Flag.number f) flags 0

    let encode buf ((id, flags), query, operation, rcode) =
      let query = if query then 0x0000 else 0x8000 in
      let flags = encode_flags flags in
      let op = (Opcode.to_int operation) lsl 11 in
      let rcode = (Rcode.to_int rcode) land 0x000F in
      let header = query lor flags lor op lor rcode in
      Bytes.set_uint16_be buf 0 id ;
      Bytes.set_uint16_be buf 2 header

    (*
    let%expect_test "encode_decode_header" =
      let eq (hdr, query, op, rc) (hdr', query', op', rc') =
        compare hdr hdr' = 0 && rc = rc' && query = query' && op = op'
      and buf = Bytes.create 12
      in
      let test_buf ?(off = 0) len =
        Format.printf "%a" Ohex.pp (String.sub (Bytes.unsafe_to_string buf) off len)
      and test_hdr a b =
        match b with
        | Error _ -> Format.printf "error"
        | Ok b -> if eq a b then Format.printf "ok" else Format.printf "not ok"
      in
      let hdr = (1, Flags.empty), true, Opcode.Query, Rcode.NoError in
      encode buf hdr; (* basic query encoding works *)
      test_buf 4;
      [%expect {|0001 0000|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr = (0x1010, Flags.empty), false, Opcode.Query, Rcode.NXDomain in
      encode buf hdr; (* second encoded header works *)
      test_buf 4;
      [%expect {|1010 8003|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr = (0x0101, Flags.singleton `Authentic_data), true, Opcode.Update, Rcode.NoError in
      encode buf hdr; (* flags look nice *)
      test_buf 4;
      [%expect {|0101 2820|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr = (0x0080, Flags.singleton `Truncation), true, Opcode.Query, Rcode.NoError in
      encode buf hdr; (* truncation flag *)
      test_buf 4;
      [%expect {|0080 0200|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr = (0x8080, Flags.singleton `Checking_disabled), true, Opcode.Query, Rcode.NoError in
      encode buf hdr; (* checking disabled flag *)
      test_buf 4;
      [%expect {|8080 0010|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr = (0x1234, Flags.singleton `Authoritative), true, Opcode.Query, Rcode.NoError in
      encode buf hdr; (* authoritative flag *)
      test_buf 4;
      [%expect {|1234 0400|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr = (0xFFFF, Flags.singleton `Recursion_desired), true, Opcode.Query, Rcode.NoError in
      encode buf hdr; (* rd flag *)
      test_buf 4;
      [%expect {|ffff 0100|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr =
        let flags = Flags.(add `Recursion_desired (singleton `Authoritative)) in
        (0xE0E0, flags), true, Opcode.Query, Rcode.NoError
      in
      encode buf hdr; (* rd + auth *)
      test_buf 4;
      [%expect {|e0e0 0500|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let hdr = (0xAA00, Flags.singleton `Recursion_available), true, Opcode.Query, Rcode.NoError in
      encode buf hdr; (* ra *)
      test_buf 4;
      [%expect {|aa00 0080|}];
      test_hdr hdr (decode (Bytes.unsafe_to_string buf));
      [%expect {|ok|}];
      let test_err = function
        | Ok _ -> Format.printf "ok, expected error"
        | Error _ -> Format.printf "ok"
      in
      let data = Ohex.decode "0000 7000 0000 0000 0000 0000" in
      test_err (decode data);
      [%expect {|ok|}];
      let data = Ohex.decode "0000 000e 0000 0000 0000 0000" in
      test_err (decode data);
      [%expect {|ok|}]
      *)
  end

  let decode_ntc names buf off =
    let* name, names, off = Name.decode names buf ~off in
    let* () = guard (String.length buf - off >= 4) `Partial in
    let typ = String.get_uint16_be buf off
    and cls = String.get_uint16_be buf (off + 2)
    (* CLS is interpreted differently by OPT, thus no int_to_clas called here *)
    in
    match typ with
    | x when x = Edns.rtyp -> Ok ((name, `Edns, cls), names, off + 4)
    | x when x = Tsig.rtyp -> Ok ((name, `Tsig, cls), names, off + 4)
    | x when x = Rr_map.ixfr_rtyp -> Ok ((name, `Ixfr, cls), names, off + 4)
    | x when x = Rr_map.axfr_rtyp -> Ok ((name, `Axfr, cls), names, off + 4)
    | x when x = Rr_map.any_rtyp -> Ok ((name, `Any, cls), names, off + 4)
    | x ->
      let* k = Rr_map.of_int x in
      Ok ((name, `K k, cls), names, off + 4)

  module Question = struct
    type qtype = [ `Any | `K of Rr_map.k ]

    let pp_qtype = Rr_map.pp_rr

    let compare_qtype a b = match a, b with
      | `Any, `Any -> 0 | `Any, _ -> 1 | _, `Any -> -1
      | `K k, `K k' -> Rr_map.comparek k k'

    type t = [ `raw ] Domain_name.t * [ qtype | `Axfr | `Ixfr ]

    let qtype (_, t) = match t with
      | `K k -> Some (`K k)
      | `Any -> Some `Any
      | _ -> None

    let create : type a b. b Domain_name.t -> a Rr_map.key -> t =
      fun name k -> Domain_name.raw name, `K (K k)

    let pp ppf (name, typ) =
      Fmt.pf ppf "%a %a?" Domain_name.pp name Rr_map.pp_rr typ

    let compare (name, typ) (name', typ') =
      andThen (Domain_name.compare name name')
        (match typ with
         | #qtype as a ->
           (match typ' with
            | #qtype as b -> compare_qtype a b
            | _ -> 1)
         | (`Axfr | `Ixfr as x) ->
           match typ' with
           | #qtype -> -1
           | (`Axfr | `Ixfr as y) -> match x, y with
             | `Axfr, `Axfr -> 0 | `Axfr, _ -> 1 | _, `Axfr -> -1
             | `Ixfr, `Ixfr -> 0 (* | `Ixfr, _ -> 1 | _, `Ixfr -> -1 *))

    let decode ?(names = Name.Int_map.empty) ?(off = Header.len) buf =
      let* (name, typ, c), names, off = decode_ntc names buf off in
      let* clas = Class.of_int ~off c in
      match typ with
      | `Edns | `Tsig ->
        let msg = Fmt.str "bad RRTYp in question %a" Rr_map.pp_rr typ in
        Error (`Malformed (off, msg))
      | (`Axfr | `Ixfr | `Any | `K _ as t) ->
        if clas = Class.IN then
          Ok ((name, t), names, off)
        else
          Error (`Not_implemented (off, Fmt.str "bad class in question 0x%x" c))

    let encode names buf off (name, typ) =
      Rr_map.encode_ntc names buf off
        (name, (typ :> Rr_map.rrtyp), Class.to_int Class.IN)
  end

  let encode_data map names buf off =
    Domain_name.Map.fold (fun name rrmap acc ->
        Rr_map.fold (fun (Rr_map.B (k, v)) ((names, off), count) ->
            let r, amount = Rr_map.encode name k v names buf off in
            (r, amount + count))
          rrmap acc)
      map ((names, off), 0)

  let decode_rr names buf off =
    let* (name, typ, clas), names, off = decode_ntc names buf off in
    let* () =
      guard (clas = Class.(to_int IN))
        (`Not_implemented (off, Fmt.str "rr class not IN 0x%x" clas))
    in
    match typ with
    | `K k ->
      let* b, names, off = Rr_map.decode names buf off k in
      Ok (name, b, names, off)
    | _ ->
      Error (`Not_implemented (off, Fmt.str "unexpected RR typ %a"
                                 Rr_map.pp_rr typ))

  let rec decode_n_aux add f names buf off acc = function
    | 0 -> acc, Ok (names, off)
    | n -> match f names buf off with
      | Ok (name, b, names, off') ->
        let acc' = add name b acc in
        decode_n_aux add f names buf off' acc' (pred n)
      | Error e -> acc, Error e

  let decode_n add f names buf off acc c =
    let acc, r = decode_n_aux add f names buf off acc c in
    match r with
    | Ok (names, off) -> Ok (names, off, acc)
    | Error e -> Error e

  let decode_n_partial names buf off acc c =
    let add name (Rr_map.B (k, v)) map = Name_rr_map.add name k v map in
    let acc, r = decode_n_aux add decode_rr names buf off acc c in
    match r with
    | Ok (names, off) -> Ok (`Full (names, off, acc))
    | Error `Partial -> Ok (`Partial acc)
    | Error e -> Error e

  let decode_one_additional map edns ~tsig names buf off =
    let* (name, typ, clas), names, off' = decode_ntc names buf off in
    match typ with
    | `Edns when edns = None ->
      (* OPT is special and needs class! (also, name is guarded to be .) *)
      begin try
        let* edns, off' = Edns.decode_exn buf ~off in
        Ok ((map, Some edns, None), names, off')
      with Invalid_argument _ -> Error `Partial
      end
    | `Tsig when tsig ->
      let* () =
        guard (clas = Class.(to_int ANY_CLASS))
          (`Malformed (off, Fmt.str "tsig class must be ANY 0x%x" clas))
      in
      begin try
        let* tsig, names, off' = Tsig.decode_exn names buf ~off:off' in
        Ok ((map, edns, Some (name, tsig, off)), names, off')
      with Invalid_argument _ -> Error `Partial
      end
    | `K t ->
      let* () =
        guard (clas = Class.(to_int IN))
          (`Malformed (off, Fmt.str "additional class must be IN 0x%x" clas))
      in
      let* B (k, v), names, off' = Rr_map.decode names buf off' t in
      Ok ((Name_rr_map.add name k v map, edns, None), names, off')
    | _ -> Error (`Malformed (off, Fmt.str "decode additional, unexpected rr %a"
                                Rr_map.pp_rr typ))

  let rec decode_n_additional names buf off map edns tsig = function
    | 0 -> Ok (`Full (off, map, edns, tsig))
    | n -> match decode_one_additional map edns ~tsig:(n = 1) names buf off with
      | Error `Partial -> Ok (`Partial (map, edns, tsig))
      | Error e -> Error e
      | Ok ((map, edns, tsig), names, off') ->
        decode_n_additional names buf off' map edns tsig (pred n)

  module Answer = struct

    type t = Name_rr_map.t * Name_rr_map.t

    let empty = Name_rr_map.empty, Name_rr_map.empty

    let is_empty (a, b) =
      Domain_name.Map.is_empty a && Domain_name.Map.is_empty b

    let equal (answer, authority) (answer', authority') =
      Name_rr_map.equal answer answer' &&
      Name_rr_map.equal authority authority'

    let pp ppf (answer, authority) =
      Fmt.pf ppf "answer %a@ authority %a"
        Name_rr_map.pp answer Name_rr_map.pp authority

    let decode (_, flags) buf names off =
      let truncated = Flags.mem `Truncation flags in
      let ancount = String.get_uint16_be buf 6
      and aucount = String.get_uint16_be buf 8
      in
      let empty = Domain_name.Map.empty in
      let* r = decode_n_partial names buf off empty ancount in
      match r with
      | `Partial answer ->
        let* () = guard truncated `Partial in
        Ok ((answer, empty), names, off, false, truncated)
      | `Full (names, off, answer) ->
        let* r = decode_n_partial names buf off empty aucount in
        match r with
        | `Partial authority ->
          let* () = guard truncated `Partial in
          Ok ((answer, authority), names, off, false, truncated)
        | `Full (names, off, authority) ->
          Ok ((answer, authority), names, off, true, truncated)

    let encode_answer (qname, qtyp) map names buf off =
      Log.debug (fun m -> m "trying to encode the answer, following question %a %a"
                     Question.pp (qname, qtyp) Name_rr_map.pp map) ;
      (* A foo.com? foo.com CNAME bar.com ; bar.com A 127.0.0.1 *)
      let rec encode_one names off count name =
        match Domain_name.Map.find name map with
        | None -> (names, off), count
        | Some rrmap ->
          let (names, off), count, alias =
            Rr_map.fold (fun (Rr_map.B (k, v)) ((names, off), count, alias) ->
                let alias' = match k, v with
                  | Cname, (_, alias) -> Some (Domain_name.raw alias)
                  | _ -> alias
                in
                let r, amount = Rr_map.encode name k v names buf off in
                (r, amount + count, alias'))
              rrmap ((names, off), count, None)
          in
          match alias with
          | None -> (names, off), count
          | Some n -> encode_one names off count n
      in
      encode_one names off 0 qname

    let encode names buf off question (answer, authority) =
      let (names, off), ancount = encode_answer question answer names buf off in
      Bytes.set_uint16_be buf 6 ancount ;
      let (names, off), aucount = encode_data authority names buf off in
      Bytes.set_uint16_be buf 8 aucount ;
      names, off
  end

  module Axfr = struct

    type t = Soa.t * Name_rr_map.t

    let equal (soa, entries) (soa', entries') =
      Soa.compare soa soa' = 0 && Name_rr_map.equal entries entries'

    let pp ppf (soa, entries) =
      Fmt.pf ppf "AXFR soa %a data %a" Soa.pp soa Name_rr_map.pp entries

    let decode (_, flags) buf names off ancount =
      let* () = guard (not (Flags.mem `Truncation flags)) `Partial in
      let empty = Domain_name.Map.empty in
      (* TODO handle partial AXFR better:
         - only first frame must have the question, subsequent frames may have
           no questions (to be adjusted in Packet.decode)
      *)
      (* an AXFR frame can be shaped in several forms:
         (a) SOA .. RRSets (no SOA) .. SOA -> full Axfr_reply
         (b) SOA .. RRSets (no SOA) -> `Axfr_partial_reply (`First soa, _)
         (c) RRSets (no SOA) -> `Axfr_partial_reply (`Mid, _)
         (d) RRSets (no SOA) .. SOA -> `Axfr_partial_reply (`Last soa, _)
         please note that a single SOA may either be the first or the last
         packet, this cannot be decided without further context (it is
         characterized to be `First in here, but user code needs to handle this)
      *)
      let* () =
        guard (ancount >= 1)
          (`Malformed (6, Fmt.str "AXFR needs at least one RRs in answer %d" ancount))
      in
      let* name, B (k, v), names, off = decode_rr names buf off in
      if ancount = 1 then
        match k, v with
        | Soa, soa -> Ok (`Axfr_partial_reply (`First (soa : Soa.t), Name_rr_map.empty), names, off)
        | k, v -> Ok (`Axfr_partial_reply (`Mid, Name_rr_map.singleton name k v), names, off)
      else (* ancount > 1 *)
        (* TODO: verify name == zname in question, also all RR sub of zname *)
        let add name (Rr_map.B (k, v)) map = Name_rr_map.add name k v map in
        let* names, off, answer = decode_n add decode_rr names buf off empty (ancount - 2) in
        let* name', B (k', v'), names, off = decode_rr names buf off in
        (* TODO: verify that answer does not contain a SOA!? *)
        match k, v, k', v' with
        | Soa, soa, Soa, soa' ->
          let* () =
            guard (Domain_name.equal name name')
              (`Malformed (off, "AXFR SOA RRs do not use the same name"))
          in
          let* () =
            guard (Soa.compare soa soa' = 0)
              (`Malformed (off, "AXFR SOA RRs are not equal"))
          in
          Ok ((`Axfr_reply ((soa, answer) : Soa.t * Name_rr_map.t)), names, off)
        | Soa, soa, k', v' ->
          Ok (`Axfr_partial_reply (`First (soa : Soa.t), add name' (B (k', v')) answer), names, off)
        | k, v, Soa, soa ->
          Ok (`Axfr_partial_reply (`Last (soa : Soa.t), add name (B (k, v)) answer), names, off)
        | k, v, k', v' ->
          Ok (`Axfr_partial_reply (`Mid, add name' (B (k', v')) (add name (B (k, v)) answer)), names, off)

    let encode names buf off question (soa, entries) =
      (* serialise: SOA .. other data .. SOA *)
      let (names, off), _ = Rr_map.encode (fst question) Soa soa names buf off in
      let (names, off), count = encode_data entries names buf off in
      let (names, off), _ = Rr_map.encode (fst question) Soa soa names buf off in
      Bytes.set_uint16_be buf 6 (count + 2) ;
      names, off

    let encode_partial names buf off question pos entries =
      let (names, off), count = match pos with
        | `First soa -> Rr_map.encode (fst question) Soa soa names buf off
        | _ -> (names, off), 0
      in
      let (names, off), count' = encode_data entries names buf off in
      let (names, off), count'' = match pos with
        | `Last soa -> Rr_map.encode (fst question) Soa soa names buf off
        | _ -> (names, off), 0
      in
      Bytes.set_uint16_be buf 6 (count + count' + count'') ;
      names, off

    let encode_reply next_buffer max_size question (soa, entries) =
      (* first packet MUST contain SOA *)
      let finish buf count off =
        Bytes.set_uint16_be buf 6 count;
        String.sub (Bytes.unsafe_to_string buf) 0 off
      in
      let names, buf, off = next_buffer () in
      let (names, off), count =
        Rr_map.encode (fst question) Soa soa names buf off
      in
      let rec encode_or_allocate acc count (names, buf, off) name k v =
        try
          let (names, off'), count' = Rr_map.encode name k v names buf off in
          if off' > max_size then
            invalid_arg "foo"
          else
            acc, count + count', (names, buf, off')
        with
        | Invalid_argument _ ->
          if count = 0 then
            match Rr_map.split k v with
            | _, None -> invalid_arg "unable to split resource record"
            | v, Some v' ->
              let acc, count, (_, buf, off) =
                encode_or_allocate acc 0 (names, buf, off) name k v
              in
              let buf' = finish buf count off in
              encode_or_allocate (buf' :: acc) 0 (next_buffer ()) name k v'
          else
            let buf' = finish buf count off in
            encode_or_allocate (buf' :: acc) 0 (next_buffer ()) name k v
      in
      let r, count, (names, buf, off) =
        Domain_name.Map.fold (fun name rrmap acc ->
            Rr_map.fold (fun (Rr_map.B (k, v)) (bufs, count, r) ->
                encode_or_allocate bufs count r name k v)
              rrmap acc)
          entries ([], count, (names, buf, off))
      in
      let r, count, (_names, buf, off) =
        encode_or_allocate r count (names, buf, off) (fst question) Soa soa
      in
      let buf' = finish buf count off in
      List.rev (buf' :: r)
  end

  module Ixfr = struct
    (* accoring to RFC 1995 there can be three formats, but in the errata
       there's a hint it's actually four:
       - full zone, as in AXFR (SOA .. RRs .. SOA)
       - difference lists (SOA DIFFS SOA) where DIFFS is of the form:
          OLD_SOA DEL_RRs NEW_SOA ADD_RRs
       - condensed lists (SOA OLD_SOA DEL_RRs NEW_SOA ADD_RRs SOA)
       - empty: a single SOA (request contained a SOA >= server's SOA)

       we support all four of them, but represent the second using the third
       (throwing away during parsing, no need to retain that information) *)
    type t = Soa.t *
             [ `Empty
             | `Full of Name_rr_map.t
             | `Difference of Soa.t * Name_rr_map.t * Name_rr_map.t ]

    let equal (soa, data) (soa', data') =
      Soa.compare soa soa' = 0 && match data, data' with
      | `Empty, `Empty -> true
      | `Full rrs, `Full rrs' -> Name_rr_map.equal rrs rrs'
      | `Difference (oldsoa, del, add), `Difference (oldsoa', del', add') ->
        Soa.compare oldsoa oldsoa' = 0 && Name_rr_map.equal del del' && Name_rr_map.equal add add'
      | _ -> false

    let pp ppf (soa, data) =
      match data with
      | `Empty -> Fmt.pf ppf "IXFR %a empty" Soa.pp soa
      | `Full data ->
        Fmt.pf ppf "IXFR %a full@ %a" Soa.pp soa Name_rr_map.pp data
      | `Difference (oldsoa, del, add) ->
        Fmt.pf ppf "IXFR %a difference oldsoa %a@ delete %a@ add %a"
          Soa.pp soa Soa.pp oldsoa Name_rr_map.pp del Name_rr_map.pp add

    let ensure_soa : Rr_map.b -> (Soa.t, unit) result = fun (Rr_map.B (k, v)) ->
      match k, v with
      | Soa, soa -> Ok soa
      | _ -> Error ()

    let soa_ok f off name soa name' soa' =
      let* () =
        guard (Domain_name.equal name name')
          (`Malformed (off, "IXFR SOA RRs do not use the same name"))
      in
      guard (f soa soa') (`Malformed (off, "IXFR SOA RRs are not equal"))

    (* parses up to count RRs until a SOA is found *)
    let rec rrs_and_soa buf names off count acc =
      match count with
      | 0 -> Ok (acc, None, 0, names, off)
      | n ->
        let* name, Rr_map.B (k, v), names, off = decode_rr names buf off in
        match k, v with
        | Rr_map.Soa, soa ->
          Ok (acc, (Some (name, soa) : ([ `raw ] Domain_name.t * Soa.t) option), pred n, names, off)
        | _ ->
          let acc = Name_rr_map.add name k v acc in
          rrs_and_soa buf names off (pred n) acc

    let decode (_, flags) buf names off ancount =
      let* () = guard (not (Flags.mem `Truncation flags)) `Partial in
      let* () =
        guard (ancount >= 1)
          (`Malformed (6, Fmt.str "IXFR needs at least one RRs in answer %d" ancount))
      in
      let* name, b, names, off = decode_rr names buf off in
      match ensure_soa b with
      | Error () -> Error (`Malformed (off, "IXFR first RR not a SOA"))
      | Ok soa ->
        let* content, names, off =
          if ancount = 1 then
            Ok (`Empty, names, off)
          else if ancount = 2 then
            Ok (`Full Name_rr_map.empty, names, off)
          else
            let* name', b, names, off = decode_rr names buf off in
            match ensure_soa b with
            | Error () ->
              (* this is a full AXFR *)
              let add name (Rr_map.B (k, v)) map = Name_rr_map.add name k v map in
              let map = add name' b Name_rr_map.empty in
              let* names, off, answer = decode_n add decode_rr names buf off map (ancount - 3) in
              Ok (`Full answer, names, off)
            | Ok oldsoa ->
              let rec diff_list dele add names off count oldname oldsoa =
                (* actual form is: curr_SOA [SOA0 .. DELE .. SOA1 .. ADD] curr_SOA'
                   - we need to ensure: curr_SOA = curr_SOA' (below)
                   - SOA0 < curr_SOA
                   - SOA1 < SOA0 *)
                let* () = soa_ok (fun old soa -> Soa.newer ~old soa) off oldname oldsoa name soa in
                let* dele', soa', count', names, off = rrs_and_soa buf names off count dele in
                match soa' with
                | None -> (* this is the end *)
                  let* () = guard (count' = 0) (`Malformed (off, "IXFR expected SOA, found end")) in
                  Ok (dele', add, names, off)
                | Some (name', soa') ->
                  let* () = soa_ok (fun old soa -> Soa.newer ~old soa) off oldname oldsoa name' soa' in
                  let* add', soa'', count'', names, off = rrs_and_soa buf names off count' add in
                  match soa'' with
                  | None -> (* this is the actual end! *)
                    let* () = guard (count'' = 0) (`Malformed (off, "IXFR expected SOA after adds, found end")) in
                    Ok (dele', add', names, off)
                  | Some (name'', soa'') ->
                    diff_list dele' add' names off count'' name'' soa''
              in
              let* dele, add, names, off = diff_list Name_rr_map.empty Name_rr_map.empty names off (ancount - 3) name' oldsoa in
              Ok (`Difference (oldsoa, dele, add), names, off)
        in
        if ancount > 1 then
          let* name', b, names, off = decode_rr names buf off in
          match ensure_soa b with
          | Ok soa' ->
            let* () = soa_ok (fun s s' -> Soa.compare s s' = 0) off name soa name' soa' in
            Ok ((soa, content), names, off)
          | Error () ->
            Error (`Malformed (off, "IXFR last RR not a SOA"))
        else
          Ok ((soa, content), names, off)

    let encode names buf off question (soa, data) =
      let (names, off), _ = Rr_map.encode (fst question) Soa soa names buf off in
      let ((names, off), count), second = match data with
        | `Empty -> ((names, off), 0), false
        | `Full data -> encode_data data names buf off, true
        | `Difference (oldsoa, del, add) ->
          let (names, off), _ = Rr_map.encode (fst question) Soa oldsoa names buf off in
          let (names, off), count = encode_data del names buf off in
          let (names, off), _ = Rr_map.encode (fst question) Soa soa names buf off in
          let (names, off), count' = encode_data add names buf off in
          ((names, off), count + count' + 2), true
      in
      let (names, off), count' =
        if second then
          Rr_map.encode (fst question) Soa soa names buf off
        else
          (names, off), 0
      in
      Bytes.set_uint16_be buf 6 (count + count' + 1) ;
      names, off
  end

  module Update = struct

    type prereq =
      | Exists of Rr_map.k
      | Exists_data of Rr_map.b
      | Not_exists of Rr_map.k
      | Name_inuse
      | Not_name_inuse

    let equal_prereq a b = match a, b with
      | Exists t, Exists t' -> Rr_map.comparek t t' = 0
      | Exists_data b, Exists_data b' -> Rr_map.equalb b b'
      | Not_exists t, Not_exists t' -> Rr_map.comparek t t' = 0
      | Name_inuse, Name_inuse -> true
      | Not_name_inuse, Not_name_inuse -> true
      | _ -> false

    let pp_prereq ppf = function
      | Exists typ -> Fmt.pf ppf "exists? %a" Rr_map.ppk typ
      | Exists_data rd -> Fmt.pf ppf "exists data? %a" Rr_map.pp_b rd
      | Not_exists typ -> Fmt.pf ppf "doesn't exists? %a" Rr_map.ppk typ
      | Name_inuse -> Fmt.string ppf "name inuse?"
      | Not_name_inuse -> Fmt.string ppf "name not inuse?"

    let decode_prereq names buf off =
      let* (name, typ, cls), names, off = decode_ntc names buf off in
      let off' = off + 6 in
      let* () = guard (String.length buf >= off') `Partial in
      let ttl = String.get_int32_be buf off in
      let* () = guard (ttl = 0l) (`Malformed (off, Fmt.str "prereq TTL not zero %lu" ttl)) in
      let rlen = String.get_uint16_be buf (off + 4) in
      let r0 = guard (rlen = 0) (`Malformed (off + 4, Fmt.str "prereq rdlength must be zero %d" rlen)) in
      let* c = Class.of_int cls in
      match c, typ with
      | ANY_CLASS, `Any ->
        let* () = r0 in
        Ok (name, Name_inuse, names, off')
      | NONE, `Any ->
        let* () = r0 in
        Ok (name, Not_name_inuse, names, off')
      | ANY_CLASS, `K k ->
        let* () = r0 in
        Ok (name, Exists k, names, off')
      | NONE, `K k ->
        let* () = r0 in
        Ok (name, Not_exists k, names, off')
      | IN, `K k->
        let* rdata, names, off'' = Rr_map.decode names buf off k in
        Ok (name, Exists_data rdata, names, off'')
      | _ -> Error (`Malformed (off, Fmt.str "prereq bad class 0x%x or typ %a"
                                  cls Rr_map.pp_rr typ))

    let encode_prereq names buf off count name = function
      | Exists typ ->
        let names, off =
          Rr_map.encode_ntc names buf off (name, `K typ, Class.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Exists_data (B (k, v)) ->
        let ret, count' = Rr_map.encode name k v names buf off in
        ret, count' + count
      | Not_exists typ ->
        let names, off =
          Rr_map.encode_ntc names buf off (name, `K typ, Class.(to_int NONE))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Name_inuse ->
        let names, off =
          Rr_map.encode_ntc names buf off (name, `Any, Class.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Not_name_inuse ->
        let names, off =
          Rr_map.encode_ntc names buf off (name, `Any, Class.(to_int NONE))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count

    type update =
      | Remove of Rr_map.k
      | Remove_all
      | Remove_single of Rr_map.b
      | Add of Rr_map.b

    let equal_update a b = match a, b with
      | Remove t, Remove t' -> Rr_map.comparek t t' = 0
      | Remove_all, Remove_all -> true
      | Remove_single b, Remove_single b' -> Rr_map.equalb b b'
      | Add b, Add b' -> Rr_map.equalb b b'
      | _ -> false

    let pp_update ppf = function
      | Remove typ -> Fmt.pf ppf "remove! %a" Rr_map.ppk typ
      | Remove_all -> Fmt.string ppf "remove all!"
      | Remove_single rd -> Fmt.pf ppf "remove single! %a" Rr_map.pp_b rd
      | Add rr -> Fmt.pf ppf "add! %a" Rr_map.pp_b rr

    let decode_update names buf off =
      let* (name, typ, cls), names, off = decode_ntc names buf off in
      let off' = off + 6 in
      let* () = guard (String.length buf >= off') `Partial in
      let ttl = String.get_int32_be buf off in
      let rlen = String.get_uint16_be buf (off + 4) in
      let r0 = guard (rlen = 0) (`Malformed (off + 4, Fmt.str "update rdlength must be zero %d" rlen)) in
      let ttl0 = guard (ttl = 0l) (`Malformed (off, Fmt.str "update ttl must be zero %lu" ttl)) in
      let* c = Class.of_int cls in
      match c, typ with
      | ANY_CLASS, `Any ->
        let* () = ttl0 in
        let* () = r0 in
        Ok (name, Remove_all, names, off')
      | ANY_CLASS, `K k ->
        let* () = ttl0 in
        let* () = r0 in
        Ok (name, Remove k, names, off')
      | NONE, `K k ->
        let* () = ttl0 in
        let* rdata, names, off = Rr_map.decode names buf off k in
        Ok (name, Remove_single rdata, names, off)
      | IN, `K k ->
        let* rdata, names, off = Rr_map.decode names buf off k in
        Ok (name, Add rdata, names, off)
      | _ -> Error (`Malformed (off, Fmt.str "bad update class 0x%x" cls))

    let encode_update names buf off count name = function
      | Remove typ ->
        let names, off =
          Rr_map.encode_ntc names buf off (name, `K typ, Class.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Remove_all ->
        let names, off =
          Rr_map.encode_ntc names buf off (name, `Any, Class.(to_int ANY_CLASS))
        in
        (* ttl + rdlen, both 0 *)
        (names, off + 6), succ count
      | Remove_single (B (k, v)) ->
        let ret, count' = Rr_map.encode ~clas:NONE name k v names buf off in
        ret, count + count'
      | Add (B (k, v)) ->
        let ret, count' = Rr_map.encode name k v names buf off in
        ret, count + count'

    type t = prereq list Domain_name.Map.t * update list Domain_name.Map.t

    let empty = Domain_name.Map.empty, Domain_name.Map.empty

    let equal (prereq, update) (prereq', update') =
      let eq_list f a b =
        List.length a = List.length b &&
        List.fold_left2 (fun acc a b -> acc && f a b) true a b
      in
      Domain_name.Map.equal (eq_list equal_prereq) prereq prereq' &&
      Domain_name.Map.equal (eq_list equal_update) update update'

    let pp ppf (prereq, update) =
      Fmt.pf ppf "%a@ %a"
        Fmt.(list ~sep:(any ";@ ")
               (pair ~sep:(any ":") Domain_name.pp
                  (list ~sep:(any ", ") pp_prereq)))
        (Domain_name.Map.bindings prereq)
        Fmt.(list ~sep:(any ";@ ")
               (pair ~sep:(any ":") Domain_name.pp
                  (list ~sep:(any ", ") pp_update)))
        (Domain_name.Map.bindings update)

    let decode _header question buf names off =
      let prcount = String.get_uint16_be buf 6
      and upcount = String.get_uint16_be buf 8
      in
      let add_to_list name a map =
        let base = match Domain_name.Map.find name map with None -> [] | Some x -> x in
        Domain_name.Map.add name (base @ [a]) map
      in
      let* () =
        guard (snd question = `K Rr_map.(K Soa))
          (`Malformed (off, Fmt.str "update question not SOA %a" Rr_map.pp_rr (snd question)))
      in
      let* names, off, prereq =
        decode_n add_to_list decode_prereq names buf off Domain_name.Map.empty prcount
      in
      let* names, off, update =
        decode_n add_to_list decode_update names buf off Domain_name.Map.empty upcount
      in
      Ok ((prereq, update), names, off)

    let encode_map map f names buf off =
      Domain_name.Map.fold (fun name v ((names, off), count) ->
          List.fold_left (fun ((names, off), count) p ->
              f names buf off count name p) ((names, off), count) v)
        map ((names, off), 0)

    let encode names buf off _question (prereq, update) =
      let (names, off), prereq_count = encode_map prereq encode_prereq names buf off in
      Bytes.set_uint16_be buf 6 prereq_count ;
      let (names, off), update_count = encode_map update encode_update names buf off in
      Bytes.set_uint16_be buf 8 update_count ;
      names, off
  end

  type request = [
    | `Query
    | `Notify of Soa.t option
    | `Axfr_request
    | `Ixfr_request of Soa.t
    | `Update of Update.t
  ]

  let equal_request a b = match a, b with
    | `Query, `Query -> true
    | `Notify soa, `Notify soa' -> opt_eq (fun a b -> Soa.compare a b = 0) soa soa'
    | `Axfr_request, `Axfr_request -> true
    | `Ixfr_request soa, `Ixfr_request soa' -> Soa.compare soa soa' = 0
    | `Update u, `Update u' -> Update.equal u u'
    | _ -> false

  let pp_request ppf = function
    | `Query -> Fmt.string ppf "query"
    | `Notify soa -> Fmt.pf ppf "notify %a" Fmt.(option ~none:(any "no") Soa.pp) soa
    | `Axfr_request -> Fmt.string ppf "axfr request"
    | `Ixfr_request soa -> Fmt.pf ppf "ixfr request %a" Soa.pp soa
    | `Update u -> Fmt.pf ppf "update %a" Update.pp u

  type reply = [
    | `Answer of Answer.t
    | `Notify_ack
    | `Axfr_reply of Axfr.t
    | `Axfr_partial_reply of [ `First of Soa.t | `Mid | `Last of Soa.t ] * Name_rr_map.t
    | `Ixfr_reply of Ixfr.t
    | `Update_ack
    | `Rcode_error of Rcode.t * Opcode.t * Answer.t option
  ]

  let equal_reply a b = match a, b with
    | `Answer q, `Answer q' -> Answer.equal q q'
    | `Notify_ack, `Notify_ack -> true
    | `Axfr_reply a, `Axfr_reply b -> Axfr.equal a b
    | `Axfr_partial_reply (x, a), `Axfr_partial_reply (y, b) ->
      (match x, y with
       | `First soa, `First soa' -> Soa.compare soa soa' = 0
       | `Mid, `Mid -> true
       | `Last soa, `Last soa' -> Soa.compare soa soa' = 0
       | _ -> false) &&
      Name_rr_map.equal a b
    | `Ixfr_reply a, `Ixfr_reply b -> Ixfr.equal a b
    | `Update_ack, `Update_ack -> true
    | `Rcode_error (rc, op, q), `Rcode_error (rc', op', q') ->
      Rcode.compare rc rc' = 0 && Opcode.compare op op' = 0 && opt_eq Answer.equal q q'
    | _ -> false

  let pp_reply ppf = function
    | `Answer a -> Answer.pp ppf a
    | `Axfr_reply a -> Axfr.pp ppf a
    | `Axfr_partial_reply (x, a) ->
      let pp_pos ppf = function
        | `First soa -> Fmt.pf ppf "first %a" Soa.pp soa
        | `Mid -> Fmt.string ppf "middle"
        | `Last soa -> Fmt.pf ppf "last %a" Soa.pp soa
      in
      Fmt.pf ppf "AXFR (partial %a) %a" pp_pos x Name_rr_map.pp a
    | `Ixfr_reply a -> Ixfr.pp ppf a
    | `Notify_ack -> Fmt.string ppf "notify ack"
    | `Update_ack -> Fmt.string ppf "update ack"
    | `Rcode_error (rc, op, q) ->
      Fmt.pf ppf "rcode %a op %a q %a" Rcode.pp rc Opcode.pp op
        Fmt.(option ~none:(any "no data") Answer.pp) q

  type data = [ request | reply ]

  let opcode_data = function
    | `Query | `Answer _
    | `Axfr_request | `Axfr_reply _ | `Axfr_partial_reply _
    | `Ixfr_request _ | `Ixfr_reply _ -> Opcode.Query
    | `Notify _ | `Notify_ack -> Notify
    | `Update _ | `Update_ack -> Update
    | `Rcode_error (_, op, _) -> op

  let rcode_data = function
    | `Rcode_error (rc, _, _) -> rc
    | _ -> Rcode.NoError

  let with_rcode data rcode = match rcode, data with
    | Rcode.NoError, `Rcode_error (rc, _, _) -> Error (`Rcode_error_cant_noerror rc)
    | Rcode.NoError, x -> Ok x
    | _, `Rcode_error (_, op, data) -> Ok (`Rcode_error (rcode, op, data))
    | _ -> Error (`Rcode_cant_change rcode)

  let equal_data a b =
    match a with
    | #reply as replya ->
      begin match b with
        | #reply as replyb -> equal_reply replya replyb
        | #request -> false
      end
    | #request as reqa ->
      match b with
      | #request as reqb -> equal_request reqa reqb
      | #reply -> false

  let pp_data ppf = function
    | #request as r -> pp_request ppf r
    | #reply as r -> pp_reply ppf r

  type t = {
    header : Header.t ;
    question : Question.t ;
    data : data ;
    additional : Name_rr_map.t ;
    edns : Edns.t option ;
    tsig : ([ `raw ] Domain_name.t * Tsig.t * int) option ;
  }

  let pp_tsig ppf (name, tsig, off) =
    Fmt.pf ppf "tsig %a %a %d" Domain_name.pp name Tsig.pp tsig off
  let eq_tsig (name, tsig, off) (name', tsig', off') =
    Domain_name.equal name name' && Tsig.equal tsig tsig' && off = off'

  let create ?max_size:_ ?(additional = Name_rr_map.empty) ?edns ?tsig header question data =
    (* TODO!? max size edns reply stuff!? *)
    { header ; question ; data ; additional ; edns ; tsig }

  let with_edns t edns = { t with edns }

  let pp_header ppf t =
    let opcode = opcode_data t.data
    and query = match t.data with #request -> true | #reply -> false
    and rcode = rcode_data t.data
    in
    Header.pp ppf (t.header, query, opcode, rcode)

  let pp ppf t =
    Fmt.pf ppf "header %a@ question %a@ data %a@ additional %a@ EDNS %a TSIG %a"
      pp_header t
      Question.pp t.question
      pp_data t.data
      Name_rr_map.pp t.additional
      Fmt.(option ~none:(any "no") Edns.pp) t.edns
      Fmt.(option ~none:(any "no") pp_tsig) t.tsig

  let equal a b =
    Header.compare a.header b.header = 0 &&
    Question.compare a.question b.question = 0 &&
    Name_rr_map.equal a.additional b.additional &&
    opt_eq (fun a b -> Edns.compare a b = 0) a.edns b.edns &&
    opt_eq eq_tsig a.tsig b.tsig &&
    equal_data a.data b.data

  type err = [
    | `Bad_edns_version of int
    | `Leftover of int * string
    | `Malformed of int * string
    | `Not_implemented of int * string
    | `Notify_ack_answer_count of int
    | `Notify_ack_authority_count of int
    | `Notify_answer_count of int
    | `Notify_authority_count of int
    | `Partial
    | `Query_answer_count of int
    | `Query_authority_count of int
    | `Rcode_cant_change of Rcode.t
    | `Rcode_error_cant_noerror of Rcode.t
    | `Request_rcode of Rcode.t
    | `Truncated_request
    | `Update_ack_answer_count of int
    | `Update_ack_authority_count of int
  ]

  let pp_err ppf = function
    | `Bad_edns_version version -> Fmt.pf ppf "bad edns version %d" version
    | `Leftover (off, n) -> Fmt.pf ppf "leftover %s at %d" n off
    | `Malformed (off, n) -> Fmt.pf ppf "malformed at %d: %s" off n
    | `Not_implemented (off, msg) -> Fmt.pf ppf "not implemented at %d: %s" off msg
    | `Notify_ack_answer_count an -> Fmt.pf ppf "notify ack answer count is %d" an
    | `Notify_ack_authority_count au -> Fmt.pf ppf "notify ack authority count is %d" au
    | `Notify_answer_count an -> Fmt.pf ppf "notify answer count is %d" an
    | `Notify_authority_count au -> Fmt.pf ppf "notify authority count is %d" au
    | `Partial -> Fmt.string ppf "partial"
    | `Query_answer_count an -> Fmt.pf ppf "query answer count is %d" an
    | `Query_authority_count au -> Fmt.pf ppf "query authority count is %d" au
    | `Rcode_cant_change rc -> Fmt.pf ppf "edns tried to change rcode from noerror to %a" Rcode.pp rc
    | `Rcode_error_cant_noerror rc -> Fmt.pf ppf "edns tried to change rcode from %a to noerror" Rcode.pp rc
    | `Request_rcode rc -> Fmt.pf ppf "query with rcode %a (must be noerr)" Rcode.pp rc
    | `Truncated_request -> Fmt.string ppf "truncated request"
    | `Update_ack_answer_count an -> Fmt.pf ppf "update ack answer count is %d" an
    | `Update_ack_authority_count au -> Fmt.pf ppf "update ack authority count is %d" au

  let decode_additional names buf off allow_trunc adcount =
    let* r = decode_n_additional names buf off Domain_name.Map.empty None None adcount in
    match r with
    | `Partial (additional, edns, tsig) ->
      Log.warn (fun m -> m "truncated packet (allowed? %B)" allow_trunc) ;
      let* () = guard allow_trunc `Partial in
      Ok (additional, edns, tsig)
    | `Full (off, additional, edns, tsig) ->
      (if String.length buf > off then
         let n = String.length buf - off in
         Log.warn (fun m -> m "received %d extra bytes %a"
                      n Ohex.pp (String.sub buf off n))) ;
      Ok (additional, edns, tsig)

  let ext_rcode ?off rcode = function
    | Some e when e.Edns.extended_rcode > 0 ->
      begin
        let rcode' =
          Rcode.to_int rcode + e.extended_rcode lsl 4
        in
        Rcode.of_int ?off rcode'
      end
    | _ -> Ok rcode

  let decode buf =
    let* header, query, operation, rcode = Header.decode buf in
    let q_count = String.get_uint16_be buf 4
    and an_count = String.get_uint16_be buf 6
    and au_count = String.get_uint16_be buf 8
    and ad_count = String.get_uint16_be buf 10
    in
    let* () = guard (q_count = 1) (`Malformed (4, "question count not one")) in
    let* question, names, off = Question.decode buf in
    let* data, names, off, cont, allow_trunc =
      if query then begin
        (* guard noerror - what's the point in handling error requests *)
        let* () = guard (rcode = Rcode.NoError) (`Request_rcode rcode) in
        (* also guard for it not being truncated!? *)
        let* () = guard (not (Flags.mem `Truncation (snd header))) `Truncated_request in
        let* request, names, off =
          match operation with
          | Opcode.Query ->
            let* () = guard (an_count = 0) (`Query_answer_count an_count) in
            begin match snd question with
              | `Axfr ->
                let* () = guard (au_count = 0) (`Query_authority_count au_count) in
                Ok (`Axfr_request, names, off)
              | `Ixfr ->
                let* () = guard (au_count = 1) (`Query_authority_count au_count) in
                let* (_, au), names, off, _, _ = Answer.decode header buf names off in
                begin match Name_rr_map.find (fst question) Rr_map.Soa au with
                  | None -> Error (`Malformed (off, "ixfr request without soa"))
                  | Some soa -> Ok (`Ixfr_request soa, names, off)
                end
              | _ ->
                let* () = guard (au_count = 0) (`Query_authority_count au_count) in
                Ok (`Query, names, off)
            end
          | Opcode.Notify ->
            let* () = guard (an_count = 0 || an_count = 1) (`Notify_answer_count an_count) in
            let* () = guard (au_count = 0) (`Notify_authority_count au_count) in
            let* (ans, _), names, off, _, _ = Answer.decode header buf names off in
            let soa = Name_rr_map.find (fst question) Rr_map.Soa ans in
            Ok (`Notify soa, names, off)
          | Opcode.Update ->
            let* update, names, off = Update.decode header question buf names off in
            Ok (`Update update, names, off)
          | x -> Error (`Not_implemented (2, Fmt.str "unsupported opcode %a" Opcode.pp x))
        in
        Ok (request, names, off, true, false)
      end else
        match rcode with
        | Rcode.NoError -> begin match operation with
            | Opcode.Query -> begin match snd question with
                | `Axfr ->
                  let* () = guard (au_count = 0) (`Malformed (8, Fmt.str "AXFR with aucount %d > 0" au_count)) in
                  let* axfr, names, off = Axfr.decode header buf names off an_count in
                  Ok (axfr, names, off, true, false)
                | `Ixfr ->
                  let* () = guard (au_count = 0) (`Malformed (8, Fmt.str "IXFR with aucount %d > 0" au_count)) in
                  let* ixfr, names, off = Ixfr.decode header buf names off an_count in
                  Ok (`Ixfr_reply ixfr, names, off, true, false)
                | _ ->
                  let* answer, names, off, cont, allow_trunc = Answer.decode header buf names off in
                  Ok (`Answer answer, names, off, cont, allow_trunc)
              end
            | Opcode.Notify ->
              let* () = guard (an_count = 0) (`Notify_ack_answer_count an_count) in
              let* () = guard (au_count = 0) (`Notify_ack_authority_count au_count) in
              Ok (`Notify_ack, names, off, true, false)
            | Opcode.Update ->
              let* () = guard (an_count = 0) (`Update_ack_answer_count an_count) in
              let* () = guard (au_count = 0) (`Update_ack_authority_count au_count) in
              Ok (`Update_ack, names, off, true, false)
            | x -> Error (`Not_implemented (2, Fmt.str "unsupported opcode %a"
                                              Opcode.pp x))
          end
        | x ->
          let* query, names, off, cont, allow_trunc = Answer.decode header buf names off in
          let query = if Answer.is_empty query then None else Some query in
          Ok (`Rcode_error (x, operation, query), names, off, cont, allow_trunc)
    in
    let* additional, edns, tsig =
      if cont then
        decode_additional names buf off allow_trunc ad_count
      else
        Ok (Name_rr_map.empty, None, None)
    in
    (* now in case of error, we may switch the rcode *)
    let* data =
      let* d = ext_rcode ~off:off rcode edns in
      with_rcode data d
    in
    Ok { header ; question ; data ; additional ; edns ; tsig }

  let opcode_match request reply =
    let opa = opcode_data request
    and opb = opcode_data reply
    in
    Opcode.compare opa opb = 0

  type mismatch = [ `Not_a_reply of request
                  | `Id_mismatch of int * int
                  | `Operation_mismatch of request * reply
                  | `Question_mismatch of Question.t * Question.t
                  | `Expected_request ]

  let pp_mismatch ppf = function
    | `Not_a_reply req ->
      Fmt.pf ppf "expected a reply, got a request %a" pp_request req
    | `Id_mismatch (id, id') ->
      Fmt.pf ppf "id mismatch, expected %04X got %04X" id id'
    | `Operation_mismatch (req, reply) ->
      Fmt.pf ppf "operation mismatch, request %a reply %a" pp_request req pp_reply reply
    | `Question_mismatch (q, q') ->
      Fmt.pf ppf "question mismatch, expected %a got %a" Question.pp q Question.pp  q'
    | `Expected_request -> Fmt.string ppf "expected request"

  let reply_matches_request ~request reply =
    match request.data with
    | #reply -> Error `Expected_request
    | #request as req -> match reply.data with
      | #request as r -> Error (`Not_a_reply r)
      | #reply as data ->
        match
          Header.compare_id request.header reply.header = 0,
          opcode_match req data,
          Question.compare request.question reply.question = 0
        with
      | true, true, true ->
        (* TODO: make this strict? configurable? *)
        if not (Domain_name.equal ~case_sensitive:true (fst request.question) (fst reply.question)) then
          Log.warn (fun m -> m "question is not case sensitive equal %a = %a"
                       Domain_name.pp (fst request.question) Domain_name.pp (fst reply.question));
        Ok data
      | false, _ ,_ -> Error (`Id_mismatch (fst request.header, fst reply.header))
      | _, false, _ -> Error (`Operation_mismatch (req, data))
      | _, _, false -> Error (`Question_mismatch (request.question, reply.question))

  let max_udp = 1484 (* in MirageOS. using IPv4 this is max UDP payload via ethernet *)
  let max_reply_udp = 400 (* we don't want anyone to amplify! *)
  let max_tcp = 1 lsl 16 - 1 (* DNS-over-TCP is 2 bytes len ++ payload *)

  let size_edns max_size edns protocol query =
    let maximum, payload_size = match protocol, max_size, query with
      | `Tcp, _, _ -> max_tcp, None
      | `Udp, None, true -> max_udp, Some 4096
      | `Udp, None, false -> max_reply_udp, Some 512
      | `Udp, Some x, true -> x, Some x
      | `Udp, Some x, false -> min x max_reply_udp, Some 512
    in
    let edns = match edns, payload_size with
      | None, _ | _, None -> edns
      | Some opts, Some s -> Some ({ opts with Edns.payload_size = s })
    in
    maximum, edns

  let encode_t names buf off question = function
    | `Query | `Axfr_request
    | `Notify_ack | `Update_ack
    | `Rcode_error (_, _, None) -> names, off
    | `Notify soa ->
      begin match soa with
        | None -> names, off
        | Some soa ->
          let soa = Name_rr_map.singleton (fst question) Soa soa in
          Answer.encode names buf off question (soa, Name_rr_map.empty)
      end
    | `Ixfr_request soa ->
      let soa = Name_rr_map.singleton (fst question) Soa soa in
      Answer.encode names buf off question (Name_rr_map.empty, soa)
    | `Update u -> Update.encode names buf off question u
    | `Answer q -> Answer.encode names buf off question q
    | `Axfr_reply data -> Axfr.encode names buf off question data
    | `Axfr_partial_reply (x, data) -> Axfr.encode_partial names buf off question x data
    | `Ixfr_reply data -> Ixfr.encode names buf off question data
    | `Rcode_error (_, _, Some q) -> Answer.encode names buf off question q

  let encode_edns rcode edns buf off = match edns with
    | None -> off
    | Some edns ->
      let extended_rcode = (Rcode.to_int rcode) lsr 4 in
      let adcount = Bytes.get_uint16_be buf 10 in
      let off = Edns.encode { edns with Edns.extended_rcode } buf off in
      Bytes.set_uint16_be buf 10 (adcount + 1) ;
      off

  let encode ?max_size protocol t =
    let query = match t.data with #request -> true | #reply -> false in
    let max, edns = size_edns max_size t.edns protocol query in
    let try_encoding buf =
      let off, trunc =
        try
          let opcode = opcode_data t.data
          and rcode = rcode_data t.data
          in
          Header.encode buf (t.header, query, opcode, rcode);
          let names, off = Question.encode Domain_name.Map.empty buf Header.len t.question in
          Bytes.set_uint16_be buf 4 1 ;
          let names, off = encode_t names buf off t.question t.data in
          (* TODO we used to drop all other additionals if rcode <> 0 *)
          let (_names, off), adcount = encode_data t.additional names buf off in
          Bytes.set_uint16_be buf 10 adcount ;
          (* TODO if edns embedding would truncate, we used to drop all other additionals and only encode EDNS *)
          (* TODO if additional would truncate, drop them (do not set truncation) *)
          encode_edns Rcode.NoError edns buf off, false
        with Invalid_argument _ -> (* set truncated *)
          (* if we failed to store data into buf, set truncation bit! *)
          Bytes.set_uint8 buf 2 (0x02 lor (Bytes.get_uint8 buf 2)) ;
          Bytes.length buf, true
      in
      String.sub (Bytes.unsafe_to_string buf) 0 off, trunc
    in
    let rec doit s =
      let cs = Bytes.make s '\000' in
      match try_encoding cs with
      | (cs, false) -> (cs, max)
      | (cs, true) ->
        let next = min max (s * 2) in
        if next = s then
          (cs, max)
        else
          doit next
    in
    doit (min max 4000) (* (mainly for TCP) we use a page as initial allocation *)

  let encode_axfr_reply ?max_size needed_for_tsig protocol t data =
    let query = false in
    let max, _edns = size_edns max_size t.edns protocol query in
    let max_size = max - needed_for_tsig in
    assert (max_size > 0);
    (* strategy:
       - fill packets up to max - needed_for_tsig
       - when encoding fails (i.e. off > allowed_size):
         - allocate a fresh buffer
         - encode header and question
         - restart with the RR
       - skip EDNS reply and additional section for now
    *)
    let opcode = opcode_data t.data
    and rcode = rcode_data t.data
    in
    let new_buffer () =
      (* we always embed a question in the AXFR reply (this is optional according to RFC) *)
      let buf = Bytes.make max '\000' in
      Header.encode buf (t.header, query, opcode, rcode);
      let names, off = Question.encode Domain_name.Map.empty buf Header.len t.question in
      Bytes.set_uint16_be buf 4 1 ;
      names, buf, off
    in
    Axfr.encode_reply new_buffer max_size t.question data, max
    (* let (_names, off), adcount = encode_data t.additional names buf off in *)
    (* encode_edns Rcode.NoError edns buf off, false *)

  let raw_error buf rcode =
    (* copy id from header, retain opcode, set rcode to ServFail
       if we receive a fragment < 12 bytes, it's not worth bothering *)
    if String.length buf < 12 then
      None
    else
      let query = String.get_uint8 buf 2 lsr 7 = 0 in
      if not query then (* never reply to an answer! *)
        None
      else
        let hdr = Bytes.make 12 '\000' in
        (* manually copy the id from the incoming buf *)
        Bytes.set_uint16_be hdr 0 (String.get_uint16_be buf 0) ;
        (* manually copy the opcode from the incoming buf, and set response *)
        Bytes.set_uint8 hdr 2 (0x80 lor ((String.get_uint8 buf 2) land 0x78)) ;
        (* set rcode *)
        Bytes.set_uint8 hdr 3 ((Rcode.to_int rcode) land 0xF) ;
        let extended_rcode = Rcode.to_int rcode lsr 4 in
        if extended_rcode = 0 then
          Some (Bytes.unsafe_to_string hdr)
        else
          (* need an edns! *)
          let edns = Edns.create ~extended_rcode () in
          let buf = Edns.allocate_and_encode edns in
          Bytes.set_uint16_be hdr 10 1 ;
          Some (Bytes.unsafe_to_string hdr ^ buf)
end

module Tsig_op = struct
  type e = [
    | `Bad_key of [ `raw ] Domain_name.t * Tsig.t
    | `Bad_timestamp of [ `raw ] Domain_name.t * Tsig.t * Dnskey.t
    | `Bad_truncation of [ `raw ] Domain_name.t * Tsig.t
    | `Invalid_mac of [ `raw ] Domain_name.t * Tsig.t
  ]

  let pp_e ppf = function
    | `Bad_key (name, tsig) -> Fmt.pf ppf "bad key %a: %a" Domain_name.pp name Tsig.pp tsig
    | `Bad_timestamp (name, tsig, key) -> Fmt.pf ppf "bad timestamp: %a %a %a" Domain_name.pp name Tsig.pp tsig Dnskey.pp key
    | `Bad_truncation (name, tsig) -> Fmt.pf ppf "bad truncation %a %a" Domain_name.pp name Tsig.pp tsig
    | `Invalid_mac (name, tsig) -> Fmt.pf ppf "invalid mac %a %a" Domain_name.pp name Tsig.pp tsig

  type verify = ?mac:string -> Ptime.t -> Packet.t ->
    [ `raw ] Domain_name.t -> ?key:Dnskey.t -> Tsig.t -> string ->
    (Tsig.t * string * Dnskey.t, e * string option) result

  let no_verify ?mac:_ _ _ _ ?key:_ tsig _ =
    Error (`Bad_key (Domain_name.of_string_exn "no.verification", tsig), None)

  type sign = ?mac:string -> ?max_size:int -> [ `raw ] Domain_name.t ->
    Tsig.t -> key:Dnskey.t -> Packet.t -> string ->
    (string * string) option

  let no_sign ?mac:_ ?max_size:_ _ _ ~key:_ _ _ = None
end

let create ~f =
  let data : (string, int) Hashtbl.t = Hashtbl.create 7 in
  (fun x ->
     let key = f x in
     let cur = match Hashtbl.find_opt data key with None -> 0 | Some x -> x in
     Hashtbl.replace data key (succ cur)),
  (fun () ->
     Hashtbl.fold (fun key value acc -> Metrics.uint key value :: acc) data [])

let counter_metrics ~f ?static name =
  let open Metrics in
  let doc = "Counter metrics" in
  let incr, get = create ~f in
  let static = Option.value ~default:(fun () -> []) static in
  let data thing = incr thing; Data.v (static () @ get ()) in
  Src.v ~doc ~tags:Metrics.Tags.[] ~data name
