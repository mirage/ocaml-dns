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

let int_compare (a : int) (b : int) = compare a b
let int32_compare (a : int32) (b : int32) = Int32.compare a b

let guard p err = if p then Ok () else Error err

let src = Logs.Src.create "dns" ~doc:"DNS core"
module Log = (val Logs.src_log src : Logs.LOG)

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

  let _compare a b = int_compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 1 -> Ok IN
    | 3 -> Ok CHAOS
    | 4 -> Ok HESIOD
    | 254 -> Ok NONE
    | 255 -> Ok ANY_CLASS
    | c -> Error (`Not_implemented (off, Fmt.strf "class %X" c))

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

  let compare a b = int_compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 0 -> Ok Query
    | 1 -> Ok IQuery
    | 2 -> Ok Status
    | 4 -> Ok Notify
    | 5 -> Ok Update
    | x -> Error (`Not_implemented (off, Fmt.strf "opcode 0x%X" x))

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
  let compare a b = int_compare (to_int a) (to_int b)

  let of_int ?(off = 0) = function
    | 0 -> Ok NoError | 1 -> Ok FormErr | 2 -> Ok ServFail
    | 3 -> Ok NXDomain | 4 -> Ok NotImp | 5 -> Ok Refused
    | 6 -> Ok YXDomain | 7 -> Ok YXRRSet | 8 -> Ok NXRRSet
    | 9 -> Ok NotAuth | 10 -> Ok NotZone | 16 -> Ok BadVersOrSig
    | 17 -> Ok BadKey | 18 -> Ok BadTime | 19 -> Ok BadMode
    | 20 -> Ok BadName | 21 -> Ok BadAlg | 22 -> Ok BadTrunc
    | 23 -> Ok BadCookie
    | x -> Error (`Not_implemented (off, Fmt.strf "rcode 0x%04X" x))
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

module Name = struct
  module Int_map = Map.Make(struct
      type t = int
      let compare = int_compare
    end)
  type name_offset_map = int Domain_name.Map.t

  let ptr_tag = 0xC0 (* = 1100 0000 *)

  let decode names buf ~off =
    let open Rresult.R.Infix in
    (* first collect all the labels (and their offsets) *)
    let rec aux offsets off =
      match Cstruct.get_uint8 buf off with
      | 0 -> Ok ((`Z, off), offsets, succ off)
      | i when i >= ptr_tag ->
        let ptr = (i - ptr_tag) lsl 8 + Cstruct.get_uint8 buf (succ off) in
        Ok ((`P ptr, off), offsets, off + 2)
      | i when i >= 64 -> Error (`Malformed (off, Fmt.strf "label tag 0x%x" i)) (* bit patterns starting with 10 or 01 *)
      | i -> (* this is clearly < 64! *)
        let name = Cstruct.to_string (Cstruct.sub buf (succ off) i) in
        aux ((name, off) :: offsets) (succ off + i)
    in
    (* Cstruct.xxx can raise, and we'll have a partial parse then *)
    (try aux [] off with _ -> Error `Partial) >>= fun (l, offs, foff) ->
    (* treat last element special -- either Z or P *)
    (match l with
     | `Z, off -> Ok (off, Domain_name.root, 1)
     | `P p, off -> match Int_map.find p names with
       | exception Not_found ->
         Error (`Malformed (off, "bad label offset: " ^ string_of_int p))
       | (exp, size) -> Ok (off, exp, size)) >>= fun (off, name, size) ->
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
    Cstruct.t -> int -> int Domain_name.Map.t * int =
    fun ?(compress = true) name names buf off ->
    let name = Domain_name.raw name in
    let encode_lbl lbl off =
      let l = String.length lbl in
      Cstruct.set_uint8 buf off l ;
      Cstruct.blit_from_string lbl 0 buf (succ off) l ;
      off + succ l
    and z off =
      Cstruct.set_uint8 buf off 0 ;
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
              Cstruct.BE.set_uint16 buf off data ;
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
    Rresult.R.reword_error (function `Msg _ ->
        `Malformed (off, Fmt.strf "invalid hostname %a" Domain_name.pp name))
      (Domain_name.host name)

  (*
  (* enable once https://github.com/ocaml/dune/issues/897 is resolved *)
  let%expect_test "decode_name" =
    let test ?(map = Int_map.empty) ?(off = 0) data rmap roff =
      match decode map (Cstruct.of_string data) ~off with
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
      match decode map (Cstruct.of_string data) ~off with
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
    let open Astring in
    let max = "s23456789012345678901234567890123456789012345678901234567890123" in
    let lst, _ = String.span ~max:61 max in
    let full = n_of_s (String.concat ~sep:"." [ max ; max ; max ; lst ]) in
    let map' =
      Int_map.add 0 (full, 255)
        (Int_map.add 64 (n_of_s (String.concat ~sep:"." [ max ; max ; lst ]), 191)
           (Int_map.add 128 (n_of_s (String.concat ~sep:"." [ max ; lst ]), 127)
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
    let cs = Cstruct.create 30 in
    let test_cs ?(off = 0) len =
      Format.printf "%a" Cstruct.hexdump_pp (Cstruct.sub cs off len)
    in
    let test ?compress ?(map = Domain_name.Map.empty) ?(off = 0) name rmap roff =
      let omap, ooff = encode ?compress name map cs off in
      if Domain_name.Map.equal (fun a b -> int_compare a b = 0) rmap omap && roff = ooff then
        Format.printf "ok"
      else
        Format.printf "error"
    in
    let n_of_s = Domain_name.of_string_exn in
    test Domain_name.root Domain_name.Map.empty 1; (* compressed encode of root is good *)
    [%expect {|ok|}];
    test_cs 1;
    [%expect {|00|}];
    test ~compress:false Domain_name.root Domain_name.Map.empty 1;
    [%expect {|ok|}];
    test_cs 1;
    [%expect {|00|}];
    let map =
      Domain_name.Map.add (n_of_s "foo.bar") 0
        (Domain_name.Map.add (n_of_s "bar") 4 Domain_name.Map.empty)
    in
    test (n_of_s "foo.bar") map 9; (* encode of foo.bar is good *)
    [%expect {|ok|}];
    test_cs 9;
    [%expect {|03 66 6f 6f 03 62 61 72  00|}];
    test ~compress:false (n_of_s "foo.bar") map 9; (* uncompressed foo.bar is good *)
    [%expect {|ok|}];
    test_cs 9;
    [%expect {|03 66 6f 6f 03 62 61 72  00|}];
    let emap = Domain_name.Map.add (n_of_s "baz.foo.bar") 9 map in
    test ~map ~off:9 (n_of_s "baz.foo.bar") emap 15; (* encode of baz.foo.bar is good *)
    [%expect {|ok|}];
    test_cs 15;
    [%expect {|03 66 6f 6f 03 62 61 72  00 03 62 61 7a c0 00|}];
    let map' =
      Domain_name.Map.add (n_of_s "baz.foo.bar") 9
        (Domain_name.Map.add (n_of_s "foo.bar") 13
           (Domain_name.Map.add (n_of_s "bar") 17 Domain_name.Map.empty))
    in
    test ~compress:false ~map ~off:9 (n_of_s "baz.foo.bar") map' 22;
    [%expect {|ok|}];
    test_cs 22;
    [%expect {|
03 66 6f 6f 03 62 61 72  00 03 62 61 7a 03 66 6f
6f 03 62 61 72 00|}]
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

  let pp ppf soa =
    Fmt.pf ppf "SOA %a %a %lu %lu %lu %lu %lu"
      Domain_name.pp soa.nameserver Domain_name.pp soa.hostmaster
      soa.serial soa.refresh soa.retry soa.expiry soa.minimum

  let compare soa soa' =
    andThen (int32_compare soa.serial soa'.serial)
      (andThen (Domain_name.compare soa.nameserver soa'.nameserver)
         (andThen (Domain_name.compare soa.hostmaster soa'.hostmaster)
            (andThen (int32_compare soa.refresh soa'.refresh)
               (andThen (int32_compare soa.retry soa'.retry)
                  (andThen (int32_compare soa.expiry soa'.expiry)
                     (int32_compare soa.minimum soa'.minimum))))))

  let newer ~old soa = Int32.sub soa.serial old.serial > 0l

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    Name.decode names buf ~off >>= fun (nameserver, names, off') ->
    Name.decode names buf ~off:off' >>| fun (hostmaster, names, off) ->
    let serial = Cstruct.BE.get_uint32 buf off in
    let refresh = Cstruct.BE.get_uint32 buf (off + 4) in
    let retry = Cstruct.BE.get_uint32 buf (off + 8) in
    let expiry = Cstruct.BE.get_uint32 buf (off + 12) in
    let minimum = Cstruct.BE.get_uint32 buf (off + 16) in
    let soa =
      { nameserver ; hostmaster ; serial ; refresh ; retry ; expiry ; minimum }
    in
    (soa, names, off + 20)

  let encode soa names buf off =
    let names, off = Name.encode soa.nameserver names buf off in
    let names, off = Name.encode soa.hostmaster names buf off in
    Cstruct.BE.set_uint32 buf off soa.serial ;
    Cstruct.BE.set_uint32 buf (off + 4) soa.refresh ;
    Cstruct.BE.set_uint32 buf (off + 8) soa.retry ;
    Cstruct.BE.set_uint32 buf (off + 12) soa.expiry ;
    Cstruct.BE.set_uint32 buf (off + 16) soa.minimum ;
    names, off + 20
end

(* name server *)
module Ns = struct
  type t = [ `host ] Domain_name.t

  let pp ppf ns = Fmt.pf ppf "NS %a" Domain_name.pp ns

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    Name.decode names buf ~off >>= fun (name, names, off') ->
    Name.host off name >>| fun host ->
    (host, names, off')

  let encode = Name.encode
end

(* mail exchange *)
module Mx = struct
  type t = {
    preference : int ;
    mail_exchange : [ `host ] Domain_name.t ;
  }

  let pp ppf { preference ; mail_exchange } =
    Fmt.pf ppf "MX %u %a" preference Domain_name.pp mail_exchange

  let compare mx mx' =
    andThen (int_compare mx.preference mx'.preference)
      (Domain_name.compare mx.mail_exchange mx'.mail_exchange)

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let preference = Cstruct.BE.get_uint16 buf off in
    let off = off + 2 in
    Name.decode names buf ~off >>= fun (mx, names, off') ->
    Name.host off mx >>| fun mail_exchange ->
    { preference ; mail_exchange }, names, off'

  let encode { preference ; mail_exchange } names buf off =
    Cstruct.BE.set_uint16 buf off preference ;
    Name.encode mail_exchange names buf (off + 2)
end

(* canonical name *)
module Cname = struct
  type t = [ `raw ] Domain_name.t

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

  let decode names buf ~off ~len:_ =
    let ip = Cstruct.BE.get_uint32 buf off in
    Ok (Ipaddr.V4.of_int32 ip, names, off + 4)

  let encode ip names buf off =
    let ip = Ipaddr.V4.to_int32 ip in
    Cstruct.BE.set_uint32 buf off ip ;
    names, off + 4
end

(* quad-a record *)
module Aaaa = struct
  type t = Ipaddr.V6.t

  let pp ppf address = Fmt.pf ppf "AAAA %a" Ipaddr.V6.pp address

  let compare = Ipaddr.V6.compare

  let decode names buf ~off ~len:_ =
    let iph = Cstruct.BE.get_uint64 buf off
    and ipl = Cstruct.BE.get_uint64 buf (off + 8)
    in
    Ok (Ipaddr.V6.of_int64 (iph, ipl), names, off + 16)

  let encode ip names buf off =
    let iph, ipl = Ipaddr.V6.to_int64 ip in
    Cstruct.BE.set_uint64 buf off iph ;
    Cstruct.BE.set_uint64 buf (off + 8) ipl ;
    names, off + 16
end

(* domain name pointer - reverse entries *)
module Ptr = struct
  type t = [ `host ] Domain_name.t

  let pp ppf rev = Fmt.pf ppf "PTR %a" Domain_name.pp rev

  let compare = Domain_name.compare

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    Name.decode names buf ~off >>= fun (rname, names, off') ->
    Name.host off rname >>| fun ptr ->
    (ptr, names, off')

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

  let pp ppf t =
    Fmt.pf ppf
      "SRV priority %d weight %d port %d target %a"
      t.priority t.weight t.port Domain_name.pp t.target

  let compare a b =
    andThen (int_compare a.priority b.priority)
      (andThen (int_compare a.weight b.weight)
         (andThen (int_compare a.port b.port)
            (Domain_name.compare a.target b.target)))

  let decode names buf ~off ~len:_ =
    let open Rresult.R.Infix in
    let priority = Cstruct.BE.get_uint16 buf off
    and weight = Cstruct.BE.get_uint16 buf (off + 2)
    and port = Cstruct.BE.get_uint16 buf (off + 4)
    in
    let off = off + 6 in
    Name.decode names buf ~off >>= fun (target, names, off') ->
    Name.host off target >>| fun target ->
    { priority ; weight ; port ; target }, names, off'

  let encode t names buf off =
    Cstruct.BE.set_uint16 buf off t.priority ;
    Cstruct.BE.set_uint16 buf (off + 2) t.weight ;
    Cstruct.BE.set_uint16 buf (off + 4) t.port ;
    (* as of rfc2782, no name compression for target! rfc2052 required it *)
    Name.encode ~compress:false t.target names buf (off + 6)
end

(* DNS key *)
module Dnskey = struct

  (* 8 bit *)
  type algorithm =
    | MD5 | SHA1 | SHA224 | SHA256 | SHA384 | SHA512 | Unknown of int

  let algorithm_to_int = function
    | MD5 -> 157
    | SHA1 -> 161
    | SHA224 -> 162
    | SHA256 -> 163
    | SHA384 -> 164
    | SHA512 -> 165
    | Unknown x -> x
  let int_to_algorithm = function
    | 157 -> MD5
    | 161 -> SHA1
    | 162 -> SHA224
    | 163 -> SHA256
    | 164 -> SHA384
    | 165 -> SHA512
    | x ->
      if x >= 0 && x < 255 then
        Unknown x
      else
        invalid_arg ("invalid DNSKEY algorithm " ^ string_of_int x)
  let algorithm_to_string = function
    | MD5 -> "MD5"
    | SHA1 -> "SHA1"
    | SHA224 -> "SHA224"
    | SHA256 -> "SHA256"
    | SHA384 -> "SHA384"
    | SHA512 -> "SHA512"
    | Unknown x -> string_of_int x
  let string_to_algorithm = function
    | "MD5" -> Ok MD5
    | "SHA1" -> Ok SHA1
    | "SHA224" -> Ok SHA224
    | "SHA256" -> Ok SHA256
    | "SHA384" -> Ok SHA384
    | "SHA512" -> Ok SHA512
    | x -> try Ok (Unknown (int_of_string x)) with
        Failure _ -> Error (`Msg ("DNSKEY algorithm not implemented " ^ x))

  let pp_algorithm ppf k = Fmt.string ppf (algorithm_to_string k)

  type t = {
    flags : int ; (* uint16 *)
    algorithm : algorithm ; (* u_int8_t *)
    key : Cstruct.t ;
  }

  let pp ppf t =
    Fmt.pf ppf "DNSKEY flags %u algo %a key %a"
      t.flags pp_algorithm t.algorithm
      Cstruct.hexdump_pp t.key

  let compare a b =
    andThen (compare a.algorithm b.algorithm)
      (Cstruct.compare a.key b.key)

  let decode names buf ~off ~len =
    let open Rresult.R.Infix in
    let flags = Cstruct.BE.get_uint16 buf off
    and proto = Cstruct.get_uint8 buf (off + 2)
    and algo = Cstruct.get_uint8 buf (off + 3)
    in
    guard (proto = 3)
      (`Not_implemented (off + 2, Fmt.strf "dnskey protocol 0x%x" proto)) >>| fun () ->
    let algorithm = int_to_algorithm algo in
    let key = Cstruct.sub buf (off + 4) (len - 4) in
    { flags ; algorithm ; key }, names, off + len

  let encode t names buf off =
    Cstruct.BE.set_uint16 buf off t.flags ;
    Cstruct.set_uint8 buf (off + 2) 3 ;
    Cstruct.set_uint8 buf (off + 3) (algorithm_to_int t.algorithm) ;
    let kl = Cstruct.len t.key in
    Cstruct.blit t.key 0 buf (off + 4) kl ;
    names, off + 4 + kl

  let of_string key =
    let open Rresult.R.Infix in
    let parse flags algo key =
      let key = Cstruct.of_string key in
      string_to_algorithm algo >>| fun algorithm ->
      { flags ; algorithm ; key }
    in
    match Astring.String.cuts ~sep:":" key with
    | [ flags ; algo ; key ] ->
      (try Ok (int_of_string flags) with Failure _ ->
         Error (`Msg ("couldn't parse flags " ^ flags))) >>= fun flags ->
      parse flags algo key
    | [ algo ; key ] -> parse 0 algo key
    | _ -> Error (`Msg ("invalid DNSKEY string " ^ key))

  let name_key_of_string str =
    let open Rresult.R.Infix in
    match Astring.String.cut ~sep:":" str with
    | None -> Error (`Msg ("couldn't parse name:key in " ^ str))
    | Some (name, key) ->
      Domain_name.of_string name >>= fun name ->
      of_string key >>| fun dnskey ->
      (name, dnskey)

  let pp_name_key ppf (name, key) =
    Fmt.pf ppf "%a %a" Domain_name.pp name pp key
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
      t.critical t.tag Fmt.(list ~sep:(unit "; ") string) t.value

  let compare a b =
    andThen (compare a.critical b.critical)
      (andThen (String.compare a.tag b.tag)
         (List.fold_left2
            (fun r a b -> match r with 0 -> String.compare a b | x -> x)
            0 a.value b.value))

  let decode names buf ~off ~len =
    let open Rresult.R.Infix in
    let critical = Cstruct.get_uint8 buf off = 0x80
    and tl = Cstruct.get_uint8 buf (succ off)
    in
    guard (tl > 0 && tl < 16)
      (`Not_implemented (succ off, Fmt.strf "caa tag 0x%x" tl)) >>= fun () ->
    let tag = Cstruct.sub buf (off + 2) tl in
    let tag = Cstruct.to_string tag in
    let vs = 2 + tl in
    let value = Cstruct.sub buf (off + vs) (len - vs) in
    let value = Astring.String.cuts ~sep:";" (Cstruct.to_string value) in
    Ok ({ critical ; tag ; value }, names, off + len)

  let encode t names buf off =
    Cstruct.set_uint8 buf off (if t.critical then 0x80 else 0x0) ;
    let tl = String.length t.tag in
    Cstruct.set_uint8 buf (succ off) tl ;
    Cstruct.blit_from_string t.tag 0 buf (off + 2) tl ;
    let value = Astring.String.concat ~sep:";" t.value in
    let vl = String.length value in
    Cstruct.blit_from_string value 0 buf (off + 2 + tl) vl ;
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

  type t = {
    cert_usage : cert_usage ;
    selector : selector ;
    matching_type : matching_type ;
    data : Cstruct.t ;
  }

  let pp ppf tlsa =
    Fmt.pf ppf "TLSA @[<v>%a %a %a@ %a@]"
      pp_cert_usage tlsa.cert_usage
      pp_selector tlsa.selector
      pp_matching_type tlsa.matching_type
      Cstruct.hexdump_pp tlsa.data

  let compare t1 t2 =
    andThen (compare t1.cert_usage t2.cert_usage)
      (andThen (compare t1.selector t2.selector)
         (andThen (compare t1.matching_type t2.matching_type)
            (Cstruct.compare t1.data t2.data)))

  let decode names buf ~off ~len =
    let usage, selector, matching_type =
      Cstruct.get_uint8 buf off,
      Cstruct.get_uint8 buf (off + 1),
      Cstruct.get_uint8 buf (off + 2)
    in
    let data = Cstruct.sub buf (off + 3) (len - 3) in
    let cert_usage = int_to_cert_usage usage in
    let selector = int_to_selector selector in
    let matching_type = int_to_matching_type matching_type in
    let tlsa = { cert_usage ; selector ; matching_type ; data } in
    Ok (tlsa, names, off + len)

  let encode tlsa names buf off =
    Cstruct.set_uint8 buf off (cert_usage_to_int tlsa.cert_usage) ;
    Cstruct.set_uint8 buf (off + 1) (selector_to_int tlsa.selector) ;
    Cstruct.set_uint8 buf (off + 2) (matching_type_to_int tlsa.matching_type) ;
    let l = Cstruct.len tlsa.data in
    Cstruct.blit tlsa.data 0 buf (off + 3) l ;
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

  type t = {
    algorithm : algorithm ;
    typ : typ ;
    fingerprint : Cstruct.t ;
  }

  let pp ppf sshfp =
    Fmt.pf ppf "SSHFP %a %a %a"
      pp_algorithm sshfp.algorithm
      pp_typ sshfp.typ
      Cstruct.hexdump_pp sshfp.fingerprint

  let compare s1 s2 =
    andThen (compare s1.algorithm s2.algorithm)
      (andThen (compare s1.typ s2.typ)
         (Cstruct.compare s1.fingerprint s2.fingerprint))

  let decode names buf ~off ~len =
    let algo, typ = Cstruct.get_uint8 buf off, Cstruct.get_uint8 buf (succ off) in
    let fingerprint = Cstruct.sub buf (off + 2) (len - 2) in
    let algorithm = int_to_algorithm algo in
    let typ = int_to_typ typ in
    let sshfp = { algorithm ; typ ; fingerprint } in
    Ok (sshfp, names, off + len)

  let encode sshfp names buf off =
    Cstruct.set_uint8 buf off (algorithm_to_int sshfp.algorithm) ;
    Cstruct.set_uint8 buf (succ off) (typ_to_int sshfp.typ) ;
    let l = Cstruct.len sshfp.fingerprint in
    Cstruct.blit sshfp.fingerprint 0 buf (off + 2) l ;
    names, off + l + 2
end

(* Text record *)
module Txt = struct
  type t = string

  let pp ppf txt = Fmt.pf ppf "TXT %s" txt

  let compare = String.compare

  let decode names buf ~off ~len =
    let decode_character_str buf off =
      let len = Cstruct.get_uint8 buf off in
      let data = Cstruct.to_string (Cstruct.sub buf (succ off) len) in
      (data, off + len + 1)
    in
    let sub = Cstruct.sub buf off len in
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
    let rec more off txt =
      if txt = "" then
        off
      else
        let len = String.length txt in
        let len, rest =
          if len > 255 then
            255, String.(sub txt 255 (len - 255))
          else
            len, ""
        in
        Cstruct.set_uint8 buf off len ;
        Cstruct.blit_from_string txt 0 buf (succ off) len ;
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
    mac : Cstruct.t ;
    original_id : int ; (* again 16 bit *)
    error : Rcode.t ;
    other : Ptime.t option
  }

  let rtyp = 250

  let equal a b =
    a.algorithm = b.algorithm &&
    Ptime.equal a.signed b.signed &&
    Ptime.Span.equal a.fudge b.fudge &&
    Cstruct.equal a.mac b.mac &&
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
         let m = Fmt.strf "algorithm name %a" Domain_name.pp b in
         Error (`Not_implemented (off, m)))

  let pp_algorithm ppf a = Domain_name.pp ppf (algorithm_to_name a)

  (* this is here because I don't like float, and rather convert Ptime.t to int64 *)
  let s_in_d = 86_400L
  let ps_in_s = 1_000_000_000_000L

  let ptime_span_to_int64 ts =
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

  let ptime_of_int64 ?(off = 0) s =
    let d, ps = Int64.(div s s_in_d, mul (rem s s_in_d) ps_in_s) in
    if d < Int64.of_int min_int || d > Int64.of_int max_int then
      Error (`Malformed (off, Fmt.strf "timestamp does not fit in time range %Ld" s))
    else
      match Ptime.Span.of_d_ps (Int64.to_int d, ps) with
      | Some span ->
        begin match Ptime.of_span span with
          | Some ts -> Ok ts
          | None -> Error (`Malformed (off, Fmt.strf "span does not fit into timestamp %Ld" s))
        end
      | None -> Error (`Malformed (off, Fmt.strf "timestamp does not fit %Ld" s))

  let valid_time now tsig =
    let ts = tsig.signed
    and fudge = tsig.fudge
    in
    match Ptime.add_span now fudge, Ptime.sub_span now fudge with
    | None, _ -> false
    | _, None -> false
    | Some late, Some early ->
      Ptime.is_earlier ts ~than:late && Ptime.is_later ts ~than:early

  let tsig ~algorithm ~signed ?(fudge = Ptime.Span.of_int_s 300)
      ?(mac = Cstruct.create 0) ?(original_id = 0) ?(error = Rcode.NoError)
      ?other () =
    match ptime_span_to_int64 (Ptime.to_span signed), ptime_span_to_int64 fudge with
    | None, _ | _, None -> None
    | Some ts, Some fu ->
      if
        Int64.logand 0xffff_0000_0000_0000L ts = 0L &&
        Int64.logand 0xffff_ffff_ffff_0000L fu = 0L
      then
        Some { algorithm ; signed ; fudge ; mac ; original_id ; error ; other }
      else
        None

  let with_mac tsig mac = { tsig with mac }

  let with_error tsig error = { tsig with error }

  let with_signed tsig signed =
    match ptime_span_to_int64 (Ptime.to_span signed) with
    | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
      Some { tsig with signed }
    | _ -> None

  let with_other tsig other =
    match other with
    | None -> Some { tsig with other }
    | Some ts ->
      match ptime_span_to_int64 (Ptime.to_span ts) with
      | Some x when Int64.logand 0xffff_0000_0000_0000L x = 0L ->
        Some { tsig with other }
      | _ -> None

  let pp ppf t =
    Fmt.pf ppf
      "TSIG %a signed %a fudge %a mac %a original id %04X err %a other %a"
      pp_algorithm t.algorithm
      (Ptime.pp_rfc3339 ()) t.signed Ptime.Span.pp t.fudge
      Cstruct.hexdump_pp t.mac t.original_id Rcode.pp t.error
      Fmt.(option ~none:(unit "none") (Ptime.pp_rfc3339 ())) t.other

  let decode_48bit_time buf off =
    let a = Cstruct.BE.get_uint16 buf off
    and b = Cstruct.BE.get_uint16 buf (off + 2)
    and c = Cstruct.BE.get_uint16 buf (off + 4)
    in
    Int64.(add
             (add (shift_left (of_int a) 32) (shift_left (of_int b) 16))
             (of_int c))

  (* TODO maybe revise, esp. all the guards *)
  let decode names buf ~off =
    let open Rresult.R.Infix in
    guard (Cstruct.len buf - off >= 6) `Partial >>= fun () ->
    let ttl = Cstruct.BE.get_uint32 buf off in
    guard (ttl = 0l) (`Malformed (off, Fmt.strf "tsig ttl is not zero %lu" ttl)) >>= fun () ->
    let len = Cstruct.BE.get_uint16 buf (off + 4) in
    let rdata_start = off + 6 in
    guard (Cstruct.len buf - rdata_start >= len) `Partial >>= fun () ->
    Name.decode names buf ~off:rdata_start >>= fun (algorithm, names, off') ->
    Name.host rdata_start algorithm >>= fun algorithm ->
    guard (Cstruct.len buf - off' >= 10) `Partial >>= fun () ->
    let signed = decode_48bit_time buf off'
    and fudge = Cstruct.BE.get_uint16 buf (off' + 6)
    and mac_len = Cstruct.BE.get_uint16 buf (off' + 8)
    in
    guard (Cstruct.len buf - off' >= 10 + mac_len + 6) `Partial >>= fun () ->
    let mac = Cstruct.sub buf (off' + 10) mac_len
    and original_id = Cstruct.BE.get_uint16 buf (off' + 10 + mac_len)
    and error = Cstruct.BE.get_uint16 buf (off' + 12 + mac_len)
    and other_len = Cstruct.BE.get_uint16 buf (off' + 14 + mac_len)
    in
    let rdata_end = off' + 10 + mac_len + 6 + other_len in
    guard (rdata_end - rdata_start = len) `Partial >>= fun () ->
    guard (Cstruct.len buf >= rdata_end) `Partial >>= fun () ->
    guard (other_len = 0 || other_len = 6)
      (`Malformed (off' + 14 + mac_len, "other timestamp should be 0 or 6 bytes!")) >>= fun () ->
    algorithm_of_name ~off:rdata_start algorithm >>= fun algorithm ->
    ptime_of_int64 ~off:off' signed >>= fun signed ->
    Rcode.of_int ~off:(off' + 12 + mac_len) error >>= fun error ->
    (if other_len = 0 then
       Ok None
     else
       let other = decode_48bit_time buf (off' + 16 + mac_len) in
       ptime_of_int64 ~off:(off' + 14 + mac_len + 2) other >>| fun x ->
       Some x) >>| fun other ->
    let fudge = Ptime.Span.of_int_s fudge in
    { algorithm ; signed ; fudge ; mac ; original_id ; error ; other },
    names,
    off' + 16 + mac_len + other_len

  let encode_48bit_time buf ?(off = 0) ts =
    match ptime_span_to_int64 (Ptime.to_span ts) with
    | None ->
      Log.warn (fun m -> m "couldn't convert (to_span %a) to int64" Ptime.pp ts)
    | Some secs ->
      if Int64.logand secs 0xffff_0000_0000_0000L > 0L then
        Log.warn (fun m -> m "secs %Lu > 48 bit" secs)
      else
        let a, b, c =
          let f s = Int64.(to_int (logand 0xffffL (shift_right secs s))) in
          f 32, f 16, f 0
        in
        Cstruct.BE.set_uint16 buf off a ;
        Cstruct.BE.set_uint16 buf (off + 2) b ;
        Cstruct.BE.set_uint16 buf (off + 4) c

  let encode_16bit_time buf ?(off = 0) ts =
    match ptime_span_to_int64 ts with
    | None ->
      Log.warn (fun m -> m "couldn't convert span %a to int64" Ptime.Span.pp ts)
    | Some secs ->
      if Int64.logand secs 0xffff_ffff_ffff_0000L > 0L then
        Log.warn (fun m -> m "secs %Lu > 16 bit" secs)
      else
        let a = Int64.(to_int (logand 0xffffL secs)) in
        Cstruct.BE.set_uint16 buf off a

  (* TODO unused -- why? *)
  let _encode t names buf off =
    let algo = algorithm_to_name t.algorithm in
    let names, off = Name.encode ~compress:false algo names buf off in
    encode_48bit_time buf ~off t.signed ;
    encode_16bit_time buf ~off:(off + 6) t.fudge ;
    let mac_len = Cstruct.len t.mac in
    Cstruct.BE.set_uint16 buf (off + 8) mac_len ;
    Cstruct.blit t.mac 0 buf (off + 10) mac_len ;
    Cstruct.BE.set_uint16 buf (off + 10 + mac_len) t.original_id ;
    Cstruct.BE.set_uint16 buf (off + 12 + mac_len) (Rcode.to_int t.error) ;
    let other_len = match t.other with None -> 0 | Some _ -> 6 in
    Cstruct.BE.set_uint16 buf (off + 14 + mac_len) other_len ;
    (match t.other with
     | None -> ()
     | Some t -> encode_48bit_time buf ~off:(off + 16 + mac_len) t) ;
    names, off + 16 + mac_len + other_len

  let canonical_name name =
    let buf = Cstruct.create 255
    and emp = Domain_name.Map.empty
    and nam = Domain_name.canonical name
    in
    let _, off = Name.encode ~compress:false nam emp buf 0 in
    Cstruct.sub buf 0 off

  let encode_raw_tsig_base name t =
    let name = canonical_name name
    and aname = canonical_name (algorithm_to_name t.algorithm)
    in
    let clttl = Cstruct.create 6 in
    Cstruct.BE.set_uint16 clttl 0 Class.(to_int ANY_CLASS) ;
    Cstruct.BE.set_uint32 clttl 2 0l ;
    let time = Cstruct.create 8 in
    encode_48bit_time time t.signed ;
    encode_16bit_time time ~off:6 t.fudge ;
    let other =
      let buf = match t.other with
        | None ->
          let buf = Cstruct.create 4 in
          Cstruct.BE.set_uint16 buf 2 0 ;
          buf
        | Some t ->
          let buf = Cstruct.create 10 in
          Cstruct.BE.set_uint16 buf 2 6 ;
          encode_48bit_time buf ~off:4 t ;
          buf
      in
      Cstruct.BE.set_uint16 buf 0 (Rcode.to_int t.error) ;
      buf
    in
    name, clttl, [ aname ; time ], other

  let encode_raw name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    Cstruct.concat (name :: clttl :: mid @ [ fin ])

  let encode_full name t =
    let name, clttl, mid, fin = encode_raw_tsig_base name t in
    let typ =
      let typ = Cstruct.create 2 in
      Cstruct.BE.set_uint16 typ 0 rtyp ;
      typ
    and mac =
      let len = Cstruct.len t.mac in
      let l = Cstruct.create 2 in
      Cstruct.BE.set_uint16 l 0 len ;
      let orig = Cstruct.create 2 in
      Cstruct.BE.set_uint16 orig 0 t.original_id ;
      [ l ; t.mac ; orig ]
    in
    let rdata = Cstruct.concat (mid @ mac @ [ fin ]) in
    let len =
      let buf = Cstruct.create 2 in
      Cstruct.BE.set_uint16 buf 0 (Cstruct.len rdata) ;
      buf
    in
    Cstruct.concat [ name ; typ ; clttl ; len ; rdata ]

  let dnskey_to_tsig_algo key =
    match key.Dnskey.algorithm with
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
    | Nsid of Cstruct.t
    | Cookie of Cstruct.t
    | Tcp_keepalive of int option
    | Padding of int
    | Extension of int * Cstruct.t

  let pp_extension ppf = function
    | Nsid cs -> Fmt.pf ppf "nsid %a" Cstruct.hexdump_pp cs
    | Cookie cs -> Fmt.pf ppf "cookie %a" Cstruct.hexdump_pp cs
    | Tcp_keepalive i -> Fmt.pf ppf "keepalive %a" Fmt.(option ~none:(unit "none") int) i
    | Padding i -> Fmt.pf ppf "padding %d" i
    | Extension (t, v) -> Fmt.pf ppf "unknown option %d: %a" t Cstruct.hexdump_pp v

  let compare_extension a b = match a, b with
    | Nsid a, Nsid b -> Cstruct.compare a b
    | Nsid _, _ -> 1 | _, Nsid _ -> -1
    | Cookie a, Cookie b -> Cstruct.compare a b
    | Cookie _, _ -> 1 | _, Cookie _ -> -1
    | Tcp_keepalive a, Tcp_keepalive b ->
      begin match a, b with
        | None, None -> 0
        | None, Some _ -> -1
        | Some _, None -> 1
        | Some a, Some b -> int_compare a b
      end
    | Tcp_keepalive _, _ -> 1 | _, Tcp_keepalive _ -> -1
    | Padding a, Padding b -> int_compare a b
    | Padding _, _ -> 1 | _, Padding _ -> -1
    | Extension (t, v), Extension (t', v') ->
      andThen (int_compare t t') (Cstruct.compare v v')

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
    | Tcp_keepalive i -> (match i with None -> Cstruct.create 0 | Some i -> let buf = Cstruct.create 2 in Cstruct.BE.set_uint16 buf 0 i ; buf)
    | Padding i -> Cstruct.create i
    | Extension (_, v) -> v

  let encode_extension t buf off =
    let code = extension_to_int t in
    let v = extension_payload t in
    let l = Cstruct.len v in
    Cstruct.BE.set_uint16 buf off code ;
    Cstruct.BE.set_uint16 buf (off + 2) l ;
    Cstruct.blit v 0 buf (off + 4) l ;
    off + 4 + l

  let decode_extension buf ~off ~len =
    let open Rresult.R.Infix in
    let code = Cstruct.BE.get_uint16 buf off
    and tl = Cstruct.BE.get_uint16 buf (off + 2)
    in
    let v = Cstruct.sub buf (off + 4) tl in
    guard (len >= tl + 4) `Partial >>= fun () ->
    let len = tl + 4 in
    match int_to_extension code with
    | Some `nsid -> Ok (Nsid v, len)
    | Some `cookie -> Ok (Cookie v, len)
    | Some `tcp_keepalive ->
      (begin match tl with
         | 0 -> Ok None
         | 2 -> Ok (Some (Cstruct.BE.get_uint16 v 0))
         | _ -> Error (`Not_implemented (off, Fmt.strf "edns keepalive 0x%x" tl))
       end >>= fun i ->
       Ok (Tcp_keepalive i, len))
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
        Logs.warn (fun m -> m "requested payload size %d is too small, using %d"
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
    andThen (int_compare a.extended_rcode b.extended_rcode)
      (andThen (int_compare a.version b.version)
         (andThen (compare a.dnssec_ok b.dnssec_ok)
            (andThen (int_compare a.payload_size b.payload_size)
               (List.fold_left2
                  (fun r a b -> if r = 0 then compare_extension a b else r)
                  (compare (List.length a.extensions) (List.length b.extensions))
                  a.extensions b.extensions))))

  let pp ppf opt =
    Fmt.(pf ppf "EDNS rcode %u version %u dnssec_ok %b payload_size %u extensions %a"
           opt.extended_rcode opt.version opt.dnssec_ok opt.payload_size
           (list ~sep:(unit ", ") pp_extension) opt.extensions)

  let decode_extensions buf ~len =
    let open Rresult.R.Infix in
    let rec one acc pos =
      if len = pos then
        Ok (List.rev acc)
      else
        decode_extension buf ~off:pos ~len:(len - pos) >>= fun (opt, len) ->
        one (opt :: acc) (pos + len)
    in
    one [] 0

  let decode buf ~off =
    let open Rresult.R.Infix in
    (* EDNS is special -- the incoming off points to before name type clas *)
    (* name must be the root, typ is OPT, class is used for length *)
    guard (Cstruct.len buf - off >= 11) `Partial >>= fun () ->
    guard (Cstruct.get_uint8 buf off = 0) (`Malformed (off, "bad edns (must be 0)")) >>= fun () ->
    (* crazyness: payload_size is encoded in class *)
    let payload_size = Cstruct.BE.get_uint16 buf (off + 3)
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    and extended_rcode = Cstruct.get_uint8 buf (off + 5)
    and version = Cstruct.get_uint8 buf (off + 6)
    and flags = Cstruct.BE.get_uint16 buf (off + 7)
    and len = Cstruct.BE.get_uint16 buf (off + 9)
    in
    let off = off + 11 in
    let dnssec_ok = flags land 0x8000 = 0x8000 in
    guard (version = 0) (`Bad_edns_version version) >>= fun () ->
    let payload_size =
      if payload_size < min_payload_size then begin
        Log.warn (fun m -> m "EDNS payload size is too small %d, using %d"
                     payload_size min_payload_size);
        min_payload_size
      end else
        payload_size
    in
    let exts_buf = Cstruct.sub buf off len in
    (try decode_extensions exts_buf ~len with _ -> Error `Partial) >>= fun extensions ->
    let opt = { extended_rcode ; version ; dnssec_ok ; payload_size ; extensions } in
    Ok (opt, off + len)

  let encode_extensions t buf off =
    List.fold_left (fun off opt -> encode_extension opt buf off) off t

  let encode t buf off =
    (* name is . *)
    Cstruct.set_uint8 buf off 0 ;
    (* type *)
    Cstruct.BE.set_uint16 buf (off + 1) rtyp ;
    (* class is payload size! *)
    Cstruct.BE.set_uint16 buf (off + 3) t.payload_size ;
    (* it continues: the ttl is split into: 8bit extended rcode, 8bit version, 1bit dnssec_ok, 7bit 0 *)
    Cstruct.set_uint8 buf (off + 5) t.extended_rcode ;
    Cstruct.set_uint8 buf (off + 6) t.version ;
    Cstruct.BE.set_uint16 buf (off + 7) (if t.dnssec_ok then 0x8000 else 0) ;
    let ext_start = off + 11 in
    let ext_end = encode_extensions t.extensions buf ext_start in
    Cstruct.BE.set_uint16 buf (off + 9) (ext_end - ext_start) ;
    ext_end

  let allocate_and_encode edns =
    (* this is unwise! *)
    let buf = Cstruct.create 128 in
    let off = encode edns buf 0 in
    Cstruct.sub buf 0 off
end

(* resource record map *)
module Rr_map = struct
  module Mx_set = Set.Make(Mx)
  module Txt_set = Set.Make(Txt)
  module Ipv4_set = Set.Make(Ipaddr.V4)
  module Ipv6_set = Set.Make(Ipaddr.V6)
  module Srv_set = Set.Make(Srv)
  module Dnskey_set = Set.Make(Dnskey)
  module Caa_set = Set.Make(Caa)
  module Tlsa_set = Set.Make(Tlsa)
  module Sshfp_set = Set.Make(Sshfp)

  module I : sig
    type t
    val of_int : ?off:int -> int -> (t, [> `Malformed of int * string ]) result
    val to_int : t -> int
    val compare : t -> t -> int
  end = struct
    type t = int
    let of_int ?(off = 0) i = match i with
      | 1 | 2 | 5 | 6 | 12 | 15 | 16 | 28 | 33 | 41 | 44 | 48 | 52 | 250 | 251 | 252 | 255 | 257 ->
        Error (`Malformed (off, "reserved and supported RTYPE not Unknown"))
      | x -> if x < 1 lsl 15 then Ok x else Error (`Malformed (off, "RTYPE exceeds 16 bit"))
    let to_int t = t
    let compare = int_compare
  end

  type 'a with_ttl = int32 * 'a

  type _ rr =
    | Soa : Soa.t rr
    | Ns : Domain_name.Host_set.t with_ttl rr
    | Mx : Mx_set.t with_ttl rr
    | Cname : Cname.t with_ttl rr
    | A : Ipv4_set.t with_ttl rr
    | Aaaa : Ipv6_set.t with_ttl rr
    | Ptr : Ptr.t with_ttl rr
    | Srv : Srv_set.t with_ttl rr
    | Dnskey : Dnskey_set.t with_ttl rr
    | Caa : Caa_set.t with_ttl rr
    | Tlsa : Tlsa_set.t with_ttl rr
    | Sshfp : Sshfp_set.t with_ttl rr
    | Txt : Txt_set.t with_ttl rr
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
    | A, (_, aas), (_, aas') -> Ipv4_set.equal aas aas'
    | Aaaa, (_, aaaas), (_, aaaas') -> Ipv6_set.equal aaaas aaaas'
    | Srv, (_, srvs), (_, srvs') -> Srv_set.equal srvs srvs'
    | Dnskey, (_, keys), (_, keys') -> Dnskey_set.equal keys keys'
    | Caa, (_, caas), (_, caas') -> Caa_set.equal caas caas'
    | Tlsa, (_, tlsas), (_, tlsas') -> Tlsa_set.equal tlsas tlsas'
    | Sshfp, (_, sshfps), (_, sshfps') -> Sshfp_set.equal sshfps sshfps'
    | Unknown _, (_, data), (_, data') -> Txt_set.equal data data'

  let equalb (B (k, v)) (B (k', v')) = match K.compare k k' with
    | Gmap.Order.Eq -> equal_rr k v v'
    | _ -> false

  let to_int : type a. a key -> int = function
    | A -> 1 | Ns -> 2 | Cname -> 5 | Soa -> 6 | Ptr -> 12 | Mx -> 15
    | Txt -> 16 | Aaaa -> 28 | Srv -> 33 | Sshfp -> 44 | Dnskey -> 48
    | Tlsa -> 52 | Caa -> 257 | Unknown x -> I.to_int x

  let any_rtyp = 255 and axfr_rtyp = 252 and ixfr_rtyp = 251

  let of_int ?(off = 0) = function
    | 1 -> Ok (K A) | 2 -> Ok (K Ns) | 5 -> Ok (K Cname) | 6 -> Ok (K Soa)
    | 12 -> Ok (K Ptr) | 15 -> Ok (K Mx) | 16 -> Ok (K Txt) | 28 -> Ok (K Aaaa)
    | 33 -> Ok (K Srv) | 44 -> Ok (K Sshfp) | 48 -> Ok (K Dnskey)
    | 52 -> Ok (K Tlsa) | 257 -> Ok (K Caa)
    | x ->
      let open Rresult.R.Infix in
      I.of_int ~off x >>| fun i ->
      K (Unknown i)

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
    | Unknown x -> Fmt.pf ppf "TYPE%d" (I.to_int x)

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

  let encode_ntc names buf off (n, t, c) =
    let names, off = Name.encode n names buf off in
    Cstruct.BE.set_uint16 buf off (rr_to_int t) ;
    Cstruct.BE.set_uint16 buf (off + 2) c ;
    names, off + 4

  let encode : type a. ?clas:Class.t -> [ `raw ] Domain_name.t -> a key -> a -> Name.name_offset_map -> Cstruct.t -> int ->
    (Name.name_offset_map * int) * int = fun ?(clas = Class.IN) name k v names buf off ->
    let clas = Class.to_int clas in
    let rr names f off ttl =
      let names, off' = encode_ntc names buf off (name, `K (K k), clas) in
      (* leave 6 bytes space for TTL and length *)
      let rdata_start = off' + 6 in
      let names, rdata_end = f names buf rdata_start in
      let rdata_len = rdata_end - rdata_start in
      Cstruct.BE.set_uint32 buf off' ttl ;
      Cstruct.BE.set_uint16 buf (off' + 4) rdata_len ;
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
      Ipv4_set.fold (fun address ((names, off), count) ->
        rr names (A.encode address) off ttl, succ count)
        addresses ((names, off), 0)
    | Aaaa, (ttl, aaaas) ->
      Ipv6_set.fold (fun address ((names, off), count) ->
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
    | Unknown _, (ttl, datas) ->
      let encode data names buf off =
        let l = String.length data in
        Cstruct.blit_from_string data 0 buf off l;
        names, off + l
      in
      Txt_set.fold (fun data ((names, off), count) ->
          rr names (encode data) off ttl, succ count)
        datas ((names, off), 0)

  let union_rr : type a. a key -> a -> a -> a = fun k l r ->
    match k, l, r with
    | Cname, _, cname -> cname
    | Mx, (_, mxs), (ttl, mxs') -> (ttl, Mx_set.union mxs mxs')
    | Ns, (_, ns), (ttl, ns') -> (ttl, Domain_name.Host_set.union ns ns')
    | Ptr, _, ptr -> ptr
    | Soa, _, soa -> soa
    | Txt, (_, txts), (ttl, txts') -> (ttl, Txt_set.union txts txts')
    | A, (_, ips), (ttl, ips') -> (ttl, Ipv4_set.union ips ips')
    | Aaaa, (_, ips), (ttl, ips') -> (ttl, Ipv6_set.union ips ips')
    | Srv, (_, srvs), (ttl, srvs') -> (ttl, Srv_set.union srvs srvs')
    | Dnskey, (_, keys), (ttl, keys') -> (ttl, Dnskey_set.union keys keys')
    | Caa, (_, caas), (ttl, caas') -> (ttl, Caa_set.union caas caas')
    | Tlsa, (_, tlsas), (ttl, tlsas') -> (ttl, Tlsa_set.union tlsas tlsas')
    | Sshfp, (_, sshfps), (ttl, sshfps') -> (ttl, Sshfp_set.union sshfps sshfps')
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
      let s = Ipv4_set.diff ips rm in
      if Ipv4_set.is_empty s then None else Some (ttl, s)
    | Aaaa, (ttl, ips), (_, rm) ->
      let s = Ipv6_set.diff ips rm in
      if Ipv6_set.is_empty s then None else Some (ttl, s)
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
    let ttl_fmt = Fmt.(option (suffix (unit "\t") uint32)) in
    let str_name = name n in
    let strs =
      match t, v with
      | Cname, (ttl, alias) ->
        [ Fmt.strf "%s\t%aCNAME\t%s" str_name ttl_fmt (ttl_opt ttl) (name alias) ]
      | Mx, (ttl, mxs) ->
        Mx_set.fold (fun { preference ; mail_exchange } acc ->
            Fmt.strf "%s\t%aMX\t%u\t%s" str_name ttl_fmt (ttl_opt ttl) preference (name mail_exchange) :: acc)
          mxs []
      | Ns, (ttl, ns) ->
        Domain_name.Host_set.fold (fun ns acc ->
            Fmt.strf "%s\t%aNS\t%s" str_name ttl_fmt (ttl_opt ttl) (name ns) :: acc)
          ns []
      | Ptr, (ttl, ptr) ->
        [ Fmt.strf "%s\t%aPTR\t%s" str_name ttl_fmt (ttl_opt ttl) (name ptr) ]
      | Soa, soa ->
        [ Fmt.strf "%s\t%aSOA\t%s\t%s\t%lu\t%lu\t%lu\t%lu\t%lu" str_name
            ttl_fmt (ttl_opt soa.minimum)
            (name soa.nameserver)
            (name soa.hostmaster)
            soa.serial soa.refresh soa.retry
            soa.expiry soa.minimum ]
      | Txt, (ttl, txts) ->
        Txt_set.fold (fun txt acc ->
            Fmt.strf "%s\t%aTXT\t\"%s\"" str_name ttl_fmt (ttl_opt ttl) txt :: acc)
          txts []
      | A, (ttl, a) ->
        Ipv4_set.fold (fun ip acc ->
          Fmt.strf "%s\t%aA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V4.to_string ip) :: acc)
          a []
      | Aaaa, (ttl, aaaa) ->
        Ipv6_set.fold (fun ip acc ->
            Fmt.strf "%s\t%aAAAA\t%s" str_name ttl_fmt (ttl_opt ttl) (Ipaddr.V6.to_string ip) :: acc)
          aaaa []
      | Srv, (ttl, srvs) ->
        Srv_set.fold (fun srv acc ->
            Fmt.strf "%s\t%aSRV\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              srv.priority srv.weight srv.port
              (name srv.target) :: acc)
          srvs []
      | Dnskey, (ttl, keys) ->
        Dnskey_set.fold (fun key acc ->
            Fmt.strf "%s%a\tDNSKEY\t%u\t3\t%d\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              key.flags
              (Dnskey.algorithm_to_int key.algorithm)
              (hex key.key) :: acc)
          keys []
      | Caa, (ttl, caas) ->
        Caa_set.fold (fun caa acc ->
            Fmt.strf "%s\t%aCAA\t%s\t%s\t\"%s\""
              str_name ttl_fmt (ttl_opt ttl)
              (if caa.critical then "128" else "0")
              caa.tag (String.concat ";" caa.value) :: acc)
          caas []
      | Tlsa, (ttl, tlsas) ->
        Tlsa_set.fold (fun tlsa acc ->
            Fmt.strf "%s\t%aTLSA\t%u\t%u\t%u\t%s"
              str_name ttl_fmt (ttl_opt ttl)
              (Tlsa.cert_usage_to_int tlsa.cert_usage)
              (Tlsa.selector_to_int tlsa.selector)
              (Tlsa.matching_type_to_int tlsa.matching_type)
              (hex tlsa.data) :: acc)
          tlsas []
      | Sshfp, (ttl, sshfps) ->
        Sshfp_set.fold (fun sshfp acc ->
            Fmt.strf "%s\t%aSSHFP\t%u\t%u\t%s" str_name ttl_fmt (ttl_opt ttl)
              (Sshfp.algorithm_to_int sshfp.algorithm)
              (Sshfp.typ_to_int sshfp.typ)
              (hex sshfp.fingerprint) :: acc)
          sshfps []
      | Unknown x, (ttl, datas) ->
        Txt_set.fold (fun data acc ->
            Fmt.strf "%s\t%aTYPE%d\t\\# %d %s" str_name ttl_fmt (ttl_opt ttl)
              (I.to_int x) (String.length data) (hex (Cstruct.of_string data)) :: acc)
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
      let one = Ipv4_set.choose ips in
      let rest = Ipv4_set.remove one ips in
      let rest' =
        if Ipv4_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Ipv4_set.singleton one), rest'
    | Aaaa, (ttl, ips) ->
      let one = Ipv6_set.choose ips in
      let rest = Ipv6_set.remove one ips in
      let rest' =
        if Ipv6_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Ipv6_set.singleton one), rest'
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
    | Unknown _, (ttl, datas) ->
      let one = Txt_set.choose datas in
      let rest = Txt_set.remove one datas in
      let rest' =
        if Txt_set.is_empty rest then None else Some (ttl, rest)
      in
      (ttl, Txt_set.singleton one), rest'

  let pp_b ppf (B (k, _)) = ppk ppf (K k)

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
    let open Rresult.R.Infix in
    guard (Cstruct.len buf - off >= 6) `Partial >>= fun () ->
    let ttl = Cstruct.BE.get_uint32 buf off
    and len = Cstruct.BE.get_uint16 buf (off + 4)
    and rdata_start = off + 6
    in
    guard (Int32.logand ttl 0x8000_0000l = 0l)
      (`Malformed (off, Fmt.strf "bad TTL (high bit set) %lu" ttl)) >>= fun () ->
    guard (Cstruct.len buf - rdata_start >= len) `Partial >>= fun () ->
    guard (len <= max_rdata_length)
      (`Malformed (off + 4, Fmt.strf "length %d exceeds maximum rdata size" len)) >>= fun () ->
    (match typ with
     | Soa ->
       Soa.decode names buf ~off:rdata_start ~len >>| fun (soa, names, off) ->
       (B (Soa, soa), names, off)
     | Ns ->
       Ns.decode names buf ~off:rdata_start ~len >>| fun (ns, names, off) ->
       (B (Ns, (ttl, Domain_name.Host_set.singleton ns)), names, off)
     | Mx ->
       Mx.decode names buf ~off:rdata_start ~len >>| fun (mx, names, off) ->
       (B (Mx, (ttl, Mx_set.singleton mx)), names, off)
     | Cname ->
       Cname.decode names buf ~off:rdata_start ~len >>| fun (alias, names, off) ->
       (B (Cname, (ttl, alias)), names, off)
     | A ->
       A.decode names buf ~off:rdata_start ~len >>| fun (address, names, off) ->
       (B (A, (ttl, Ipv4_set.singleton address)), names, off)
     | Aaaa ->
       Aaaa.decode names buf ~off:rdata_start ~len >>| fun (address, names, off) ->
       (B (Aaaa, (ttl, Ipv6_set.singleton address)), names, off)
     | Ptr ->
       Ptr.decode names buf ~off:rdata_start ~len >>| fun (rev, names, off) ->
       (B (Ptr, (ttl, rev)), names, off)
     | Srv ->
       Srv.decode names buf ~off:rdata_start ~len >>| fun (srv, names, off) ->
       (B (Srv, (ttl, Srv_set.singleton srv)), names, off)
     | Dnskey ->
       Dnskey.decode names buf ~off:rdata_start ~len >>| fun (dnskey, names, off) ->
       (B (Dnskey, (ttl, Dnskey_set.singleton dnskey)), names, off)
     | Caa ->
       Caa.decode names buf ~off:rdata_start ~len >>| fun (caa, names, off) ->
       (B (Caa, (ttl, Caa_set.singleton caa)), names, off)
     | Tlsa ->
       Tlsa.decode names buf ~off:rdata_start ~len >>| fun (tlsa, names, off) ->
       (B (Tlsa, (ttl, Tlsa_set.singleton tlsa)), names, off)
     | Sshfp ->
       Sshfp.decode names buf ~off:rdata_start ~len >>| fun (sshfp, names, off) ->
       (B (Sshfp, (ttl, Sshfp_set.singleton sshfp)), names, off)
     | Txt ->
       Txt.decode names buf ~off:rdata_start ~len >>| fun (txt, names, off) ->
       (B (Txt, (ttl, Txt_set.singleton txt)), names, off)
     | Unknown x ->
       let data = Cstruct.sub buf rdata_start len in
       Ok (B (Unknown x, (ttl, Txt_set.singleton (Cstruct.to_string data))), names, rdata_start + len)
    ) >>= fun (b, names, rdata_end) ->
    guard (len = rdata_end - rdata_start) (`Leftover (rdata_end, "rdata")) >>| fun () ->
    (b, names, rdata_end)

  let text_b ?origin ?default_ttl name (B (key, v)) =
    text ?origin ?default_ttl name key v
end

module Name_rr_map = struct
  type t = Rr_map.t Domain_name.Map.t

  let empty = Domain_name.Map.empty

  let equal a b =
    Domain_name.Map.equal (Rr_map.equal { f = Rr_map.equal_rr }) a b

  let pp ppf map =
    List.iter (fun (name, rr_map) ->
        Fmt.(list ~sep:(unit "@.") string) ppf
          (List.map (Rr_map.text_b name) (Rr_map.bindings rr_map)))
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

    let compare_id (id, _) (id', _) = int_compare id id'

    let compare (id, flags) (id', flags') =
      andThen (int_compare id id') (Flags.compare flags flags')

    let pp ppf ((id, flags), query, operation, rcode) =
      Fmt.pf ppf "%04X (%s) operation %a rcode @[%a@] flags: @[%a@]"
        id (if query then "query" else "response")
        Opcode.pp operation
        Rcode.pp rcode
        Fmt.(list ~sep:(unit ", ") Flag.pp) (Flags.elements flags)

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
      let open Rresult.R.Infix in
      (* we only access the first 4 bytes, but anything <12 is a bad DNS frame *)
      guard (Cstruct.len buf >= len) `Partial >>= fun () ->
      let hdr = Cstruct.BE.get_uint16 buf 2 in
      let op = (hdr land 0x7800) lsr 11
      and rc = hdr land 0x000F
      in
      Opcode.of_int ~off:2 op >>= fun operation ->
      Rcode.of_int ~off:3 rc >>= fun rcode ->
      let id = Cstruct.BE.get_uint16 buf 0
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
      Cstruct.BE.set_uint16 buf 0 id ;
      Cstruct.BE.set_uint16 buf 2 header

    (*
    let%expect_test "encode_decode_header" =
      let eq (hdr, query, op, rc) (hdr', query', op', rc') =
        compare hdr hdr' = 0 && rc = rc' && query = query' && op = op'
      and cs = Cstruct.create 12
      in
      let test_cs ?(off = 0) len =
        Format.printf "%a" Cstruct.hexdump_pp (Cstruct.sub cs off len)
      and test_hdr a b =
        match b with
        | Error _ -> Format.printf "error"
        | Ok b -> if eq a b then Format.printf "ok" else Format.printf "not ok"
      in
      let hdr = (1, Flags.empty), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* basic query encoding works *)
      test_cs 4;
      [%expect {|00 01 00 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x1010, Flags.empty), false, Opcode.Query, Rcode.NXDomain in
      encode cs hdr; (* second encoded header works *)
      test_cs 4;
      [%expect {|10 10 80 03|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x0101, Flags.singleton `Authentic_data), true, Opcode.Update, Rcode.NoError in
      encode cs hdr; (* flags look nice *)
      test_cs 4;
      [%expect {|01 01 28 20|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x0080, Flags.singleton `Truncation), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* truncation flag *)
      test_cs 4;
      [%expect {|00 80 02 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x8080, Flags.singleton `Checking_disabled), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* checking disabled flag *)
      test_cs 4;
      [%expect {|80 80 00 10|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0x1234, Flags.singleton `Authoritative), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* authoritative flag *)
      test_cs 4;
      [%expect {|12 34 04 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0xFFFF, Flags.singleton `Recursion_desired), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* rd flag *)
      test_cs 4;
      [%expect {|ff ff 01 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr =
        let flags = Flags.(add `Recursion_desired (singleton `Authoritative)) in
        (0xE0E0, flags), true, Opcode.Query, Rcode.NoError
      in
      encode cs hdr; (* rd + auth *)
      test_cs 4;
      [%expect {|e0 e0 05 00|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let hdr = (0xAA00, Flags.singleton `Recursion_available), true, Opcode.Query, Rcode.NoError in
      encode cs hdr; (* ra *)
      test_cs 4;
      [%expect {|aa 00 00 80|}];
      test_hdr hdr (decode cs);
      [%expect {|ok|}];
      let test_err = function
        | Ok _ -> Format.printf "ok, expected error"
        | Error _ -> Format.printf "ok"
      in
      let data = Cstruct.of_hex "0000 7000 0000 0000 0000 0000" in
      test_err (decode data);
      [%expect {|ok|}];
      let data = Cstruct.of_hex "0000 000e 0000 0000 0000 0000" in
      test_err (decode data);
      [%expect {|ok|}]
      *)
  end

  let decode_ntc names buf off =
    let open Rresult.R.Infix in
    Name.decode names buf ~off >>= fun (name, names, off) ->
    guard (Cstruct.len buf - off >= 4) `Partial >>= fun () ->
    let typ = Cstruct.BE.get_uint16 buf off
    and cls = Cstruct.BE.get_uint16 buf (off + 2)
    (* CLS is interpreted differently by OPT, thus no int_to_clas called here *)
    in
    match typ with
    | x when x = Edns.rtyp -> Ok ((name, `Edns, cls), names, off + 4)
    | x when x = Tsig.rtyp -> Ok ((name, `Tsig, cls), names, off + 4)
    | x when x = Rr_map.ixfr_rtyp -> Ok ((name, `Ixfr, cls), names, off + 4)
    | x when x = Rr_map.axfr_rtyp -> Ok ((name, `Axfr, cls), names, off + 4)
    | x when x = Rr_map.any_rtyp -> Ok ((name, `Any, cls), names, off + 4)
    | x ->
      Rr_map.of_int x >>| fun k ->
      (name, `K k, cls), names, off + 4

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
      let open Rresult.R.Infix in
      decode_ntc names buf off >>= fun ((name, typ, c), names, off) ->
      Class.of_int ~off c >>= fun clas ->
      match typ with
      | `Edns | `Tsig ->
        let msg = Fmt.strf "bad RRTYp in question %a" Rr_map.pp_rr typ in
        Error (`Malformed (off, msg))
      | (`Axfr | `Ixfr | `Any | `K _ as t) ->
        if clas = Class.IN then
          Ok ((name, t), names, off)
        else
          Error (`Not_implemented (off, Fmt.strf "bad class in question 0x%x" c))

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
    let open Rresult.R.Infix in
    decode_ntc names buf off >>= fun ((name, typ, clas), names, off) ->
    guard (clas = Class.(to_int IN))
      (`Not_implemented (off, Fmt.strf "rr class not IN 0x%x" clas)) >>= fun () ->
    match typ with
    | `K k ->
      Rr_map.decode names buf off k >>| fun (b, names, off) ->
      (name, b, names, off)
    | _ ->
      Error (`Not_implemented (off, Fmt.strf "unexpected RR typ %a"
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
    let open Rresult.R.Infix in
    decode_ntc names buf off >>= fun ((name, typ, clas), names, off') ->
    match typ with
    | `Edns when edns = None ->
      (* OPT is special and needs class! (also, name is guarded to be .) *)
      Edns.decode buf ~off >>| fun (edns, off') ->
      (map, Some edns, None), names, off'
    | `Tsig when tsig ->
      guard (clas = Class.(to_int ANY_CLASS))
        (`Malformed (off, Fmt.strf "tsig class must be ANY 0x%x" clas)) >>= fun () ->
      Tsig.decode names buf ~off:off' >>| fun (tsig, names, off') ->
      (map, edns, Some (name, tsig, off)), names, off'
    | `K t ->
      guard (clas = Class.(to_int IN))
        (`Malformed (off, Fmt.strf "additional class must be IN 0x%x" clas)) >>= fun () ->
      Rr_map.decode names buf off' t >>| fun (B (k, v), names, off') ->
      (Name_rr_map.add name k v map, edns, None), names, off'
    | _ -> Error (`Malformed (off, Fmt.strf "decode additional, unexpected rr %a"
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
      let open Rresult.R.Infix in
      let truncated = Flags.mem `Truncation flags in
      let ancount = Cstruct.BE.get_uint16 buf 6
      and aucount = Cstruct.BE.get_uint16 buf 8
      in
      let empty = Domain_name.Map.empty in
      decode_n_partial names buf off empty ancount >>= function
      | `Partial answer -> guard truncated `Partial >>| fun () -> (answer, empty), names, off, false, truncated
      | `Full (names, off, answer) ->
        decode_n_partial names buf off empty aucount >>= function
        | `Partial authority -> guard truncated `Partial >>| fun () -> (answer, authority), names, off, false, truncated
        | `Full (names, off, authority) -> Ok ((answer, authority), names, off, true, truncated)

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
      Cstruct.BE.set_uint16 buf 6 ancount ;
      let (names, off), aucount = encode_data authority names buf off in
      Cstruct.BE.set_uint16 buf 8 aucount ;
      names, off
  end

  module Axfr = struct

    type t = Soa.t * Name_rr_map.t

    let equal (soa, entries) (soa', entries') =
      Soa.compare soa soa' = 0 && Name_rr_map.equal entries entries'

    let pp ppf (soa, entries) =
      Fmt.pf ppf "AXFR soa %a data %a" Soa.pp soa Name_rr_map.pp entries

    let decode (_, flags) buf names off ancount =
      let open Rresult.R.Infix in
      guard (not (Flags.mem `Truncation flags)) `Partial >>= fun () ->
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
      guard (ancount >= 1)
        (`Malformed (6, Fmt.strf "AXFR needs at least one RRs in answer %d" ancount)) >>= fun () ->
      decode_rr names buf off >>= fun (name, B (k, v), names, off) ->
      if ancount = 1 then
        match k, v with
        | Soa, soa -> Ok (`Axfr_partial_reply (`First (soa : Soa.t), Name_rr_map.empty), names, off)
        | k, v -> Ok (`Axfr_partial_reply (`Mid, Name_rr_map.singleton name k v), names, off)
      else (* ancount > 1 *)
        (* TODO: verify name == zname in question, also all RR sub of zname *)
        let add name (Rr_map.B (k, v)) map = Name_rr_map.add name k v map in
        decode_n add decode_rr names buf off empty (ancount - 2) >>= fun (names, off, answer) ->
        decode_rr names buf off >>= fun (name', B (k', v'), names, off) ->
        (* TODO: verify that answer does not contain a SOA!? *)
        match k, v, k', v' with
        | Soa, soa, Soa, soa' ->
          guard (Domain_name.equal name name')
            (`Malformed (off, "AXFR SOA RRs do not use the same name")) >>= fun () ->
          guard (Soa.compare soa soa' = 0)
            (`Malformed (off, "AXFR SOA RRs are not equal")) >>| fun () ->
          (`Axfr_reply ((soa, answer) : Soa.t * Name_rr_map.t)), names, off
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
      Cstruct.BE.set_uint16 buf 6 (count + 2) ;
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
      Cstruct.BE.set_uint16 buf 6 (count + count' + count'') ;
      names, off

    let encode_reply next_buffer max_size question (soa, entries) =
      (* first packet MUST contain SOA *)
      let finish buf count off =
        Cstruct.BE.set_uint16 buf 6 count;
        Cstruct.sub buf 0 off
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
      let open Rresult.R.Infix in
      guard (Domain_name.equal name name')
        (`Malformed (off, "IXFR SOA RRs do not use the same name")) >>= fun () ->
      guard (f soa soa') (`Malformed (off, "IXFR SOA RRs are not equal"))

    (* parses up to count RRs until a SOA is found *)
    let rec rrs_and_soa buf names off count acc =
      let open Rresult.R.Infix in
      match count with
      | 0 -> Ok (acc, None, 0, names, off)
      | n ->
        decode_rr names buf off >>= fun (name, Rr_map.(B (k, v)), names, off) ->
        match k, v with
        | Rr_map.Soa, soa ->
          Ok (acc, (Some (name, soa) : ([ `raw ] Domain_name.t * Soa.t) option), pred n, names, off)
        | _ ->
          let acc = Name_rr_map.add name k v acc in
          rrs_and_soa buf names off (pred n) acc

    let decode (_, flags) buf names off ancount =
      let open Rresult.R.Infix in
      guard (not (Flags.mem `Truncation flags)) `Partial >>= fun () ->
      guard (ancount >= 1)
        (`Malformed (6, Fmt.strf "IXFR needs at least one RRs in answer %d" ancount)) >>= fun () ->
      decode_rr names buf off >>= fun (name, b, names, off) ->
      match ensure_soa b with
      | Error () -> Error (`Malformed (off, "IXFR first RR not a SOA"))
      | Ok soa ->
        (if ancount = 1 then
           Ok (`Empty, names, off)
         else if ancount = 2 then
           Ok (`Full Name_rr_map.empty, names, off)
         else
           decode_rr names buf off >>= fun (name', b, names, off) ->
           match ensure_soa b with
           | Error () ->
             (* this is a full AXFR *)
             let add name (Rr_map.B (k, v)) map = Name_rr_map.add name k v map in
             let map = add name' b Name_rr_map.empty in
             decode_n add decode_rr names buf off map (ancount - 3) >>| fun (names, off, answer) ->
             `Full answer, names, off
           | Ok oldsoa ->
             let rec diff_list dele add names off count oldname oldsoa =
               (* actual form is: curr_SOA [SOA0 .. DELE .. SOA1 .. ADD] curr_SOA'
                  - we need to ensure: curr_SOA = curr_SOA' (below)
                  - SOA0 < curr_SOA
                  - SOA1 < SOA0 *)
               soa_ok (fun old soa -> Soa.newer ~old soa) off oldname oldsoa name soa >>= fun () ->
               rrs_and_soa buf names off count dele >>= fun (dele', soa', count', names, off) ->
               match soa' with
               | None -> (* this is the end *)
                 guard (count' = 0) (`Malformed (off, "IXFR expected SOA, found end")) >>| fun () ->
                 dele', add, names, off
               | Some (name', soa') ->
                 soa_ok (fun old soa -> Soa.newer ~old soa) off oldname oldsoa name' soa' >>= fun () ->
                 rrs_and_soa buf names off count' add >>= fun (add', soa'', count'', names, off) ->
                 match soa'' with
                 | None -> (* this is the actual end! *)
                   guard (count'' = 0) (`Malformed (off, "IXFR expected SOA after adds, found end")) >>| fun () ->
                   dele', add', names, off
                 | Some (name'', soa'') ->
                   diff_list dele' add' names off count'' name'' soa''
             in
             diff_list Name_rr_map.empty Name_rr_map.empty names off (ancount - 3) name' oldsoa >>| fun (dele, add, names, off) ->
             `Difference (oldsoa, dele, add), names, off) >>= fun (content, names, off) ->
        if ancount > 1 then
          decode_rr names buf off >>= fun (name', b, names, off) ->
          match ensure_soa b with
          | Ok soa' ->
            soa_ok (fun s s' -> Soa.compare s s' = 0) off name soa name' soa' >>| fun () ->
            ((soa, content), names, off)
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
      Cstruct.BE.set_uint16 buf 6 (count + count' + 1) ;
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
      let open Rresult.R.Infix in
      decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
      let off' = off + 6 in
      guard (Cstruct.len buf >= off') `Partial >>= fun () ->
      let ttl = Cstruct.BE.get_uint32 buf off in
      guard (ttl = 0l) (`Malformed (off, Fmt.strf "prereq TTL not zero %lu" ttl)) >>= fun () ->
      let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
      let r0 = guard (rlen = 0) (`Malformed (off + 4, Fmt.strf "prereq rdlength must be zero %d" rlen)) in
      Class.of_int cls >>= fun c ->
      match c, typ with
      | ANY_CLASS, `Any -> r0 >>= fun () -> Ok (name, Name_inuse, names, off')
      | NONE, `Any -> r0 >>= fun () -> Ok (name, Not_name_inuse, names, off')
      | ANY_CLASS, `K k -> r0 >>= fun () -> Ok (name, Exists k, names, off')
      | NONE, `K k -> r0 >>= fun () -> Ok (name, Not_exists k, names, off')
      | IN, `K k->
        Rr_map.decode names buf off k >>= fun (rdata, names, off'') ->
        Ok (name, Exists_data rdata, names, off'')
      | _ -> Error (`Malformed (off, Fmt.strf "prereq bad class 0x%x or typ %a"
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
      let open Rresult.R.Infix in
      decode_ntc names buf off >>= fun ((name, typ, cls), names, off) ->
      let off' = off + 6 in
      guard (Cstruct.len buf >= off') `Partial >>= fun () ->
      let ttl = Cstruct.BE.get_uint32 buf off in
      let rlen = Cstruct.BE.get_uint16 buf (off + 4) in
      let r0 = guard (rlen = 0) (`Malformed (off + 4, Fmt.strf "update rdlength must be zero %d" rlen)) in
      let ttl0 = guard (ttl = 0l) (`Malformed (off, Fmt.strf "update ttl must be zero %lu" ttl)) in
      Class.of_int cls >>= fun c ->
      match c, typ with
      | ANY_CLASS, `Any ->
        ttl0 >>= fun () ->
        r0 >>= fun () ->
        Ok (name, Remove_all, names, off')
      | ANY_CLASS, `K k ->
        ttl0 >>= fun () ->
        r0 >>= fun () ->
        Ok (name, Remove k, names, off')
      | NONE, `K k ->
        ttl0 >>= fun () ->
        Rr_map.decode names buf off k >>= fun (rdata, names, off) ->
        Ok (name, Remove_single rdata, names, off)
      | IN, `K k ->
        Rr_map.decode names buf off k >>= fun (rdata, names, off) ->
        Ok (name, Add rdata, names, off)
      | _ -> Error (`Malformed (off, Fmt.strf "bad update class 0x%x" cls))

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
        Fmt.(list ~sep:(unit ";@ ")
               (pair ~sep:(unit ":") Domain_name.pp
                  (list ~sep:(unit ", ") pp_prereq)))
        (Domain_name.Map.bindings prereq)
        Fmt.(list ~sep:(unit ";@ ")
               (pair ~sep:(unit ":") Domain_name.pp
                  (list ~sep:(unit ", ") pp_update)))
        (Domain_name.Map.bindings update)

    let decode _header question buf names off =
      let open Rresult.R.Infix in
      let prcount = Cstruct.BE.get_uint16 buf 6
      and upcount = Cstruct.BE.get_uint16 buf 8
      in
      let add_to_list name a map =
        let base = match Domain_name.Map.find name map with None -> [] | Some x -> x in
        Domain_name.Map.add name (base @ [a]) map
      in
      guard (snd question = `K Rr_map.(K Soa))
        (`Malformed (off, Fmt.strf "update question not SOA %a" Rr_map.pp_rr (snd question))) >>= fun () ->
      decode_n add_to_list decode_prereq names buf off Domain_name.Map.empty prcount >>= fun (names, off, prereq) ->
      decode_n add_to_list decode_update names buf off Domain_name.Map.empty upcount >>= fun (names, off, update) ->
      Ok ((prereq, update), names, off)

    let encode_map map f names buf off =
      Domain_name.Map.fold (fun name v ((names, off), count) ->
          List.fold_left (fun ((names, off), count) p ->
              f names buf off count name p) ((names, off), count) v)
        map ((names, off), 0)

    let encode names buf off _question (prereq, update) =
      let (names, off), prereq_count = encode_map prereq encode_prereq names buf off in
      Cstruct.BE.set_uint16 buf 6 prereq_count ;
      let (names, off), update_count = encode_map update encode_update names buf off in
      Cstruct.BE.set_uint16 buf 8 update_count ;
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
    | `Notify soa -> Fmt.pf ppf "notify %a" Fmt.(option ~none:(unit "no") Soa.pp) soa
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
        Fmt.(option ~none:(unit "no data") Answer.pp) q

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
      Fmt.(option ~none:(unit "no") Edns.pp) t.edns
      Fmt.(option ~none:(unit "no") pp_tsig) t.tsig

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
    let open Rresult.R.Infix in
    decode_n_additional names buf off Domain_name.Map.empty None None adcount >>= function
    | `Partial (additional, edns, tsig) ->
      Log.warn (fun m -> m "truncated packet (allowed? %B)" allow_trunc) ;
      guard allow_trunc `Partial >>= fun () ->
      Ok (additional, edns, tsig)
    | `Full (off, additional, edns, tsig) ->
      (if Cstruct.len buf > off then
         let n = Cstruct.len buf - off in
         Log.warn (fun m -> m "received %d extra bytes %a"
                       n Cstruct.hexdump_pp (Cstruct.sub buf off n))) ;
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
    let open Rresult.R.Infix in
    Header.decode buf >>= fun (header, query, operation, rcode) ->
    let q_count = Cstruct.BE.get_uint16 buf 4
    and an_count = Cstruct.BE.get_uint16 buf 6
    and au_count = Cstruct.BE.get_uint16 buf 8
    and ad_count = Cstruct.BE.get_uint16 buf 10
    in
    guard (q_count = 1) (`Malformed (4, "question count not one")) >>= fun () ->
    Question.decode buf >>= fun (question, names, off) ->
    begin
      if query then begin
        (* guard noerror - what's the point in handling error requests *)
        guard (rcode = Rcode.NoError) (`Request_rcode rcode) >>= fun () ->
        (* also guard for it not being truncated!? *)
        guard (not (Flags.mem `Truncation (snd header)))
          `Truncated_request >>= fun () ->
        begin match operation with
          | Opcode.Query ->
            guard (an_count = 0) (`Query_answer_count an_count) >>= fun () ->
            begin match snd question with
              | `Axfr ->
                guard (au_count = 0) (`Query_authority_count au_count) >>| fun () ->
                `Axfr_request, names, off
              | `Ixfr ->
                guard (au_count = 1) (`Query_authority_count au_count) >>= fun () ->
                Answer.decode header buf names off >>= fun ((_, au), names, off, _, _) ->
                begin match Name_rr_map.find (fst question) Rr_map.Soa au with
                  | None -> Error (`Malformed (off, "ixfr request without soa"))
                  | Some soa -> Ok (`Ixfr_request soa, names, off)
                end
              | _ ->
                guard (au_count = 0) (`Query_authority_count au_count) >>| fun () ->
                `Query, names, off
            end
          | Opcode.Notify ->
            guard (an_count = 0 || an_count = 1) (`Notify_answer_count an_count) >>= fun () ->
            guard (au_count = 0) (`Notify_authority_count au_count) >>= fun () ->
            Answer.decode header buf names off >>| fun ((ans, _), names, off, _, _) ->
            let soa = Name_rr_map.find (fst question) Rr_map.Soa ans in
            `Notify soa, names, off
          | Opcode.Update ->
            Update.decode header question buf names off >>| fun (update, names, off) ->
            `Update update, names, off
          | x -> Error (`Not_implemented (2, Fmt.strf "unsupported opcode %a" Opcode.pp x))
        end >>| fun (request, names, off) ->
        request, names, off, true, false
      end else begin match rcode with
        | Rcode.NoError -> begin match operation with
            | Opcode.Query -> begin match snd question with
                | `Axfr ->
                  guard (au_count = 0) (`Malformed (8, Fmt.strf "AXFR with aucount %d > 0" au_count)) >>= fun () ->
                  Axfr.decode header buf names off an_count >>| fun (axfr, names, off) ->
                  axfr, names, off, true, false
                | `Ixfr ->
                  guard (au_count = 0) (`Malformed (8, Fmt.strf "IXFR with aucount %d > 0" au_count)) >>= fun () ->
                  Ixfr.decode header buf names off an_count >>| fun (ixfr, names, off) ->
                  `Ixfr_reply ixfr, names, off, true, false
                | _ ->
                  Answer.decode header buf names off >>| fun (answer, names, off, cont, allow_trunc) ->
                  `Answer answer, names, off, cont, allow_trunc
              end
            | Opcode.Notify ->
              guard (an_count = 0) (`Notify_ack_answer_count an_count) >>= fun () ->
              guard (au_count = 0) (`Notify_ack_authority_count au_count) >>| fun () ->
              `Notify_ack, names, off, true, false
            | Opcode.Update ->
              guard (an_count = 0) (`Update_ack_answer_count an_count) >>= fun () ->
              guard (au_count = 0) (`Update_ack_authority_count au_count) >>| fun () ->
              `Update_ack, names, off, true, false
            | x -> Error (`Not_implemented (2, Fmt.strf "unsupported opcode %a"
                                              Opcode.pp x))
          end
        | x ->
          Answer.decode header buf names off >>| fun (query, names, off, cont, allow_trunc) ->
          let query = if Answer.is_empty query then None else Some query in
          `Rcode_error (x, operation, query), names, off, cont, allow_trunc
      end >>| fun (reply, names, off, cont, allow_trunc) ->
        reply, names, off, cont, allow_trunc
    end >>= fun (data, names, off, cont, allow_trunc) ->
    (if cont then
       decode_additional names buf off allow_trunc ad_count
     else
       Ok (Name_rr_map.empty, None, None)) >>= fun (additional, edns, tsig) ->
    (* now in case of error, we may switch the rcode *)
    ext_rcode ~off:off rcode edns >>= with_rcode data >>| fun data ->
    { header ; question ; data ; additional ; edns ; tsig }

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
      let adcount = Cstruct.BE.get_uint16 buf 10 in
      let off = Edns.encode { edns with Edns.extended_rcode } buf off in
      Cstruct.BE.set_uint16 buf 10 (adcount + 1) ;
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
          Cstruct.BE.set_uint16 buf 4 1 ;
          let names, off = encode_t names buf off t.question t.data in
          (* TODO we used to drop all other additionals if rcode <> 0 *)
          let (_names, off), adcount = encode_data t.additional names buf off in
          Cstruct.BE.set_uint16 buf 10 adcount ;
          (* TODO if edns embedding would truncate, we used to drop all other additionals and only encode EDNS *)
          (* TODO if additional would truncate, drop them (do not set truncation) *)
          encode_edns Rcode.NoError edns buf off, false
        with Invalid_argument _ -> (* set truncated *)
          (* if we failed to store data into buf, set truncation bit! *)
          Cstruct.set_uint8 buf 2 (0x02 lor (Cstruct.get_uint8 buf 2)) ;
          Cstruct.len buf, true
      in
      Cstruct.sub buf 0 off, trunc
    in
    let rec doit s =
      let cs = Cstruct.create s in
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
      let buf = Cstruct.create max in
      Header.encode buf (t.header, query, opcode, rcode);
      let names, off = Question.encode Domain_name.Map.empty buf Header.len t.question in
      Cstruct.BE.set_uint16 buf 4 1 ;
      names, buf, off
    in
    Axfr.encode_reply new_buffer max_size t.question data, max
    (* let (_names, off), adcount = encode_data t.additional names buf off in *)
    (* encode_edns Rcode.NoError edns buf off, false *)

  let raw_error buf rcode =
    (* copy id from header, retain opcode, set rcode to ServFail
       if we receive a fragment < 12 bytes, it's not worth bothering *)
    if Cstruct.len buf < 12 then
      None
    else
      let query = Cstruct.get_uint8 buf 2 lsr 7 = 0 in
      if not query then (* never reply to an answer! *)
        None
      else
        let hdr = Cstruct.create 12 in
        (* manually copy the id from the incoming buf *)
        Cstruct.BE.set_uint16 hdr 0 (Cstruct.BE.get_uint16 buf 0) ;
        (* manually copy the opcode from the incoming buf, and set response *)
        Cstruct.set_uint8 hdr 2 (0x80 lor ((Cstruct.get_uint8 buf 2) land 0x78)) ;
        (* set rcode *)
        Cstruct.set_uint8 hdr 3 ((Rcode.to_int rcode) land 0xF) ;
        let extended_rcode = Rcode.to_int rcode lsr 4 in
        if extended_rcode = 0 then
          Some hdr
        else
          (* need an edns! *)
          let edns = Edns.create ~extended_rcode () in
          let buf = Edns.allocate_and_encode edns in
          Cstruct.BE.set_uint16 hdr 10 1 ;
          Some (Cstruct.append hdr buf)
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

  type verify = ?mac:Cstruct.t -> Ptime.t -> Packet.t ->
    [ `raw ] Domain_name.t -> ?key:Dnskey.t -> Tsig.t -> Cstruct.t ->
    (Tsig.t * Cstruct.t * Dnskey.t, e * Cstruct.t option) result

  let no_verify ?mac:_ _ _ _ ?key:_ tsig _ =
    Error (`Bad_key (Domain_name.of_string_exn "no.verification", tsig), None)

  type sign = ?mac:Cstruct.t -> ?max_size:int -> [ `raw ] Domain_name.t ->
    Tsig.t -> key:Dnskey.t -> Packet.t -> Cstruct.t ->
    (Cstruct.t * Cstruct.t) option

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

let counter_metrics ~f name =
  let open Metrics in
  let doc = "Counter metrics" in
  let incr, get = create ~f in
  let data thing = incr thing; Data.v (get ()) in
  Src.v ~doc ~tags:Metrics.Tags.[] ~data name
