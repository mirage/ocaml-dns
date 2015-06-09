
open OUnit2
open Printf

(* Adapted from ocaml-pcap/print/print.ml *)

cstruct ethernet {
    uint8_t        dst[6];
    uint8_t        src[6];
    uint16_t       ethertype
  } as big_endian

cstruct ipv4 {
    uint8_t        hlen_version;
    uint8_t        tos;
    uint16_t       len;
    uint16_t       id;
    uint16_t       off;
    uint8_t        ttl;
    uint8_t        proto;
    uint16_t       csum;
    uint8_t        src[4];
    uint8_t        dst[4]
  } as big_endian

cstruct udpv4 {
    uint16_t source_port;
    uint16_t dest_port;
    uint16_t length;
    uint16_t checksum
  } as big_endian

let load_pcap path =
  let fd = Unix.(openfile path [O_RDONLY] 0) in
  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  let buf = Cstruct.of_bigarray buf in
  let header, body = Cstruct.split buf Pcap.sizeof_pcap_header in
  match Pcap.detect header with
  | Some h ->
    Pcap.packets h body
  | None ->
    assert_failure "Not pcap format"

let load_packet path =
  match (load_pcap path) () with
  | Some (hdr, eth) ->
    assert_equal 0x0800 (get_ethernet_ethertype eth);
    let ip = Cstruct.shift eth sizeof_ethernet in
    let version = get_ipv4_hlen_version ip lsr 4 in
    assert_equal 4 version;
    assert_equal 17 (get_ipv4_proto ip);
    let udp = Cstruct.shift ip sizeof_ipv4 in
    let body = Cstruct.shift udp sizeof_udpv4 in
    Dns.Buf.of_cstruct body
  | None ->
    assert_failure "No packets"

let hexdump ibuf =
  let n = Dns.Buf.length ibuf in
  let obuf = Buffer.create (3 * n) in
  let rec acc i =
    let ch = (int_of_char ibuf.{i}) in
    Buffer.add_char obuf (if ch < 32 || ch >= 127 then '.' else ibuf.{i});
    Buffer.add_string obuf (sprintf "%.2x " ch);
    if i mod 16 = 15 then Buffer.add_char obuf '\n';
    if i < n - 1 then acc (i + 1);
  in
  if n >= 1 then acc 0;
  if n mod 16 != 15 then Buffer.add_char obuf '\n';
  Buffer.contents obuf

open Dns
open Packet

let tests =
  "Packet" >:::
  [
    "parse-dns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-q-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0x930b packet.id;
        assert_equal ~msg:"qr" Query packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" false packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" true packet.detail.rd;
        assert_equal ~msg:"ra" false packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 1 (List.length packet.questions);
        assert_equal ~msg:"#an" 0 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let q = List.hd packet.questions in
        assert_equal ~msg:"q_name" "www.google.com" (Name.to_string q.q_name);
        assert_equal ~msg:"q_type" Q_A q.q_type;
        assert_equal ~msg:"q_class" Q_IN q.q_class;
        assert_equal ~msg:"q_unicast" Q_Normal q.q_unicast;
    );

    "marshal-dns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-q-A.pcap" in
        let packet =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=true; ra=false; rcode=NoError
          } in
          let q = make_question Q_A (Name.of_string "www.google.com") in
          {
            id=0x930b; detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          } in
        let buf = marshal (Dns.Buf.create 512) packet in
        assert_equal ~printer:hexdump raw buf
          [@ref mdns "s18.8_p1_c1"] [@ref mdns "s18.9_p1_c1"] [@ref mdns "s18.10_p1_c1"]
    );

    "parse-dns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-r-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0x930b packet.id;
        assert_equal ~msg:"qr" Response packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" false packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" true packet.detail.rd;
        assert_equal ~msg:"ra" true packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 1 (List.length packet.questions);
        assert_equal ~msg:"#an" 5 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let q = List.hd packet.questions in
        assert_equal ~msg:"q_name" "www.google.com" (Name.to_string q.q_name);
        assert_equal ~msg:"q_type" Q_A q.q_type;
        assert_equal ~msg:"q_class" Q_IN q.q_class;
        assert_equal ~msg:"q_unicast" Q_Normal q.q_unicast;

        let rev_answers = List.rev packet.answers in
        let expected_fourth = [208; 211; 209; 212; 210] in
        List.iter2 (fun fourth a ->
            assert_equal ~msg:"name" "www.google.com" (Name.to_string a.name);
            assert_equal ~msg:"cls" RR_IN a.cls;
            assert_equal ~msg:"flush" false a.flush;
            assert_equal ~msg:"ttl" (Int32.of_int 220) a.ttl;
            let expected_addr = "74.125.237." ^ (string_of_int fourth) in
            match a.rdata with
            | A addr -> assert_equal ~msg:"A" ~printer:(fun s -> s) expected_addr (Ipaddr.V4.to_string addr)
            | _ -> assert_failure "RR type";
          ) expected_fourth rev_answers
    );

    "marshal-dns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "dns-r-A.pcap" in
        let packet =
          let detail = {
            qr=Response; opcode=Standard; aa=false;
            tc=false; rd=true; ra=true; rcode=NoError
          } in
          let q = make_question ~q_class:Q_IN ~q_unicast:Q_Normal Q_A (Name.of_string "www.google.com") in
          let answers = List.map (fun fourth -> {
                name=q.q_name; cls=RR_IN; flush=false; ttl=Int32.of_int 220;
                rdata=A (Ipaddr.V4.of_string_exn (sprintf "74.125.237.%d" fourth));
              }) [208; 211; 209; 212; 210]
          in
          {
            id=0x930b; detail; questions=[q];
            answers; authorities=[]; additionals=[];
          } in
        let buf = marshal (Dns.Buf.create 512) packet in
        assert_equal ~printer:hexdump raw buf
    );

    "parse-mdns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-q-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0 packet.id;
        assert_equal ~msg:"qr" Query packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" false packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" false packet.detail.rd;
        assert_equal ~msg:"ra" false packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 1 (List.length packet.questions);
        assert_equal ~msg:"#an" 0 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let q = List.hd packet.questions in
        assert_equal ~msg:"q_name" "cubieboard2.local" (Name.to_string q.q_name);
        assert_equal ~msg:"q_type" Q_A q.q_type;
        assert_equal ~msg:"q_class" Q_IN q.q_class;
        assert_equal ~msg:"q_unicast" Q_Normal q.q_unicast;
    );

    "marshal-mdns-q-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-q-A.pcap" in
        let packet =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=false; ra=false; rcode=NoError
          } in
          let q = {
            q_name=(Name.of_string "cubieboard2.local");
            q_type=Q_A; q_class=Q_IN; q_unicast=Q_Normal;
          } in
          {
            id=0; detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          } in
        let buf = marshal (Dns.Buf.create 512) packet in
        assert_equal ~printer:hexdump raw buf
    );

    "parse-mdns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-r-A.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"id" 0 packet.id;
        assert_equal ~msg:"qr" Response packet.detail.qr;
        assert_equal ~msg:"opcode" Standard packet.detail.opcode;
        assert_equal ~msg:"aa" true packet.detail.aa;
        assert_equal ~msg:"tc" false packet.detail.tc;
        assert_equal ~msg:"rd" false packet.detail.rd;
        assert_equal ~msg:"ra" false packet.detail.ra;
        assert_equal ~msg:"rcode" NoError packet.detail.rcode;
        assert_equal ~msg:"#qu" 0 (List.length packet.questions);
        assert_equal ~msg:"#an" 1 (List.length packet.answers);
        assert_equal ~msg:"#au" 0 (List.length packet.authorities);
        assert_equal ~msg:"#ad" 0 (List.length packet.additionals);

        let a = List.hd packet.answers in
        assert_equal ~msg:"name" "cubieboard2.local" (Name.to_string a.name);
        assert_equal ~msg:"cls" RR_IN a.cls;
        assert_equal ~msg:"flush" true a.flush;
        assert_equal ~msg:"ttl" (Int32.of_int 120) a.ttl;
        match a.rdata with
        | A addr -> assert_equal ~msg:"A" "192.168.2.106" (Ipaddr.V4.to_string addr)
        | _ -> assert_failure "RR type";
    );

    "marshal-mdns-r-A" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-r-A.pcap" in
        let packet =
          let detail = {
            qr=Response; opcode=Standard; aa=true;
            tc=false; rd=false; ra=false; rcode=NoError
          } in
          let a = {
            name=(Name.of_string "cubieboard2.local"); cls=RR_IN; flush=true; ttl=Int32.of_int 120;
            rdata=A (Ipaddr.V4.of_string_exn "192.168.2.106");
          } in
          {
            id=0; detail; questions=[];
            answers=[a]; authorities=[]; additionals=[];
          } in
        let buf = marshal (Dns.Buf.create 512) packet in
        assert_equal ~printer:hexdump raw buf
    );

    "q_unicast" >:: (fun test_ctxt ->
        (* Verify that q_unicast=Q_mDNS_Unicast can be marshalled and then parsed *)
        let packet =
          let detail = {
            qr=Query; opcode=Standard; aa=false;
            tc=false; rd=false; ra=false; rcode=NoError
          } in
          let q = {
            q_name=(Name.of_string "cubieboard2.local");
            q_type=Q_A; q_class=Q_IN; q_unicast=Q_mDNS_Unicast;
          } in
          {
            id=0; detail; questions=[q];
            answers=[]; authorities=[]; additionals=[];
          } in
        let buf = marshal (Dns.Buf.create 512) packet in
        let parsed = parse buf in
        let q = List.hd parsed.questions in
        assert_equal Q_mDNS_Unicast q.q_unicast
      );

    "parse-mdns-r-SD" >:: (fun test_ctxt ->
        let raw = load_packet "mdns-r-SD.pcap" in
        let packet = parse raw in
        assert_equal ~msg:"#an" ~printer:string_of_int 4 (List.length packet.answers);
        let srv_name = "_udisks-ssh._tcp.local" in
        let srv_inst = "luke-xps." ^ srv_name in

        let a = List.nth packet.answers 3 in
        begin
          assert_equal ~msg:"TXT name" ~printer:(fun s -> s) srv_inst
                       (Name.to_string a.name);
          assert_equal ~msg:"TXT cls" RR_IN a.cls;
          assert_equal ~msg:"TXT flush" true a.flush;
          assert_equal ~msg:"TXT ttl" (Int32.of_int 4500) a.ttl;
          match a.rdata with
          | TXT l ->
            assert_equal ~msg:"TXT#" 1 (List.length l);
            assert_equal ~msg:"TXT" "" (List.hd l)
          | _ -> assert_failure "not TXT";
        end;

        let a = List.nth packet.answers 2 in
        begin
          assert_equal ~msg:"PTR name" ~printer:(fun s -> s) srv_name (Name.to_string a.name);
          assert_equal ~msg:"PTR cls" RR_IN a.cls;
          assert_equal ~msg:"PTR flush" false a.flush;
          assert_equal ~msg:"PTR ttl" (Int32.of_int 4500) a.ttl;
          match a.rdata with
          | PTR ptr -> assert_equal ~msg:"PTR" ~printer:(fun s -> s) srv_inst (Name.to_string ptr)
          | _ -> assert_failure "not PTR";
        end;

        let a = List.nth packet.answers 1 in
        begin
          assert_equal ~msg:"SRV name" ~printer:(fun s -> s) srv_inst (Name.to_string a.name);
          assert_equal ~msg:"SRV cls" RR_IN a.cls;
          assert_equal ~msg:"SRV flush" true a.flush;
          assert_equal ~msg:"SRV ttl" (Int32.of_int 120) a.ttl;
          match a.rdata with
          | SRV (priority, weight, port, srv) ->
            assert_equal 0 priority;
            assert_equal 0 weight;
            assert_equal 22 port;
            assert_equal ~msg:"SRV" ~printer:(fun s -> s) "luke-xps.local" (Name.to_string srv)
          | _ -> assert_failure "not SRV";
        end;

        let a = List.nth packet.answers 0 in
        begin
          assert_equal ~msg:"PTR2 name" ~printer:(fun s -> s) "_services._dns-sd._udp.local" (Name.to_string a.name);
          assert_equal ~msg:"PTR2 cls" RR_IN a.cls;
          assert_equal ~msg:"PTR2 flush" false a.flush;
          assert_equal ~msg:"PTR2 ttl" (Int32.of_int 4500) a.ttl;
          match a.rdata with
          | PTR ptr -> assert_equal ~msg:"PTR2" ~printer:(fun s -> s) srv_name (Name.to_string ptr)
          | _ -> assert_failure "not PTR2";
        end;
      );

    "parse-mdns-r-SD2" >:: (fun test_ctxt ->
        (* Compared to parse-mdns-r-SD above, this one is a better test of decompression *)
        (* TODO: this packet was generated by ocaml-dns so it may not be 100% realistic *)
        let raw = load_packet "mdns-r-SD2.pcap" in
        let packet = parse raw in
        let expected_str =
          "0000 Response:0 a:c:nr:rn 0 <qs:> \
           <an:\
           _snake._tcp.local <IN|120> [PTR (dugite._snake._tcp.local)],\
           _snake._tcp.local <IN|120> [PTR (tiger._snake._tcp.local)],\
           _snake._tcp.local <IN|120> [PTR (king brown._snake._tcp.local)]> \
           <au:> <ad:\
           king brown._snake._tcp.local <IN|120> [TXT (txtvers=1species=Pseudechis australis)],\
           king brown._snake._tcp.local <IN|120> [SRV (0,0,33333, fake3.local)],\
           tiger._snake._tcp.local <IN|120> [TXT (txtvers=1species=Notechis scutatus)],\
           tiger._snake._tcp.local <IN|120> [SRV (0,0,33333, fake1.local)],\
           dugite._snake._tcp.local <IN|120> [TXT (txtvers=1species=Pseudonaja affinis)],\
           dugite._snake._tcp.local <IN|120> [SRV (0,0,33333, fake2.local)]\
           >" in
        assert_equal ~msg:"Packet.to_string" ~printer:(fun s -> s) expected_str (to_string packet)
          [@ref mdns "s18.14_p5_c1"] [@ref mdns "s18.14_p6_c1"]
      );

  ]

