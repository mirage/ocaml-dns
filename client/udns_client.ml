type 'key query_state =
  { protocol : Udns_packet.proto ;
    key: 'key ;
    header : Udns_packet.header ;
    question : Udns_packet.question ; (* we only handle one *)
  } constraint 'key = 'a Udns_map.key

let make_query protocol hostname
    : 'xy  ->
      Cstruct.t * 'xy query_state =
  (* SRV records: Service + Protocol are case-insensitive, see RFC2728 pg2. *)
  fun record_type ->
  let question : Udns_packet.question =
    (* Udns_map.k_to_rr_typ *)
    { q_name = hostname ; q_type = Udns_map.k_to_rr_typ record_type } in
  let query : Udns_packet.query =
    { question = [question] ;
      answer = [] ; authority = [] ; additional = [] } in
  let header = {
    Udns_packet.id = Random.int 0xffff ; (* TODO *)
      query = true ; operation = Udns_enum.Query;
      authoritative = false ; truncation = false; recursion_desired = true ;
      recursion_available = true; authentic_data = false;
      checking_disabled = false; rcode = Udns_enum.NoError } in
  (*let max_size, edns = Udns_packet.size_edns None None proto query in*)
  let cs , _ =
    Udns_packet.encode ~max_size:1200 ?edns:None
      protocol header (`Query query) in
  begin match protocol with
    | `Udp -> cs
    | `Tcp ->
      let len_field = Cstruct.create 2 in
      Cstruct.BE.set_uint16 len_field 0 (Cstruct.len cs) ;
      Cstruct.concat [len_field ; cs]
  end, { protocol ; header; question ; key = record_type }

let parse_response (type requested)
  : requested Udns_map.k query_state -> Cstruct.t ->
    (requested, [< `Partial | `Msg of string]) result =
  fun state buf ->
  let open Rresult in
  begin match state.protocol with (* consume TCP two-byte length prefix: *)
    | `Udp -> Ok buf
    | `Tcp ->
      begin match Cstruct.BE.get_uint16 buf 0 with
        | exception Invalid_argument _ -> Error `Partial (* TODO *)
        | pkt_len when pkt_len > Cstruct.len buf -2 ->
          Error `Partial (* TODO return remaining # *)
        | pkt_len -> Ok (Cstruct.sub buf 2 pkt_len)
      end
  end >>= fun buf ->
  match Udns_packet.decode buf with
  | Ok (({rcode = NoError ; operation = Query ; id = hdr_id;
          query = false; _ },
         `Query resp, _ (* what is flags? *), _tsig), _intwhatisthisTODO)
    when hdr_id = state.header.id
      && resp.question = [state.question]
    ->
    let rr_map = Udns_map.of_rrs resp.answer in
    let rec follow_cname counter q_name =
      if counter <= 0 then Error (`Msg "CNAME recursion too deep")
      else
        Domain_name.Map.find_opt q_name rr_map
        |> R.of_option ~none:(fun () ->
            R.error_msgf "Can't find relevant map in response:@ \
                          %a in [%a]"
              Domain_name.pp q_name
              Udns_packet.pp_rrs resp.answer
          ) >>= fun relevant_map ->
      begin match (state.key : requested Udns_map.k) with
        | (Udns_map.Any : requested Udns_map.k) ->
          Ok (((resp.answer:Udns_packet.rr list) ,
               (((Udns_map.of_rrs resp.answer
                  |> Domain_name.Map.bindings
                  |> List.map fst
                  |> Domain_name.Set.of_list)
                ) : Domain_name.Set.t)):requested)
        | _ ->
          begin match Udns_map.find state.key relevant_map with
            | Some response -> Ok response
            | None ->
              begin match Udns_map.find Cname relevant_map with
                | None -> Error (`Msg "Invalid DNS response")
                | Some (_ttl, redirected_host) ->
                  follow_cname (pred counter) redirected_host
              end
          end
      end
    in
    follow_cname 20 state.question.q_name
  | Ok ((h, `Query q, opt, dsig), optint) ->
    R.error_msgf
      "QUERY: @[<v>hdr:%a (id: %d = %d) (q=q: %B)@ query:%a  opt:%a dsig:%B\
       optint:%a@,@]"
      Udns_packet.pp_header h
      h.id state.header.id
      (q.question = [state.question])
      Udns_packet.pp_query q
      (Fmt.option Udns_packet.pp_opt) opt
      (match dsig with None -> false | Some _ -> true)
      Fmt.(option ~none:(unit "NONE") int) optint
  | Ok ((_, `Notify _, _, _), _)-> Error (`Msg "Ok _ Notify _")
  | Ok ((_, `Update _, _, _), _) -> Error (`Msg "Ok _ Update todo")
  | Error `Partial as err -> err
  | Error err -> R.error_msgf "Error parsing response: %a" Udns_packet.pp_err err
