open Dns

type 'key query_state =
  { protocol : Dns.proto ;
    key: 'key ;
    query : Packet.t ;
  } constraint 'key = 'a Rr_map.key

let make_query rng protocol hostname
    : 'xy  ->
      Cstruct.t * 'xy query_state =
  (* SRV records: Service + Protocol are case-insensitive, see RFC2728 pg2. *)
  fun record_type ->
  let question = Packet.Question.create hostname record_type in
  let header = Randomconv.int16 rng, Packet.Flags.singleton `Recursion_desired in
  let query = Packet.create header question `Query in
  let cs , _ = Packet.encode protocol query in
  begin match protocol with
    | `Udp -> cs
    | `Tcp ->
      let len_field = Cstruct.create 2 in
      Cstruct.BE.set_uint16 len_field 0 (Cstruct.len cs) ;
      Cstruct.concat [len_field ; cs]
  end, { protocol ; query ; key = record_type }

let parse_response (type requested)
  : requested Rr_map.key query_state -> Cstruct.t ->
    (requested, [< `Partial | `Msg of string]) result =
  fun state buf ->
  let open Rresult in
  begin match state.protocol with (* consume TCP two-byte length prefix: *)
    | `Udp -> Ok buf
    | `Tcp ->
      begin match Cstruct.BE.get_uint16 buf 0 with
        | exception Invalid_argument _ -> Error `Partial (* TODO *)
        | pkt_len when pkt_len > Cstruct.len buf -2 ->
          Logs.debug (fun m -> m "Partial: %d >= %d-2"
                         pkt_len (Cstruct.len buf));
          Error `Partial (* TODO return remaining # *)
        | pkt_len ->
          if 2 + pkt_len < Cstruct.len buf then
            Logs.warn (fun m -> m "Extraneous data in DNS response");
          Ok (Cstruct.sub buf 2 pkt_len)
      end
  end >>= fun buf ->
  let to_msg t = function Ok a -> Ok a | Error e ->
    R.error_msgf
      "QUERY: @[<v>hdr:%a (id: %d = %d) (q=q: %B)@ query:%a%a  opt:%a tsig:%B@,failed: %a@,@]"
      Packet.pp_header t
      (fst t.header) (fst state.query.header)
      (Packet.Question.compare t.question state.query.question = 0)
      Packet.Question.pp t.question
      Packet.pp_data t.data
      (Fmt.option Dns.Edns.pp) t.edns
      (match t.tsig with None -> false | Some _ -> true)
      Packet.pp_mismatch e
  in
  match Packet.decode buf with
  | Ok t ->
    begin
      to_msg t (Packet.reply_matches_request ~request:state.query t) >>= function
      | `Answer (answer, _) ->
        let rec follow_cname counter q_name =
          if counter <= 0 then Error (`Msg "CNAME recursion too deep")
          else
            Domain_name.Map.find_opt q_name answer
            |> R.of_option ~none:(fun () ->
                R.error_msgf "Can't find relevant map in response:@ \
                              %a in [%a]"
                  Domain_name.pp q_name
                  Name_rr_map.pp answer
              ) >>= fun relevant_map ->
            begin match Rr_map.find state.key relevant_map with
              | Some response -> Ok response
              | None ->
                begin match Rr_map.(find Cname relevant_map) with
                  | None -> Error (`Msg "Invalid DNS response")
                  | Some (_ttl, redirected_host) ->
                    follow_cname (pred counter) redirected_host
                end
            end
        in
        follow_cname 20 (fst state.query.question)
      | r -> Error (`Msg (Fmt.strf "Ok %a, expected answer" Packet.pp_reply r))
    end
  | Error `Partial as err -> err
  | Error err -> R.error_msgf "Error parsing response: %a" Packet.pp_err err
