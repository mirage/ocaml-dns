(** The pure interface to the client part of uDns.

    Various helper modules to do with side effects are available from
    {!Udns_client_lwt}, {!Udns_client_unix} and so forth.

    To learn more about the high-level API, I suggest reading the docstrings
    of {!Udns_client_flow}.
*)

type 'key query_state constraint 'key = 'a Udns_map.k
(** [query_state] is parameterized over the query type, so the type of
    the representation of the answer depends on what the name server
    was asked to provide. See {!Udns_map.k} for a list of response types.
    The first element (the [int32]) in most of the tuples is the
    Time-To-Live (TTL) field returned from the server, which you can use to
    calculate when you should request fresh information in case you are writing
    a long-running application.
*)

val make_query :
  Udns_packet.proto -> Domain_name.t ->
  'query_type Udns_map.k->
  Cstruct.t * 'query_type Udns_map.k query_state
(** [make_query protocol name query_type] is [query, query_state]
    where [query] is the serialized DNS query to send to the name server,
    and [query_state] is the information required to validate the response.

    NB: When querying for [TLSA] records, it is important to use the optional
    [~hostname:false] parameter with the conversion functions within {!Domain_name}
    when constructing the {!Domain_name.t} for the search, since these contain
    labels prefixed with underscores.
*)

val parse_response : 'query_type Udns_map.k query_state -> Cstruct.t ->
  ('query_type, [`Msg of string | `Partial]) result
(** [parse_response query_state response] is the information contained in
    [response] parsed using [query_state] when the query was successful, or
    an [Error _] if the [response] did not match the [query_state]
    (or if the query failed).
*)
