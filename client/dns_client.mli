(** The pure interface to the client part of uDns.

    Various helper modules to do with side effects are available from
    {!Dns_client_lwt}, {!Dns_client_unix} and so forth.

    To learn more about the high-level API, I suggest reading the docstrings
    of {!Dns_client_flow}.
*)

type 'key query_state constraint 'key = 'a Dns.Rr_map.key
(** [query_state] is parameterized over the query type, so the type of
    the representation of the answer depends on what the name server
    was asked to provide. See {!Dns_map.k} for a list of response types.
    The first element (the [int32]) in most of the tuples is the
    Time-To-Live (TTL) field returned from the server, which you can use to
    calculate when you should request fresh information in case you are writing
    a long-running application.
*)

val make_query :
  (int -> Cstruct.t) -> Dns.proto -> 'a Domain_name.t ->
  'query_type Dns.Rr_map.key ->
  Cstruct.t * 'query_type Dns.Rr_map.key query_state
(** [make_query rng protocol name query_type] is [query, query_state]
    where [query] is the serialized DNS query to send to the name server,
    and [query_state] is the information required to validate the response. *)

val parse_response : 'query_type Dns.Rr_map.key query_state -> Cstruct.t ->
  ('query_type, [`Msg of string | `Partial]) result
(** [parse_response query_state response] is the information contained in
    [response] parsed using [query_state] when the query was successful, or
    an [Error _] if the [response] did not match the [query_state]
    (or if the query failed).
*)
