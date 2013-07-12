open Core.Std
open Async.Std
open Async_unix
open Printf
open Dns.Name
open Dns.Operators
open Dns.Resolvconf
open Dns.Packet

(** Get DNS Resolver config, either from file or /etc/resolv.conf  *)

val get_resolvers :
  ?file:string -> unit -> Dns.Resolvconf.KeywordValue.t list Deferred.t

(** given the resolver config and request parameters, do resolvution *)

val resolve :
  Dns.Resolvconf.KeywordValue.t list ->
  Dns.Packet.q_class -> Dns.Packet.q_type -> Dns.Name.domain_name -> [ `Result of Dns.Packet.t | `Timeout ] Deferred.t option
