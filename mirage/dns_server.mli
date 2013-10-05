type 'a process =
  src:Net.Datagram.UDPv4.src -> dst:Net.Datagram.UDPv4.dst -> 'a
  -> Dns.Query.answer option Lwt.t

module type PROCESSOR = sig
  include Dns.Protocol.SERVER
  val process : context process
end


val listen :
  ?mode:[ `none ] ->
  ?origin:string list ->
  zb:string ->
  Net.Datagram.UDPv4.mgr ->
  Net.Datagram.UDPv4.src ->
  processor:(module PROCESSOR) -> unit Lwt.t
