
(* likely this should contain:
- a primary server (handling updates)
- a client on steroids: multiplexing on connections
- listening for DNS requests from clients:
  first find them in primary server
  if not found, use the client
*)

(* task management
   - multiple requests for the same name, type can be done at the same "time"
     -> need to remember outstanding requests and signal to clients

*)

module Stub (CS : Dns_client.S) = struct
  module Client = Dns_client.Make(CS)

  (*  let handle_buf *)

end
