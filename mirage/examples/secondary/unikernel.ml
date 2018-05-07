(* (c) 2017, 2018 Hannes Mehnert, all rights reserved *)

open Lwt.Infix

open Mirage_types_lwt

module Main (R : RANDOM) (P : PCLOCK) (M : MCLOCK) (T : TIME) (S : STACKV4) = struct
  module D = Dns_mirage.Make(R)(P)(M)(T)(S)

  let start _rng pclock mclock _ s _ =
    let keys = List.fold_left (fun acc key ->
        match Astring.String.cut ~sep:":" key with
        | None -> Logs.err (fun m -> m "couldn't parse %s" key) ; acc
        | Some (name, key) -> match Dns_name.of_string ~hostname:false name, Dns_packet.dnskey_of_string key with
          | Error _, _ | _, None -> Logs.err (fun m -> m "failed to parse key %s" key) ; acc
          | Ok name, Some dnskey -> (name, dnskey) :: acc)
        [] (Key_gen.keys ())
    in
    let t =
      UDns_server.Secondary.create ~a:[ UDns_server.tsig_auth ]
        ~tsig_verify:Dns_tsig.verify ~tsig_sign:Dns_tsig.sign
        ~rng:R.generate keys
    in
    D.secondary s pclock mclock t ;
    S.listen s
end
