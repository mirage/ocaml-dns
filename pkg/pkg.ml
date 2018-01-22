#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let coverage = Conf.with_pkg ~default:false "coverage"

let cmd c os files =
  let build =
    if Conf.value c coverage then
      let coverage_arg = Cmd.(v "-pkg" % "bisect_ppx") in
      let coverage_cmd c os = Cmd.(Pkg.build_cmd c os %% coverage_arg) in
      coverage_cmd
    else
      Pkg.build_cmd
  in
  OS.Cmd.run @@ Cmd.(build c os %% of_list files)

let () =
  Pkg.describe ~build:(Pkg.build ~cmd ()) "udns" @@ fun c ->
  Ok [
    Pkg.mllib "src/udns.mllib" ;
    Pkg.mllib "crypto/udns_crypto.mllib" ;
    Pkg.mllib "server/udns_server.mllib" ;
    Pkg.mllib ~api:["Zonefile"] "zonefile/udns_zonefile.mllib" ;
    Pkg.mllib "resolver/udns_resolver.mllib" ;
    Pkg.mllib "mirage/udns_mirage.mllib" ;
    Pkg.test "test/tests" ;
    Pkg.test "test/tsig" ;
    Pkg.test "test/resolver" ;
    Pkg.test "test/server" ;
    (* Pkg.test ~run:false "test/afl" *)
    Pkg.test ~run:false "test/bench" ;
  ]
