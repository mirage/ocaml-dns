#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let lwt = Conf.with_pkg ~default:false "lwt"
let mirage = Conf.with_pkg ~default:false "mirage"
let async = Conf.with_pkg ~default:false "async"

let opams =
  let lint_deps_excluding =
    Some ["ounit"; "oUnit"; "ppx_tools"; "async_kernel"; "ppx_cstruct"]
  in
  [Pkg.opam_file ~lint_deps_excluding "opam"]

let () =
  Pkg.describe ~opams "dns" @@ fun c ->
  let lwt = Conf.value c lwt
  and mirage = Conf.value c mirage
  and async = Conf.value c async
  in
  let exts = Exts.(cmx @ library @ exts [".cmi" ; ".cmt" ]) in
  Ok [
    Pkg.lib ~exts "lib/dns" ;
    Pkg.bin ~cond:lwt "lwt/dig_unix" ~dst:"mldig" ;
    Pkg.mllib ~cond:lwt "lwt/dns-lwt-core.mllib" ;
    Pkg.mllib ~cond:lwt "lwt/dns-lwt.mllib" ;
    Pkg.mllib ~cond:mirage "mirage/dns-lwt-mirage.mllib" ;
    Pkg.mllib ~cond:async "async/dns-async.mllib" ;
    Pkg.mllib ~cond:async "async/dns-async-unix.mllib" ;
    Pkg.test ~run:false ~cond:async "lib_test/async/test_async_dns_resolver_unix";
    Pkg.test ~run:false "examples/forward" ;
    Pkg.test ~run:false "lib_test/unix/lwt_server" ;
    Pkg.test ~run:false "lib_test/unix/time_server" ;
    Pkg.test "lib_test/ounit/test"
  ]
