(* mostly copied from Canopy/canopy_store.ml at b8f8183cc33263e4a99b41828b976a3e85337750 *)

open Lwt.Infix

let src = Logs.Src.create "git-store" ~doc:"Git store logger"
module Log = (val Logs.src_log src : Logs.LOG)

module Make (CTX: Irmin_git.IO) (INFL: Git.Inflate.S) = struct
  module Hash = Irmin.Hash.SHA1
  module Mirage_git_memory = Irmin_mirage.Git.Mem.KV(CTX)(INFL)
  module Store = Mirage_git_memory(Irmin.Contents.String)
  module Sync = Irmin.Sync(Store)

  let store_config = Irmin_mem.config ()
  let repo _ = Store.Repo.v store_config

  let store () = repo () >>= Store.master

  let upstream = Irmin.remote_uri (Key_gen.remote ())

  let pull () =
    store () >>= fun t ->
    Log.info (fun f -> f "pulling repository") ;
    Lwt.catch
      (fun () ->
         Sync.pull_exn t upstream `Set >|= fun _ ->
         Log.info (fun f -> f "repository pulled"))
      (fun e ->
         Log.warn (fun f -> f "failed pull %a" Fmt.exn e);
         Lwt.return ())

  let retrieve k =
    store () >>= fun t ->
    Store.list t k >>= fun childs ->
    Lwt_list.fold_left_s (fun acc (s, c) ->
        let k = k @ [s] in
        match c with
        | `Node     -> Lwt.return acc
        | `Contents ->
          Store.get t k >|= fun v ->
          (k, v) :: acc
      ) [] childs

  let get k =
    store () >>= fun t ->
    Store.get t k
end
