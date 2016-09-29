#!/usr/bin/env ocaml
#use "topfind"
#require "topkg"
open Topkg

let () =
  Pkg.describe "tlstunnel" @@ fun _c ->
  Ok [ Pkg.bin "tlstunnel" ]
