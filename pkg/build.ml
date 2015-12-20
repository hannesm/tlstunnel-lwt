#!/usr/bin/env ocaml
#directory "pkg";;
#use "topkg.ml";;

let () = Pkg.describe "tlstunnel" ~builder:(`OCamlbuild []) [
    Pkg.lib "pkg/META";
    Pkg.bin ~auto:true "tlstunnel";
    Pkg.man ~dst:"man1/tlstunnel.1" "tlstunnel.1";
    Pkg.doc "README.md"; ]
