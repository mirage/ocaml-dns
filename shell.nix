with import <nixpkgs> {};
mkShell {
  nativeBuildInputs = [
    ocaml
    opam
    dune_2
    ocamlPackages.utop
    pkg-config
    gcc
    bintools-unwrapped
    gmp
  ];
}
