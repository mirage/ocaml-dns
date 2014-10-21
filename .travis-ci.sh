case "$OCAML_VERSION,$OPAM_VERSION" in
3.12.1,1.2.0) ppa=avsm/ocaml312+opam12; pinx="add";;
3.12.1,1.1.0) ppa=avsm/ocaml312+opam11 ;;
4.00.1,1.2.0) ppa=avsm/ocaml40+opam12; pinx="add";;
4.00.1,1.1.0) ppa=avsm/ocaml40+opam11 ;;
4.01.0,1.2.0) ppa=avsm/ocaml41+opam12; pinx="add" ;;
4.01.0,1.1.0) ppa=avsm/ocaml41+opam11 ;;
4.02.0,1.2.0) ppa=avsm/ocaml42+opam12; pinx="add" ;;
4.02.0,1.1.0) ppa=avsm/ocaml42+opam11 ;;
*) echo Unknown $OCAML_VERSION,$OPAM_VERSION; exit 1 ;;
esac

echo "yes" | sudo add-apt-repository ppa:$ppa
sudo apt-get update -qq
sudo apt-get install -qq ocaml ocaml-native-compilers camlp4-extra opam aspcud

export OPAMYES=1
echo OCaml version
ocaml -version
echo OPAM versions
opam --version
opam --git-version

opam init git://github.com/ocaml/opam-repository >/dev/null 2>&1
opam pin $pinx dns .
opam install base64 # can remove with opam 1.2?
opam install dns
opam install mirage-types tcpip
opam reinstall dns # local depopt not picked up by opam 1.1
export OPAMVERBOSE=1
opam install async

eval `opam config env`
make clean
make
cd examples
make

opam install mirage crunch
git clone git://github.com/mirage/mirage-skeleton
cd mirage-skeleton
make dns-configure
make dns-depend
make dns-build
