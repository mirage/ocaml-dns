opam install -y mirage crunch
git clone git://github.com/mirage/mirage-skeleton
cd mirage-skeleton
make dns-configure
make dns-build
