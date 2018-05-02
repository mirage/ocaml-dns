#!/bin/sh -ex

eval `opam config env`

opam install mirage

UNIKERNELS="primary primary-with-zone secondary resolver stub"

cd mirage/examples

for x in $UNIKERNELS; do
    cd $x
    echo "now working in $x, compiling for unix"
    mirage configure -t unix && make depend && mirage build && mirage clean
    cd ..
done

for x in $UNIKERNELS; do
    cd $x
    echo "now working in $x, compiling for ukvm"
    mirage configure -t ukvm && make depend && mirage build && mirage clean
    cd ..
done

for x in $UNIKERNELS; do
    cd $x
    echo "now working in $x, compiling for virtio"
    mirage configure -t virtio && make depend && mirage build && mirage clean
    cd ..
done
