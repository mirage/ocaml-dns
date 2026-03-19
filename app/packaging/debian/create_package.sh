#!/bin/sh -e

# only execute anything if either
# - running under orb with package = dns-cli
# - not running under opam at all
if [ "$ORB_BUILDING_PACKAGE" != "dns-cli" -a "$OPAM_PACKAGE_NAME" != "" ]; then
    exit 0;
fi

basedir=$(realpath "$(dirname "$0")"/../../..)
bdir=$basedir/_build/install/default/bin
tmpd=$basedir/_build/stage
rootdir=$tmpd/rootdir
bindir=$rootdir/usr/bin
debiandir=$rootdir/DEBIAN

trap 'rm -rf $tmpd' 0 INT EXIT

mkdir -p "$bindir" "$debiandir"

# stage app binaries
for f in onotify oupdate ozone
do install $bdir/$f $bindir/$f; done

# install debian metadata
install -m 0644 $basedir/app/packaging/debian/control $debiandir/control
install -m 0644 $basedir/app/packaging/debian/changelog $debiandir/changelog
install -m 0644 $basedir/app/packaging/debian/copyright $debiandir/copyright

ARCH=$(dpkg-architecture -q DEB_TARGET_ARCH)
sed -i -e "s/^Architecture:.*/Architecture: ${ARCH}/" $debiandir/control

dpkg-deb --build $rootdir $basedir/dns-cli.deb
echo 'bin: [ "dns-cli.deb" ]' > $basedir/dns-cli.install
