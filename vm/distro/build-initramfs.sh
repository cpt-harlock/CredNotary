#!/bin/sh
# First-stage initramfs for the Debian VM (vm/distro/init).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/../../build/initramfs-distro.cpio.gz}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE"/bin
cp /usr/bin/busybox "$STAGE"/bin/busybox
cp "$HERE"/init "$STAGE"/init
chmod 755 "$STAGE"/init
mkdir -p "$(dirname "$OUT")"
(cd "$STAGE" && find . -print0 | cpio --null -o -H newc --owner=0:0 2>/dev/null) | gzip -9 > "$OUT"
echo "initramfs: $OUT"
