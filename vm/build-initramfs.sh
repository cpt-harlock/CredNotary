#!/bin/sh
# Builds a minimal initramfs (static busybox + an unprivileged user).
# Everything else (BPF loader, test module, scripts) comes over 9p from /mnt/host.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-$HERE/../build/initramfs.cpio.gz}
STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

mkdir -p "$STAGE"/bin "$STAGE"/etc "$STAGE"/home/alice "$STAGE"/root
chmod 755 "$STAGE" "$STAGE"/bin "$STAGE"/etc "$STAGE"/home
chmod 700 "$STAGE"/root
cp /usr/bin/busybox "$STAGE"/bin/busybox
cp "$HERE"/init "$STAGE"/init
chmod 755 "$STAGE"/init

cat > "$STAGE"/etc/passwd <<'EOF'
root:x:0:0:root:/root:/bin/sh
alice:x:1000:1000:alice:/home/alice:/bin/sh
EOF
cat > "$STAGE"/etc/group <<'EOF'
root:x:0:
alice:x:1000:
EOF

mkdir -p "$(dirname "$OUT")"
(cd "$STAGE" && find . -print0 | cpio --null -o -H newc --owner=0:0 2>/dev/null) | gzip -9 > "$OUT"
echo "initramfs: $OUT"
