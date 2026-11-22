#!/bin/sh
# Debian 13 VM with a locally built kernel and CredNotary active (log mode) from boot.
#   vm/distro/run.sh tests/distro-provision.sh   -> installs the packages (once)
#   vm/distro/run.sh tests/distro-workloads.sh   -> real workloads
# The base disk (build/distro/debian-13-nocloud-amd64.qcow2) stays untouched:
# writes go to an overlay (build/distro/lab.qcow2).
# Base disk (verify it with SHA512SUMS in the same directory):
#   https://cloud.debian.org/images/cloud/trixie/latest/debian-13-nocloud-amd64.qcow2
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(cd "$HERE/../.." && pwd)
D=$PROJ/build/distro
KERNEL=${KERNEL:-$HOME/kernels/linux-7.3.1/arch/x86/boot/bzImage}
INITRD=$PROJ/build/initramfs-distro.cpio.gz

"$HERE"/build-initramfs.sh "$INITRD" >/dev/null
[ -f "$D/lab.qcow2" ] || qemu-img create -q -f qcow2 -F qcow2 \
	-b "$D/debian-13-nocloud-amd64.qcow2" "$D/lab.qcow2" 8G

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	ACCEL="-accel kvm -cpu host"
else
	ACCEL="-accel tcg,thread=multi -cpu max"
fi
echo "[run.sh] accel: $ACCEL"

APPEND="console=ttyS0 root=/dev/vda1 rw systemd.firstboot=off lsm=landlock,lockdown,yama,integrity,bpf panic=-1 loglevel=4"
[ $# -gt 0 ] && APPEND="$APPEND run=$1"

exec qemu-system-x86_64 $ACCEL -smp "${SMP:-4}" -m "${MEM:-4G}" \
	-kernel "$KERNEL" -initrd "$INITRD" -append "$APPEND" \
	-drive file="$D/lab.qcow2",if=virtio,format=qcow2 \
	-nic user,model=virtio-net-pci \
	-virtfs local,path="$PROJ",mount_tag=host,security_model=none,id=host \
	-nographic -no-reboot
