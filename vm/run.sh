#!/bin/sh
# Boots the lab VM with a locally built kernel.
#   vm/run.sh                      -> interactive shell (exit with: poweroff -f)
#   vm/run.sh tests/crednotary.sh  -> runs the script (path relative to the repo) and powers off
# KVM is used when /dev/kvm is accessible, TCG (emulation) otherwise.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
PROJ=$(cd "$HERE/.." && pwd)
KERNEL=${KERNEL:-$HOME/kernels/linux-7.3.1/arch/x86/boot/bzImage}
INITRD=${INITRD:-$PROJ/build/initramfs.cpio.gz}
SMP=${SMP:-4}
MEM=${MEM:-2G}

[ -f "$INITRD" ] || "$HERE/build-initramfs.sh" "$INITRD"

if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	ACCEL="-accel kvm -cpu host"
else
	ACCEL="-accel tcg,thread=multi -cpu max"
fi
# log which accelerator was used (TCG timings are not comparable with KVM)
echo "[run.sh] accel: $ACCEL"

APPEND="console=ttyS0 lsm=landlock,lockdown,yama,integrity,bpf oops=panic loglevel=4"
# extra kernel command-line options (e.g. APPEND_EXTRA=init_on_alloc=0)
[ -n "${APPEND_EXTRA:-}" ] && APPEND="$APPEND $APPEND_EXTRA"
[ $# -gt 0 ] && APPEND="$APPEND run=$1"

# -nic none: the VM loads privsim, which lets any user become root, so it
# stays offline. Everything else comes over 9p (mounted by init on /mnt/host).
exec qemu-system-x86_64 $ACCEL -smp "$SMP" -m "$MEM" \
	-kernel "$KERNEL" -initrd "$INITRD" -append "$APPEND" \
	-virtfs local,path="$PROJ",mount_tag=host,security_model=none,id=host \
	-nic none -nographic -no-reboot
