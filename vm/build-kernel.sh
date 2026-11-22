#!/bin/sh
# Builds a kernel.org kernel of any version (5.x included) for the lab VM, with
# what CredNotary (BPF LSM, BTF, fentry) and privsim need.
#   vm/build-kernel.sh 5.15             -> ~/kernels/old/linux-5.15/arch/x86/boot/bzImage
#   EXTRA_CONFIG="USER_NS IO_URING" vm/build-kernel.sh 5.11.22
# Download and verify the tarball first (sha256sums.asc on kernel.org), into
# ~/kernels/old (or OLD_KERNELS). Then:  KERNEL=<bzImage> vm/run.sh ...
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
V=${1:?version}
BASE=${OLD_KERNELS:-$HOME/kernels/old}
SRC=$BASE/linux-$V
JOBS=${JOBS:-$(nproc)}

[ -d "$SRC" ] || tar -C "$BASE" -xf "$BASE/linux-$V.tar.xz"
cd "$SRC"

major=${V%%.*}; rest=${V#*.}; minor=${rest%%.*}
# pahole >= 1.24 emits BTF that kernels < 6.0 reject (ENUM64, DECL_TAG,
# kind_flag on enums): without valid BTF there is no BPF LSM and no modules
PAHOLE_ARG=
[ "$major" -lt 6 ] && PAHOLE_ARG="PAHOLE=$HERE/pahole-compat.py"

# gcc >= 12 flags a use-after-free in libsubcmd's xrealloc() (tools are built
# with -Werror): apply the upstream fix (commit 52a9dab6d892)
python3 - tools/lib/subcmd/subcmd-util.h <<'EOF'
import re, sys
p = sys.argv[1]; s = open(p).read()
new = '''static inline void *xrealloc(void *ptr, size_t size)
{
	void *ret;

	if (!size) {
		free(ptr);
		return malloc(1);
	}

	ret = realloc(ptr, size);
	if (!ret)
		die("Out of memory, realloc failed");
	return ret;
}'''
s2 = re.sub(r'static inline void \*xrealloc\(void \*ptr, size_t size\)\n\{.*?\n\}', new, s, flags=re.S)
if s2 != s:
	open(p, 'w').write(s2)
EOF

make -s defconfig
make -s kvm_guest.config
C=scripts/config
$C -e BPF -e BPF_SYSCALL -e BPF_JIT -e BPF_JIT_ALWAYS_ON -e BPF_LSM -e BPF_EVENTS \
   -e SECURITY -e SECURITYFS -e SECURITY_NETWORK \
   --set-str LSM "landlock,lockdown,yama,integrity,bpf" \
   -e DEBUG_INFO -d DEBUG_INFO_REDUCED -d DEBUG_INFO_SPLIT -e DEBUG_INFO_DWARF4 \
   -d DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT -e DEBUG_INFO_BTF -e DEBUG_INFO_BTF_MODULES \
   -e FTRACE -e FUNCTION_TRACER -e DYNAMIC_FTRACE -e KPROBES -e KPROBE_EVENTS \
   -e DEBUG_FS -e CGROUPS -e CGROUP_BPF -e CGROUP_FREEZER \
   -e MODULES -e MODULE_UNLOAD -d MODULE_SIG \
   -e NET_9P -e NET_9P_VIRTIO -e 9P_FS -e 9P_FS_POSIX_ACL -e VIRTIO_PCI \
   -e BLK_DEV_INITRD -e DEVTMPFS -e TMPFS -e USER_NS -e IO_URING \
   -e CHECKPOINT_RESTORE -e FHANDLE \
   -e KALLSYMS -e KALLSYMS_ALL -d WERROR
for o in ${EXTRA_CONFIG:-}; do $C -e "$o"; done
make -s olddefconfig
for o in BPF_LSM DEBUG_INFO_BTF FUNCTION_TRACER 9P_FS KALLSYMS_ALL; do
	grep -q "^CONFIG_$o=y" .config || { echo "CONFIG_$o is not set" >&2; exit 1; }
done
make -j"$JOBS" $PAHOLE_ARG bzImage modules
echo "kernel: $SRC/arch/x86/boot/bzImage"
