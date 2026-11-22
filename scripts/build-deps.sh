#!/bin/sh
# Builds the toolchain the Makefile expects, from a kernel source tree:
#   build/libbpf/          static libbpf and headers (tools/lib/bpf)
#   build/bpftool/         bpftool, for skeleton generation on the host
#   build/bpftool-static/  static bpftool, used inside the busybox VM by the tests
#
#   scripts/build-deps.sh [KSRC] [BUILD]     (normally through "make deps")
set -eu
KSRC=${1:-$HOME/kernels/linux-7.3.1}
BUILD=${2:-$(cd "$(dirname "$0")/.." && pwd)/build}
JOBS=${JOBS:-$(nproc)}
# bpftool strips its embedded BPF objects with llvm-strip; distributions often ship it versioned
LLVM_STRIP=${LLVM_STRIP:-$(command -v llvm-strip || ls /usr/bin/llvm-strip-* 2>/dev/null | sort -V | tail -1)}

[ -d "$KSRC/tools/lib/bpf" ] || { echo "no kernel tree in $KSRC (set KSRC)" >&2; exit 1; }
mkdir -p "$BUILD/libbpf-obj" "$BUILD/bpftool" "$BUILD/bpftool-static"

make -s -C "$KSRC/tools/lib/bpf" -j"$JOBS" OUTPUT="$BUILD/libbpf-obj/" \
	prefix="$BUILD/libbpf" install install_headers >/dev/null
make -s -C "$KSRC/tools/bpf/bpftool" -j"$JOBS" OUTPUT="$BUILD/bpftool/" LLVM_STRIP="$LLVM_STRIP" >/dev/null
make -s -C "$KSRC/tools/bpf/bpftool" -j"$JOBS" OUTPUT="$BUILD/bpftool-static/" \
	LLVM_STRIP="$LLVM_STRIP" EXTRA_LDFLAGS=-static >/dev/null

ls -l "$BUILD/libbpf/lib64/libbpf.a" "$BUILD/bpftool/bpftool" "$BUILD/bpftool-static/bpftool"
