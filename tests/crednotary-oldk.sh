#!/bin/sh
# The tests/crednotary.sh suite on an older kernel (5.11-6.12):
#   KERNEL=~/kernels/old/linux-5.15/arch/x86/boot/bzImage vm/run.sh tests/crednotary-oldk.sh
# Picks the CredNotary variant that fits the version and the privsim.ko built
# for that kernel (make oldk-privsim OLDK=..., in build/oldk/privsim-<version>/).
B=/mnt/host/build
R=$(uname -r)
V=${R%%-*}
maj=${V%%.*}; rest=${V#*.}; min=${rest%%.*}
if [ "$maj" -lt 5 ] || { [ "$maj" -eq 5 ] && [ "$min" -lt 11 ]; }; then
	echo "kernel $R: CredNotary needs at least 5.11"; exit 1
elif [ "$maj" -eq 5 ] && [ "$min" -lt 13 ]; then
	PG=$B/crednotary-compat-hash
elif [ "$maj" -lt 6 ] || { [ "$maj" -eq 6 ] && [ "$min" -lt 13 ]; }; then
	PG=$B/crednotary-compat
else
	PG=$B/crednotary
fi
PRIVSIM=$B/oldk/privsim-$V/privsim.ko
echo "[oldk] kernel $R -> $(basename $PG), $PRIVSIM"
. /mnt/host/tests/crednotary.sh
