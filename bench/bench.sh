#!/bin/sh
# Microbenchmarks, run inside the lab VM (build them with "make bench"):
#   vm/run.sh bench/bench.sh > bench.log; bench/summarize.py bench.log
# Under QEMU these are guest numbers, not bare metal: compare ratios, and use
# KVM (TCG timings are meaningless). Baseline and CredNotary (-m block)
# alternate for REPS rounds to spread drift.
B=/mnt/host/build
PGB=$B/pgbench
REPS=${REPS:-10}

run_ops() {	# $1 = config label
	for spec in null:2000000 open:200000 stat:200000 setuid:200000 fork:5000 exec:2000; do
		op=${spec%%:*}; n=${spec##*:}
		echo "CFG=$1 $($PGB $op $n)"
	done
}

mkdir -p /tmp/b/1/2/3/4/5/6 && : > /tmp/b/1/2/3/4/5/6/f
echo "BENCH-ENV kernel=$(uname -r) nproc=$(nproc) reps=$REPS"
for r in $(seq $REPS); do
	echo "== round $r"
	run_ops base
	: > /tmp/pg.log
	$B/crednotary -m block > /tmp/pg.log 2>&1 &
	PGPID=$!
	for i in $(seq 100); do grep -q ready /tmp/pg.log && break; sleep 0.1; done
	run_ops crednotary-block
	kill $PGPID; wait $PGPID 2>/dev/null
	grep -v allowlist /tmp/pg.log | grep -v ready | sed 's/^/  pg: /'
done
