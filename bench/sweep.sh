#!/bin/sh
# Cost of one sweep pass as a function of the number of tasks:
#   vm/run.sh bench/sweep.sh
# The loader times each pass with -v ("sweep N us"); -s 200 = 5 passes per second.
B=/mnt/host/build
for n in 0 1000 4000; do
	pids=""
	i=0
	while [ $i -lt $n ]; do sleep 600 & pids="$pids $!"; i=$((i+1)); done
	: > /tmp/pg.log
	$B/crednotary -m block -v -s 200 > /tmp/pg.log 2>&1 &
	P=$!
	sleep 3
	kill $P; wait $P 2>/dev/null
	echo "SWEEP tasks=$(ls -d /proc/[0-9]* | wc -l) us: $(grep 'sweep [0-9]* us' /tmp/pg.log | awk '{print $3}' | sort -n | tr '\n' ' ')"
	[ -n "$pids" ] && kill $pids 2>/dev/null
	for p in $pids; do wait $p 2>/dev/null; done
done
