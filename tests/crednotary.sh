#!/bin/sh
# CredNotary test suite, run inside the VM (vm/run.sh tests/crednotary.sh).
# For each mode it runs the simulated attack scenarios (privsim) as an
# unprivileged user (uid 1000) and the legitimate workloads, and reports the
# outcome of each one on a "RESULT" line.
B=/mnt/host/build
PG=${PG:-$B/crednotary}
ALICE="$B/runas 1000"

setup() {
	insmod ${PRIVSIM:-/mnt/host/testmod/privsim.ko} i_understand_this_grants_root=1 || exit 1
	echo "lab-secret-42" > /root/secret-lab
	chmod 600 /root/secret-lab
	chmod 711 /root
	cp $B/suid-check /tmp/suid-check && chmod 4755 /tmp/suid-check
	printf '#!/bin/sh\nid > /tmp/pwned\n' > /tmp/evil.sh && chmod 755 /tmp/evil.sh
	echo "secret-of-group0" > /root/secret-group
	chown 0:0 /root/secret-group && chmod 640 /root/secret-group
	echo "secret-of-1001" > /tmp/secret-1001
	chown 1001:1001 /tmp/secret-1001 && chmod 600 /tmp/secret-1001
	cp $B/privsim-test /tmp/fcap-reader && chmod 755 /tmp/fcap-reader
	$B/setfcap /tmp/fcap-reader || echo "setfcap failed"
}

pg_start() {	# $1 = mode, $2... = extra options
	m=$1; shift
	: > /tmp/pg.log	# truncate FIRST: the redirection of the background job is asynchronous
	$PG -m "$m" "$@" > /tmp/pg.log 2>&1 &
	PGPID=$!
	for i in $(seq 100); do grep -q "ready" /tmp/pg.log && return; sleep 0.1; done
	echo "crednotary did not start:"; cat /tmp/pg.log; exit 1
}

pg_stop() {
	sleep 0.3
	kill $PGPID; wait $PGPID 2>/dev/null
	grep -v "allowlist" /tmp/pg.log | sed 's/^/    /'
}

attacks() {
	for s in commit overwrite swap cve caps uidswap redirect inherit tokenrace rootgroup dormant; do
		$ALICE $B/privsim-test $s; rc=$?
		[ $rc -ge 128 ] && echo "RESULT $s: process killed by signal $((rc-128))"
	done
}

legit() {
	$ALICE /tmp/suid-check
	/tmp/suid-check dance
	$ALICE $B/privsim-test cve-benign
	$ALICE unshare -Ur id >/dev/null && echo "RESULT unshare -Ur: ok"
	$ALICE sh -c 'for i in $(seq 50); do ls / >/dev/null; cat /etc/passwd >/dev/null; done' && echo "RESULT shell-loop: ok"
	$ALICE sh -c 'cat /proc/1/status >/dev/null && kill -0 $$' && echo "RESULT proc/kill: ok"
	$ALICE sh -c 'echo x > /tmp/alice-f && chmod 600 /tmp/alice-f && rm /tmp/alice-f' && echo "RESULT create/chmod/unlink: ok"
	$ALICE /tmp/fcap-reader read fcap-legit
	$B/runas 1000:0,10 $B/privsim-test readfile /root/secret-group	# legitimate setgroups with GID 0
	chmod 711 /root && kill -0 1 && echo "RESULT root chmod/kill: ok"
}

# alive = exists and is not a zombie
alive() { [ -d /proc/$1 ] && ! grep -q '^State:.*Z' /proc/$1/status; }

# Self-protection: a process with tampered creds tries to kill the loader
selfprot() {
	echo "---- block: compromised task kills the loader"
	pg_start block
	$ALICE $B/privsim-test kill $PGPID
	alive $PGPID && echo "RESULT selfprot-block: crednotary alive" || echo "RESULT selfprot-block: crednotary KILLED"
	pg_stop
	echo "---- log: compromised task kills the loader (expected: succeeds, observation-only mode)"
	pg_start log
	$ALICE $B/privsim-test kill $PGPID
	for i in $(seq 50); do alive $PGPID || break; sleep 0.1; done	# exit detaches 33 links: slow under TCG
	alive $PGPID && echo "RESULT selfprot-log: crednotary alive" || echo "RESULT selfprot-log: crednotary killed"
	pg_stop
	echo "---- root tries to add a helper to the allowlist (expected: map frozen)"
	pg_start block
	KEY=$(i=0; while [ $i -lt 128 ]; do printf '00 '; i=$((i+1)); done)
	if out=$($B/bpftool-static/bpftool map update name umh_allow key hex $KEY value hex 01 2>&1); then
		echo "RESULT freeze: allowlist modified"
	else
		echo "RESULT freeze: allowlist not modifiable ($(echo "$out" | tail -1))"
	fi
	pg_stop
	echo "---- block -P: the loader exits, the pinned links stay"
	pg_start block -P /sys/fs/bpf/crednotary
	kill $PGPID; wait $PGPID 2>/dev/null
	alive $PGPID || echo "RESULT pinned: loader exited, pins: $(ls /sys/fs/bpf/crednotary | wc -l)"
	$ALICE $B/privsim-test overwrite
	echo "---- compromised task tries to remove a pin (expected: EPERM)"
	$ALICE $B/privsim-test unpin /sys/fs/bpf/crednotary/pg_commit_creds
	echo "RESULT pinned-after-unpin: pins: $(ls /sys/fs/bpf/crednotary | wc -l)"
	echo "---- orderly detach with -U, immediately followed by legitimate transitions"
	$PG -U /sys/fs/bpf/crednotary
	$ALICE /tmp/suid-check
	/tmp/suid-check dance
	echo "---- after -U (expected: protection removed)"
	$ALICE $B/privsim-test overwrite
}

umh() {
	rm -f /tmp/pwned
	echo /tmp/evil.sh > /proc/sys/kernel/modprobe	# simulates the overwrite of modprobe_path
	$ALICE $B/privsim-test umh
	sleep 0.5
	if [ -f /tmp/pwned ]; then echo "RESULT umh: /tmp/pwned created -> $(cat /tmp/pwned)"; else echo "RESULT umh: helper NOT executed"; fi
	echo /sbin/modprobe > /proc/sys/kernel/modprobe
}

setup

echo "================ BASELINE (no protection) ================"
attacks
umh
echo "================ LEGIT (no protection) ================"
legit

for mode in log block kill; do
	echo "================ crednotary -m $mode: attacks ================"
	pg_start $mode
	attacks
	umh
	pg_stop
	echo "================ crednotary -m $mode: legitimate workloads ================"
	pg_start $mode
	legit
	pg_stop
done

echo "================ quarantine ================"
Q=/sys/fs/cgroup/crednotary-quarantine
pg_start quarantine
# dormant task: the sweep finds it while it computes in user space, the loader freezes it
$ALICE $B/privsim-test dormant > /tmp/dormant.out 2>&1 &
AP=$!
for i in $(seq 50); do grep -qx $AP $Q/cgroup.procs 2>/dev/null && break; sleep 0.1; done
sleep 6	# well beyond the loop duration (~3 s): if it were not frozen it would have finished
echo "RESULT quarantine: in cgroup=$(grep -qx $AP $Q/cgroup.procs && echo yes || echo no) $(grep frozen $Q/cgroup.events) output=[$(cat /tmp/dormant.out | tr '\n' ' ')]"
kill -9 $AP; wait $AP 2>/dev/null
pg_stop
rmdir $Q

echo "================ self-protection ================"
selfprot
