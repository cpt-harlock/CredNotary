#!/bin/sh
# Real workloads under CredNotary (log mode, active from boot):
# counts the events; each one is a false positive to explain.
LOG=/var/log/crednotary-boot.log
ALICE="runuser -u alice --"
ok() { echo "RESULT $1: ok"; }
ko() { echo "RESULT $1: FAILED"; }

echo "=== boot: systemd $(systemctl is-system-running), failed units: $(systemctl --failed --no-legend | wc -l)"
pgrep -x crednotary >/dev/null || { echo "crednotary is not running"; exit 1; }

# sudo / su / runuser
$ALICE sudo -n true && ok "sudo" || ko "sudo"
$ALICE sudo -n -u nobody id >/dev/null && ok "sudo -u nobody" || ko "sudo -u nobody"
su -s /bin/sh -c 'id -u' alice >/dev/null && ok "su alice" || ko "su alice"
setpriv --reuid=1000 --regid=1000 --init-groups id >/dev/null && ok "setpriv" || ko "setpriv"
# full PAM login with a systemd session (logind, user cgroup)
systemd-run --wait -q -p User=alice -p PAMName=login true && ok "systemd-run PAM" || ko "systemd-run PAM"
# services with DynamicUser, capabilities and sandboxing
systemd-run --wait -q -p DynamicUser=yes -p AmbientCapabilities=CAP_NET_BIND_SERVICE id && ok "DynamicUser+ambient" || ko "DynamicUser+ambient"
systemctl restart cron ssh && ok "restart cron/ssh" || ko "restart cron/ssh"
# local ssh (sshd privilege separation, setuid of the child)
rm -f /root/.ssh/id_lab /root/.ssh/id_lab.pub; mkdir -p /root/.ssh; ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_lab 2>/dev/null </dev/null
mkdir -p /home/alice/.ssh && cp /root/.ssh/id_lab.pub /home/alice/.ssh/authorized_keys
chown -R alice:alice /home/alice/.ssh
ssh -q -i /root/.ssh/id_lab -o StrictHostKeyChecking=no -o BatchMode=yes alice@127.0.0.1 id >/dev/null && ok "ssh" || ko "ssh"
# passwd/chage (setuid root, modifies /etc/shadow)
$ALICE chage -l alice >/dev/null && ok "chage (setuid)" || ko "chage (setuid)"
# rootless containers (user namespaces, newuidmap/newgidmap with file capabilities)
# the lab kernel has no TUN and no FUSE: vfs storage and no network (user namespaces and newuidmap remain)
$ALICE sh -c 'cd ~ && podman --root $HOME/vfs --storage-driver=vfs pull -q docker.io/library/alpine:3.20 >/dev/null && podman --root $HOME/vfs --storage-driver=vfs run --rm --network=none docker.io/library/alpine:3.20 sh -c "id; cat /proc/self/uid_map"' && ok "podman rootless" || ko "podman rootless"
$ALICE unshare -Ur id >/dev/null && ok "unshare -Ur" || ko "unshare -Ur"
# io_uring (io-wq workers with the submitter's credentials)
fio --name=uring --ioengine=io_uring --rw=randrw --size=64m --bs=4k --direct=0 \
	--numjobs=2 --runtime=5 --time_based --filename=/tmp/fio.dat >/dev/null && ok "fio io_uring (root)" || ko "fio io_uring (root)"
$ALICE fio --name=uring --ioengine=io_uring --rw=randrw --size=64m --bs=4k \
	--numjobs=2 --runtime=5 --time_based --filename=/tmp/fio-alice.dat >/dev/null && ok "fio io_uring (alice)" || ko "fio io_uring (alice)"
# compilation (many fork/exec)
$ALICE sh -c 'cd /tmp && for i in $(seq 20); do echo "int main(){return 0;}" > t$i.c && gcc -O2 -o t$i t$i.c; done' && ok "gcc x20" || ko "gcc x20"

echo "=== CredNotary events (expected: none)"
grep -E 'UNAUTH_COMMIT|CRED_TAMPER|UMH_' $LOG
echo "RESULT events: $(grep -cE 'UNAUTH_COMMIT|CRED_TAMPER|UMH_' $LOG)"
# denominators for the false-positive rate
echo "RESULT authorized transitions with a gain (AUTH_GAIN): $(grep -c AUTH_GAIN $LOG)"
echo "RESULT distinct processes with AUTH_GAIN: $(grep AUTH_GAIN $LOG | sed 's/.* comm=\([^ ]*\).*/\1/' | sort | uniq -c | sort -rn | head -15 | tr '\n' ';')"
echo "RESULT sweeps run: $(grep -c 'sweep [0-9]* us' $LOG)"
echo "RESULT uptime (s) at the end of the workloads: $(cut -d' ' -f1 /proc/uptime)"
