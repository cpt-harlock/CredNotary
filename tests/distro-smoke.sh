#!/bin/sh
# Minimal check of the Debian VM: kernel, LSMs, systemd state, CredNotary running.
echo "kernel $(uname -r); LSM $(cat /sys/kernel/security/lsm)"
systemctl is-system-running
systemctl --failed --no-legend
pgrep -a crednotary
head -3 /var/log/crednotary-boot.log
ip -4 addr show | grep inet
ip -br link
networkctl --no-pager 2>&1 | head
ls /etc/systemd/network/ 2>/dev/null; cat /etc/systemd/network/*.network 2>/dev/null | head -20
