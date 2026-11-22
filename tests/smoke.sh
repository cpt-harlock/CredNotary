#!/bin/sh
# Minimal check of the VM environment: kernel, active LSMs, 9p mount, helpers.
echo "uname: $(uname -a)"
echo "lsm: $(cat /sys/kernel/security/lsm)"
ls /mnt/host
id; /mnt/host/build/runas 1000 id
