#!/bin/sh
# Installs the workload packages in the Debian VM (once; they stay in the overlay).
set -x
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q sudo podman uidmap slirp4netns fuse-overlayfs fio liburing-dev \
	gcc libc6-dev openssh-server cron passwd login util-linux procps
id alice 2>/dev/null || useradd -m -s /bin/bash alice
echo 'alice ALL=(ALL) NOPASSWD: ALL' > /etc/sudoers.d/alice
grep -q '^alice:' /etc/subuid || usermod --add-subuids 100000-165535 --add-subgids 100000-165535 alice
# minimal image for rootless containers (from the public registry)
sudo -u alice -H podman pull -q docker.io/library/alpine:3.20
df -h /
