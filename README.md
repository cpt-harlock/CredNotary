# CredNotary

CredNotary detects, and on request blocks, kernel privilege escalation on an **unmodified** Linux kernel. It is written entirely in eBPF (BPF LSM, fentry/fexit, BTF tracepoints and task iterators): no kernel patch and no kernel module.

The name comes from its core mechanism. Like a notary, CredNotary records every credential that one of the kernel's security checks has approved, and treats any credential without that record as illegitimate.

## What it detects

An attacker who holds a kernel memory-corruption primitive usually turns it into root in one of four ways. CredNotary looks only at the end state, not at the vulnerability:

| | End state | How CredNotary sees it |
|---|---|---|
| **G1** | `commit_creds()` installs a privileged cred that no LSM decision hook approved (the classic ROP payload `commit_creds(prepare_kernel_cred(...))`), or the approved cred is rewritten before the commit | `fentry/commit_creds` finds no matching authorization token |
| **G2** | the fields of the current cred (IDs, groups, any of the five capability sets) are overwritten in place | the next LSM checkpoint, or the periodic sweep, finds a mismatch with the per-task shadow |
| **G3** | `real_cred` and/or `cred` are redirected to another, privileged cred (DirtyCred style) | pointer mismatch at a checkpoint, or `cred != real_cred` at system call entry |
| **G4** | `modprobe_path` or `core_pattern` is overwritten so that the kernel runs the attacker's program as root | the usermode-helper thread may only execute binaries from a frozen allowlist |

In `block`, `kill` and `quarantine` mode the first operation that would use the stolen privileges fails with `EPERM`, the task is killed, or it is frozen in a cgroup. The same checkpoints stop a compromised task from killing the loader or detaching the programs, and with `-P` the links stay pinned after the loader exits.

[`docs/design.md`](docs/design.md) explains how the kernel changes credentials, how each attack bypasses that protocol, how the shadow, the tokens, the checkpoints and the sweep work, and what CredNotary does not cover, with diagrams of the architecture and of each attack flow. A PDF version is in [`docs/design.pdf`](docs/design.pdf); `make docs` rebuilds it (needs node and npm).

## Requirements

| Requirement | Why |
|---|---|
| `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_JIT` | eBPF |
| `CONFIG_BPF_LSM` and `bpf` in the active LSM list (`lsm=...,bpf` on the command line, or `CONFIG_LSM`) | checkpoints and decision hooks |
| `CONFIG_DEBUG_INFO_BTF` | CO-RE, BTF-typed programs, direct loads |
| `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS` | fentry/fexit |
| Linux ≥ 6.13 recommended (5.11–6.12: see [Older kernels](#older-kernels)) | the `bpf_send_signal_task` kfunc, used by the sweep in `kill` mode. It is declared `__weak`: on kernels without it loading still succeeds, but the sweep only flags the task, which the checkpoints then deny |
| cgroup v2 mounted | only for `-m quarantine` |
| bpffs mounted (`/sys/fs/bpf`) | only for `-P` and `-U` |

CredNotary was developed on Linux 7.3.1. The loader must run as root.

## Building

The build uses libbpf and bpftool from a kernel source tree, and links the loader statically so that it also runs in the busybox VM below. You need clang, gcc, make, libelf, zlib and libzstd (static versions included), and a configured kernel tree in `KSRC` (default `~/kernels/linux-7.3.1`).

```sh
make deps KSRC=~/kernels/linux-7.3.1   # once: build/libbpf, build/bpftool, build/bpftool-static
make crednotary                        # -> build/crednotary
make                                   # also compat variants, privsim, test helpers, benchmark
```

`include/vmlinux.h` was generated from Linux 7.3.1. CO-RE relocates the offsets at load time, so the same binary runs on other kernels with BTF that meet the requirements above.

## Usage

```
crednotary [-m log|block|kill|quarantine] [-q cgroup] [-v] [-a /path/helper]... [-t seconds] [-s ms] [-P dir]
crednotary -U dir
```

| Option | Effect |
|---|---|
| `-m` | response mode (default `log`) |
| `-q dir` | cgroup v2 for quarantine (only with `-m quarantine`; default `/sys/fs/cgroup/crednotary-quarantine`) |
| `-a path` | adds a helper to the usermode-helper allowlist (up to 16) |
| `-s ms` | sweep period (default 1000, `0` turns it off) |
| `-t s` | exits after `s` seconds |
| `-v` | also reports legitimate gains (`AUTH_GAIN`) and the duration of each sweep |
| `-P dir` | pins the links and the on/off switch in `dir` (bpffs) |
| `-U dir` | orderly detach of a pinned instance |

```sh
crednotary -m log                                   # observe only
crednotary -m block -P /sys/fs/bpf/crednotary &     # persistent protection
crednotary -U /sys/fs/bpf/crednotary                # orderly removal
crednotary -m quarantine                            # freeze instead of kill
```

The allowlist of usermode helpers starts from the current value of `/proc/sys/kernel/modprobe` and `core_pattern` (if it is a pipe) and is frozen after start-up. Events are printed one per line on stdout:

```
[crednotary] UNAUTH_COMMIT hook=commit_creds pid=245 ppid=98 comm=privsim-test uid=1000 euid=1000 -> new uid=0 euid=0 gain=uid,gid,caps,id_change reason=no_token action=denied(-1)
[crednotary] CRED_TAMPER hook=inode pid=246 ppid=98 comm=privsim-test cred uid=0 euid=0 vs shadow uid=1000 euid=1000 ptr_swapped=0 gain=uid,gid,caps,id_change reason=fields action=denied(-1)
```

The fields are described in [`docs/design.md`](docs/design.md#6-events).

## Testing

> **Warning:** the tests use `privsim` (`testmod/`), a lab kernel module that **lets any local user become root** through `/dev/privsim`. Load it only in a disposable test VM, never on a real machine. To prevent loading it by mistake, it refuses to load (`EPERM`) unless you pass `i_understand_this_grants_root=1`; the test scripts do this inside the VM.

Attacks are **simulated**: privsim reproduces the end state of each class by calling kernel APIs directly (for example `commit_creds(prepare_kernel_cred(&init_task))` from an ioctl, or an in-place write to the current cred), plus a simulated vulnerable function (SIM-2026-0001). It contains no exploit.

Everything runs in QEMU, with KVM when `/dev/kvm` is accessible and TCG otherwise. The VM boots a kernel you build (`KERNEL=` points to its `bzImage`) and mounts the repository over 9p:

```sh
vm/run.sh tests/smoke.sh                    # environment check
vm/run.sh tests/crednotary.sh               # attacks x modes, legitimate workloads, quarantine, self-protection
vm/run.sh bench/bench.sh > bench.log && bench/summarize.py bench.log   # microbenchmarks (KVM only)
vm/run.sh bench/sweep.sh                    # cost of one sweep pass
```

`vm/run.sh` uses a busybox initramfs and keeps the VM offline. The kernel needs the options that `vm/build-kernel.sh` sets (BPF LSM, BTF, fentry, `KALLSYMS_ALL`, 9p); that script builds any kernel.org version with them.

`tests/crednotary.sh` prints one `RESULT` line per check: for each attack scenario, whether the unprivileged process managed to read a root-only secret or was killed, and for each legitimate workload (setuid binary, seteuid dance, `unshare -Ur`, file capabilities, `setgroups` with GID 0...) whether it still works.

**Debian 13.** `vm/distro/run.sh` boots the official `debian-13-nocloud-amd64.qcow2` cloud image (download it into `build/distro/`) with CredNotary in log mode from early boot:

```sh
vm/distro/run.sh tests/distro-provision.sh  # once: workload packages
vm/distro/run.sh tests/distro-workloads.sh  # sudo, su, PAM, ssh, DynamicUser, rootless Podman, io_uring, gcc
```

### Older kernels

Two variants built from the same source and loader cover 5.11–6.12. The detection logic is the same; only the response mechanism and the location of the shadow change.

| Binary | Kernel | Differences |
|---|---|---|
| `build/crednotary` | ≥ 6.13 | full version |
| `build/crednotary-compat` (`-DPG_COMPAT`) | 5.13–6.12 | no `bpf_send_signal_task` kfunc: in `kill` mode the loader kills the task found by the sweep; the previous hook's `ret` is not read, because its position changes with the hook signatures |
| `build/crednotary-compat-hash` (`-DPG_COMPAT -DPG_SHADOW_HASH`) | 5.11–5.12 | as compat, plus the shadow lives in a hash map keyed by `task_struct`, because task storage is not available to fentry/tp_btf/iter before 5.13 |

All variants adapt to the running kernel: the loader skips programs for hooks the kernel lacks (`task_fix_setgroups` before 6.1, `inode_get_acl` before 6.2), and without `task_fix_setgroups` the `setgroups()` token is deposited by `fentry/set_groups`. Below 5.11 `bpf_get_current_task_btf` is missing and CredNotary does not load.

```sh
vm/build-kernel.sh 5.15                                  # from ~/kernels/old/linux-5.15.tar.xz
make crednotary-compat oldk-privsim OLDK=~/kernels/old/linux-5.15
KERNEL=~/kernels/old/linux-5.15/arch/x86/boot/bzImage vm/run.sh tests/crednotary-oldk.sh
```

Below 6.0 the build uses `vm/pahole-compat.py`, because pahole ≥ 1.24 emits BTF that those kernels reject.

## Results

Measured in a QEMU/KVM guest on Linux 7.3.1; the scripts above reproduce them.

- **Simulated attacks:** the 11 credential scenarios of `tests/crednotary.sh` and the `modprobe_path` hijack are all detected, and in `block`, `kill` and `quarantine` mode the stolen privileges are never used. The suite gives the same outcomes on 5.11.22, 5.15, 6.2 and 6.8.12.
- **False positives:** none in the lab workloads, and no event on Debian 13 from boot to shutdown across the workloads listed above.
- **Overhead:** +54 ns per system call, +24–34% on `stat` and `open`, 2.07× on a `seteuid` pair, fork and exec within noise; one sweep pass costs about 0.5 µs per task.

These numbers come from a guest, not from bare metal, and the attacks are simulated end states, not real exploits.

## Repository layout

```
src/        BPF programs (crednotary.bpf.c), loader (crednotary.c), shared types
include/    vmlinux.h (Linux 7.3.1)
testmod/    privsim lab module (lab VMs only)
tests/      test suite and helpers (runas, privsim-test, suid-check, setfcap)
bench/      microbenchmarks
vm/         QEMU scripts: busybox VM, Debian VM, kernel build
scripts/    build of libbpf and bpftool from the kernel tree, PDF of the design document
docs/       design document (Markdown and PDF)
```

## License

GPL-2.0, see [`LICENSE`](LICENSE). The BPF programs declare a GPL license, as the BPF LSM and the helpers they use require.
