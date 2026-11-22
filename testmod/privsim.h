/* SPDX-License-Identifier: GPL-2.0 */
/*
 * privsim: ioctl interface of the lab driver that SIMULATES the effects of
 * the primitives typical of a kernel privilege escalation, to test
 * CredNotary. It contains no exploit technique: each "attack" is a direct
 * call to kernel APIs that produces the same end state a real exploit would
 * reach.
 *
 * Header shared by the module and the user-space test programs.
 */
#ifndef PRIVSIM_H
#define PRIVSIM_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
typedef uint32_t __u32;
#endif

#define PRIVSIM_MAGIC 'P'

/* Effect of a classic "ROP" payload: commit_creds(prepare_kernel_cred(&init_task)) */
#define PRIVSIM_COMMIT_ROOT	_IO(PRIVSIM_MAGIC, 1)
/* Effect of a data-only attack: in-place overwrite of the cred fields */
#define PRIVSIM_OVERWRITE_CRED	_IO(PRIVSIM_MAGIC, 2)
/* Effect of a cred pointer swap (DirtyCred / cred spraying style) */
#define PRIVSIM_SWAP_CRED	_IO(PRIVSIM_MAGIC, 3)

/* Commit of capabilities only (uid unchanged): CAP_FULL_SET in effective/permitted */
#define PRIVSIM_COMMIT_CAPS	_IO(PRIVSIM_MAGIC, 5)
/* Commit towards another, NON-root user (uid/gid 1001) without going through setuid() */
#define PRIVSIM_COMMIT_UID	_IO(PRIVSIM_MAGIC, 6)
/* Only task->cred (the subjective cred) points to a root cred; real_cred unchanged */
#define PRIVSIM_REDIRECT_CRED	_IO(PRIVSIM_MAGIC, 7)
/* In-place overwrite of the inheritable set only (it becomes real at execve) */
#define PRIVSIM_OVERWRITE_INH	_IO(PRIVSIM_MAGIC, 8)
/*
 * Arms a write into the ALREADY authorized cred: at the calling process's
 * next setuid(), after the LSM hooks have approved the new cred and before
 * commit_creds(), its fields become root.
 */
#define PRIVSIM_ARM_TOKEN_RACE	_IO(PRIVSIM_MAGIC, 9)
/* GID 0 added in place to the supplementary groups of the current cred */
#define PRIVSIM_ROOT_GROUP	_IO(PRIVSIM_MAGIC, 10)

/*
 * Simulated vulnerability SIM-2026-0001: PRIVSIM_SET_CFG accepts a
 * configuration; because of a bug (a missing permission check on a debug
 * flag left in the code), the PRIVSIM_F_DEBUG flag grants root to anyone who
 * can open the device. Legitimate use: flags without PRIVSIM_F_DEBUG.
 */
struct privsim_cfg {
	__u32 mode;
	__u32 flags;
};
#define PRIVSIM_F_DEBUG		0x8000
#define PRIVSIM_SET_CFG		_IOW(PRIVSIM_MAGIC, 4, struct privsim_cfg)

#endif /* PRIVSIM_H */
