/* SPDX-License-Identifier: GPL-2.0 */
/* Types shared by crednotary.bpf.c and the user-space loader crednotary.c */
#ifndef CREDNOTARY_H
#define CREDNOTARY_H

#define PG_PATH_LEN 128

/* Response mode (rodata, set by the loader) */
enum pg_mode {
	PG_MODE_LOG	= 0,	/* events only */
	PG_MODE_BLOCK	= 1,	/* events + synchronous denial at the LSM checkpoints */
	PG_MODE_KILL	= 2,	/* like BLOCK + SIGKILL to the offending task */
};

/* Event types */
enum pg_event_type {
	PG_EV_UNAUTH_COMMIT	= 1,	/* commit_creds with a privilege gain and no LSM authorization */
	PG_EV_CRED_TAMPER	= 2,	/* real_cred (pointer or fields) differs from the shadow */
	PG_EV_UMH_EXEC_BLOCKED	= 3,	/* usermode helper executing a binary not in the allowlist */
	PG_EV_UMH_REQUEST	= 4,	/* usermode helper request for a path not in the allowlist */
	PG_EV_AUTH_GAIN		= 5,	/* legitimate privilege gain (only with -v) */
};

/* Checkpoint / hook that raised the event */
enum pg_hook {
	PG_H_COMMIT_CREDS = 1,
	PG_H_CAPABLE,
	PG_H_FILE_OPEN,
	PG_H_BPRM_CHECK,
	PG_H_TASK_ALLOC,
	PG_H_SETID,
	PG_H_UMH,
	PG_H_INODE,	/* inode_{create,link,unlink,...,setattr,getattr,setxattr} */
	PG_H_SIGNAL,	/* task_kill */
	PG_H_PTRACE,	/* ptrace_access_check */
	PG_H_TASKCTL,	/* task_setnice/setioprio/setscheduler/prlimit */
	PG_H_BPF,	/* bpf() */
	PG_H_SYSCALL,	/* system call entry (tp_btf/sys_enter) */
	PG_H_SWEEP,	/* periodic sweep of all tasks (iter/task) */
};

/* Reason for the event (reason field) */
enum pg_reason {
	PG_R_NO_TOKEN		= 1,	/* commit with a gain or identity change and no token */
	PG_R_TOKEN_CONTENT	= 2,	/* token present, but the cred changed after authorization */
	PG_R_REAL_PTR		= 3,	/* real_cred points to a cred other than the authorized one */
	PG_R_FIELDS		= 4,	/* real_cred fields differ from the shadow (in-place overwrite) */
	PG_R_CRED_REDIRECT	= 5,	/* task->cred != task->real_cred at system call entry */
};

/* "Gain" bits, computed by comparing the old and the new cred */
#define PG_GAIN_UID		(1u << 0)
#define PG_GAIN_GID		(1u << 1)
#define PG_GAIN_CAPS		(1u << 2)
#define PG_GAIN_USERNS_ESC	(1u << 3)
#define PG_GAIN_ID_CHANGE	(1u << 4)	/* uid/gid changed (also towards a non-root user) */

struct pg_event {
	unsigned long long ts_ns;
	unsigned int type;
	unsigned int hook;
	unsigned int pid;
	unsigned int tgid;
	unsigned int ppid;
	unsigned int uid;	/* current real_cred */
	unsigned int euid;
	unsigned int shadow_uid;	/* last authorized state */
	unsigned int shadow_euid;
	unsigned int gain;
	unsigned int new_uid;	/* for UNAUTH_COMMIT: incoming cred */
	unsigned int new_euid;
	int action;		/* 0 = allowed/logged, <0 = errno returned, 9 = SIGKILL */
	unsigned int ptr_mismatch;
	unsigned int reason;	/* enum pg_reason */
	char comm[16];
	char path[PG_PATH_LEN];
};

#endif
