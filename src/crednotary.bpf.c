// SPDX-License-Identifier: GPL-2.0
/*
 * crednotary: detection (and optional blocking) of kernel privilege
 * escalation primitives with eBPF, on a stock kernel.
 *
 * Principle: "shadow state + authorized transitions".
 *  - For each task, task-local storage keeps a *shadow* of the credentials in
 *    their last legitimate state: the real_cred pointer, uid/gid (real,
 *    effective, saved, fs), supplementary groups (count, hash, presence of
 *    GID 0), the five capability sets, securebits and user_ns. The initial
 *    state comes from iter/task (trust on first use for missed tasks).
 *  - Legitimate privilege transitions ALWAYS go through an LSM decision point
 *    that sees the new cred before it is committed:
 *      execve             -> bprm_committing_creds(bprm)   (bprm->cred)
 *      set*uid / set*gid  -> task_fix_setuid / task_fix_setgid (new)
 *      setgroups          -> task_fix_setgroups (new)
 *      capset             -> capset (new)
 *    These hooks deposit a "token": the pointer of the new cred plus a copy
 *    of its contents (a write between the hook and the commit voids it).
 *  - Rule 1 (fentry/commit_creds): a commit that changes identity or raises
 *    privileges with respect to the shadow, without a token matching `new`
 *    (pointer and contents), is illegitimate: the typical effect of
 *    commit_creds(prepare_kernel_cred(...)) or of a tampered token.
 *  - Rule 2 (LSM checkpoints: capable, file_open, bprm_check_security,
 *    task_alloc, set*id, inode operations, signals, ptrace, control of other
 *    tasks, bpf(), reads of links/xattrs/ACLs): if real_cred (pointer or
 *    fields) differs from the shadow without going through commit_creds, it
 *    was tampered with in memory (data-only attack / pointer swap). In BLOCK
 *    mode the checkpoint denies the operation (-EPERM) BEFORE the stolen
 *    privileges are used.
 *  - Rule 2b (tp_btf/sys_enter): at system call entry task->cred must equal
 *    real_cred; otherwise the subjective cred was redirected and every later
 *    checkpoint of the task denies.
 *  - Rule 2c (sweep, iter/task every -s ms): the same check as rule 2 on all
 *    tasks, including those that reach no checkpoint (sleeping, or computing
 *    in user space); in kill mode the task is killed with
 *    bpf_send_signal_task.
 *  - Rule 3 (usermode helpers): UMH threads (modprobe, core_pattern "|",
 *    request-key...) may only execute allowlisted binaries; a modprobe_path
 *    overwritten in memory is blocked at exec.
 *  - Self-protection: the checkpoints on task_kill, ptrace and bpf() prevent
 *    a compromised task from killing the loader or detaching the programs
 *    (BLOCK); with -P the links stay pinned even if the loader exits. The UMH
 *    allowlist is frozen (BPF_MAP_FREEZE) after loading.
 *  - Quarantine (-m quarantine): in the kernel, like block; the loader moves
 *    the flagged process into a frozen cgroup v2.
 *
 * Compatibility builds (kernels 5.11-6.12):
 *  -DPG_COMPAT        no bpf_send_signal_task kfunc (in kill mode the loader
 *                     kills the task found by the sweep) and no read of the
 *                     previous hook's return value (the position of the
 *                     `ret` argument changes with the hook signatures);
 *  -DPG_SHADOW_HASH   shadow in a hash map keyed by task instead of task
 *                     storage (kernels < 5.13: task storage is not available
 *                     to fentry/tp_btf/iter); the entry is removed in
 *                     task_free.
 * Hooks missing from the kernel (task_fix_setgroups < 6.1, inode_get_acl
 * < 6.2) are skipped by the loader; without task_fix_setgroups the token for
 * setgroups() is deposited by fentry/set_groups.
 *
 * Performance: creds are read with direct BTF loads (no
 * bpf_probe_read_kernel), and instead of inode_permission, which runs for
 * every component of every path, the per-operation hooks are attached.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "crednotary.h"

char LICENSE[] SEC("license") = "GPL";

#define EPERM		1
#define SIGKILL		9
#define PF_KTHREAD	0x00200000

const volatile __u32 pg_mode = PG_MODE_LOG;
const volatile bool pg_verbose = false;

/* typeless ksym: only its address is needed, to recognise the initial namespace */
extern const void init_user_ns __ksym;

struct credv {
	__u32 uid, euid, suid, fsuid;
	__u32 gid, egid, sgid, fsgid;
	__u32 securebits;
	__u32 ngroups;		/* supplementary groups: count, */
	__u32 root_group;	/* presence of GID 0 among the first PG_MAX_GROUPS, */
	__u64 groups_hash;	/* FNV-1a hash of the first PG_MAX_GROUPS */
	__u64 cap_eff, cap_prm, cap_inh, cap_amb, cap_bset;
	__u64 user_ns;
};

#define PG_MAX_GROUPS	32

struct shadow {
	struct credv v;		/* last authorized state */
	__u64 cred_ptr;		/* authorized real_cred */
	__u64 auth_cred;	/* token deposited by an LSM transition hook */
	struct credv auth_v;	/* contents of the authorized cred when the token was taken */
	__u8 valid;
	__u8 flagged;		/* event already emitted for this task */
	__u8 is_umh;		/* usermode-helper thread waiting to exec */
	__u8 cred_redirect;	/* task->cred != real_cred seen at a system call */
	__u8 committing;	/* inside commit_creds: shadow already updated, real_cred not yet */
	__u64 auth_groups;	/* set_groups token (kernels without task_fix_setgroups) */
};

#ifdef PG_SHADOW_HASH
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, __u64);	/* address of the task_struct */
	__type(value, struct shadow);
} shadows SEC(".maps");

/* initial value of new entries (232+ bytes: kept off the stack) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct shadow);
} shadow_zero SEC(".maps");
#else
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct shadow);
} shadows SEC(".maps");
#endif

#ifdef PG_COMPAT
#define PG_PREV(ret)	0
#else
#define PG_PREV(ret)	(ret)	/* verdict of an earlier BPF program on the same hook */
#endif

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct umh_key {
	char path[PG_PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, struct umh_key);
	__type(value, __u8);
} umh_allow SEC(".maps");

/*
 * Global switch, written only by the loader: 0 until all programs are attached
 * and the snapshot is taken, and 0 again before detaching. Links are detached
 * (loader exit, removal of the pins) one program at a time: with commit_creds
 * still attached and task_fix_setuid already detached, a legitimate setuid
 * would look tokenless. With the switch off no rule fires, and commit_creds
 * only follows the commits (the shadow is kept up to date).
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} pg_ctl SEC(".maps");

static __always_inline bool pg_enabled(void)
{
	__u32 zero = 0, *on = bpf_map_lookup_elem(&pg_ctl, &zero);

	return on && *on;
}

/* per-CPU scratch for the UMH key (avoids 128 bytes on the stack) */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct umh_key);
} umh_scratch SEC(".maps");

/* ------------------------------------------------------------------------ */

/*
 * Supplementary groups: group_info is shared and immutable, like the cred.
 * The first PG_MAX_GROUPS GIDs are copied with a single read (the array is a
 * flexible member, so no direct access at a variable index) and hashed.
 */
static __always_inline void read_groups(struct credv *v, const struct cred *c)
{
	struct group_info *gi = c->group_info;
#ifdef PG_COMPAT
	/* verifiers < 6.x treat the variable-size write as a read */
	__u32 gids[PG_MAX_GROUPS] = {};
#else
	__u32 gids[PG_MAX_GROUPS];
#endif
	__u64 h = 0xcbf29ce484222325ULL;
	__u32 n, cnt, root = 0;

	v->ngroups = 0;
	v->root_group = 0;
	v->groups_hash = 0;
	if (!gi)
		return;
	n = gi->ngroups;
	v->ngroups = n;
	if (!n)
		return;
	cnt = n > PG_MAX_GROUPS ? PG_MAX_GROUPS : n;
	if (bpf_probe_read_kernel(gids, cnt * sizeof(__u32), &gi->gid))
		return;
	for (int i = 0; i < PG_MAX_GROUPS; i++) {
		if (i >= cnt)
			break;
		root |= gids[i] == 0;
		h = (h ^ gids[i]) * 0x100000001b3ULL;
	}
	v->root_group = root;
	v->groups_hash = h;
}

/* kernel_cap_t: { u64 val } since 6.3, { u32 cap[2] } before */
struct kernel_cap_struct___old {
	__u32 cap[2];
};

static __always_inline __u64 cap_u64(const kernel_cap_t *k)
{
	const struct kernel_cap_struct___old *o = (const void *)k;

	if (bpf_core_field_exists(k->val))
		return k->val;
	return o->cap[0] | ((__u64)o->cap[1] << 32);
}

static __always_inline void read_cred(struct credv *v, const struct cred *c)
{
	v->uid = c->uid.val;
	v->euid = c->euid.val;
	v->suid = c->suid.val;
	v->fsuid = c->fsuid.val;
	v->gid = c->gid.val;
	v->egid = c->egid.val;
	v->sgid = c->sgid.val;
	v->fsgid = c->fsgid.val;
	v->cap_eff = cap_u64(&c->cap_effective);
	v->cap_prm = cap_u64(&c->cap_permitted);
	v->cap_inh = cap_u64(&c->cap_inheritable);
	v->cap_amb = cap_u64(&c->cap_ambient);
	v->cap_bset = cap_u64(&c->cap_bset);
	v->securebits = c->securebits;
	v->user_ns = (__u64)c->user_ns;
	read_groups(v, c);
}

static __always_inline bool credv_eq(const struct credv *a, const struct credv *b)
{
	return a->uid == b->uid && a->euid == b->euid && a->suid == b->suid &&
	       a->fsuid == b->fsuid && a->gid == b->gid && a->egid == b->egid &&
	       a->sgid == b->sgid && a->fsgid == b->fsgid &&
	       a->cap_eff == b->cap_eff && a->cap_prm == b->cap_prm &&
	       a->cap_inh == b->cap_inh && a->cap_amb == b->cap_amb &&
	       a->cap_bset == b->cap_bset && a->securebits == b->securebits &&
	       a->ngroups == b->ngroups && a->groups_hash == b->groups_hash &&
	       a->user_ns == b->user_ns;
}

static __always_inline bool credv_eq_nogroups(const struct credv *a, const struct credv *b)
{
	return a->uid == b->uid && a->euid == b->euid && a->suid == b->suid &&
	       a->fsuid == b->fsuid && a->gid == b->gid && a->egid == b->egid &&
	       a->sgid == b->sgid && a->fsgid == b->fsgid &&
	       a->cap_eff == b->cap_eff && a->cap_prm == b->cap_prm &&
	       a->cap_inh == b->cap_inh && a->cap_amb == b->cap_amb &&
	       a->cap_bset == b->cap_bset && a->securebits == b->securebits &&
	       a->user_ns == b->user_ns;
}

/* Privilege-gain bits for a transition from o to n */
static __always_inline __u32 cred_gain(const struct credv *o, const struct credv *n)
{
	__u64 init_ns = (__u64)&init_user_ns;
	__u32 g = 0;

	if ((o->uid && !n->uid) || (o->euid && !n->euid) ||
	    (o->suid && !n->suid) || (o->fsuid && !n->fsuid))
		g |= PG_GAIN_UID;
	if ((o->gid && !n->gid) || (o->egid && !n->egid) ||
	    (o->sgid && !n->sgid) || (o->fsgid && !n->fsgid))
		g |= PG_GAIN_GID;
	/* GID 0 among the supplementary groups grants the same access as gid == 0 */
	if (!o->root_group && n->root_group)
		g |= PG_GAIN_GID;
	/* any identity change counts, also towards another non-root user */
	if (o->uid != n->uid || o->euid != n->euid || o->suid != n->suid ||
	    o->fsuid != n->fsuid || o->gid != n->gid || o->egid != n->egid ||
	    o->sgid != n->sgid || o->fsgid != n->fsgid ||
	    o->ngroups != n->ngroups || o->groups_hash != n->groups_hash)
		g |= PG_GAIN_ID_CHANGE;
	if (n->user_ns == init_ns) {
		if (o->user_ns != init_ns)
			g |= PG_GAIN_USERNS_ESC;
		/*
		 * Besides effective/permitted: the bounding set (which can only
		 * shrink), inheritable beyond I|P (the capset rule) and ambient
		 * beyond P&I (the PR_CAP_AMBIENT_RAISE rule). I and A become real
		 * capabilities at the next execve, so raising them is a gain.
		 */
		else if ((n->cap_eff & ~o->cap_eff) || (n->cap_prm & ~o->cap_prm) ||
			 (n->cap_bset & ~o->cap_bset) ||
			 (n->cap_inh & ~(o->cap_inh | o->cap_prm)) ||
			 (n->cap_amb & ~(o->cap_prm & o->cap_inh)))
			g |= PG_GAIN_CAPS;
	}
	return g;
}

static __always_inline bool is_kthread(struct task_struct *t)
{
	return t->flags & PF_KTHREAD;
}

#ifdef PG_SHADOW_HASH
static __always_inline struct shadow *peek_shadow(struct task_struct *t)
{
	__u64 k = (__u64)t;

	return bpf_map_lookup_elem(&shadows, &k);
}

static __always_inline struct shadow *get_shadow(struct task_struct *t)
{
	__u64 k = (__u64)t;
	__u32 zero = 0;
	struct shadow *s = bpf_map_lookup_elem(&shadows, &k), *z;

	if (s)
		return s;
	z = bpf_map_lookup_elem(&shadow_zero, &zero);
	if (!z)
		return NULL;
	bpf_map_update_elem(&shadows, &k, z, BPF_NOEXIST);
	return bpf_map_lookup_elem(&shadows, &k);
}
#else
static __always_inline struct shadow *peek_shadow(struct task_struct *t)
{
	return bpf_task_storage_get(&shadows, t, 0, 0);
}

static __always_inline struct shadow *get_shadow(struct task_struct *t)
{
	return bpf_task_storage_get(&shadows, t, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
}
#endif

static __always_inline void shadow_set(struct shadow *s, const struct cred *c,
				       const struct credv *v)
{
	s->v = *v;
	s->cred_ptr = (__u64)c;
	s->valid = 1;
}

static __always_inline void emit(__u32 type, __u32 hook, struct task_struct *t,
				 const struct shadow *s, const struct credv *cur,
				 const struct credv *nw, __u32 gain, int action,
				 __u32 ptr_mm, const char *kpath, __u32 reason)
{
	struct pg_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);

	if (!e)
		return;
	e->ts_ns = bpf_ktime_get_ns();
	e->type = type;
	e->hook = hook;
	e->pid = BPF_CORE_READ(t, pid);
	e->tgid = BPF_CORE_READ(t, tgid);
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	e->uid = cur ? cur->uid : 0;
	e->euid = cur ? cur->euid : 0;
	e->shadow_uid = s ? s->v.uid : 0;
	e->shadow_euid = s ? s->v.euid : 0;
	e->new_uid = nw ? nw->uid : 0;
	e->new_euid = nw ? nw->euid : 0;
	e->gain = gain;
	e->action = action;
	e->ptr_mismatch = ptr_mm;
	e->reason = reason;
	BPF_CORE_READ_STR_INTO(&e->comm, t, comm);
	if (kpath)
		bpf_probe_read_kernel_str(e->path, sizeof(e->path), kpath);
	else
		e->path[0] = 0;
	bpf_ringbuf_submit(e, 0);
}

/* Response to a compromised task: errno for the checkpoint to return (0 = allow) */
static __always_inline int respond(void)
{
	if (pg_mode == PG_MODE_KILL)
		bpf_send_signal(SIGKILL);
	return pg_mode >= PG_MODE_BLOCK ? -EPERM : 0;
}

/*
 * Integrity checkpoint for the current task.
 * Returns 0 if everything is consistent, otherwise the errno to use (0 in LOG mode).
 */
static __always_inline int checkpoint(__u32 hook)
{
	struct task_struct *t = bpf_get_current_task_btf();
	const struct cred *rc;
	struct credv cur;
	struct shadow *s;
	__u32 ptr_mm;
	int act;

	if (is_kthread(t) || !pg_enabled())
		return 0;
	s = get_shadow(t);
	if (!s)
		return 0;
	rc = t->real_cred;
	read_cred(&cur, rc);
	if (!s->valid) {
		/* task created before loading and missed by the snapshot: TOFU */
		shadow_set(s, rc, &cur);
		return 0;
	}
	/* subjective cred redirected (event already emitted in pg_sys_enter) */
	if (s->cred_redirect)
		return respond();
	ptr_mm = s->cred_ptr != (__u64)rc;
	if (!ptr_mm && credv_eq(&s->v, &cur))
		return 0;

	act = respond();
	if (!s->flagged) {
		s->flagged = 1;
		emit(PG_EV_CRED_TAMPER, hook, t, s, &cur, NULL,
		     cred_gain(&s->v, &cur), pg_mode == PG_MODE_KILL ? SIGKILL : act,
		     ptr_mm, NULL, ptr_mm ? PG_R_REAL_PTR : PG_R_FIELDS);
	}
	return act;
}

/* Deposits the authorization token after checking the current state */
static __always_inline int authorize(const struct cred *new, __u32 hook)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct shadow *s;
	int ret;

	ret = checkpoint(hook);
	if (PG_PREV(ret))
		return ret;
	s = get_shadow(t);
	/* a tampered state (even in LOG mode) is not "recycled" into a legitimate commit */
	if (s && !s->flagged) {
		s->auth_cred = (__u64)new;
		/* the token also covers the contents: a later write voids it */
		read_cred(&s->auth_v, new);
	}
	return 0;
}

/* ---------------- LSM decision points (legitimate transitions) ---------- */

SEC("lsm/task_fix_setuid")
int BPF_PROG(pg_fix_setuid, struct cred *new, const struct cred *old, int flags, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return authorize(new, PG_H_SETID);
}

SEC("lsm/task_fix_setgid")
int BPF_PROG(pg_fix_setgid, struct cred *new, const struct cred *old, int flags, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return authorize(new, PG_H_SETID);
}

SEC("lsm/task_fix_setgroups")
int BPF_PROG(pg_fix_setgroups, struct cred *new, const struct cred *old, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return authorize(new, PG_H_SETID);
}

SEC("lsm/capset")
int BPF_PROG(pg_capset, struct cred *new, const struct cred *old,
	     const kernel_cap_t *effective, const kernel_cap_t *inheritable,
	     const kernel_cap_t *permitted, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return authorize(new, PG_H_SETID);
}

SEC("lsm/bprm_committing_creds")
void BPF_PROG(pg_bprm_committing, const struct linux_binprm *bprm)
{
	/* void hook: it cannot deny; blocking happens in bprm_check_security */
	authorize(bprm->cred, PG_H_BPRM_CHECK);
}

/*
 * Kernels without task_fix_setgroups (< 6.1): setgroups() installs the groups
 * in the new cred with set_groups() after the CAP_SETGID check (not with
 * set_current_groups(), which the compiler may inline into the system call);
 * the cred that the next commit must install is recorded. The loader loads
 * this program only when the LSM hook is missing.
 */
SEC("fentry/set_groups")
int BPF_PROG(pg_set_groups, struct cred *new, struct group_info *gi)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct shadow *s;

	if (is_kthread(t) || checkpoint(PG_H_SETID))
		return 0;
	s = get_shadow(t);
	if (s && !s->flagged)
		s->auth_groups = (__u64)new;
	return 0;
}

/* ---------------- credential commit ------------------------------------ */

SEC("fentry/commit_creds")
int BPF_PROG(pg_commit_creds, struct cred *new)
{
	struct task_struct *t = bpf_get_current_task_btf();
	const struct cred *old;
	struct credv o, n;
	struct shadow *s;
	bool token, authorized, tampered;
	__u32 gain;

	if (is_kthread(t))
		return 0;
	s = get_shadow(t);
	if (!s)
		return 0;
	old = t->real_cred;
	read_cred(&o, old);
	read_cred(&n, new);
	/* the sweep skips the task until fexit/commit_creds has installed new */
	s->committing = 1;
	if (!pg_enabled()) {
		/* start-up or detach in progress: follow the commits without judging them */
		s->auth_cred = 0;
		if (!s->flagged)
			shadow_set(s, new, &n);
		return 0;
	}
	if (!s->valid)
		shadow_set(s, old, &o);

	token = s->auth_cred && s->auth_cred == (__u64)new;
	authorized = token && credv_eq(&s->auth_v, &n);
	s->auth_cred = 0;
	/*
	 * setgroups() on kernels without task_fix_setgroups: the commit of the
	 * cred passed to set_groups is authorized if nothing but the groups
	 * changes with respect to the shadow.
	 */
	if (!authorized && s->auth_groups && s->auth_groups == (__u64)new)
		authorized = credv_eq_nogroups(&s->v, &n);
	s->auth_groups = 0;
	tampered = s->cred_ptr != (__u64)old || !credv_eq(&s->v, &o);
	/* the gain is measured against the last AUTHORIZED state, not against `old` */
	gain = cred_gain(&s->v, &n);

	if (gain && !authorized) {
		if (pg_mode == PG_MODE_KILL)
			bpf_send_signal(SIGKILL);
		if (!s->flagged) {
			s->flagged = 1;
			/* fentry cannot deny the commit: in BLOCK mode the later checkpoints deny */
			emit(PG_EV_UNAUTH_COMMIT, PG_H_COMMIT_CREDS, t, s, &o, &n, gain,
			     pg_mode == PG_MODE_KILL ? SIGKILL :
			     (pg_mode == PG_MODE_BLOCK ? -EPERM : 0), 0, NULL,
			     token ? PG_R_TOKEN_CONTENT : PG_R_NO_TOKEN);
		}
		/* shadow unchanged: the later checkpoints will see the mismatch */
		return 0;
	}
	if (tampered) {
		if (pg_mode == PG_MODE_KILL)
			bpf_send_signal(SIGKILL);
		if (!s->flagged) {
			s->flagged = 1;
			emit(PG_EV_CRED_TAMPER, PG_H_COMMIT_CREDS, t, s, &o, &n,
			     cred_gain(&s->v, &o), pg_mode == PG_MODE_KILL ? SIGKILL :
			     (pg_mode == PG_MODE_BLOCK ? -EPERM : 0),
			     s->cred_ptr != (__u64)old, NULL,
			     s->cred_ptr != (__u64)old ? PG_R_REAL_PTR : PG_R_FIELDS);
		}
		return 0;
	}
	if (gain && pg_verbose)
		emit(PG_EV_AUTH_GAIN, PG_H_COMMIT_CREDS, t, s, &o, &n, gain, 0, 0, NULL, 0);
	shadow_set(s, new, &n);
	return 0;
}

SEC("fexit/commit_creds")
int BPF_PROG(pg_commit_creds_exit, struct cred *new, int ret)
{
	struct shadow *s = peek_shadow(bpf_get_current_task_btf());

	if (s)
		s->committing = 0;
	return 0;
}

/* A cred that was prepared but discarded must not leave a reusable token */
SEC("fentry/abort_creds")
int BPF_PROG(pg_abort_creds, struct cred *new)
{
	struct shadow *s = peek_shadow(bpf_get_current_task_btf());

	if (s && s->auth_cred == (__u64)new)
		s->auth_cred = 0;
	return 0;
}

/* ---------------- integrity checkpoints ---------------------------------- */

SEC("lsm/capable")
int BPF_PROG(pg_capable, const struct cred *cred, struct user_namespace *ns,
	     int cap, unsigned int opts, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_CAPABLE);
}

SEC("lsm/file_open")
int BPF_PROG(pg_file_open, struct file *file, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_FILE_OPEN);
}

/*
 * Additional checkpoints: operations whose permission check compares the
 * uid/capabilities of the current cred directly, without going through
 * capable() or file_open (DAC permissions on inodes, chmod/chown, signals,
 * ptrace, priority/limits of other processes), and bpf(), for
 * self-protection.
 */
/*
 * Filesystem namespace operations: the DAC check on the parent directory
 * (inode_permission with MAY_WRITE) always precedes them, but inode_permission
 * also runs for every component of every resolved path. Attaching the
 * specific hooks gives the same coverage with one invocation per operation.
 */
#define PG_INODE_OP(name, ...)						\
SEC("lsm/inode_" #name)							\
int BPF_PROG(pg_inode_##name, __VA_ARGS__, int ret)			\
{									\
	if (PG_PREV(ret))					\
		return ret;						\
	return checkpoint(PG_H_INODE);					\
}

PG_INODE_OP(create, struct inode *dir, struct dentry *dentry, umode_t mode)
PG_INODE_OP(link, struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
PG_INODE_OP(unlink, struct inode *dir, struct dentry *dentry)
PG_INODE_OP(symlink, struct inode *dir, struct dentry *dentry, const char *old_name)
PG_INODE_OP(mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
PG_INODE_OP(rmdir, struct inode *dir, struct dentry *dentry)
PG_INODE_OP(mknod, struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
PG_INODE_OP(rename, struct inode *old_dir, struct dentry *old_dentry,
	    struct inode *new_dir, struct dentry *new_dentry)
PG_INODE_OP(setxattr, struct mnt_idmap *idmap, struct dentry *dentry, const char *name,
	    const void *value, size_t size, int flags)
PG_INODE_OP(removexattr, struct mnt_idmap *idmap, struct dentry *dentry, const char *name)
/* stat()/statx(): covers metadata reached without opening the file */
PG_INODE_OP(getattr, const struct path *path)
/* reads that do not open the file: symbolic links, xattrs, ACLs */
PG_INODE_OP(readlink, struct dentry *dentry)
PG_INODE_OP(getxattr, struct dentry *dentry, const char *name)
PG_INODE_OP(listxattr, struct dentry *dentry)
PG_INODE_OP(get_acl, struct mnt_idmap *idmap, struct dentry *dentry, const char *acl_name)

SEC("lsm/inode_setattr")
int BPF_PROG(pg_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_INODE);
}

SEC("lsm/task_kill")
int BPF_PROG(pg_task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_SIGNAL);
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(pg_ptrace_access, struct task_struct *child, unsigned int mode, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_PTRACE);
}

SEC("lsm/task_setnice")
int BPF_PROG(pg_task_setnice, struct task_struct *p, int nice, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_TASKCTL);
}

SEC("lsm/task_setioprio")
int BPF_PROG(pg_task_setioprio, struct task_struct *p, int ioprio, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_TASKCTL);
}

SEC("lsm/task_setscheduler")
int BPF_PROG(pg_task_setscheduler, struct task_struct *p, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_TASKCTL);
}

SEC("lsm/task_prlimit")
int BPF_PROG(pg_task_prlimit, const struct cred *cred, const struct cred *tcred,
	     unsigned int flags, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_TASKCTL);
}

SEC("lsm/bpf")
int BPF_PROG(pg_bpf, int cmd, union bpf_attr *attr, unsigned int size, bool kernel, int ret)
{
	if (PG_PREV(ret))
		return ret;
	return checkpoint(PG_H_BPF);
}

/*
 * Redirected subjective cred: at system call entry task->cred always equals
 * task->real_cred (override_creds() is temporary and is reverted before the
 * return to user space). If they differ, someone rewrote task->cred. The LSM
 * checkpoints of the same system call will see cred_redirect and deny the
 * operation in BLOCK mode.
 */
SEC("tp_btf/sys_enter")
int BPF_PROG(pg_sys_enter, struct pt_regs *regs, long id)
{
	struct task_struct *t = bpf_get_current_task_btf();
	const struct cred *c = t->cred;
	struct credv cur;
	struct shadow *s;

	if ((__u64)c == (__u64)t->real_cred || is_kthread(t) || !pg_enabled())
		return 0;
	s = get_shadow(t);
	if (!s)
		return 0;
	if (!s->cred_redirect) {
		s->cred_redirect = 1;
		s->flagged = 1;
		read_cred(&cur, c);
		emit(PG_EV_CRED_TAMPER, PG_H_SYSCALL, t, s, &cur, NULL,
		     cred_gain(&s->v, &cur),
		     pg_mode == PG_MODE_KILL ? SIGKILL : (pg_mode == PG_MODE_BLOCK ? -EPERM : 0),
		     2, NULL, PG_R_CRED_REDIRECT);
	}
	if (pg_mode == PG_MODE_KILL)
		bpf_send_signal(SIGKILL);
	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(pg_task_alloc, struct task_struct *task, unsigned long clone_flags, int ret)
{
	struct task_struct *cur_t = bpf_get_current_task_btf();
	struct shadow *ps, *cs;
	const struct cred *crc;
	struct credv cv;
	int act;

	if (PG_PREV(ret))
		return ret;
	if (is_kthread(cur_t))
		return 0;
	act = checkpoint(PG_H_TASK_ALLOC);
	if (act)
		return act;

	ps = peek_shadow(cur_t);
	cs = get_shadow(task);
	if (!ps || !cs || !ps->valid)
		return 0;
	crc = task->real_cred;
	if (ps->flagged) {
		/* child of a compromised task (LOG mode): inherits the authorized state */
		cs->v = ps->v;
		cs->cred_ptr = (__u64)crc;
		cs->valid = 1;
		return 0;
	}
	read_cred(&cv, crc);
	shadow_set(cs, crc, &cv);
	return 0;
}

/* ---------------- usermode helper (modprobe_path, core_pattern, ...) ------ */

static __always_inline bool umh_allowed(const char *kpath)
{
	__u32 zero = 0;
	struct umh_key *k = bpf_map_lookup_elem(&umh_scratch, &zero);

	if (!k)
		return true;
	__builtin_memset(k->path, 0, sizeof(k->path));
	bpf_probe_read_kernel_str(k->path, sizeof(k->path), kpath);
	return bpf_map_lookup_elem(&umh_allow, k) != NULL;
}

/* UMH request: current is the process that triggered it (e.g. socket() of an unloaded family) */
SEC("fentry/call_usermodehelper_exec")
int BPF_PROG(pg_umh_request, struct subprocess_info *sub_info, int wait)
{
	const char *path = BPF_CORE_READ(sub_info, path);

	if (!umh_allowed(path))
		emit(PG_EV_UMH_REQUEST, PG_H_UMH, bpf_get_current_task_btf(), NULL,
		     NULL, NULL, 0, 0, 0, path, 0);
	return 0;
}

/* Body of the UMH thread: marks the task; the check happens at exec */
SEC("fentry/call_usermodehelper_exec_async")
int BPF_PROG(pg_umh_thread, void *data)
{
	struct shadow *s = get_shadow(bpf_get_current_task_btf());

	if (s)
		s->is_umh = 1;
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(pg_bprm_check, struct linux_binprm *bprm, int ret)
{
	struct task_struct *t = bpf_get_current_task_btf();
	struct shadow *s;
	const char *fname;

	if (PG_PREV(ret))
		return ret;
	s = peek_shadow(t);
	if (s && s->is_umh && pg_enabled()) {
		s->is_umh = 0;
		fname = BPF_CORE_READ(bprm, filename);
		if (!umh_allowed(fname)) {
			int act = pg_mode >= PG_MODE_BLOCK ? -EPERM : 0;

			emit(PG_EV_UMH_EXEC_BLOCKED, PG_H_UMH, t, NULL, NULL, NULL, 0,
			     act, 0, fname, 0);
			return act;
		}
		return 0;
	}
	return checkpoint(PG_H_BPRM_CHECK);
}

/* ---------------- periodic sweep ----------------------------------------- */

#ifndef PG_COMPAT
/* __weak: on kernels without the kfunc (< 6.13) loading still succeeds */
extern int bpf_send_signal_task(struct task_struct *task, int sig,
				enum pid_type type, __u64 value) __ksym __weak;
#endif

/*
 * Run by the loader every -s milliseconds: compares the real_cred of every
 * task with its shadow, even if the task reaches no checkpoint (sleeping
 * tasks, or tasks in user space without system calls). task->cred is not
 * compared: a task stopped inside a system call may hold a legitimate
 * override_creds.
 */
SEC("iter/task")
int pg_sweep(struct bpf_iter__task *ctx)
{
	struct task_struct *t = ctx->task;
	const struct cred *rc;
	struct credv cur;
	struct shadow *s;
	__u32 ptr_mm;

	if (!t || is_kthread(t) || !pg_enabled())
		return 0;
	s = peek_shadow(t);
	if (!s || !s->valid || s->flagged || s->committing)
		return 0;
	rc = t->real_cred;
	read_cred(&cur, rc);
	ptr_mm = s->cred_ptr != (__u64)rc;
	if (!ptr_mm && credv_eq(&s->v, &cur))
		return 0;
	/* the task's later checkpoints deny anyway (the shadow does not change) */
	s->flagged = 1;
	emit(PG_EV_CRED_TAMPER, PG_H_SWEEP, t, s, &cur, NULL, cred_gain(&s->v, &cur),
	     pg_mode == PG_MODE_KILL ? SIGKILL : (pg_mode == PG_MODE_BLOCK ? -EPERM : 0),
	     ptr_mm, NULL, ptr_mm ? PG_R_REAL_PTR : PG_R_FIELDS);
#ifndef PG_COMPAT
	/* without the kfunc (or in compat builds) the loader sends the SIGKILL */
	if (pg_mode == PG_MODE_KILL && bpf_ksym_exists(bpf_send_signal_task))
		bpf_send_signal_task(t, SIGKILL, PIDTYPE_PID, 0);
#endif
	return 0;
}

/* ---------------- initial snapshot of all tasks --------------------------- */

SEC("iter/task")
int pg_snapshot(struct bpf_iter__task *ctx)
{
	struct task_struct *t = ctx->task;
	const struct cred *rc;
	struct credv v;
	struct shadow *s;

	if (!t || is_kthread(t))
		return 0;
	s = get_shadow(t);
	if (!s || s->valid)
		return 0;
	rc = t->real_cred;
	read_cred(&v, rc);
	shadow_set(s, rc, &v);
	return 0;
}

#ifdef PG_SHADOW_HASH
/* with task storage the entry goes away with the task; with the hash map it must be removed */
SEC("lsm/task_free")
void BPF_PROG(pg_task_free, struct task_struct *task)
{
	__u64 k = (__u64)task;

	bpf_map_delete_elem(&shadows, &k);
}
#endif
