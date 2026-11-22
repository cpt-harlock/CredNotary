// SPDX-License-Identifier: GPL-2.0
/*
 * privsim - LAB-ONLY driver (test VMs only) that simulates the end state left
 * by kernel privilege-escalation primitives, to validate CredNotary. See
 * privsim.h for the interface.
 *
 * NEVER load it on a real system: it exposes /dev/privsim with mode 0666 and
 * grants root to any user. To prevent loading it by mistake, the module
 * starts only with explicit consent:
 *     insmod privsim.ko i_understand_this_grants_root=1
 */
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/capability.h>
#include <linux/error-injection.h>
#include <linux/kprobes.h>
#include <linux/atomic.h>
#include "privsim.h"

static u32 privsim_mode;

static bool i_understand_this_grants_root;
module_param(i_understand_this_grants_root, bool, 0444);
MODULE_PARM_DESC(i_understand_this_grants_root,
		 "Required (=1): /dev/privsim lets ANY local user become root. Lab VMs only.");

/* "ROP payload" effect: new root credentials committed from the ioctl context */
static long privsim_commit_root(void)
{
	struct cred *new = prepare_kernel_cred(&init_task);

	if (!new)
		return -ENOMEM;
	return commit_creds(new);
}

/* "Data-only" effect: the fields of the current cred are rewritten in place */
static long privsim_overwrite_cred(void)
{
	struct cred *c = (struct cred *)current->real_cred;

	c->uid = c->euid = c->suid = c->fsuid = GLOBAL_ROOT_UID;
	c->gid = c->egid = c->sgid = c->fsgid = GLOBAL_ROOT_GID;
	c->cap_effective = c->cap_permitted = CAP_FULL_SET;
	return 0;
}

/* "Pointer swap" effect: real_cred/cred point to a root cred without commit_creds */
static long privsim_swap_cred(void)
{
	struct cred *new = prepare_kernel_cred(&init_task);

	if (!new)
		return -ENOMEM;
	get_cred(new);	/* one reference for real_cred and one for cred */
	/* the old creds are deliberately leaked, as in an exploit */
	rcu_assign_pointer(current->real_cred, new);
	rcu_assign_pointer(current->cred, new);
	return 0;
}

/* Capabilities only: uid unchanged, full effective/permitted */
static long privsim_commit_caps(void)
{
	struct cred *new = prepare_creds();

	if (!new)
		return -ENOMEM;
	new->cap_effective = new->cap_permitted = CAP_FULL_SET;
	return commit_creds(new);
}

/* Identity change towards a non-root user, without setuid() */
static long privsim_commit_uid(void)
{
	struct cred *new = prepare_creds();
	kuid_t u = KUIDT_INIT(1001);
	kgid_t g = KGIDT_INIT(1001);

	if (!new)
		return -ENOMEM;
	new->uid = new->euid = new->suid = new->fsuid = u;
	new->gid = new->egid = new->sgid = new->fsgid = g;
	return commit_creds(new);
}

/* Only the subjective cred (task->cred) is redirected to a root cred */
static long privsim_redirect_cred(void)
{
	struct cred *new = prepare_kernel_cred(&init_task);

	if (!new)
		return -ENOMEM;
	/* new's reference moves to task->cred; the old cred's reference is leaked */
	rcu_assign_pointer(current->cred, new);
	return 0;
}

/* Only the inheritable set, in place */
static long privsim_overwrite_inh(void)
{
	struct cred *c = (struct cred *)current->real_cred;

	c->cap_inheritable = CAP_FULL_SET;
	return 0;
}

static long privsim_root_group(void)
{
	struct cred *c = (struct cred *)current->real_cred;
	struct group_info *gi = groups_alloc(1);

	if (!gi)
		return -ENOMEM;
	gi->gid[0] = GLOBAL_ROOT_GID;
	c->group_info = gi;	/* the old group_info stays referenced: lab only */
	return 0;
}

/*
 * Write into the authorized cred: a kretprobe on the return of
 * security_task_fix_setuid(), that is after the decision of every LSM (BPF
 * included) and before commit_creds().
 */
static atomic_t race_tgid = ATOMIC_INIT(0);

struct race_data {
	struct cred *new;
};

static int race_entry(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct race_data *d = (struct race_data *)ri->data;

	if (atomic_read(&race_tgid) != current->tgid)
		return 1;	/* not of interest: no return handler */
	d->new = (struct cred *)regs_get_kernel_argument(regs, 0);
	return 0;
}

static int race_ret(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	struct race_data *d = (struct race_data *)ri->data;

	if (regs_return_value(regs) == 0 &&
	    atomic_cmpxchg(&race_tgid, current->tgid, 0) == current->tgid) {
		struct cred *c = d->new;

		c->uid = c->euid = c->suid = c->fsuid = GLOBAL_ROOT_UID;
		c->gid = c->egid = c->sgid = c->fsgid = GLOBAL_ROOT_GID;
		c->cap_effective = c->cap_permitted = CAP_FULL_SET;
	}
	return 0;
}

static struct kretprobe race_krp = {
	.kp.symbol_name	= "security_task_fix_setuid",
	.entry_handler	= race_entry,
	.handler	= race_ret,
	.data_size	= sizeof(struct race_data),
	.maxactive	= 16,
};
static bool race_registered;

int privsim_apply_cfg(const struct privsim_cfg *cfg);

/*
 * Vulnerable function of the simulated vulnerability SIM-2026-0001. noinline +
 * ALLOW_ERROR_INJECTION make it attachable by fmod_ret / bpf_override_return.
 */
noinline int privsim_apply_cfg(const struct privsim_cfg *cfg)
{
	privsim_mode = cfg->mode;
	if (cfg->flags & PRIVSIM_F_DEBUG) {
		/* BUG: missing capable(CAP_SYS_ADMIN) before the debug branch */
		return privsim_commit_root();
	}
	return 0;
}
ALLOW_ERROR_INJECTION(privsim_apply_cfg, ERRNO);

static long privsim_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	struct privsim_cfg cfg;

	switch (cmd) {
	case PRIVSIM_COMMIT_ROOT:
		return privsim_commit_root();
	case PRIVSIM_OVERWRITE_CRED:
		return privsim_overwrite_cred();
	case PRIVSIM_SWAP_CRED:
		return privsim_swap_cred();
	case PRIVSIM_COMMIT_CAPS:
		return privsim_commit_caps();
	case PRIVSIM_COMMIT_UID:
		return privsim_commit_uid();
	case PRIVSIM_REDIRECT_CRED:
		return privsim_redirect_cred();
	case PRIVSIM_OVERWRITE_INH:
		return privsim_overwrite_inh();
	case PRIVSIM_ROOT_GROUP:
		return privsim_root_group();
	case PRIVSIM_ARM_TOKEN_RACE:
		if (!race_registered)
			return -ENODEV;
		atomic_set(&race_tgid, current->tgid);
		return 0;
	case PRIVSIM_SET_CFG:
		if (copy_from_user(&cfg, (void __user *)arg, sizeof(cfg)))
			return -EFAULT;
		return privsim_apply_cfg(&cfg);
	}
	return -ENOTTY;
}

static const struct file_operations privsim_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= privsim_ioctl,
};

static struct miscdevice privsim_dev = {
	.minor	= MISC_DYNAMIC_MINOR,
	.name	= "privsim",
	.fops	= &privsim_fops,
	.mode	= 0666,
};

static int __init privsim_init(void)
{
	if (!i_understand_this_grants_root) {
		pr_err("privsim: refusing to load: it lets any local user become root; "
		       "load with i_understand_this_grants_root=1 in a lab VM only\n");
		return -EPERM;
	}
	pr_warn("privsim: LAB-ONLY privilege escalation simulator loaded\n");
	if (register_kretprobe(&race_krp) == 0)
		race_registered = true;
	else
		pr_warn("privsim: kretprobe on security_task_fix_setuid not available\n");
	return misc_register(&privsim_dev);
}

static void __exit privsim_exit(void)
{
	misc_deregister(&privsim_dev);
	if (race_registered)
		unregister_kretprobe(&race_krp);
}

module_init(privsim_init);
module_exit(privsim_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Lab-only simulator of kernel privilege-escalation end states");
