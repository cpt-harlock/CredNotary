// SPDX-License-Identifier: GPL-2.0
/*
 * crednotary: user-space loader.
 *
 *   crednotary [-m log|block|kill|quarantine] [-v] [-a /path/helper]... [-t seconds] [-P dir]
 *
 * With -P the BPF links are pinned in dir (on bpffs): protection stays active
 * even if the loader exits or is killed. To remove it in order:
 * crednotary -U dir.
 *
 * Loads the BPF programs, fills the usermode-helper allowlist with the
 * *current* value of /proc/sys/kernel/modprobe and core_pattern (if it is a
 * pipe), takes a snapshot of the credentials of all existing tasks and prints
 * the ring-buffer events, one line per event.
 */
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include "crednotary.h"
#include "crednotary.skel.h"

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static const char *ev_name(unsigned int t)
{
	switch (t) {
	case PG_EV_UNAUTH_COMMIT:	return "UNAUTH_COMMIT";
	case PG_EV_CRED_TAMPER:		return "CRED_TAMPER";
	case PG_EV_UMH_EXEC_BLOCKED:	return "UMH_EXEC_BLOCKED";
	case PG_EV_UMH_REQUEST:		return "UMH_REQUEST";
	case PG_EV_AUTH_GAIN:		return "AUTH_GAIN";
	}
	return "?";
}

static const char *hook_name(unsigned int h)
{
	switch (h) {
	case PG_H_COMMIT_CREDS:	return "commit_creds";
	case PG_H_CAPABLE:	return "capable";
	case PG_H_FILE_OPEN:	return "file_open";
	case PG_H_BPRM_CHECK:	return "bprm_check";
	case PG_H_TASK_ALLOC:	return "task_alloc";
	case PG_H_SETID:	return "set*id";
	case PG_H_UMH:		return "umh";
	case PG_H_INODE:	return "inode";
	case PG_H_SIGNAL:	return "task_kill";
	case PG_H_PTRACE:	return "ptrace";
	case PG_H_TASKCTL:	return "task_ctl";
	case PG_H_BPF:		return "bpf";
	case PG_H_SYSCALL:	return "sys_enter";
	case PG_H_SWEEP:	return "sweep";
	}
	return "?";
}

static const char *reason_name(unsigned int r)
{
	switch (r) {
	case PG_R_NO_TOKEN:		return "no_token";
	case PG_R_TOKEN_CONTENT:	return "token_content_changed";
	case PG_R_REAL_PTR:		return "real_cred_ptr";
	case PG_R_FIELDS:		return "fields";
	case PG_R_CRED_REDIRECT:	return "cred_redirect";
	}
	return "-";
}

static void gain_str(unsigned int g, char *buf, size_t n)
{
	snprintf(buf, n, "%s%s%s%s%s%s", g ? "" : "none",
		 g & PG_GAIN_UID ? "uid," : "", g & PG_GAIN_GID ? "gid," : "",
		 g & PG_GAIN_CAPS ? "caps," : "",
		 g & PG_GAIN_USERNS_ESC ? "userns_escape," : "",
		 g & PG_GAIN_ID_CHANGE ? "id_change," : "");
	size_t l = strlen(buf);
	if (l && buf[l - 1] == ',')
		buf[l - 1] = 0;
}

static void action_str(int a, char *buf, size_t n)
{
	if (a == 0)
		snprintf(buf, n, "logged");
	else if (a == SIGKILL)
		snprintf(buf, n, "SIGKILL");
	else
		snprintf(buf, n, "denied(%d)", a);
}

static enum pg_mode mode = PG_MODE_LOG;

/* Quarantine mode: frozen cgroup v2 into which the loader moves flagged processes */
static const char *quarantine_dir;
static bool quarantine_mode;

static int write_file(const char *dir, const char *name, const char *val)
{
	char path[512];
	FILE *f;
	int err = 0;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "w");
	if (!f)
		return -errno;
	if (fputs(val, f) < 0)
		err = -errno;
	if (fclose(f) && !err)
		err = -errno;
	return err;
}

static int quarantine_setup(const char *dir)
{
	int err;

	if (mkdir(dir, 0700) && errno != EEXIST)
		return -errno;
	/* whatever enters a frozen cgroup is frozen too */
	err = write_file(dir, "cgroup.freeze", "1");
	if (err)
		return err;
	printf("[crednotary] quarantine cgroup %s (frozen)\n", dir);
	return 0;
}

/* Moves the whole process (tgid) into the quarantine cgroup */
static void quarantine(unsigned int tgid)
{
	char buf[16];
	int err;

	snprintf(buf, sizeof(buf), "%u", tgid);
	err = write_file(quarantine_dir, "cgroup.procs", buf);
	if (err)
		fprintf(stderr, "crednotary: quarantine %u: %s\n", tgid, strerror(-err));
	else
		printf("[crednotary] QUARANTINED tgid=%u\n", tgid);
}

static int on_event(void *ctx, void *data, size_t len)
{
	const struct pg_event *e = data;
	char g[64], a[32];

	(void)ctx;
	if (len < sizeof(*e))
		return 0;
	gain_str(e->gain, g, sizeof(g));
	action_str(e->action, a, sizeof(a));

	switch (e->type) {
	case PG_EV_UNAUTH_COMMIT:
	case PG_EV_AUTH_GAIN:
		printf("[crednotary] %s hook=%s pid=%u ppid=%u comm=%s uid=%u euid=%u -> new uid=%u euid=%u gain=%s reason=%s action=%s\n",
		       ev_name(e->type), hook_name(e->hook), e->pid, e->ppid, e->comm,
		       e->uid, e->euid, e->new_uid, e->new_euid, g, reason_name(e->reason), a);
		break;
	case PG_EV_CRED_TAMPER:
		printf("[crednotary] %s hook=%s pid=%u ppid=%u comm=%s cred uid=%u euid=%u vs shadow uid=%u euid=%u ptr_swapped=%u gain=%s reason=%s action=%s\n",
		       ev_name(e->type), hook_name(e->hook), e->pid, e->ppid, e->comm,
		       e->uid, e->euid, e->shadow_uid, e->shadow_euid, e->ptr_mismatch, g,
		       reason_name(e->reason), a);
		break;
	case PG_EV_UMH_EXEC_BLOCKED:
	case PG_EV_UMH_REQUEST:
		printf("[crednotary] %s path=%s pid=%u ppid=%u comm=%s action=%s\n",
		       ev_name(e->type), e->path, e->pid, e->ppid, e->comm, a);
		break;
	}
	/*
	 * The sweep runs in the loader's context: without the
	 * bpf_send_signal_task kfunc (< 6.13, compat builds) the kernel cannot
	 * kill the task it found, so the loader does (a second SIGKILL is
	 * harmless).
	 */
	if (mode == PG_MODE_KILL && e->hook == PG_H_SWEEP && e->type == PG_EV_CRED_TAMPER)
		kill(e->pid, SIGKILL);
	/* helper (UMH) threads are kernel workers: their exec is already denied */
	if (quarantine_dir && e->tgid &&
	    (e->type == PG_EV_UNAUTH_COMMIT || e->type == PG_EV_CRED_TAMPER))
		quarantine(e->tgid);
	fflush(stdout);
	return 0;
}

static int allow_umh(struct crednotary_bpf *skel, const char *path)
{
	char key[PG_PATH_LEN] = {};
	unsigned char one = 1;

	if (!path || !*path)
		return 0;
	strncpy(key, path, sizeof(key) - 1);
	if (bpf_map__update_elem(skel->maps.umh_allow, key, sizeof(key), &one,
				 sizeof(one), BPF_ANY)) {
		fprintf(stderr, "crednotary: allowlist %s: %s\n", path, strerror(errno));
		return -1;
	}
	printf("[crednotary] umh allowlist += %s\n", key);
	return 0;
}

/* Reads the first "word" of a sysctl file; for core_pattern only if it starts with '|' */
static void allow_from_sysctl(struct crednotary_bpf *skel, const char *file, bool pipe_only)
{
	char buf[PG_PATH_LEN] = {}, *p;
	FILE *f = fopen(file, "r");

	if (!f)
		return;
	if (fgets(buf, sizeof(buf), f)) {
		p = buf;
		if (pipe_only) {
			if (*p != '|')
				goto out;
			p++;
		}
		p[strcspn(p, " \t\n")] = 0;
		allow_umh(skel, p);
	}
out:
	fclose(f);
}

/* One pass of an attached iterator: each read() runs the program over the tasks */
static int run_iter(struct bpf_link *link)
{
	char buf[64];
	int fd = bpf_iter_create(bpf_link__fd(link));

	if (fd < 0)
		return fd;
	while (read(fd, buf, sizeof(buf)) > 0)
		;
	close(fd);
	return 0;
}

static long long now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000LL + ts.tv_nsec / 1000;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static int snapshot_tasks(struct crednotary_bpf *skel)
{
	struct bpf_link *link;
	int err;

	link = bpf_program__attach_iter(skel->progs.pg_snapshot, NULL);
	if (!link)
		return -errno;
	err = run_iter(link);
	bpf_link__destroy(link);
	return err;
}

static int set_enabled(int ctl_fd, __u32 on)
{
	__u32 zero = 0;

	return bpf_map_update_elem(ctl_fd, &zero, &on, BPF_ANY) ? -errno : 0;
}

/* Pins on bpffs all the links attached by the skeleton, and the pg_ctl switch */
static int pin_links(struct crednotary_bpf *skel, const char *dir)
{
	const struct bpf_object_skeleton *sk = skel->skeleton;
	char path[256];

	if (mkdir(dir, 0700) && errno != EEXIST) {
		fprintf(stderr, "crednotary: mkdir %s: %s\n", dir, strerror(errno));
		return -errno;
	}
	for (int i = 0; i < sk->prog_cnt; i++) {
		struct bpf_link *l = *sk->progs[i].link;

		if (!l)
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, sk->progs[i].name);
		if (bpf_link__pin(l, path)) {
			fprintf(stderr, "crednotary: pin %s: %s\n", path, strerror(errno));
			return -errno;
		}
	}
	snprintf(path, sizeof(path), "%s/pg_ctl", dir);
	if (bpf_map__pin(skel->maps.pg_ctl, path)) {
		fprintf(stderr, "crednotary: pin %s: %s\n", path, strerror(errno));
		return -errno;
	}
	printf("[crednotary] links pinned in %s\n", dir);
	return 0;
}

/*
 * Orderly detach of a pinned instance: first the switch is turned off (no rule
 * fires any more), then the links are removed one at a time, and finally the
 * switch itself. An "rm -r" of the pins detaches the programs in arbitrary
 * order and leaves windows in which a legitimate transition looks illegal.
 */
static int unpin_all(const char *dir)
{
	char path[512];
	struct dirent *de;
	DIR *d;
	int fd, err;

	snprintf(path, sizeof(path), "%s/pg_ctl", dir);
	fd = bpf_obj_get(path);
	if (fd < 0) {
		fprintf(stderr, "crednotary: %s: %s\n", path, strerror(errno));
		return 1;
	}
	err = set_enabled(fd, 0);
	close(fd);
	if (err) {
		fprintf(stderr, "crednotary: disable: %s\n", strerror(-err));
		return 1;
	}
	d = opendir(dir);
	if (!d) {
		fprintf(stderr, "crednotary: %s: %s\n", dir, strerror(errno));
		return 1;
	}
	while ((de = readdir(d))) {
		if (de->d_name[0] == '.' || !strcmp(de->d_name, "pg_ctl"))
			continue;
		snprintf(path, sizeof(path), "%s/%s", dir, de->d_name);
		if (unlink(path))
			fprintf(stderr, "crednotary: unlink %s: %s\n", path, strerror(errno));
	}
	closedir(d);
	snprintf(path, sizeof(path), "%s/pg_ctl", dir);
	unlink(path);
	if (rmdir(dir)) {
		fprintf(stderr, "crednotary: rmdir %s: %s\n", dir, strerror(errno));
		return 1;
	}
	printf("[crednotary] unpinned %s\n", dir);
	return 0;
}

/*
 * Old kernels: programs attached to LSM hooks or functions that the kernel
 * lacks (task_fix_setgroups < 6.1, inode_get_acl < 6.2) are not loaded.
 * The fentry/set_groups fallback is needed only where task_fix_setgroups is
 * missing.
 */
static int adapt_to_kernel(struct crednotary_bpf *skel)
{
	struct btf *vmlinux = btf__load_vmlinux_btf();
	struct bpf_program *prog;
	bool has_setgroups;
	char name[128];

	if (!vmlinux)
		return -errno;
	has_setgroups = btf__find_by_name_kind(vmlinux, "bpf_lsm_task_fix_setgroups",
					       BTF_KIND_FUNC) >= 0;
	bpf_object__for_each_program(prog, skel->obj) {
		const char *sec = bpf_program__section_name(prog), *fn;

		if (!strncmp(sec, "lsm/", 4)) {
			snprintf(name, sizeof(name), "bpf_lsm_%s", sec + 4);
			fn = name;
		} else if (!strncmp(sec, "fentry/", 7) || !strncmp(sec, "fexit/", 6)) {
			fn = strchr(sec, '/') + 1;
		} else {
			continue;
		}
		if (btf__find_by_name_kind(vmlinux, fn, BTF_KIND_FUNC) < 0 ||
		    (has_setgroups && !strcmp(fn, "set_groups"))) {
			bpf_program__set_autoload(prog, false);
			if (strcmp(fn, "set_groups"))
				printf("[crednotary] %s: not in this kernel, not loaded\n", sec);
		}
	}
	if (!has_setgroups)
		printf("[crednotary] setgroups authorized via fentry/set_groups\n");
	btf__free(vmlinux);
	return 0;
}

static void usage(const char *p)
{
	fprintf(stderr, "usage: %s [-m log|block|kill|quarantine] [-q cgroup] [-v] [-a /path/helper]... [-t seconds] [-s ms] [-P dir]\n"
			"       -q dir cgroup v2 for quarantine mode (default /sys/fs/cgroup/crednotary-quarantine)\n"
			"       -s ms  interval of the sweep over all tasks (default 1000, 0 = off)\n"
			"       %s -U dir    (orderly detach of a pinned instance)\n", p, p);
	exit(2);
}

int main(int argc, char **argv)
{
	struct crednotary_bpf *skel;
	struct ring_buffer *rb = NULL;
	const char *extra[16], *pin_dir = NULL;
	int nextra = 0, opt, err, timeout = 0, sweep_ms = 1000;
	struct bpf_link *sweep = NULL;
	long long next_sweep;
	bool verbose = false;
	time_t start;

	while ((opt = getopt(argc, argv, "m:q:va:t:s:P:U:h")) != -1) {
		switch (opt) {
		case 'm':
			if (!strcmp(optarg, "log"))
				mode = PG_MODE_LOG;
			else if (!strcmp(optarg, "block"))
				mode = PG_MODE_BLOCK;
			else if (!strcmp(optarg, "kill"))
				mode = PG_MODE_KILL;
			else if (!strcmp(optarg, "quarantine")) {
				/* in the kernel, like block; in addition the loader freezes the process */
				mode = PG_MODE_BLOCK;
				quarantine_mode = true;
				if (!quarantine_dir)
					quarantine_dir = "/sys/fs/cgroup/crednotary-quarantine";
			}
			else
				usage(argv[0]);
			break;
		case 'v':
			verbose = true;
			break;
		case 'a':
			if (nextra < 16)
				extra[nextra++] = optarg;
			break;
		case 'q':
			quarantine_dir = optarg;
			break;
		case 's':
			sweep_ms = atoi(optarg);
			break;
		case 't':
			timeout = atoi(optarg);
			break;
		case 'P':
			pin_dir = optarg;
			break;
		case 'U':
			return unpin_all(optarg);
		default:
			usage(argv[0]);
		}
	}

	if (quarantine_dir && !quarantine_mode)
		usage(argv[0]);	/* -q is valid only with -m quarantine */

	skel = crednotary_bpf__open();
	if (!skel) {
		fprintf(stderr, "crednotary: open failed\n");
		return 1;
	}
	skel->rodata->pg_mode = mode;
	skel->rodata->pg_verbose = verbose;
	/* the iterators are attached by hand after the other programs */
	bpf_program__set_autoattach(skel->progs.pg_snapshot, false);
	bpf_program__set_autoattach(skel->progs.pg_sweep, false);

	err = adapt_to_kernel(skel);
	if (err) {
		fprintf(stderr, "crednotary: vmlinux BTF: %s\n", strerror(-err));
		goto out;
	}
	if (quarantine_dir) {
		err = quarantine_setup(quarantine_dir);
		if (err) {
			fprintf(stderr, "crednotary: quarantine cgroup %s: %s\n", quarantine_dir, strerror(-err));
			goto out;
		}
	}
	err = crednotary_bpf__load(skel);
	if (err) {
		fprintf(stderr, "crednotary: load failed: %d\n", err);
		goto out;
	}

	allow_from_sysctl(skel, "/proc/sys/kernel/modprobe", false);
	allow_from_sysctl(skel, "/proc/sys/kernel/core_pattern", true);
	for (int i = 0; i < nextra; i++)
		allow_umh(skel, extra[i]);
	/*
	 * Frozen allowlist: from here on nobody, root included, can modify it
	 * from user space (only a direct write to kernel memory still can).
	 */
	if (bpf_map_freeze(bpf_map__fd(skel->maps.umh_allow)))
		fprintf(stderr, "crednotary: freeze allowlist: %s\n", strerror(errno));

	err = crednotary_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "crednotary: attach failed: %d\n", err);
		goto out;
	}
	if (pin_dir) {
		err = pin_links(skel, pin_dir);
		if (err)
			goto out;
	}
	err = snapshot_tasks(skel);
	if (err)
		fprintf(stderr, "crednotary: snapshot failed (%d), fallback TOFU\n", err);
	/* all programs attached and shadows initialized: the rules apply from now on */
	err = set_enabled(bpf_map__fd(skel->maps.pg_ctl), 1);
	if (err) {
		fprintf(stderr, "crednotary: enable failed: %d\n", err);
		goto out;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.events), on_event, NULL, NULL);
	if (!rb) {
		err = -errno;
		goto out;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	printf("[crednotary] ready mode=%s\n",
	       mode == PG_MODE_LOG ? "log" : mode == PG_MODE_KILL ? "kill" :
	       quarantine_dir ? "quarantine" : "block");
	fflush(stdout);

	if (sweep_ms > 0) {
		sweep = bpf_program__attach_iter(skel->progs.pg_sweep, NULL);
		if (!sweep) {
			err = -errno;
			fprintf(stderr, "crednotary: sweep attach failed: %d\n", err);
			goto out;
		}
	}
	start = time(NULL);
	next_sweep = now_ms() + sweep_ms;
	while (!stop) {
		err = ring_buffer__poll(rb, sweep_ms > 0 && sweep_ms < 200 ? sweep_ms : 200);
		if (err < 0 && err != -EINTR)
			break;
		err = 0;
		if (sweep && now_ms() >= next_sweep) {
			long long t0 = now_us();

			if (run_iter(sweep))
				fprintf(stderr, "crednotary: sweep failed\n");
			else if (verbose)
				printf("[crednotary] sweep %lld us\n", now_us() - t0);
			next_sweep = now_ms() + sweep_ms;
		}
		if (timeout && time(NULL) - start >= timeout)
			break;
	}
out:
	bpf_link__destroy(sweep);
	ring_buffer__free(rb);
	/* without pins the links go away with the process: turn the switch off first */
	if (!pin_dir && skel->maps.pg_ctl)
		set_enabled(bpf_map__fd(skel->maps.pg_ctl), 0);
	crednotary_bpf__destroy(skel);
	return err ? 1 : 0;
}
