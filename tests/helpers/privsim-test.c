/*
 * privsim-test <scenario>: test client for /dev/privsim. Runs a scenario and
 * then tries to USE the privileges obtained (reading /root/secret-lab, a 0600
 * root file created by the test), printing the outcome on one line.
 *
 * Scenarios:
 *   commit     effect of the payload commit_creds(prepare_kernel_cred(&init_task))
 *   overwrite  in-place overwrite of the cred fields
 *   swap       swap of the real_cred/cred pointers
 *   cve        simulated vulnerability SIM-2026-0001 (SET_CFG ioctl with the debug flag)
 *   cve-benign legitimate use of the same ioctl (without the debug flag)
 *   umh        triggers a usermode helper (request_module "net-pf-12"), as an
 *              exploit would after overwriting modprobe_path
 *   caps       commit of capabilities only (uid unchanged)
 *   uidswap    commit towards uid 1001 (not root); tries to read /tmp/secret-1001
 *   redirect   redirects only task->cred to a root cred
 *   inherit    rewrites the inheritable set, then executes /tmp/fcap-reader
 *              (a copy of this program with inheritable file capabilities)
 *   tokenrace  the cred approved by setuid() is rewritten before the commit
 *   kill PID   cred overwrite, then SIGKILL to PID (self-protection)
 *   rootgroup  GID 0 added in place to the supplementary groups; tries to read
 *              /root/secret-group (0640 root:root)
 *   dormant    cred overwrite, then ~3 s of computation in user space without
 *              system calls (no checkpoint): only the periodic sweep sees it
 *   unpin PATH cred overwrite, then bpf(BPF_OBJ_GET) and unlink of a pinned
 *              link (self-protection)
 *   readfile PATH  only tries to read PATH
 *   read NAME  only tries to read the secret (used by fcap-reader)
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <x86intrin.h>
#include <sys/socket.h>
#include "privsim.h"

#define SECRET "/root/secret-lab"

static void try_read(const char *scenario, const char *path)
{
	char buf[64] = {};
	int fd = open(path, O_RDONLY);

	if (fd >= 0) {
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0)
			buf[strcspn(buf, "\n")] = 0;
		printf("RESULT %s: uid=%d euid=%d secret_read=YES (%s)\n", scenario,
		       getuid(), geteuid(), buf);
	} else {
		printf("RESULT %s: uid=%d euid=%d secret_read=NO (%s)\n", scenario,
		       getuid(), geteuid(), strerror(errno));
	}
	fflush(stdout);
}

static void try_use_privileges(const char *scenario)
{
	try_read(scenario, SECRET);
}

static int do_ioctl(const char *name, unsigned long cmd, void *arg)
{
	int fd = open("/dev/privsim", O_RDWR), ret;

	if (fd < 0) {
		perror("open /dev/privsim");
		return -1;
	}
	ret = ioctl(fd, cmd, arg);
	printf("ioctl %s -> %d (%s)\n", name, ret, ret ? strerror(errno) : "ok");
	fflush(stdout);
	close(fd);
	return ret;
}

int main(int argc, char **argv)
{
	unsigned long cmd;
	struct privsim_cfg cfg = { .mode = 1, .flags = 0 };
	void *arg = NULL;
	int fd, ret;

	if (argc == 2 && !strcmp(argv[1], "umh")) {
		/* AF_DECnet (12) is no longer in the kernel: socket() calls request_module() */
		int s = socket(12, SOCK_STREAM, 0);
		printf("socket(12) -> %d (%s)\n", s, s < 0 ? strerror(errno) : "ok");
		return 0;
	}
	if (argc == 3 && !strcmp(argv[1], "readfile")) {
		try_read("readfile", argv[2]);
		return 0;
	}
	if (argc == 3 && !strcmp(argv[1], "read")) {
		try_use_privileges(argv[2]);
		return 0;
	}
	if (argc == 3 && !strcmp(argv[1], "kill")) {
		int pid = atoi(argv[2]);

		if (do_ioctl("overwrite", PRIVSIM_OVERWRITE_CRED, NULL))
			return 1;
		ret = kill(pid, SIGKILL);
		printf("RESULT kill: uid=%d kill(%d, SIGKILL) -> %s\n", getuid(), pid,
		       ret ? strerror(errno) : "ok");
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "rootgroup")) {
		if (do_ioctl("rootgroup", PRIVSIM_ROOT_GROUP, NULL))
			return 1;
		try_read("rootgroup", "/root/secret-group");
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "dormant")) {
		unsigned long long t0;
		int fd = open("/dev/privsim", O_RDWR);

		if (fd < 0 || ioctl(fd, PRIVSIM_OVERWRITE_CRED, NULL))
			return 1;
		/* no system calls until the loop ends: ~3 s at a 2-3 GHz TSC */
		t0 = __rdtsc();
		while (__rdtsc() - t0 < 8000000000ULL)
			;
		printf("RESULT dormant-spin: done (uid=%d)\n", getuid());
		try_use_privileges("dormant");
		return 0;
	}
	if (argc == 3 && !strcmp(argv[1], "unpin")) {
		union bpf_attr attr;
		int fd;

		if (do_ioctl("overwrite", PRIVSIM_OVERWRITE_CRED, NULL))
			return 1;
		memset(&attr, 0, sizeof(attr));
		attr.pathname = (unsigned long)argv[2];
		fd = syscall(SYS_bpf, BPF_OBJ_GET, &attr, sizeof(attr));
		printf("RESULT unpin-objget: uid=%d bpf(OBJ_GET %s) -> %s\n", getuid(), argv[2],
		       fd < 0 ? strerror(errno) : "ok");
		ret = unlink(argv[2]);
		printf("RESULT unpin-unlink: uid=%d unlink(%s) -> %s\n", getuid(), argv[2],
		       ret ? strerror(errno) : "ok");
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "uidswap")) {
		if (do_ioctl("uidswap", PRIVSIM_COMMIT_UID, NULL))
			return 1;
		try_read("uidswap", "/tmp/secret-1001");
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "inherit")) {
		if (do_ioctl("inherit", PRIVSIM_OVERWRITE_INH, NULL))
			return 1;
		execl("/tmp/fcap-reader", "fcap-reader", "read", "inherit", (char *)NULL);
		printf("RESULT inherit: exec fcap-reader -> %s secret_read=NO\n", strerror(errno));
		return 0;
	}
	if (argc == 2 && !strcmp(argv[1], "tokenrace")) {
		if (do_ioctl("arm-tokenrace", PRIVSIM_ARM_TOKEN_RACE, NULL))
			return 1;
		ret = setuid(getuid());
		printf("setuid(%d) -> %d (%s)\n", getuid(), ret, ret ? strerror(errno) : "ok");
		try_use_privileges("tokenrace");
		return 0;
	}
	if (argc != 2) {
		fprintf(stderr, "usage: %s commit|overwrite|swap|cve|cve-benign|umh|caps|uidswap|redirect|inherit|tokenrace|rootgroup|dormant|kill PID|unpin PATH|readfile PATH|read NAME\n", argv[0]);
		return 2;
	}
	if (!strcmp(argv[1], "commit"))
		cmd = PRIVSIM_COMMIT_ROOT;
	else if (!strcmp(argv[1], "overwrite"))
		cmd = PRIVSIM_OVERWRITE_CRED;
	else if (!strcmp(argv[1], "swap"))
		cmd = PRIVSIM_SWAP_CRED;
	else if (!strcmp(argv[1], "caps"))
		cmd = PRIVSIM_COMMIT_CAPS;
	else if (!strcmp(argv[1], "redirect"))
		cmd = PRIVSIM_REDIRECT_CRED;
	else if (!strcmp(argv[1], "cve") || !strcmp(argv[1], "cve-benign")) {
		cmd = PRIVSIM_SET_CFG;
		if (!strcmp(argv[1], "cve"))
			cfg.flags = PRIVSIM_F_DEBUG;
		arg = &cfg;
	} else {
		fprintf(stderr, "unknown scenario\n");
		return 2;
	}

	fd = open("/dev/privsim", O_RDWR);
	if (fd < 0) {
		perror("open /dev/privsim");
		return 1;
	}
	ret = ioctl(fd, cmd, arg);
	printf("ioctl %s -> %d (%s)\n", argv[1], ret, ret ? strerror(errno) : "ok");
	fflush(stdout);
	close(fd);
	try_use_privileges(argv[1]);
	return 0;
}
