/*
 * pgbench <op> <iterations>: microbenchmark of the CredNotary hot paths.
 * Prints the mean wall-clock time per operation in nanoseconds.
 *   open   open("/etc/passwd") + close        -> lsm/file_open checkpoint
 *   fork   fork() + child _exit + waitpid      -> lsm/task_alloc checkpoint + shadow copy
 *   setuid seteuid(1000) + seteuid(0) as root  -> task_fix_setuid token + 2x commit_creds
 *   exec   fork + execve(/bin/true) + waitpid  -> bprm_check + bprm_committing_creds + commit_creds
 *   null   syscall(getppid)                    -> tp_btf/sys_enter only
 *   stat   stat() of an 8-component path       -> lsm/inode_getattr checkpoint
 * Must run as root (setuid op).
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>

static long long now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

int main(int argc, char **argv)
{
	long n;
	long long t0, t1;

	if (argc != 3) {
		fprintf(stderr, "usage: %s open|fork|setuid|exec|null|stat N\n", argv[0]);
		return 2;
	}
	n = atol(argv[2]);
	t0 = now_ns();
	for (long i = 0; i < n; i++) {
		if (!strcmp(argv[1], "open")) {
			int fd = open("/etc/passwd", O_RDONLY);
			if (fd < 0) { perror("open"); return 1; }
			close(fd);
		} else if (!strcmp(argv[1], "fork")) {
			pid_t p = fork();
			if (p == 0)
				_exit(0);
			waitpid(p, NULL, 0);
		} else if (!strcmp(argv[1], "setuid")) {
			if (seteuid(1000) || seteuid(0)) { perror("seteuid"); return 1; }
		} else if (!strcmp(argv[1], "null")) {
			syscall(SYS_getppid);
		} else if (!strcmp(argv[1], "stat")) {
			struct stat st;
			if (stat("/tmp/b/1/2/3/4/5/6/f", &st)) { perror("stat"); return 1; }
		} else if (!strcmp(argv[1], "exec")) {
			pid_t p = fork();
			if (p == 0) {
				execl("/bin/true", "true", (char *)NULL);
				_exit(127);
			}
			waitpid(p, NULL, 0);
		} else {
			fprintf(stderr, "unknown op\n");
			return 2;
		}
	}
	t1 = now_ns();
	printf("BENCH op=%s n=%ld ns_per_op=%lld\n", argv[1], n, (t1 - t0) / n);
	return 0;
}
