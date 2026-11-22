/*
 * suid-check [dance]: a LEGITIMATE workload, to measure false positives.
 *  - installed setuid-root in /tmp: a user runs it and reads the secret
 *    (the same pattern as sudo/passwd: privilege gain through execve).
 *  - "dance": as root, seteuid(1000) and then seteuid(0) (the pattern of
 *    daemons that drop and regain privileges through the saved uid).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	char buf[64] = {};
	int fd;

	if (argc > 1 && !strcmp(argv[1], "dance")) {
		if (seteuid(1000) || seteuid(0))
			perror("seteuid");
	}
	fd = open("/root/secret-lab", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0)
			buf[strcspn(buf, "\n")] = 0;
	}
	printf("RESULT suid-check%s: uid=%d euid=%d secret_read=%s\n",
	       argc > 1 ? "-dance" : "", getuid(), geteuid(), fd >= 0 ? "YES" : "NO");
	return 0;
}
