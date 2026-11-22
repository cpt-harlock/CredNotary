/* runas <uid>[:g1,g2,...] <cmd> [args...]: drops privileges (uid=gid=<uid>,
 * supplementary groups as given, none otherwise) and executes cmd. The tests
 * use it to act as an unprivileged user in the VM (busybox setpriv does not
 * support --reuid). */
#define _GNU_SOURCE
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc < 3) {
		fprintf(stderr, "usage: %s <uid> <cmd> [args...]\n", argv[0]);
		return 2;
	}
	uid_t id = (uid_t)atoi(argv[1]);
	gid_t groups[16];
	size_t ng = 0;
	char *g = strchr(argv[1], ':');

	while (g && ng < 16) {
		groups[ng++] = (gid_t)atoi(g + 1);
		g = strchr(g + 1, ',');
	}
	if (setgroups(ng, groups) || setresgid(id, id, id) || setresuid(id, id, id)) {
		perror("runas: drop privileges");
		return 1;
	}
	execvp(argv[2], &argv[2]);
	perror("runas: exec");
	return 127;
}
