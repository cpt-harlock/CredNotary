/*
 * setfcap <file>: sets the file capability "all inheritable + effective" on
 * the file (security.capability xattr, revision 2). Used by the "inherit"
 * scenario: a process with a rewritten inheritable set that executes the file
 * gets pP' = pI & fI. Needs CAP_SETFCAP (run by root during setup).
 */
#include <stdint.h>
#include <stdio.h>
#include <sys/xattr.h>

#define VFS_CAP_REVISION_2	0x02000000
#define VFS_CAP_FLAGS_EFFECTIVE	0x000001

struct vfs_cap_data {
	uint32_t magic_etc;
	struct {
		uint32_t permitted;
		uint32_t inheritable;
	} data[2];
};

int main(int argc, char **argv)
{
	struct vfs_cap_data c = {
		.magic_etc = VFS_CAP_REVISION_2 | VFS_CAP_FLAGS_EFFECTIVE,
		.data = { { 0, 0xffffffff }, { 0, 0x000001ff } },
	};

	if (argc != 2) {
		fprintf(stderr, "usage: %s file\n", argv[0]);
		return 2;
	}
	if (setxattr(argv[1], "security.capability", &c, sizeof(c), 0)) {
		perror("setxattr");
		return 1;
	}
	return 0;
}
