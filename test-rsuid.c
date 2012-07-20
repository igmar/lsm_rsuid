/*
 * Some basic tests to see if a change to the kernel module didn't screw
   thinks up
*/
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#ifndef FALSE
# define FALSE 0
#endif

#ifndef TRUE
# define TRUE 1
#endif

#define RSUID_FMT_ENABLE	"/proc/%d/attr/exec"
#define RSUID_CMD_ENABLE	"rsuid enable"

int main(int argc, char **argv)
{
	int s;

	if (enable_rsuid() == FALSE)
		return 1;

	if (setresuid(100,100,100) == -1) {
		fprintf(stderr, "setresuid(100, 100, 100) failed : %s", strerror(errno));
		return 1;
	}

	if (setresuid(200,200,200) == -1) {
		fprintf(stderr, "setresuid(200, 200, 200) failed : %s", strerror(errno));
		return 1;
	}

	s = socket(PF_PACKET, SOCK_RAW, 0);
	if (s != -1 || (s == -1 && errno != EPERM)) {
		fprintf(stderr, "Creating a raw socket should FAIL !!\n");
		return 1;
	}

	if (setresuid(0,0,0) != -1 && errno != EACCES ) {
		fprintf(stderr, "setresuid(0,0,0) should FAIL !!\n");
		return 1;
	}

	return 0;
}

int enable_rsuid(void)
{
	int fd;
	char buffer[512];
	pid_t pid;
	size_t size, len;

	/* Enable */
	pid = getpid();
	snprintf(buffer, sizeof(buffer), RSUID_FMT_ENABLE, pid);
	fd = open(buffer, O_WRONLY);
	if (fd == -1) {
		fprintf(stderr, "open of '%s' failed : %s\n", buffer, strerror(errno));
		return FALSE;
	}
	len = strlen(RSUID_CMD_ENABLE);
	if (write(fd, RSUID_CMD_ENABLE, len) != len) {
		fprintf(stderr, "write of '%s' failed : %s\n", RSUID_CMD_ENABLE, strerror(errno));
		close(fd);
		return FALSE;
	}
	close(fd);


	/* Check if it is actually enabled */
	pid = getpid();
	snprintf(buffer, sizeof(buffer), RSUID_FMT_ENABLE, pid);
	fd = open(buffer, O_RDONLY);
	if (fd == -1) {
		fprintf(stderr, "open of '%s' failed : %s\n", buffer, strerror(errno));
		return FALSE;
	}
	if (read(fd, buffer, 1024) != -1 && errno != EINVAL) {
		fprintf(stderr, "Read should return EINVAL\n");
		close(fd);
		return FALSE;
	}
	close(fd);

	return TRUE;
}
