#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
int skbox_new(const char *pathname) {
	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s == -1) return -1;
	struct sockaddr_un addr = {AF_UNIX, {0}};
	/* FIXME: abstract socket support and unlinking of socket */
	strncpy(addr.sun_path, pathname, sizeof(addr.sun_path));
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr))) {
		close(s);
		return -1;
	}
	return s;
}
int skbox_make_fd_nonblocking(int fd) {
	int f = fcntl(fd, F_GETFL, 0);
	if (f == -1) return -1;
	if (fcntl(fd, F_SETFL, f | O_NONBLOCK)) return -1;
	return 0;
}
int skbox_getsockopt_integer(int fd, int level, int opt) {
	int buf = -1;
	socklen_t l = sizeof(int);
	if (getsockopt(fd, level, opt, &buf, &l)) return -1;
	if (l != sizeof(int)) return -1;
	return buf;
}
