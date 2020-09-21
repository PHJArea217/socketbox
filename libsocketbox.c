#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
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
