#include "libsocketbox.h"
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <arpa/inet.h>
int skbox_new(const char *pathname) {
	int s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (s == -1) return -1;
	struct sockaddr_un addr = {AF_UNIX, {0}};
	/* FIXME: abstract socket support and unlinking of socket */
	strncpy(addr.sun_path, pathname, sizeof(addr.sun_path) - 1);
	addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
	if (bind(s, (struct sockaddr *) &addr, sizeof(addr))) {
		close(s);
		return -1;
	}
	if (chmod(addr.sun_path, 0660)) {
		close(s);
		return -1;
	}
	return s;
}
int skbox_register_fd(int fd, uint32_t target) {
	struct skbox_reg_request req = {0};
	req.req = 1;
	req.group = htonl(target);
	if (send(fd, &req, sizeof(req), MSG_NOSIGNAL) != sizeof(req)) {
		errno = EPIPE;
		return -1;
	}
do_again:;
	struct skbox_reg_response res = {0};
	ssize_t n_read = recv(fd, &res, sizeof(res), 0);
	if (n_read < 0) {
		if (errno == EINTR) goto do_again;
		if (errno == EAGAIN) goto do_again;
		return -1;
	}
	if (n_read != sizeof(res)) {
		errno = EPERM;
		return -1;
	}
	if (res.res_code == 128) {
		return 0;
	}
	errno = EINVAL;
	return -1;
}
int skbox_register_bind(const char *pathname, uint32_t target) {
	if ((pathname == NULL) || (pathname[0] == 0)) {
		errno = EFAULT;
		return -1;
	}
	struct sockaddr_un unix_addr = {AF_UNIX, {0}};
	strncpy(unix_addr.sun_path, pathname, sizeof(unix_addr.sun_path) - 1);
	int unix_fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (unix_fd < 0) {
		return -1;
	}
	if (connect(unix_fd, (struct sockaddr *) &unix_addr, sizeof(unix_addr))) {
		close(unix_fd);
		return -1;
	}
	if (skbox_register_fd(unix_fd, target)) {
		close(unix_fd);
		return -1;
	}
	return unix_fd;
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
int skbox_parse_port_filter(const char *filter, uint16_t result[32]) {
	if (!filter) return 0; /* filter == NULL */
	if (filter[0] == 0) return 0; /* filter == "" */
	char *filter_s = strdup(filter);
	if (filter_s == NULL) return -1;
	char *saveptr = NULL;
	char *first = strtok_r(filter_s, ",", &saveptr);
	if (!first) {
		free(filter_s);
		return 0;
	}
	unsigned long first_int = strtoul(first, NULL, 0);
	if (first_int > 65535) {
		goto fail;
	}
	char *second = strtok_r(NULL, ",", &saveptr);
	if (!second) {
		result[0] = first_int;
		result[1] = first_int;
		result[2] = 0;
		goto success;
	}
	unsigned long second_int = strtoul(second, NULL, 0);
	if (second_int > 65535) {
		goto fail;
	}
	result[0] = first_int;
	result[1] = second_int;
	for (int i = 2; i < 32; i++) {
		char *next = strtok_r(NULL, ",", &saveptr);
		if (!next) {
			result[i] = 0;
			goto success;
		}
		unsigned long next_int = strtoul(next, NULL, 0);
		if ((next_int == 0) || (next_int > 65535)) {
			goto fail;
		}
		result[i] = next_int;
	}
	char *overflow_i = strtok_r(NULL, ",", &saveptr);
	if (overflow_i) goto fail;
success:
	free(filter_s);
	return 1;
fail:
	free(filter_s);
	return -1;
}
int skbox_check_port_filter(uint16_t port_to_test, const uint16_t filter[32]) {
	if (port_to_test == 0) {
		return 0;
	}
	if ((port_to_test & 1) == 0) /* even */ {
		if (port_to_test < filter[1]) return 1;
	} else /* odd */ {
		if (port_to_test < filter[0]) return 1;
	}
	for (int i = 2; i < 32; i++) {
		if (filter[i] == 0) return 0;
		if (port_to_test == filter[i]) return 1;
	}
	return 0;
}
