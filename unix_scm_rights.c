#include "libsocketbox.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
#define SCM_MAX_FD 256
int skbox_receive_fd_from_socket(int fd) {
	while (1) {
		char data[128] = {0};
		char anc_data[1280] = {0};
		struct msghdr m = {NULL, 0, &(struct iovec) {data, 128}, 1, anc_data, 1280, 0};
		ssize_t r = recvmsg(fd, &m, MSG_CMSG_CLOEXEC);
		if (r < 0) break;
		if (r == 0) {
			int sock_type = skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE);
			if (sock_type < 0) {
				errno = EINVAL;
				return -1;
			}
			if (sock_type != SOCK_DGRAM) {
				errno = ENOLINK;
				return -1;
			}
		}
		int has_fd_to_return = 0;
		int fd_to_return = -1;
		for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
			if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= sizeof(struct cmsghdr)) {
				unsigned int nr_fds = (c->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
				if (nr_fds == 0 || nr_fds > SCM_MAX_FD) continue;
				int *fd_list = (int *) CMSG_DATA(c);
				if (has_fd_to_return) {
					for (unsigned int excess_fds = 0; excess_fds < nr_fds; excess_fds++) {
						close(fd_list[excess_fds]);
					}
					continue;
				}
				fd_to_return = fd_list[0];
				has_fd_to_return = 1;
				for (unsigned int excess_fds = 1; excess_fds < nr_fds; excess_fds++) {
					close(fd_list[excess_fds]);
				}
			}
		}
		if (has_fd_to_return) {
			return fd_to_return;
		}
	}
	return -1;
}
int skbox_send_fd(int sockfd, int fd, const struct sockaddr *addr, socklen_t addrlen) {
	union {
		struct cmsghdr c;
		char buf[CMSG_SPACE(sizeof(int))];
	} my_cmsg = {{0}};
	struct msghdr m = {(struct sockaddr *) addr, addrlen, &(struct iovec) {"\0", 1}, 1, &my_cmsg, sizeof(my_cmsg), 0};
	struct cmsghdr *c = CMSG_FIRSTHDR(&m);
	c->cmsg_level = SOL_SOCKET;
	c->cmsg_type = SCM_RIGHTS;
	c->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(c), &fd, sizeof(int));
	return sendmsg(sockfd, &m, MSG_DONTWAIT|MSG_NOSIGNAL) == 1 ? 0 : -1;
}
