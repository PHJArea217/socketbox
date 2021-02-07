#include "unix_scm_rights.h"
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
int skbox_receive_fd_from_socket(int fd) {
	char data[128] = {0};
	char anc_data[1280] = {0};
	while (1) {
		struct msghdr m = {NULL, 0, &(struct iovec) {data, 128}, 1, anc_data, 1280, 0};
		ssize_t r = recvmsg(fd, &m, MSG_CMSG_CLOEXEC);
		if (r <= 0) break;
		for (struct cmsghdr *c = CMSG_FIRSTHDR(&m); c; c = CMSG_NXTHDR(&m, c)) {
			if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len >= sizeof(struct cmsghdr)) {
				unsigned int nr_fds = (c->cmsg_len - sizeof(struct cmsghdr)) / sizeof(int);
				if (nr_fds == 0 || nr_fds > 256) continue;
				int *fd_list = (int *) CMSG_DATA(c);
				int fd_to_return = fd_list[0];
				for (unsigned int excess_fds = 1; excess_fds < nr_fds; excess_fds++) {
					close(fd_list[excess_fds]);
				}
				return fd_to_return;
			}
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
