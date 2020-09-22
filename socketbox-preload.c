#define _GNU_SOURCE
#include "libsocketbox.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <syscall.h>
static const char *prefixes[] = {
	"./skbox-",
	"/run/socketbox/skbox-",
	"/tmp/socketbox/skbox-",
	"/proc/self/fd/3/socketbox/skbox-"
};
__attribute__((visibility("default")))
int listen(int fd, int backlog) {
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE) != SOCK_STREAM) goto real_listen;
	int orig_flags = fcntl(fd, F_GETFL, 0);
	if (orig_flags == -1) goto real_listen;
	int orig_flags2 = fcntl(fd, F_GETFD, 0);
	if (orig_flags2 == -1) goto real_listen;
	struct sockaddr_storage orig_bindaddr = {0};
	socklen_t bindaddr_len = sizeof(orig_bindaddr);
	getsockname(fd, (struct sockaddr *) &orig_bindaddr, &bindaddr_len);
	switch(orig_bindaddr.ss_family) {
		case AF_UNIX:
			;struct sockaddr_un *u = (struct sockaddr_un *) &orig_bindaddr;
			char *repl = memmem(u->sun_path, sizeof(u->sun_path), "__SKBOX1__", 10);
			if (repl) {
				int new_socket = socket(AF_UNIX, SOCK_DGRAM
						| (orig_flags & O_NONBLOCK ? SOCK_NONBLOCK : 0)
						| (orig_flags2 & FD_CLOEXEC ? SOCK_CLOEXEC : 0), 0);
				if (new_socket == -1) return -1;
				repl[7] = 'T';
				if (bind(new_socket, u, sizeof(struct sockaddr_un))) {
					close(new_socket);
					return -1;
				}
				if (dup3(new_socket, fd, orig_flags2 & FD_CLOEXEC ? O_CLOEXEC : 0) != fd) {
					close(new_socket);
					return -1;
				}
				close(new_socket);
				return 0;
			}
			break;
		case AF_INET6:
			;struct sockaddr_in6 *i = (struct sockaddr_in6 *) &orig_bindaddr;
			
			if (memcmp(&i->sin6_addr, "\0\0\0\0\0\0\0\0\0\0\377\377\177\177", 14)) break;
			uint8_t req_class = i->sin6_addr.s6_addr[14];
			if (req_class >= (sizeof(prefixes)/sizeof(prefixes[0]))) break;

			char appended_string[] = "000000\0";
			const char hexdigits[] = "0123456789abcdef";
			appended_string[0] = hexdigits[((uint8_t) i->sin6_addr.s6_addr[15] >> 4) & 15];
			appended_string[1] = hexdigits[((uint8_t) i->sin6_addr.s6_addr[15]) & 15];
			appended_string[2] = hexdigits[((uint16_t) i->sin6_port >> 12) & 15];
			appended_string[3] = hexdigits[((uint16_t) i->sin6_port >> 8) & 15];
			appended_string[4] = hexdigits[((uint16_t) i->sin6_port >> 4) & 15];
			appended_string[5] = hexdigits[((uint16_t) i->sin6_port) & 15];
			struct sockaddr_un new_address = {AF_UNIX, {0}};
			strncpy(new_address.sun_path, prefixes[req_class], sizeof(new_address.sun_path));
			strncat(new_address.sun_path, appended_string, sizeof(new_address.sun_path));
			int new_socket = socket(AF_UNIX, SOCK_DGRAM
					| (orig_flags & O_NONBLOCK ? SOCK_NONBLOCK : 0)
					| (orig_flags2 & FD_CLOEXEC ? SOCK_CLOEXEC : 0), 0);
			if (new_socket == -1) return -1;
			if (bind(new_socket, &new_address, sizeof(struct sockaddr_un))) {
				close(new_socket);
				return -1;
			}
			if (dup3(new_socket, fd, orig_flags2 & FD_CLOEXEC ? O_CLOEXEC : 0) != fd) {
				close(new_socket);
				return -1;
			}
			close(new_socket);
			return 0;
		/* TODO: AF_INET */
	}
real_listen:
	return syscall(SYS_listen, fd, backlog);
}
__attribute__((visibility("default")))
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE) != SOCK_DGRAM) goto real_accept;
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN) != AF_UNIX) return -1;
	int new_fd = skbox_receive_fd_from_socket(fd);
	if (new_fd == -1) return -1;
	/* FIXME: inherit flags from fd? */
	int orig_flags = fcntl(new_fd, F_GETFL, 0);
	if (orig_flags == -1) goto close_fail;
	int orig_flags2 = fcntl(new_fd, F_GETFD, 0);
	if (orig_flags2 == -1) goto close_fail;
	if (fcntl(new_fd, F_SETFL, (flags & SOCK_NONBLOCK) ? (orig_flags | O_NONBLOCK) : (orig_flags & ~O_NONBLOCK))) goto close_fail;
	if (fcntl(new_fd, F_SETFD, (flags & SOCK_CLOEXEC) ? (orig_flags2 | FD_CLOEXEC) : (orig_flags2 & ~FD_CLOEXEC))) goto close_fail;
	if (!!addr && !!len) {
		if (getpeername(new_fd, addr, len)) {
			*len = 0;
		}
	}
	return new_fd;
real_accept:
	return syscall(SYS_accept4, fd, addr, len, flags);
close_fail:
	close(new_fd);
	return -1;
}
__attribute__((visibility("default")))
int accept(int fd, struct sockaddr *addr, socklen_t *len) {
	return accept4(fd, addr, len, 0);
}
