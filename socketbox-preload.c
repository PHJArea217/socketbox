#define _GNU_SOURCE
#include "libsocketbox.h"
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/un.h>
#include <dlfcn.h>
#include <netinet/in.h>
#include <limits.h>
#include <syscall.h>
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_listen)(int, int) = NULL;
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int) = NULL;
volatile static int directory_fd = -1;
static char directory_path[PATH_MAX+1] = {0};
static int enable_stealth_mode = 0;
/*
static const char *prefixes[] = {
	"./skbox-",
	"/run/socketbox/skbox-",
	"/tmp/socketbox/skbox-",
	"/proc/self/fd/3/socketbox/skbox-"
};
*/
static void int16tonum(uint16_t num, char *result) {
	const char *numbers = "0123456789";
	result[4] = numbers[num % 10];
	num = num / 10;
	result[3] = numbers[num % 10];
	num = num / 10;
	result[2] = numbers[num % 10];
	num = num / 10;
	result[1] = numbers[num % 10];
	num = num / 10;
	result[0] = numbers[num % 10];
}
/* Preconditions: sin6_scope_id == 0, sin6_addr in fe8f:1::/32 */
static int bind_to_ll(int fd, const struct sockaddr_in6 *addr) {
	struct sockaddr_in6 modified_address;
	memcpy(&modified_address, addr, sizeof(struct sockaddr_in6));
	modified_address.sin6_scope_id = ntohl(addr->sin6_addr.s6_addr32[1]);
	memcpy(&modified_address.sin6_addr, "\376\200\0\0\0\0\0\0", 8); /* fe80::/64 */
	return real_bind(fd, (struct sockaddr *) &modified_address, sizeof(modified_address));
}
__attribute__((visibility("default")))
int bind(int fd, const struct sockaddr *addr, socklen_t len) {
	/* We should only act on a very narrow set of circumstances:
	 * addr actually represents an AF_INET6 socket address
	 * sin6_scope_id is zero
	 * sin6_addr is in fe8f::/32
	 * If sin6_addr is in fe8f:1::/32 at this point, do the other routine.
	 * sin6_port is nonzero and less than 1024
	 * socket's domain is AF_INET6
	 * socket's type is SOCK_STREAM
	 * FIXME: link local connect hack
	 */
	if (len != sizeof(struct sockaddr_in6)) goto do_real_bind;
	if (addr->sa_family != AF_INET6) goto do_real_bind;
	const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *) addr;
	if (addr6->sin6_scope_id) goto do_real_bind;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	if (addr6->sin6_addr.s6_addr32[0] == 0x01008ffe) return bind_to_ll(fd, addr6);
	if (addr6->sin6_addr.s6_addr32[0] != 0x8ffe) goto do_real_bind;
#elif __BYTE_ORDER == __BIG_ENDIAN
	if (addr6->sin6_addr.s6_addr32[0] == 0xfe8f0001) return bind_to_ll(fd, addr6);
	if (addr6->sin6_addr.s6_addr32[0] != 0xfe8f0000) goto do_real_bind;
#else
#error Whatever
#endif
	if (directory_fd == -1) goto do_real_bind;
	if (!addr6->sin6_port) goto do_real_bind;
	uint16_t p_host = ntohs(addr6->sin6_port);
	if (p_host >= 1024) goto do_real_bind;
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE) != SOCK_STREAM) goto do_real_bind;
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN) != AF_INET6) goto do_real_bind;
	/* Middle 64 bits are reserved for future use. Check that they're zero for the moment. */
	if (addr6->sin6_addr.s6_addr32[1]) goto do_real_bind;
	// if (addr6->sin6_addr.s6_addr32[2]) goto do_real_bind;
	uint32_t second_part_of_address = ntohl(addr6->sin6_addr.s6_addr32[2]);
	int do_stream = 0;
	switch (second_part_of_address) {
		case 0:
			break;
		case 1:
			do_stream = 1;
			break;
		default:
			goto do_real_bind;
			break;
	}
	if (directory_fd != -10) goto do_real_bind;
	__sync_synchronize();
	uint16_t dir_file = ntohs(addr6->sin6_addr.s6_addr16[6]);
	char filename[20] = "/skbox_dir_XXXXX\0";
	int16tonum(dir_file, &filename[11]);

	char directory_full_path[PATH_MAX + 1] = {0};
	strncpy(directory_full_path, directory_path, PATH_MAX);
	strncat(directory_full_path, filename, PATH_MAX);
	if (directory_full_path[PATH_MAX - 1]) goto do_real_bind;

	int lookup_fd = open(directory_full_path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
	if (lookup_fd == -1) return -1;

	uint16_t offset = ntohs(addr6->sin6_addr.s6_addr16[7]);
	struct sockaddr_un result = {AF_UNIX, {0}};
	if (pread(lookup_fd, result.sun_path, sizeof(result.sun_path), offset * 128) != sizeof(result.sun_path)) {
		close(lookup_fd);
		errno = ERANGE;
		return -1;
	}
	close(lookup_fd);
	/* Replace _@SB_ with the actual given port number */
	char *m = memmem(result.sun_path, sizeof(result.sun_path), "_@SB_", 5);
	if (m) {
		int16tonum(p_host, m);
	}
	/* Try to inherit the original socket flags */
	int orig_flags = fcntl(fd, F_GETFL, 0);
	int orig_flags2 = fcntl(fd, F_GETFD, 0);
	if (orig_flags == -1) return -1;
	if (orig_flags2 == -1) return -1;

	/* Actually do the bind to the unix socket */
	int new_socket_fd = socket(AF_UNIX, (do_stream ? SOCK_STREAM : SOCK_DGRAM)|SOCK_CLOEXEC|((orig_flags & O_NONBLOCK) ? SOCK_NONBLOCK : 0), 0);
	if (new_socket_fd == -1) return -1;
	if (real_bind(new_socket_fd, (struct sockaddr *) &result, sizeof(result))) {
		if (errno == EADDRINUSE) {
			char socket_string[sizeof(result.sun_path) + 1] = {0};
			memcpy(socket_string, result.sun_path, sizeof(result.sun_path));
			socket_string[sizeof(result.sun_path)] = 0;
			struct stat s = {0};
			if ((lstat(socket_string, &s) == 0) && ((s.st_mode & S_IFMT) == S_IFSOCK)) {
				unlink(socket_string);
				if (real_bind(new_socket_fd, (struct sockaddr *) &result, sizeof(result)) == 0) goto bind_succeeded;
			}
		}
		close(new_socket_fd);
		return -1;
	}
bind_succeeded:
	if (1) { /* FIXME: make this selectable; most cases require 0660 so it's not that big of a deal; use directory permissions instead. */
		char socket_string[sizeof(result.sun_path) + 1] = {0};
		memcpy(socket_string, result.sun_path, sizeof(result.sun_path));
		socket_string[sizeof(result.sun_path)] = 0;
		chmod(socket_string, 0660);
	}
	/* And replace the original socket under the hood */
	if (dup3(new_socket_fd, fd, (orig_flags2 & FD_CLOEXEC) ? O_CLOEXEC : 0) != fd) {
		close(new_socket_fd);
		return -1;
	}
	close(new_socket_fd);
	return 0;
do_real_bind:
	return real_bind(fd, addr, len);
}
__attribute__((visibility("default")))
int listen(int fd, int backlog) {
	/* Check that it's AF_UNIX, SOCK_DGRAM. If so, do nothing; otherwise just listen as normal. */
	/* FIXME: SOCK_STREAM/SOCK_SEQPACKET if socket is connected */
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE) != SOCK_DGRAM) return real_listen(fd, backlog);
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN) != AF_UNIX) return real_listen(fd, backlog);
	return 0;
}
#if 0
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
#endif
__attribute__((visibility("default")))
int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
	socklen_t the_length = 0;
	if (len) {
		the_length = *len;
		if (the_length < 0) {
			errno = EINVAL;
			return -1;
		}
	}
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
		if (enable_stealth_mode && (the_length > 0) && (skbox_getsockopt_integer(new_fd, SOL_SOCKET, SO_DOMAIN) == AF_UNIX)) {
			struct sockaddr_in6 fake_addr = {.sin6_family = AF_INET6, .sin6_port = 0, .sin6_addr = {{{0}}}, .sin6_scope_id = 0, .sin6_flowinfo = 0};
			fake_addr.sin6_addr.s6_addr[15] = 1;
			size_t limit = sizeof(struct sockaddr_in6);
			if (the_length < limit) limit = the_length;
			memcpy(addr, &fake_addr, limit);
			*len = sizeof(struct sockaddr_in6);
		} else if (getpeername(new_fd, addr, len)) {
			*len = 0;
		}
	}
	return new_fd;
real_accept:
	return real_accept4(fd, addr, len, flags);
close_fail:
	close(new_fd);
	return -1;
}
__attribute__((visibility("default")))
int accept(int fd, struct sockaddr *addr, socklen_t *len) {
	return accept4(fd, addr, len, 0);
}
// __attribute__((visibility("default")))
__attribute__((constructor))
void __socketbox_preload_init(void) {
	real_bind = dlsym(RTLD_NEXT, "bind");
	if (!real_bind) abort();
	real_listen = dlsym(RTLD_NEXT, "listen");
	if (!real_listen) abort();
	real_accept4 = dlsym(RTLD_NEXT, "accept4");
	if (!real_accept4) abort();
	char *stealth_mode = getenv("SKBOX_STEALTH_MODE");
	if (stealth_mode && (stealth_mode[0] == '1')) {
		enable_stealth_mode = 1;
	}
	char *directory = getenv("SKBOX_DIRECTORY_ROOT");
	if (directory) {
		if (strlen(directory) < PATH_MAX) {
			strncpy(directory_path, directory, PATH_MAX);
			__sync_synchronize();
			directory_fd = -10;
		}
#if 0
		if (fcntl(950, F_GETFD) == -1) {
			int f = open(directory, O_RDONLY|O_DIRECTORY|O_CLOEXEC);
			if (f >= 0) {
				int new_fd = dup3(f, 950, O_CLOEXEC);
				close(f);
				directory_fd = new_fd;
			}
		}
#endif
	}
}
