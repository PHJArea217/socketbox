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
#include <sched.h>
#define SKBOX_PATH_MAX 256
static int (*real_bind)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_connect)(int, const struct sockaddr *, socklen_t) = NULL;
static int (*real_listen)(int, int) = NULL;
static int (*real_accept4)(int, struct sockaddr *, socklen_t *, int) = NULL;
static int (*real_getsockname)(int, struct sockaddr *, socklen_t *) = NULL;
static int (*real_getpeername)(int, struct sockaddr *, socklen_t *) = NULL;
volatile static int directory_fd = -1;
static char * volatile directory2_path = NULL;
volatile static int has_directory2 = 0;
static char directory_path[SKBOX_PATH_MAX+1] = {0};
static int enable_stealth_mode = 0;
static int enable_connect = 0;
static int enable_override_scope_id = 0;
static int enable_accept_hack = 0;
static int enable_getpeername_protection = 2;
static int enable_stream_seqpacket = 0;
static int enable_block_listen = 1;
static int enable_strict_socket_mode = 2;
static int enable_yield_counter = 0;
static volatile uint32_t yield_counter = 0;
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
static size_t write_string_to_buf(char *buf, size_t n, const char *s1, const char *s2) {
	size_t dptr = 0;
	const char *a = s1;
	const char *b = s2;
	while (*a) {
		if (dptr >= n) return dptr;
		buf[dptr] = *a;
		dptr++;
		a++;
	}
	while (*b) {
		if (dptr >= n) return dptr;
		buf[dptr] = *b;
		dptr++;
		b++;
	}
	return dptr;
}
__attribute__((visibility("default")))
int getsockname(int fd, struct sockaddr *addr, socklen_t *len) {
	if (enable_getpeername_protection) {
		if ((!!addr) && (!!len)) {
			socklen_t l = *len;
			if (l > 0) {
				if ((enable_getpeername_protection >= 2) || (l == sizeof(struct sockaddr_in)) || (l == sizeof(struct sockaddr_in6))) {
					memset(addr, 0, l);
				}
			}
		}
	}
	return real_getsockname(fd, addr, len);
}
__attribute__((visibility("default")))
int getpeername(int fd, struct sockaddr *addr, socklen_t *len) {
	if (enable_getpeername_protection) {
		if ((!!addr) && (!!len)) {
			socklen_t l = *len;
			if (l > 0) {
				if ((enable_getpeername_protection >= 2) || (l == sizeof(struct sockaddr_in)) || (l == sizeof(struct sockaddr_in6))) {
					memset(addr, 0, l);
				}
			}
		}
	}
	return real_getpeername(fd, addr, len);
}
/* Preconditions: sin6_scope_id == 0, sin6_addr in fe8f:1::/32 */
static int bind_to_ll(int fd, const struct sockaddr_in6 *addr, int is_connect) {
	struct sockaddr_in6 modified_address;
	memcpy(&modified_address, addr, sizeof(struct sockaddr_in6));
	modified_address.sin6_scope_id = ntohl(addr->sin6_addr.s6_addr32[1]);
	memcpy(&modified_address.sin6_addr, "\376\200\0\0\0\0\0\0", 8); /* fe80::/64 */
	if (is_connect) {
		return real_connect(fd, (struct sockaddr *) &modified_address, sizeof(modified_address));
	}
	return real_bind(fd, (struct sockaddr *) &modified_address, sizeof(modified_address));
}
static int my_bind_connect(int fd, const struct sockaddr *addr, socklen_t len, int is_connect) {
	/* We should only act on a very narrow set of circumstances:
	 * addr actually represents an AF_INET6 socket address
	 * sin6_scope_id is zero
	 * sin6_addr is in fe8f::/32
	 * If sin6_addr is in fe8f:1::/32 at this point, do the other routine.
	 * sin6_port is nonzero and less than 1024
	 * socket's domain is AF_INET6 or AF_INET
	 * socket's type is SOCK_STREAM
	 * FIXME: link local connect hack
	 */
	if (len != sizeof(struct sockaddr_in6)) goto do_real_bind;
	if (addr->sa_family != AF_INET6) goto do_real_bind;
	struct sockaddr_in6 addr6_buf;
	memcpy(&addr6_buf, addr, sizeof(struct sockaddr_in6));
	const struct sockaddr_in6 *addr6 = &addr6_buf;
	if (!enable_override_scope_id && !!addr6->sin6_scope_id) goto do_real_bind;
#if __BYTE_ORDER == __LITTLE_ENDIAN
	if (addr6->sin6_addr.s6_addr32[0] == 0x01008ffe) return bind_to_ll(fd, addr6, is_connect);
	if (addr6->sin6_addr.s6_addr32[0] != 0x8ffe) goto do_real_bind;
#elif __BYTE_ORDER == __BIG_ENDIAN
	if (addr6->sin6_addr.s6_addr32[0] == 0xfe8f0001) return bind_to_ll(fd, addr6, is_connect);
	if (addr6->sin6_addr.s6_addr32[0] != 0xfe8f0000) goto do_real_bind;
#else
#error Whatever
#endif
	if (!addr6->sin6_port) goto do_real_bind;
	uint16_t p_host = ntohs(addr6->sin6_port);
	if ((!is_connect) && ((p_host == 0) || (p_host >= 1024))) goto do_real_bind;
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE) != SOCK_STREAM) goto do_real_bind;
	/* if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN) != AF_INET6) goto do_real_bind; */
	/* fix guacd bug */
	int sock_domain = skbox_getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN);
	switch(sock_domain) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			goto do_real_bind;
	}
	/* Middle 64 bits are reserved for future use. Check that they're zero for the moment. */
	if (addr6->sin6_addr.s6_addr32[1]) goto do_real_bind;
	// if (addr6->sin6_addr.s6_addr32[2]) goto do_real_bind;
	uint32_t second_part_of_address = ntohl(addr6->sin6_addr.s6_addr32[2]);
	int do_stream = 0;
	int alt_mode = 0;
	switch (second_part_of_address) {
		case 0:
			break;
		case 1:
			do_stream = 1;
			break;
		case 2:
			alt_mode = 1;
			break;
		case 3:
			alt_mode = 1;
			do_stream = 1;
			break;
		default:
			goto do_real_bind;
			break;
	}
	struct sockaddr_un result = {AF_UNIX, {0}};
	if (alt_mode) {
		if (!has_directory2) goto do_real_bind;
		__sync_synchronize();
		char filename[20] = "/XXXXX/XXXXX_XXXXX\0";
		int16tonum(ntohs(addr6->sin6_addr.s6_addr16[6]), &filename[1]);
		int16tonum(ntohs(addr6->sin6_addr.s6_addr16[7]), &filename[7]);
		int16tonum(p_host, &filename[13]);
		write_string_to_buf(result.sun_path, sizeof(result.sun_path), directory2_path, filename);
	} else {
		if (directory_fd != -10) goto do_real_bind;
		__sync_synchronize();
		uint16_t dir_file = ntohs(addr6->sin6_addr.s6_addr16[6]);
		char filename[20] = "/skbox_dir_XXXXX\0";
		int16tonum(dir_file, &filename[11]);

		char directory_full_path[SKBOX_PATH_MAX + 1] = {0};
		size_t n = write_string_to_buf(directory_full_path, SKBOX_PATH_MAX, directory_path, filename);
		directory_full_path[n] = 0;
		/*
		 * This might actually be a security vulnerability
		 * if directory_path is longer than PATH_MAX-20 bytes.
		 * Not remotely exploitable even if they have control of the bind address,
		 * unless they also have arbitrary control of environment variables, and even in
		 * the case of setuid/setgid, LD_PRELOAD is ignored.
		strncpy(directory_full_path, directory_path, SKBOX_PATH_MAX);
		strncat(directory_full_path, filename, SKBOX_PATH_MAX);
		if (directory_full_path[SKBOX_PATH_MAX - 1]) goto do_real_bind;
		*/

		int lookup_fd = open(directory_full_path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
		if (lookup_fd == -1) return -1;

		uint16_t offset = ntohs(addr6->sin6_addr.s6_addr16[7]);
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
	}
	/* Try to inherit the original socket flags */
	int orig_flags = fcntl(fd, F_GETFL, 0);
	int orig_flags2 = fcntl(fd, F_GETFD, 0);
	if (orig_flags == -1) return -1;
	if (orig_flags2 == -1) return -1;

	int new_socket_fd = -1;
	if (is_connect) {
		/* "Connect" to the requested socket address */
		if (do_stream) {
			/* Easy: simply connect to the socket */
			new_socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC|((orig_flags & O_NONBLOCK) ? SOCK_NONBLOCK : 0), 0);
			if (new_socket_fd == -1) return -1;
			if (real_connect(new_socket_fd, (struct sockaddr *) &result, sizeof(result)) == 0) goto connect_succeeded;
		} else {
			if (enable_connect >= 2) {
				/* This is a bit more interesting. Create a socketpair, simulating a connection.
				 * Return one end as the "connected socket", the other side goes to the actual unix socket,
				 * just like how socketbox itself would operate */
				int dgram_socket = socket(AF_UNIX, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
				if (dgram_socket == -1) return -1;
				int my_sockets[2] = {-1, -1};
				if (socketpair(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0, my_sockets)) {
					close(dgram_socket);
					return -1;
				}
				if ((!!(orig_flags & O_NONBLOCK)) && skbox_make_fd_nonblocking(my_sockets[0])) {
					close(dgram_socket);
					close(my_sockets[1]);
					close(my_sockets[0]);
					return -1;
				}
				int send_result = skbox_send_fd(dgram_socket, my_sockets[1], (struct sockaddr *) &result, sizeof(result));
				if (send_result == 0) {
					close(dgram_socket);
					close(my_sockets[1]);
					new_socket_fd = my_sockets[0];
					goto connect_succeeded;
				}
				close(dgram_socket);
				close(my_sockets[1]);
				close(my_sockets[0]);
			} else {
				errno = EINVAL;
			}
		}
		return -1;
	}
	/* Actually do the bind to the unix socket */
	new_socket_fd = socket(AF_UNIX, (do_stream ? SOCK_STREAM : SOCK_DGRAM)|SOCK_CLOEXEC|((orig_flags & O_NONBLOCK) ? SOCK_NONBLOCK : 0), 0);
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
connect_succeeded:
	/* And replace the original socket under the hood */
	if (dup3(new_socket_fd, fd, (orig_flags2 & FD_CLOEXEC) ? O_CLOEXEC : 0) != fd) {
		close(new_socket_fd);
		return -1;
	}
	close(new_socket_fd);
	return 0;
do_real_bind:
	if (is_connect) {
		return real_connect(fd, addr, len);
	}
	return real_bind(fd, addr, len);
}
__attribute__((visibility("default")))
int bind(int fd, const struct sockaddr *addr, socklen_t len) {
	return my_bind_connect(fd, addr, len, 0);
}
__attribute__((visibility("default")))
int connect(int fd, const struct sockaddr *addr, socklen_t len) {
	if (!enable_connect) {
		return real_connect(fd, addr, len);
	}
	return my_bind_connect(fd, addr, len, 1);
}
__attribute__((visibility("default")))
int listen(int fd, int backlog) {
	int sock_domain = skbox_getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN);
	if (sock_domain < 0) return -1;
	int sock_type = skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE);
	if (sock_type < 0) return -1;
	/* Check that it's AF_UNIX, SOCK_DGRAM. If so, do nothing; otherwise just listen as normal. */
	/* FIXME: SOCK_STREAM/SOCK_SEQPACKET if socket is connected */

	switch (sock_domain) {
		case AF_INET:
			if (enable_block_listen) {
				struct sockaddr_in local_addr = {0};
				socklen_t addr_size = sizeof(local_addr);
				if (getsockname(fd, (struct sockaddr *) &local_addr, &addr_size)) {
					return -1;
				}
				if (local_addr.sin_family != AF_INET) {
					errno = EINVAL;
					return -1;
				}
				if (addr_size == sizeof(local_addr)) {
					if ((local_addr.sin_addr.s_addr == INADDR_ANY) && (local_addr.sin_port == 0)) {
						errno = EINVAL;
						return -1;
					}
				}
			}
			return real_listen(fd, backlog);
			break;
		case AF_INET6:
			if (enable_block_listen) {
				struct sockaddr_in6 local_addr2 = {0};
				socklen_t addr_size = sizeof(local_addr2);
				if (getsockname(fd, (struct sockaddr *) &local_addr2, &addr_size)) {
					return -1;
				}
				if (local_addr2.sin6_family != AF_INET6) {
					errno = EINVAL;
					return -1;
				}
				if (addr_size == sizeof(local_addr2)) {
					if (local_addr2.sin6_port == 0) {
						errno = EINVAL;
						return -1;
					}
				}
			}
			return real_listen(fd, backlog);
			break;
		case AF_UNIX:
			if (sock_type == SOCK_DGRAM) {
				return 0;
			}
			return real_listen(fd, backlog);
			break;
	}
	return real_listen(fd, backlog);
}
static int check_socket_mode(int fd) {
	/* AF_UNIX, SOCK_DGRAM */
	/* AF_UNIX, SOCK_STREAM, SO_ACCEPTCONN=0 */
	if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_DOMAIN) != AF_UNIX) return 0;
	int sock_type = skbox_getsockopt_integer(fd, SOL_SOCKET, SO_TYPE);
	switch (sock_type) {
		case SOCK_STREAM:
		case SOCK_SEQPACKET:
			if (enable_stream_seqpacket) {
				if (skbox_getsockopt_integer(fd, SOL_SOCKET, SO_ACCEPTCONN) == 0) return 1;
			}
			break;
		case SOCK_DGRAM:
			return 1;
		default:
			return 0;
	}
	return 0;
}
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
	if (!check_socket_mode(fd)) {
		goto real_accept;
	}
	if (enable_yield_counter) {
		uint32_t counter = __sync_fetch_and_add(&yield_counter, 1);
		if ((counter % 7) == 0) {
			sched_yield();
		}
	}
	int new_fd = skbox_receive_fd_from_socket(fd);
	if (new_fd == -1) return -1;
	if (enable_strict_socket_mode) {
		if (skbox_getsockopt_integer(new_fd, SOL_SOCKET, SO_TYPE) != SOCK_STREAM) {
			errno = EAGAIN;
			goto close_fail;
		}
		if (enable_strict_socket_mode >= 2) {
			switch (skbox_getsockopt_integer(new_fd, SOL_SOCKET, SO_DOMAIN)) {
				case AF_UNIX:
				case AF_INET:
				case AF_INET6:
					break;
					/* I would add AF_VSOCK here but it might break programs that rely on the proper functioning of MSG_PEEK */
				default:
					errno = EAGAIN;
					goto close_fail;
			}
		}
	}
	/* FIXME: inherit flags from fd? */
	int orig_flags = fcntl(new_fd, F_GETFL, 0);
	if (orig_flags == -1) goto close_fail;
	int orig_flags2 = fcntl(new_fd, F_GETFD, 0);
	if (orig_flags2 == -1) goto close_fail;
	if (fcntl(new_fd, F_SETFL, (flags & SOCK_NONBLOCK) ? (orig_flags | O_NONBLOCK) : (orig_flags & ~O_NONBLOCK))) goto close_fail;
	if (fcntl(new_fd, F_SETFD, (flags & SOCK_CLOEXEC) ? (orig_flags2 | FD_CLOEXEC) : (orig_flags2 & ~FD_CLOEXEC))) goto close_fail;
	if (!!addr && !!len) {
		if (enable_getpeername_protection) {
			if (the_length > 0) {
				if ((enable_getpeername_protection >= 2) || (the_length == sizeof(struct sockaddr_in)) || (the_length == sizeof(struct sockaddr_in6))) {
					memset(addr, 0, the_length);
				}
			}
		}
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
	if (len == NULL) return real_accept4(fd, addr, len, flags);
	socklen_t orig_len = *len;
	if (orig_len == 0) return real_accept4(fd, addr, len, flags);
	socklen_t f_len = orig_len;
	int rv = real_accept4(fd, addr, &f_len, flags);
	if ((rv >= 0) && (f_len > 0) && (orig_len > 0) && (f_len < orig_len)) {
		/* Zero out the excess buffer, to prevent any data leakage
		 * from not expecting the right address length */
		memset(&((char *)addr)[f_len], 0, orig_len - f_len);
	}
	*len = f_len;
	return rv;
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
	real_connect = dlsym(RTLD_NEXT, "connect");
	if (!real_connect) abort();
	real_accept4 = dlsym(RTLD_NEXT, "accept4");
	if (!real_accept4) abort();
	real_getsockname = dlsym(RTLD_NEXT, "getsockname");
	if (!real_getsockname) abort();
	real_getpeername = dlsym(RTLD_NEXT, "getpeername");
	if (!real_getpeername) abort();
	char *stealth_mode = getenv("SKBOX_STEALTH_MODE");
	if (stealth_mode && (stealth_mode[0] == '1')) {
		enable_stealth_mode = 1;
	}
	stealth_mode = getenv("SKBOX_ENABLE_CONNECT");
	if (stealth_mode && (stealth_mode[0] >= '1') && (stealth_mode[0] <= '9')) {
		enable_connect = stealth_mode[0] - '0';
	}
	stealth_mode = getenv("SKBOX_CLEAR_SCOPE_ID");
	if (stealth_mode && (stealth_mode[0] == '1')) {
		enable_override_scope_id = 1;
	}
	stealth_mode = getenv("SKBOX_ACCEPT_HACK");
	if (stealth_mode && (stealth_mode[0] >= '1') && (stealth_mode[0] <= '9')) {
		enable_accept_hack = stealth_mode[0] - '0';
	}
	char *directory = getenv("SKBOX_DIRECTORY_ROOT");
	if (directory) {
		if (strlen(directory) < SKBOX_PATH_MAX) {
			strncpy(directory_path, directory, SKBOX_PATH_MAX);
			__sync_synchronize();
			directory_fd = -10;
		}
	}
	char *directory2 = getenv("SKBOX_DIRECTORY_ROOT2");
	if (directory2 && !directory2_path) {
		char *new_value = strdup(directory2);
		if (!new_value) abort();
		directory2_path = new_value;
		__sync_synchronize();
		has_directory2 = 1;
	}
	stealth_mode = getenv("SKBOX_GETPEERNAME_PROTECTION");
	if (stealth_mode && (stealth_mode[0] >= '0') && (stealth_mode[0] <= '9')) {
		enable_getpeername_protection = stealth_mode[0] - '0';
	}
	stealth_mode = getenv("SKBOX_ACCEPT_STREAM");
	if (stealth_mode && (stealth_mode[0] == '1')) {
		enable_stream_seqpacket = 1;
	}
	stealth_mode = getenv("SKBOX_BLOCK_LISTEN_EMPTY_ADDR");
	if (stealth_mode && (stealth_mode[0] == '0')) {
		enable_block_listen = 0;
	}
	stealth_mode = getenv("SKBOX_STRICT_STREAM_MODE");
	if (stealth_mode && (stealth_mode[0] >= '0') && (stealth_mode[0] <= '9')) {
		enable_strict_socket_mode = atoi(stealth_mode);
	}
	stealth_mode = getenv("SKBOX_SCHED_YIELD");
	if (stealth_mode && (stealth_mode[0] == '1')) {
		enable_yield_counter = 1;
	}
}
