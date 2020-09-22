/* Originally inet-relay.c by Peter H. Jin */
/* TODO set up system to allow relaying between any two descriptors received from unix domain socket */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <stddef.h>
#include <sys/mman.h>
#include <net/if.h>
#include <time.h>
#include "libsocketbox.h"
static void *static_buf = NULL;

struct fd_relay_entry {
	int infd;
	int outfd;
	int16_t state_inout;
	int16_t state_outin;
	uint8_t ref_infd;
	uint8_t ref_outfd;
	struct eventfd_event_type *efd_ptr_in;
	struct eventfd_event_type *efd_ptr_out;
};
struct eventfd_event_type {
	/* types: 0 = accepting socket, 1 = infd, 2 = outfd */
	int type;
	struct fd_relay_entry *entry;
};
/* -1 = error occurred
 * 0 = no data available yet
 * 1 = end of file
 * 2 = cannot write; must poll out now
 * 3 = successful transfer
 * 4 = partial transfer; must poll out now */
static int fd_relay(int infd, int outfd, size_t length) {
// #ifdef USE_RECV_SEND
	ssize_t recv_len = recv(infd, static_buf, length, MSG_PEEK|MSG_DONTWAIT);
	if (recv_len < 0) {
		if (errno == ECONNRESET) {
			shutdown(infd, SHUT_RD);
			shutdown(outfd, SHUT_WR);
			return 1;
		}
		return errno == EAGAIN ? 0 : -1;
	}
	if (recv_len == 0) {
		shutdown(infd, SHUT_RD);
		shutdown(outfd, SHUT_WR);
		return 1;
	}
	if ((size_t)recv_len > length) recv_len = length;
	ssize_t sendlen = send(outfd, static_buf, recv_len, MSG_DONTWAIT|MSG_NOSIGNAL);
	if (sendlen <= 0) {
		if (errno == EAGAIN) {
			return 2;
		} else {
			return -1;
		}
	}
	if (recv(infd, static_buf, sendlen, MSG_DONTWAIT) != sendlen) {
		return -1;
	}
	return sendlen != recv_len ? 4 : 3;
// #else
#if 0
	ssize_t cfr_len = copy_file_range(infd, NULL, outfd, NULL, length, 0);
	if (cfr_len == -1) {
		int s = 0;
		if (errno == EAGAIN && ioctl(infd, FIONREAD, &s) == 0) {
			return s ? 2 : 0;
		} else {
			return -1;
		}
	} else if (cfr_len == 0) {
		return 1;
	}
	return 3;
#endif
}
/* states:
 * -1 = still connecting
 * 0 = normal transfer, poll in
 * 1 = normal transfer, poll out
 * 3 = end of file seen
 */
static int try_fd_relay(struct fd_relay_entry *entry, int backwards, int epoll_fd) {
	int changed = 0;
	if (backwards == 1) {
		switch(fd_relay(entry->outfd, entry->infd, 98304)) {
			case 1:
			case -1:
				if (entry->state_outin != 3) changed = 1;
				entry->state_outin = 3;
				break;
			case 2:
			case 4:
				if (entry->state_outin != 1) changed = 1;
				entry->state_outin = 1;
				break;
			case 3:
			case 0:
				if (entry->state_outin != 0) changed = 1;
				entry->state_outin = 0;
				break;
		}
	} else if (backwards == 0) {
		switch(fd_relay(entry->infd, entry->outfd, 98304)) {
			case 1:
			case -1:
				if (entry->state_inout != 3) changed = 1;
				entry->state_inout = 3;
				break;
			case 2:
			case 4:
				if (entry->state_inout != 1) changed = 1;
				entry->state_inout = 1;
				break;
			case 3:
			case 0:
				if (entry->state_inout != 0) changed = 1;
				entry->state_inout = 0;
				break;
		}
	}
	if (changed || backwards == 2) {
		struct epoll_event new_event_in = {
			(entry->state_inout == 0 ? EPOLLIN : 0)
			| (entry->state_outin == 1 ? EPOLLOUT : 0),
			{.ptr = entry->efd_ptr_in}};
		struct epoll_event new_event_out = {
			(entry->state_outin == 0 ? EPOLLIN : 0)
			| (entry->state_inout == 1 ? EPOLLOUT : 0),
			{.ptr = entry->efd_ptr_out}};
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, entry->infd, &new_event_in)) {
			perror("epoll_ctl");
			exit(1);
		}
		if (epoll_ctl(epoll_fd, EPOLL_CTL_MOD, entry->outfd, &new_event_out)) {
			perror("epoll_ctl");
			exit(1);
		}
	}
	return (changed ? 2 : 0) | !!(entry->state_outin == 3 && entry->state_inout == 3);
}
int main(int argc, char **argv) {
	int listen_fd = 0;
	int opt = 0;
	struct sockaddr_in6 remote_addr = {AF_INET6, htons(80), 0, IN6ADDR_LOOPBACK_INIT, 0};
	struct in6_addr nat64_addr = {{0}};
	nat64_addr.s6_addr32[0] = htonl(0x0064ff9b);
	struct sockaddr_un remote_addr_unix = {AF_UNIX, {0}};
	size_t remote_addr_unix_len = 0;
	int nat64_mode = 0;
	const char *socketbox_listen = NULL;
	int recvmsg_only = 0;
	while ((opt = getopt(argc, argv, "I:n:c:p:l:u:NP:s:e")) != -1) {
		unsigned int new_scope_id;
		switch(opt) {
			case 'I':
				new_scope_id = if_nametoindex(optarg);
				if (new_scope_id == 0) {
					perror(optarg);
					return -1;
				}
				remote_addr.sin6_scope_id = new_scope_id;
				break;
			case 'n':
				remote_addr.sin6_scope_id = atol(optarg);
				break;
			case 'c':
				if (inet_pton(AF_INET6, optarg, &remote_addr.sin6_addr) != 1) {
					fprintf(stderr, "Invalid IP address %s\nUse ::ffff: before address for IPv4 or -I to specify scope id\n", optarg);
				}
				break;
			case 'p':
				remote_addr.sin6_port = htons(atoi(optarg));
				break;
			case 'l':
				listen_fd = atoi(optarg);
				break;
			case 'u':
				strncpy(remote_addr_unix.sun_path, optarg, sizeof(remote_addr_unix.sun_path) - 1);
				remote_addr_unix_len = strnlen(remote_addr_unix.sun_path, sizeof(remote_addr_unix.sun_path));
				break;
			case 'N':
				nat64_mode = 1;
				break;
			case 'P':
				if (inet_pton(AF_INET6, optarg, &nat64_addr) != 1) {
					fprintf(stderr, "Invalid IP address %s\n", optarg);
				}
				break;
			case 'e':
				recvmsg_only = 1;
				break;
			case 's':
				socketbox_listen = optarg;
				break;
			default:
				fprintf(stderr, "%s [-I interface] [-n interface_id] [-c connect_addr] [-p connect_port] [-l listen_fd] [-u unix_socket] [-N (nat64_range)]\n", argv[0]);
				return 1;
				break;
		}
	}
	if (socketbox_listen) {
		listen_fd = skbox_new(socketbox_listen);
		if (listen_fd == -1) {
			perror("skbox_new()");
			return -1;
		}
	} else if (recvmsg_only) {
		int type;
		socklen_t length = sizeof(int);
		if (getsockopt(listen_fd, SOL_SOCKET, SO_TYPE, &type, &length)) {
			perror("getsockopt()");
			return -1;
		}
	} else {
		if (listen(listen_fd, 100)) {
			perror("listen()");
			return -1;
		}
	}
	if (skbox_make_fd_nonblocking(listen_fd)) {
		perror("skbox_make_fd_nonblocking");
		return -1;
	}
	static_buf = mmap(NULL, 98304, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
	if (static_buf == MAP_FAILED) {
		perror("mmap");
		return -1;
	}
	struct eventfd_event_type accepting_socket_entry = {0, NULL};
	int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
	if (epoll_fd == -1) {
		perror("epoll_create");
		return -1;
	}
	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &(struct epoll_event) {EPOLLIN, {.ptr = &accepting_socket_entry}})) {
		perror("epoll_ctl");
		return -1;
	}
	while (1) {
		struct epoll_event events[100] = {0};
		int epoll_result = epoll_wait(epoll_fd, events, 100, -1);
		if (epoll_result < 0 && errno != EINTR) {
			perror("epoll_wait");
			return -1;
		}
		for (int i = 0; i < epoll_result; i++) {
			if (i >= 100) break;
			struct eventfd_event_type *current_entry = events[i].data.ptr;
			int revents = events[i].events;
			struct fd_relay_entry *e = current_entry->entry;
			switch (current_entry->type) {
				case 0:
					;
					struct sockaddr_in6 conn_remote_addr = {0};
					int newfd = -1;
					if (socketbox_listen || recvmsg_only) {
						newfd = skbox_receive_fd_from_socket(listen_fd);
						if (skbox_make_fd_nonblocking(newfd)) {
							close(newfd);
							break;
						}
						getpeername(newfd, &conn_remote_addr, &(socklen_t) {sizeof(struct sockaddr_in6)});
					} else {
						newfd = accept4(listen_fd, &conn_remote_addr, &(socklen_t) {sizeof(struct sockaddr_in6)}, SOCK_NONBLOCK);
					}
					if (conn_remote_addr.sin6_family != AF_INET6) memset(&conn_remote_addr, 0, sizeof(conn_remote_addr));
					if (newfd == -1) {
						break;
					}
					/* logging of ip addresses */
					char r_addrstr[INET6_ADDRSTRLEN + 40] = {0};
					char l_addrstr[INET6_ADDRSTRLEN + 40] = {0};
					struct sockaddr_in6 conn_local_addr = {0};
					inet_ntop(AF_INET6, &conn_remote_addr.sin6_addr, r_addrstr, sizeof(r_addrstr));
					getsockname(newfd, &conn_local_addr, &(socklen_t) {sizeof(struct sockaddr_in6)});
					if (conn_local_addr.sin6_family != AF_INET6) memset(&conn_local_addr, 0, sizeof(conn_local_addr));
					inet_ntop(AF_INET6, &conn_local_addr.sin6_addr, l_addrstr, sizeof(l_addrstr));
					fprintf(stderr, "%lu [%s]:%d -> [%s]:%d\n",
							(unsigned long) time(NULL), r_addrstr, (int) ntohs(conn_remote_addr.sin6_port),
							l_addrstr, (int) ntohs(conn_local_addr.sin6_port));

					int new_socket_fd = -1;
					int connect_deferred = 0;
					if (remote_addr_unix_len) {
						int new_remote_addr_unix_len = remote_addr_unix_len;
						if ((new_socket_fd = socket(AF_UNIX, SOCK_STREAM|SOCK_NONBLOCK, 0)) == -1) {
							close(newfd);
							break;
						}
						struct sockaddr_un new_address_unix = remote_addr_unix;
						if (nat64_mode) {
							if ((conn_local_addr.sin6_addr.s6_addr32[0] == nat64_addr.s6_addr32[0])
									&& (conn_local_addr.sin6_addr.s6_addr32[1] == nat64_addr.s6_addr32[1])
									&& (conn_local_addr.sin6_addr.s6_addr32[2] == nat64_addr.s6_addr32[2])) {
							} else {
								close(newfd);
								close(new_socket_fd);
								break;
							}
							snprintf(new_address_unix.sun_path, sizeof(new_address_unix.sun_path),
									"%s-%08x", remote_addr_unix.sun_path, ntohl(conn_local_addr.sin6_addr.s6_addr32[3]));
							new_remote_addr_unix_len = strlen(new_address_unix.sun_path);
						}
						if (new_address_unix.sun_path[0] == '@') {
							new_address_unix.sun_path[0] = '\0';
						}
						if (connect(new_socket_fd, &new_address_unix, offsetof(struct sockaddr_un, sun_path) + new_remote_addr_unix_len)) {
							perror("connect");
							close(newfd);
							close(new_socket_fd);
							break;
						}
					} else {
						if ((new_socket_fd = socket(AF_INET6, SOCK_STREAM|SOCK_NONBLOCK, 0)) == -1) {
							close(newfd);
							break;
						}
						struct sockaddr_in6 new_addr = {0};
						if (nat64_mode) {
							uint32_t last_4octet = conn_local_addr.sin6_addr.s6_addr32[3];
							uint16_t last_port = conn_local_addr.sin6_port;
							if ((conn_local_addr.sin6_addr.s6_addr32[0] == nat64_addr.s6_addr32[0])
									&& (conn_local_addr.sin6_addr.s6_addr32[1] == nat64_addr.s6_addr32[1])
									&& (conn_local_addr.sin6_addr.s6_addr32[2] == nat64_addr.s6_addr32[2])) {
							} else {
								close(newfd);
								close(new_socket_fd);
								break;
							}
							memcpy(&new_addr, &remote_addr, sizeof(struct sockaddr_in6));
							if (remote_addr.sin6_port == 0) {
								new_addr.sin6_port = last_port;
							}
							new_addr.sin6_addr.s6_addr32[3] = last_4octet;
						} else {
							memcpy(&new_addr, &remote_addr, sizeof(struct sockaddr_in6));
						}
						setsockopt(new_socket_fd, SOL_TCP, TCP_NODELAY, &(int) {1}, sizeof(int));
						setsockopt(newfd, SOL_TCP, TCP_NODELAY, &(int) {1}, sizeof(int));
						if (connect(new_socket_fd, &new_addr, sizeof(remote_addr))) {
							if (errno == EINPROGRESS) {
								connect_deferred = 1;
							} else {
								perror("connect");
								close(newfd);
								close(new_socket_fd);
								break;
							}
						}
					}
					struct fd_relay_entry *state = calloc(sizeof(struct fd_relay_entry), 1);
					struct eventfd_event_type *new_entry_localfd = calloc(sizeof(struct eventfd_event_type), 1);
					struct eventfd_event_type *new_entry_remotefd = calloc(sizeof(struct eventfd_event_type), 1);
					struct epoll_event epoll_infd = {0, {.ptr = new_entry_localfd}};
					struct epoll_event epoll_outfd = {0, {.ptr = new_entry_remotefd}};
					state->infd = newfd;
					state->outfd = new_socket_fd;
					state->state_inout = connect_deferred ? -1 : 0;
					state->state_outin = connect_deferred ? -1 : 0;
					state->ref_infd = 1;
					state->ref_outfd = 1;
					state->efd_ptr_in = new_entry_localfd;
					state->efd_ptr_out = new_entry_remotefd;
					new_entry_localfd->type = 1;
					new_entry_localfd->entry = state;
					new_entry_remotefd->type = 2;
					new_entry_remotefd->entry = state;
					if (connect_deferred) {
						state->state_inout = -1;
						state->state_outin = -1;
						epoll_infd.events = 0;
						epoll_outfd.events = EPOLLOUT;
					} else {
						state->state_inout = 0;
						state->state_outin = 0;
						epoll_infd.events = EPOLLIN;
						epoll_outfd.events = EPOLLIN;
					}
					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, state->infd, &epoll_infd)) {
						free(new_entry_localfd);
						free(new_entry_remotefd);
						free(state);
						close(newfd);
						close(new_socket_fd);
						break;
					}
					if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, state->outfd, &epoll_outfd)) {
						if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, state->infd, NULL)) {
							perror("epoll_ctl");
							return 1;
						}
						free(new_entry_localfd);
						free(new_entry_remotefd);
						free(state);
						close(newfd);
						close(new_socket_fd);
						break;
					}
					break;
				case 1:
					if (revents & (EPOLLIN|EPOLLHUP)) {
						try_fd_relay(e, 0, epoll_fd);
					}
					if (revents & EPOLLOUT) {
						try_fd_relay(e, 1, epoll_fd);
					}
					break;
				case 2:
					if ((revents & (EPOLLIN|EPOLLHUP)) && e->state_outin != -1) {
						try_fd_relay(e, 1, epoll_fd);
					}
					if (revents & EPOLLOUT) {
						if (e->state_outin == -1) {
							int so_error = -1;
							getsockopt(e->outfd, SOL_SOCKET, SO_ERROR, &so_error, &(socklen_t) {sizeof(int)});
							if (so_error == 0) {
								e->state_outin = 0;
								e->state_inout = 0;
								try_fd_relay(e, 2, epoll_fd);
							} else {
								e->state_inout = 3;
								e->state_outin = 3;
							}
						} else {
							try_fd_relay(e, 0, epoll_fd);
						}
					}
					break;
			}
			if (!e) continue;
			if (e->state_inout == 3) {
				e->ref_infd = 0;
			}
			if (e->state_outin == 3) {
				e->ref_outfd = 0;
			}
			if ((e->ref_infd == 0 && e->ref_outfd == 0) || (revents & EPOLLERR)) {
				if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, e->infd, NULL)) {
					perror("epoll_ctl");
					return 1;
				}
				if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, e->outfd, NULL)) {
					perror("epoll_ctl");
					return 1;
				}
				shutdown(e->outfd, SHUT_RDWR);
				shutdown(e->infd, SHUT_RDWR);
				close(e->infd);
				close(e->outfd);
				free(e->efd_ptr_in);
				free(e->efd_ptr_out);
				free(e);
				break;
			}
		}
	}
}
