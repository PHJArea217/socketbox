#include <sys/socket.h>
#include <netinet/ip6.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#define Q_LOCAL_ADDR 1
#define Q_REMOTE_ADDR 2
#define Q_LOCAL_PORT 3
#define Q_REMOTE_PORT 4
#define Q_LOCAL_ALL 5
#define Q_REMOTE_ALL 6
int main(int argc, char **argv) {
	int use_raw = 0;
	int type = 0;
	int opt = 0;
	int socket_num = 0;
	while ((opt = getopt(argc, argv, "aplrRf:")) >= 0) {
		switch(opt) {
			case 'a':
				if (type == Q_LOCAL_ALL) type = Q_LOCAL_ADDR;
				else if (type == Q_REMOTE_ALL) type = Q_REMOTE_ADDR;
				else goto invalid_ap;
				break;
			case 'p':
				if (type == Q_LOCAL_ALL) type = Q_LOCAL_PORT;
				else if (type == Q_REMOTE_ALL) type = Q_REMOTE_PORT;
				else goto invalid_ap;
				break;
			case 'l':
				type = Q_LOCAL_ALL;
				break;
			case 'r':
				type = Q_REMOTE_ALL;
				break;
			case 'R':
				use_raw = 1;
				break;
			case 'f':
				socket_num = atoi(optarg);
				break;
			default:
			invalid_ap:
				fprintf(stderr, "Usage: %s [-l[a|p]] [-r[a|p]] -R [-f SOCKET_FD]\n", argv[0]);
				return 1;
				break;
		}
	}
	socklen_t l = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 result = {0};
	socklen_t l2 = sizeof(struct sockaddr_in6);
	struct sockaddr_in6 result2 = {0};
	switch(type) {
		case Q_REMOTE_ADDR:
		case Q_REMOTE_PORT:
		case Q_REMOTE_ALL:
			if (getpeername(socket_num, (struct sockaddr *) &result, &l) || result.sin6_family != AF_INET6) {
				perror("getpeername");
				return 1;
			}
			break;
		case Q_LOCAL_ADDR:
		case Q_LOCAL_PORT:
		case Q_LOCAL_ALL:
			if (getsockname(socket_num, (struct sockaddr *) &result, &l) || result.sin6_family != AF_INET6) {
				perror("getsockname");
				return 1;
			}
			break;
		default:
			if (getpeername(socket_num, (struct sockaddr *) &result, &l) || result.sin6_family != AF_INET6) {
				perror("getpeername");
				return 1;
			}
			if (getsockname(socket_num, (struct sockaddr *) &result2, &l2) || result2.sin6_family != AF_INET6) {
				perror("getsockname");
				return 1;
			}
			break;
	}
	switch(type) {
		case Q_REMOTE_ADDR:
		case Q_LOCAL_ADDR:
			if (use_raw) {
				printf("%08lX%08lX%08lX%08lX\n",
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[0]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[1]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[2]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[3]));
			} else {
				printf("%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx\n",
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[0]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[1]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[2]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[3]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[4]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[5]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[6]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[7]));
			}
			break;
		case Q_LOCAL_PORT:
		case Q_REMOTE_PORT:
			if (use_raw) {
				printf("%04lX\n", (unsigned long) ntohs(result.sin6_port));
			} else {
				printf("%lu\n", (unsigned long) ntohs(result.sin6_port));
			}
			break;
		case Q_LOCAL_ALL:
		case Q_REMOTE_ALL:
			if (use_raw) {
				printf("%08lX%08lX%08lX%08lX:%04lX\n",
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[0]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[1]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[2]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[3]),
						(unsigned long) ntohs(result.sin6_port));
			} else {
				printf("[%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx]:%lu\n",
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[0]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[1]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[2]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[3]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[4]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[5]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[6]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[7]),
						(unsigned long) ntohs(result.sin6_port));
			}
			break;
		default:
			if (use_raw) {
				printf("%08lX%08lX%08lX%08lX:%04lX %08lX%08lX%08lX%08lX:%04lX\n",
						(unsigned long) ntohl(result2.sin6_addr.s6_addr32[0]),
						(unsigned long) ntohl(result2.sin6_addr.s6_addr32[1]),
						(unsigned long) ntohl(result2.sin6_addr.s6_addr32[2]),
						(unsigned long) ntohl(result2.sin6_addr.s6_addr32[3]),
						(unsigned long) ntohs(result2.sin6_port),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[0]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[1]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[2]),
						(unsigned long) ntohl(result.sin6_addr.s6_addr32[3]),
						(unsigned long) ntohs(result.sin6_port));
			} else {
				printf("[%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx]:%lu [%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx:%04lx]:%lu\n",
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[0]),
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[1]),
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[2]),
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[3]),
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[4]),
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[5]),
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[6]),
						(unsigned long) ntohs(result2.sin6_addr.s6_addr16[7]),
						(unsigned long) ntohs(result2.sin6_port),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[0]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[1]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[2]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[3]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[4]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[5]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[6]),
						(unsigned long) ntohs(result.sin6_addr.s6_addr16[7]),
						(unsigned long) ntohs(result.sin6_port));
			}
			break;
	}
	return 0;
}
