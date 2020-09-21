#include "config.h"
#include "unix_scm_rights.h"
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
int main(int argc, char **argv) {
	int server_socket_fd = -1;
	struct in6_addr bind_addr = IN6ADDR_ANY_INIT;
	uint16_t port = 80;
	int force_transparent = 0;
	int force_freebind = 0;
	int force_reuseaddr = 1;
	int force_reuseport = 0;
	const char *config_file = "/etc/socketbox.conf";
	int opt = -1;
	/* FIXME: nsenter + enter user namespace */
	while ((opt = getopt(argc, argv, "f:l:p:tFRrs:")) >= 0) {
		switch(opt) {
			case 'f':
				config_file = optarg;
				break;
			case 'l':
				if (inet_pton(AF_INET6, optarg, &bind_addr) != 1) {
					fprintf(stderr, "Invalid IP address %s\n", optarg);
					return 1;
				}
			case 'p':
				port = atoi(optarg);
				break;
			case 't':
				force_transparent = 1;
				break;
			case 'F':
				force_freebind = 1;
				break;
			case 'R':
				force_reuseaddr = 0;
				break;
			case 'r':
				force_reuseport = 1;
				break;
			case 's':
				server_socket_fd = atoi(optarg);
				break;
			default:
				/* FIXME: help text */
				return 1;
				break;
		}
	}
	if (server_socket_fd == -1) {
		server_socket_fd = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (server_socket_fd == -1) {
			perror("socket");
			return 1;
		}
		/* FIXME: scope id */
		struct sockaddr_in6 addr = {0};
		addr.sin6_family = AF_INET6;
		memcpy(&addr.sin6_addr, &bind_addr, sizeof(struct in6_addr));
		addr.sin6_port = htons(port);
		if (force_transparent && setsockopt(server_socket_fd, SOL_IPV6, IPV6_TRANSPARENT, &(int) {1}, sizeof(int))) {perror("setsockopt"); return 1;}
		if (force_freebind && setsockopt(server_socket_fd, SOL_IPV6, IPV6_FREEBIND, &(int) {1}, sizeof(int))) {perror("setsockopt"); return 1;}
		if (force_reuseaddr && setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEADDR, &(int) {1}, sizeof(int))) {perror("setsockopt"); return 1;}
		if (force_reuseport && setsockopt(server_socket_fd, SOL_SOCKET, SO_REUSEPORT, &(int) {1}, sizeof(int))) {perror("setsockopt"); return 1;}
		if (bind(server_socket_fd, (struct sockaddr *) &addr, sizeof(addr))) {
			perror("bind");
			return 1;
		}
	}
	FILE *config_f = fopen(config_file, "r");
	if (!config_f) {
		perror(config_file);
		return 1;
	}
	struct skbox_config *my_config = skbox_parse_config(config_f);
	fclose(config_f);
	if (!my_config) {
		fprintf(stderr, "Error parsing configuration file\n");
		return 1;
	}
	if (listen(server_socket_fd, 100)) {
		perror("listen");
		return 1;
	}
	while (1) {
		struct skbox_ip_port_tuple current_connection = {0};
		struct sockaddr_in6 remote_addr = {0};
		socklen_t l = sizeof(struct sockaddr_in6);
		int new_fd = accept(server_socket_fd, (struct sockaddr *) &remote_addr, &l);
		if (new_fd == -1) {
			perror("accept");
			break;
		}
		if (l == sizeof(struct sockaddr_in6) && remote_addr.sin6_family == AF_INET6) {
			memcpy(&current_connection.remote_addr, &remote_addr.sin6_addr, sizeof(struct in6_addr));
			current_connection.rport = ntohs(remote_addr.sin6_port);
		}
		struct sockaddr_in6 local_addr = {0};
		l = sizeof(struct sockaddr_in6);
		getsockname(new_fd, (struct sockaddr *) &local_addr, &l);
		if (l == sizeof(struct sockaddr_in6) && local_addr.sin6_family == AF_INET6) {
			memcpy(&current_connection.local_addr, &local_addr.sin6_addr, sizeof(struct in6_addr));
			current_connection.lport = ntohs(local_addr.sin6_port);
		}
		const struct skbox_action *result_action = skbox_iterative_lookup(&current_connection, my_config->rules, my_config->nr_rules, my_config->maps, my_config->nr_maps, 100);
		if (result_action) {
			switch(result_action->type) {
				case SKBOX_ACTION_FD:
					if (skbox_send_fd(result_action->action.send_fd, new_fd, NULL, 0)) {
						perror("sendmsg");
					}
					break;
				case SKBOX_ACTION_SOCKET:
					;int send_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
					if (send_socket == -1) break;
					if (skbox_send_fd(send_socket, new_fd, (struct sockaddr *) result_action->action.name, sizeof(struct sockaddr_un))) {
//						perror("sendmsg");
					}
					close(send_socket);
					break;
			}
		}
		close(new_fd);
	}
	return 1;
}
