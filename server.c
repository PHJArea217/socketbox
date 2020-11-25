#include "config.h"
#include "unix_scm_rights.h"
#include <string.h>
#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pwd.h>
#include <grp.h>
#include <sys/prctl.h>
#include <ctype.h>
#include <limits.h>
int main(int argc, char **argv) {
	int server_socket_fd = -1;
	struct in6_addr bind_addr = IN6ADDR_ANY_INIT;
	uint16_t port = 80;
	int force_transparent = 0;
	int force_freebind = 0;
	int force_reuseaddr = 1;
	int force_reuseport = 0;
	int do_exec = 0;
	const char *config_file = "/etc/socketbox.conf";
	int opt = -1;
	uid_t change_uid = -1;
	gid_t change_gid = -1;
	int keep_groups = 0;
	int nr_groups = 0;
	gid_t *group_list = malloc(NGROUPS_MAX * sizeof(gid_t));
	char *chroot_dir = NULL;
	struct skbox_action *forced_action = NULL;
	int do_daemon = 0;
	/* FIXME: nsenter + enter user namespace */
	while ((opt = getopt(argc, argv, "+f:l:p:tFRrs:eu:g:G:kdx:S:i:")) >= 0) {
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
			case 'e':
				do_exec = 1;
				break;
			case 'u':
				if (isdigit(optarg[0])) {
					change_uid = strtoll(optarg, NULL, 0);
				} else {
					struct passwd *s = getpwnam(optarg);
					if (s) {
						change_uid = s->pw_uid;
						if (change_gid == -1) change_gid = s->pw_gid;
					} else {
						fprintf(stderr, "User %s not found\n", optarg);
						return 1;
					}
				}
				break;
			case 'g':
				if (isdigit(optarg[0])) {
					change_gid = strtoll(optarg, NULL, 0);
				} else {
					struct group *s = getgrnam(optarg);
					if (s) {
						change_gid = s->gr_gid;
					} else {
						fprintf(stderr, "Group %s not found\n", optarg);
						return 1;
					}
				}
				break;
			case 'G':
				nr_groups = 0;
				char *d = strdup(optarg);
				if (!d) return 1;
				for (char *start = strtok(d, ","); start; start = strtok(NULL, ",")) {
					gid_t gid_to_add = -1;
					if (isdigit(start[0])) {
						gid_to_add = strtoll(start, NULL, 0);
					} else {
						struct group *s = getgrnam(start);
						if (s) {
							gid_to_add = s->gr_gid;
						} else {
							fprintf(stderr, "Group %s not found\n", start);
							return 1;
						}
					}
					if (nr_groups >= NGROUPS_MAX) {
						fprintf(stderr, "%s: too many groups\n", start);
						return 1;
					}
					group_list[nr_groups++] = gid_to_add;
				}
				keep_groups = 2;
				free(d);
				break;
			case 'k':
				keep_groups = 1;
				break;
			case 'x':
				chroot_dir = optarg;
				break;
			case 'd':
				do_daemon = 1;
				break;
			case 'S':
				if (forced_action) {
					if (forced_action->type == SKBOX_ACTION_SOCKET) free(forced_action->action.name);
					free(forced_action);
				}
				forced_action = calloc(sizeof(struct skbox_action), 1);
				forced_action->type = SKBOX_ACTION_SOCKET;
				forced_action->action.name = calloc(sizeof(struct sockaddr_un), 1);
				forced_action->action.name->sun_family = AF_UNIX;
				strncpy(forced_action->action.name->sun_path, optarg, sizeof(((struct sockaddr_un *) 0)->sun_path));
				break;
			case 'i':
				if (forced_action) {
					if (forced_action->type == SKBOX_ACTION_SOCKET) free(forced_action->action.name);
					free(forced_action);
				}
				forced_action = calloc(sizeof(struct skbox_action), 1);
				forced_action->type = SKBOX_ACTION_FD;
				forced_action->action.send_fd = atoi(optarg);
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
	if (do_daemon) {
		if (daemon(0, 1)) {
			return 1;
		}
	}
	FILE *config_f = NULL;
	if (!do_exec && !forced_action) config_f = fopen(config_file, "r");
	if (chroot_dir) {
		if (chroot(chroot_dir) || chdir("/")) {
			perror("chroot");
			return 1;
		}
	}
	/* 0: no -k or -G; 1: -k; 2: -G */
	if ((keep_groups == 2) || (change_gid != -1 && keep_groups == 0)) {
		if (setgroups(nr_groups, group_list)) {
			perror("setgroups");
			return 1;
		}
	}
	free(group_list);
	if (change_gid != -1) {
		if (setgid(change_gid)) {
			perror("setgid");
			return 1;
		}
	}
	if (change_uid != -1) {
		if (setuid(change_uid)) {
			perror("setuid");
			return 1;
		}
	}
	if (do_exec) {
		char tmpbuf[40] = {0};
		if (snprintf(tmpbuf, 40, "%d", server_socket_fd) < 0) return 1;
		if (setenv("SKBOX_LISTEN_FD", tmpbuf, 1)) return 1;
		execvp(argv[optind], &argv[optind]);
		return 127;
	}
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
		perror("prctl");
		return 1;
	}
	struct skbox_config *my_config = NULL;
	if (!forced_action) {
		if (!config_f) {
			perror(config_file);
			return 1;
		}
		my_config = skbox_parse_config(config_f);
		fclose(config_f);
		if (!my_config) {
			fprintf(stderr, "Error parsing configuration file\n");
			return 1;
		}
		skbox_sort_maps(my_config);
	}
	if (listen(server_socket_fd, 100)) {
		perror("listen");
		return 1;
	}
	int send_socket = socket(AF_UNIX, SOCK_DGRAM, 0);
	if (send_socket == -1) {
		perror("socket");
		return 1;
	}
	while (1) {
		struct skbox_ip_port_tuple current_connection = {0};
		struct sockaddr_in6 remote_addr = {0};
		socklen_t l = sizeof(struct sockaddr_in6);
		int new_fd = accept(server_socket_fd, (struct sockaddr *) &remote_addr, &l);
		if (new_fd == -1) {
			perror("accept");
			continue;
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
		const struct skbox_action *result_action = forced_action ? forced_action : skbox_iterative_lookup(&current_connection, my_config->rules, my_config->nr_rules, my_config->maps, my_config->nr_maps, 100);
		if (result_action) {
			switch(result_action->type) {
				case SKBOX_ACTION_FD:
					if (skbox_send_fd(result_action->action.send_fd, new_fd, NULL, 0)) {
						perror("sendmsg");
					}
					break;
				case SKBOX_ACTION_SOCKET:
					if (skbox_send_fd(send_socket, new_fd, (struct sockaddr *) result_action->action.name, sizeof(struct sockaddr_un))) {
					}
					break;
			}
		}
		close(new_fd);
	}
	close(send_socket);
	return 1;
}
