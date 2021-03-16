#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "unix_scm_rights.h"
#include "libsocketbox.h"
int main(int argc, char **argv) {
	signal(SIGCHLD, SIG_IGN);
	if (argc<4) {
		fprintf(stderr, "Usage: %s [socket] [group_nr] [program] [arguments]\n", argv[0]);
		return 1;
	}
	unsigned long n = strtoul(argv[2], NULL, 0);
	int socket_fd = skbox_register_bind(argv[1], n);
	if (socket_fd == -1) {
		perror("Failed to create socket");
		return 1;
	}
	while (1) {
		int s = skbox_receive_fd_from_socket_p(socket_fd, 1);
		if (s < 0) {
			if (errno == ENOLINK) {
				break;
			} else if (errno != EINTR) {
				perror("Failed to receive from socket");
			}
			continue;
		}
		if (!fork()) {
			if (setsid() < 0) _exit(1);
			if (dup2(s, 1) < 0) _exit(1);
			if (dup2(s, 0) < 0) _exit(1);
			if (s > 1) close(s);
			execvp(argv[3], &argv[3]);
			_exit(127);
		}
		close(s);
	}
	return 0;
}
