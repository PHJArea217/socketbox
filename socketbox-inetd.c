#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include "unix_scm_rights.h"
#include "libsocketbox.h"
int main(int argc, char **argv) {
	signal(SIGCHLD, SIG_IGN);
	if (argc<3) {
		fprintf(stderr, "Usage: %s [socket] [program] [arguments]\n", argv[0]);
		return 1;
	}
	int socket_fd = skbox_new(argv[1]);
	if (socket_fd == -1) {
		perror("Failed to create socket");
		return 1;
	}
	while (1) {
		int s = skbox_receive_fd_from_socket(socket_fd);
		if (s == -1 && errno != EINTR) {
			perror("Failed to receive from socket");
			continue;
		}
		if (!fork()) {
			if (dup2(s, 1) < 0) _exit(1);
			if (dup2(s, 0) < 0) _exit(1);
			if (s > 1) close(s);
			execvp(argv[2], &argv[2]);
			_exit(127);
		}
		close(s);
	}
}
