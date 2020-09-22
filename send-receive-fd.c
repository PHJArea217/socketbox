#include "libsocketbox.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
int main(int argc, char **argv) {
	int receive_fd = -1;
	int send_fd = -1;
	int opt = -1;
	while ((opt = getopt(argc, argv, "rs:")) >= 0) {
		switch(opt) {
			case 'r':
				receive_fd = -2;
				break;
			case 's':
				send_fd = atoi(optarg);
				break;
			default:
				return 1;
		}
	}
	if (!argv[optind] || (receive_fd == -1 && send_fd < 0)) {
		fprintf(stderr, "%s: File descriptor number and one of -r or -s required\n", argv[0]);
		return 1;
	}
	int fdnum = atoi(argv[optind]);
	if (receive_fd == -2) {
		int new_fd = skbox_receive_fd_from_socket(fdnum);
		if (new_fd == -1) {
			perror("recvmsg");
			return 1;
		}
		int fl = fcntl(new_fd, F_GETFD, 0);
		if (fl == -1) return 1;
		if (fcntl(new_fd, F_SETFD, fl & ~FD_CLOEXEC)) return 1;
		char buf[40] = {0};
		if (snprintf(buf, 40, "%d", new_fd) < 0) return 1;
		if (setenv("SKBOX_RECEIVED_FD", buf, 1)) return 1;
		execvp(argv[optind+1], &argv[optind+1]);
		return 127;
	}
	if (skbox_send_fd(fdnum, send_fd, NULL, 0)) {
		perror("skbox_send_fd");
		return 1;
	}
	return 0;
}
