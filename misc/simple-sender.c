#include <sys/socket.h>
#include <sys/un.h>
int main(int argc, char **argv) {
	if (argc<2) {
		return 255;
	}
	struct sockaddr_un u = {AF_UNIX, {0}};
	strncpy(u.sun_path, argv[1], sizeof(u.sun_path));
	union {
		char anc_buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr h;
	} anc_data = {0};
	struct msghdr mh = {&u, sizeof(u), &(struct iovec){"\0", 1}, 1, anc_data.anc_buf, sizeof(anc_data.anc_buf), 0};
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
	cmsg->cmsg_level = SOL_SOCKET;
	cmsg->cmsg_type = SCM_RIGHTS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(int));
	((int *) CMSG_DATA(cmsg))[0] = 0;
	int my_s = socket(AF_UNIX, SOCK_DGRAM|SOCK_NONBLOCK|SOCK_CLOEXEC, 0);
	return sendmsg(my_s, &mh, 0) == 1 ? 0 : 1;
}
