#include "unix_scm_rights.h"
int skbox_receive_fd_from_socket(int fd);
int skbox_new(const char *pathname);
int skbox_make_fd_nonblocking(int fd);
int skbox_getsockopt_integer(int fd, int level, int opt);
