#include <sys/socket.h>
#include <stdint.h>
int skbox_send_fd(int sockfd, int fd, const struct sockaddr *addr, socklen_t addrlen);
// int skbox_receive_fd_from_socket(int fd);
void skbox_set_validation_level(int level);
