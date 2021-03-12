#include "unix_scm_rights.h"
struct skbox_reg_request {
	uint8_t req;
	uint8_t reserved_1;
	uint16_t reserved_2;
	uint32_t group;
};
struct skbox_reg_response {
	uint8_t res_code;
	uint8_t reserved_1;
	uint16_t reserved_2;
};
int skbox_receive_fd_from_socket(int fd);
int skbox_receive_fd_from_socket_p(int fd, int notify_disconnect);
int skbox_new(const char *pathname);
int skbox_make_fd_nonblocking(int fd);
int skbox_getsockopt_integer(int fd, int level, int opt);
int skbox_register_fd(int fd, uint32_t target);
int skbox_register_bind(const char *pathname, uint32_t target);
