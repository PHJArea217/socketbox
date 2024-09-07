#include <stdint.h>
#define SKBOX_PATH_MAX 256
struct socketbox_preload {
	void (*int16tonum)(uint16_t, char *);
	int (*real_bind)(int, const struct sockaddr *, socklen_t);
	int (*real_connect)(int, const struct sockaddr *, socklen_t);
	int (*real_listen)(int, int);
	int (*real_accept4)(int, struct sockaddr *, socklen_t *, int);
	int (*real_getsockname)(int, struct sockaddr *, socklen_t *);
	int (*real_getpeername)(int, struct sockaddr *, socklen_t *);
	volatile int directory_fd; /* = -1 */
	volatile int has_directory2;
	char * volatile directory2_path;
	char directory_path[SKBOX_PATH_MAX+1];
	int enable_stealth_mode;
	int enable_connect;
	int enable_connect_b;
	int enable_override_scope_id;
	int enable_accept_hack;
	int enable_getpeername_protection; /* = 2 */
	int enable_stream_seqpacket;
	int enable_block_listen; /* = 1 */
	int enable_strict_socket_mode; /* = 2 */
	int enable_yield_counter;
	volatile uint32_t yield_counter;
	uint16_t filter_fe8f[32];
	uint16_t filter_127180[32];
	uint16_t filter_wildcard4[32];
	uint16_t filter_wildcard6[32];
};
extern struct socketbox_preload *socketbox_preload_globals;
