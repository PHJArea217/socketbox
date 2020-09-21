#include <stdlib.h>
#include <stdint.h>
#include <netinet/ip6.h>
#include <sys/un.h>
struct skbox_ip_port_tuple {
	struct in6_addr local_addr;
	struct in6_addr remote_addr;
	uint16_t lport;
	uint16_t rport;
};
typedef enum {
	SKBOX_ACTION_FAIL = 0,
	SKBOX_ACTION_FD,
	SKBOX_ACTION_SOCKET,
	SKBOX_ACTION_JUMP_MAP,
	SKBOX_ACTION_JUMP_RULE,
} skbox_action_type_t;
struct skbox_action {
	unsigned int type;
	union {
		int send_fd;
		struct sockaddr_un *name;
		uint32_t map_or_rule_id;
	} action;
};
struct skbox_rule_elem {
	struct skbox_ip_port_tuple match_pattern;
	struct skbox_ip_port_tuple match_mask;
	struct skbox_action action;
};
struct skbox_map_elem {
	struct skbox_ip_port_tuple match_pattern;
	struct skbox_action action;
};
struct skbox_rule_list {
	struct skbox_rule_elem *rules;
	struct skbox_action default_action;
	uint32_t nr_rules;
	uint32_t max_rules;
};
struct skbox_map_list {
	struct skbox_map_elem *items;
	struct skbox_action default_action;
	struct skbox_ip_port_tuple mask;
	uint32_t nr_items;
	uint32_t max_items;
};
int skbox_compare_tuples(
		const struct skbox_ip_port_tuple *left,
		const struct skbox_ip_port_tuple *right,
		const struct skbox_ip_port_tuple *mask);
const struct skbox_action *skbox_find_action_for_map(const struct skbox_ip_port_tuple *this_socket, const struct skbox_map_list *map);
const struct skbox_action *skbox_find_action_for_list(const struct skbox_ip_port_tuple *this_socket, const struct skbox_rule_list *list);
const struct skbox_action *skbox_iterative_lookup(const struct skbox_ip_port_tuple *this_socket, const struct skbox_rule_list *rules, uint32_t nr_rules, const struct skbox_map_list *maps, uint32_t nr_maps, int max_lookups);
