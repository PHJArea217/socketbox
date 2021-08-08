#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#define SKBOX_CONFIG_TYPE_GLOBAL 0
#define SKBOX_CONFIG_TYPE_MAP 1
#define SKBOX_CONFIG_TYPE_RULE 2
#define SKBOX_CONFIG_TYPE_DEFAULT_MAP 3
#define SKBOX_CONFIG_TYPE_DEFAULT_RULE 4
struct config_token {
	const char *token;
	int (*token_handler)(const char *, struct skbox_config *);
};
static int compare_strings_before_colon(const void *a, const void *b) {
	struct config_token *ct_a = (struct config_token *) a;
	struct config_token *ct_b = (struct config_token *) b;
	const char *str_a = ct_a->token;
	const char *str_b = ct_b->token;
	const char *a_colon = strchr(str_a, ':');
	const char *b_colon = strchr(str_b, ':');
	size_t maximum_a = 0xffffffff;
	size_t maximum_b = 0xffffffff;
	if (a_colon) maximum_a = a_colon - str_a;
	if (b_colon) maximum_b = b_colon - str_b;
	if (maximum_a < maximum_b) maximum_b = maximum_a;
	return maximum_b > 0xffff ? strcmp(str_a, str_b) : strncmp(str_a, str_b, maximum_b);
}
static int parse_ip_with_mask(const char *spec, struct in6_addr *addr_out, struct in6_addr *mask_out) {
	char *s = strdup(spec);
	if (!s) abort();
	char *slashbrk = strchr(s, '/');
	if (slashbrk) {
		*slashbrk++ = 0;
		if (strchr(slashbrk, ':')) {
			if (inet_pton(AF_INET6, slashbrk, mask_out) != 1) {
				free(s);
				return -1;
			}
		} else if ((slashbrk[0] >= '0') && (slashbrk[0] <= '9')) {
			int cidr_len = atoi(slashbrk);
			if ((cidr_len < 0) || (cidr_len > 128)) {
				free(s);
				return -1;
			}
			memset(mask_out, 0, sizeof(struct in6_addr));
			int n = 0;
			/* FIXME: check out of bounds conditions */
			while (cidr_len > 8) {
				mask_out->s6_addr[n] = 0xff;
				n++;
				cidr_len -= 8;
			}
			uint8_t nbits[] = {0, 128, 192, 224, 240, 248, 252, 254, 255};
			mask_out->s6_addr[n] = nbits[cidr_len];
		} else {
			free(s);
			return -1;
		}
	} else {
		memset(mask_out, 255, sizeof(struct in6_addr));
	}
	if (inet_pton(AF_INET6, s, addr_out) != 1) {
		free(s);
		return -1;
	}
	free(s);
	return 0;
}
static struct skbox_map_elem *init_new_map_entry(struct skbox_config *c) {
	if (c->state != SKBOX_CONFIG_TYPE_MAP || !c->maps) return NULL;
	struct skbox_map_list *current_map = &c->maps[c->curr_rule_or_map];
	if (c->continue_entry) return &current_map->items[current_map->nr_items - 1];
	if (current_map->nr_items < current_map->max_items) {
		c->continue_entry = 1;
		return &current_map->items[current_map->nr_items++];
	}
	/* FIXME: dynamic reallocation */
	return NULL;
}
static struct skbox_rule_elem *init_new_rule_entry(struct skbox_config *c) {
	if (c->state != SKBOX_CONFIG_TYPE_RULE || !c->rules) return NULL;
	struct skbox_rule_list *current_rule_list = &c->rules[c->curr_rule_or_map];
	if (c->continue_entry) return &current_rule_list->rules[current_rule_list->nr_rules - 1];
	if (current_rule_list->nr_rules < current_rule_list->max_rules) {
		c->continue_entry = 1;
		return &current_rule_list->rules[current_rule_list->nr_rules++];
	}
	return NULL;
}
static int common_ip_handler(const char *s, struct skbox_config *c, int remote) {
	switch (c->state) {
		case SKBOX_CONFIG_TYPE_MAP:
			;struct skbox_map_elem *m1 = init_new_map_entry(c);
			return inet_pton(AF_INET6, s, remote ? &m1->match_pattern.remote_addr : &m1->match_pattern.local_addr) == 1 ? 0 : -1;
		case SKBOX_CONFIG_TYPE_RULE:
			;struct skbox_rule_elem *m = init_new_rule_entry(c);
			if (remote) {
				return parse_ip_with_mask(s, &m->match_pattern.remote_addr, &m->match_mask.remote_addr);
			} else {
				return parse_ip_with_mask(s, &m->match_pattern.local_addr, &m->match_mask.local_addr);
			}
			break;
		default:
			return -1;
	}
}
static int common_port_handler(const char *s, struct skbox_config *c, int remote) {
	switch (c->state) {
		case SKBOX_CONFIG_TYPE_MAP:
			;struct skbox_map_elem *m = init_new_map_entry(c);
			if (remote) {
				m->match_pattern.rport = atoi(s);
			} else {
				m->match_pattern.lport = atoi(s);
			}
			return 0;
		case SKBOX_CONFIG_TYPE_RULE:
			;struct skbox_rule_elem *m1 = init_new_rule_entry(c);
			if (remote) {
				m1->match_mask.rport = 0xffff;
				m1->match_pattern.rport = atoi(s);
			} else {
				m1->match_mask.lport = 0xffff;
				m1->match_pattern.lport = atoi(s);
			}
			return 0;
		default:
			return -1;
	}
}
static void common_jump_action_handler(const char *s, struct skbox_action *result, skbox_action_type_t type) {
	result->type = type;
	switch(type) {
		case SKBOX_ACTION_FAIL:
			break;
		case SKBOX_ACTION_FD:
			result->action.send_fd = atoi(s);
			break;
		case SKBOX_ACTION_SOCKET:
			/* FIXME: When to free memory? */
			;struct sockaddr_un *addr = calloc(sizeof(struct sockaddr_un), 1);
			addr->sun_family = AF_UNIX;
			strncpy(addr->sun_path, s, sizeof(addr->sun_path) - 1);
			result->action.name = addr;
			break;
		case SKBOX_ACTION_JUMP_MAP:
		case SKBOX_ACTION_JUMP_RULE:
			result->action.map_or_rule_id = atoi(s);
			break;
	}
}
static int common_jump_handler(const char *s, struct skbox_config *c, skbox_action_type_t type) {
	switch (c->state) {
		case SKBOX_CONFIG_TYPE_MAP:
			;struct skbox_map_elem *m = init_new_map_entry(c);
			common_jump_action_handler(s, &m->action, type);
			return 0;
		case SKBOX_CONFIG_TYPE_RULE:
			;struct skbox_rule_elem *m1 = init_new_rule_entry(c);
			common_jump_action_handler(s, &m1->action, type);
			return 0;
		case SKBOX_CONFIG_TYPE_DEFAULT_MAP:
			if (!c->maps) return -1;
			common_jump_action_handler(s, &c->maps[c->curr_rule_or_map].default_action, type);
			return 0;
		case SKBOX_CONFIG_TYPE_DEFAULT_RULE:
			if (!c->rules) return -1;
			common_jump_action_handler(s, &c->rules[c->curr_rule_or_map].default_action, type);
			return 0;
		default:
			return -1;
	}
}
static int local_port_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_port_handler(s, c, 0);
}
static int remote_port_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_port_handler(s, c, 1);
}
static int local_ip_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_ip_handler(s, c, 0);
}
static int remote_ip_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_ip_handler(s, c, 1);
}
static int jump_fd_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_jump_handler(s, c, SKBOX_ACTION_FD);
}
static int jump_map_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_jump_handler(s, c, SKBOX_ACTION_JUMP_MAP);
}
static int jump_rule_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_jump_handler(s, c, SKBOX_ACTION_JUMP_RULE);
}
static int jump_unix_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	return common_jump_handler(s, c, SKBOX_ACTION_SOCKET);
}
static int jump_fail_handler(const char *s, struct skbox_config *c) {
	return common_jump_handler(s, c, SKBOX_ACTION_FAIL);
}
static int set_default_handler(const char *s, struct skbox_config *c) {
	if (c->continue_entry) return -1;
	if (c->state == SKBOX_CONFIG_TYPE_MAP) c->state = SKBOX_CONFIG_TYPE_DEFAULT_MAP;
	else if (c->state == SKBOX_CONFIG_TYPE_RULE) c->state = SKBOX_CONFIG_TYPE_DEFAULT_RULE;
	else return -1;
	return 0;
}
static int map_set_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	if (c->continue_entry) return -1;
	unsigned int map_id = atoi(s); /* FIXME: atoi -> strtoul */
	if (map_id >= c->nr_maps) return -1;
	c->curr_rule_or_map = map_id;
	c->state = SKBOX_CONFIG_TYPE_MAP;
	return 0;
}
static int rule_set_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	if (c->continue_entry) return -1;
	unsigned int rule_id = atoi(s); /* FIXME: atoi -> strtoul */
	if (rule_id >= c->nr_rules) return -1;
	c->curr_rule_or_map = rule_id;
	c->state = SKBOX_CONFIG_TYPE_RULE;
	return 0;
}
static int size_handler(const char *s, struct skbox_config *c) {
	if (!s) return -1;
	unsigned int req_size = atoi(s);
	if (req_size == 0 || req_size > 1000) return -1;
	switch(c->state) {
		case SKBOX_CONFIG_TYPE_RULE:
			;struct skbox_rule_list *mz = &c->rules[c->curr_rule_or_map];
			if (mz->max_rules) return -1;
			mz->max_rules = req_size;
			mz->rules = calloc(sizeof(struct skbox_rule_elem), mz->max_rules);
			if (!mz->rules) return -1;
			return 0;
		case SKBOX_CONFIG_TYPE_MAP:
			;struct skbox_map_list *m = &c->maps[c->curr_rule_or_map];
			if (m->max_items) return -1;
			m->max_items = req_size;
			m->items = calloc(sizeof(struct skbox_map_elem), m->max_items);
			if (!m->items) return -1;
			return 0;
		default:
			return -1;
	}
	return 0;
}
static int max_maps_handler(const char *s, struct skbox_config *cfg) {
	if (!s) return -1;
	unsigned int max_maps = atoi(s);
	if (cfg->nr_maps) return -1;
	if (max_maps == 0 || max_maps > 1000) return -1;
	cfg->nr_maps = max_maps;
	cfg->maps = calloc(sizeof(struct skbox_map_list), cfg->nr_maps);
	if (!cfg->maps) return -1;
	return 0;
}
static int max_rules_handler(const char *s, struct skbox_config *cfg) {
	if (!s) return -1;
	unsigned int max_rules = atoi(s);
	if (cfg->nr_rules) return -1;
	if (max_rules == 0 || max_rules > 1000) return -1;
	cfg->nr_rules = max_rules;
	cfg->rules = calloc(sizeof(struct skbox_rule_list), cfg->nr_rules);
	if (!cfg->rules) return -1;
	return 0;
}
static int match_lip_handler(const char *s, struct skbox_config *cfg) {
	if (!s) return -1;
	if (cfg->state != SKBOX_CONFIG_TYPE_MAP) return -1;
	int lip_mask = atoi(s);
	struct skbox_map_list *m = &cfg->maps[cfg->curr_rule_or_map];
	if (lip_mask < 0 || lip_mask > 128) return -1;
	int n = lip_mask / 8;
	memset(&m->mask.local_addr, 0, sizeof(struct in6_addr));
	memset(&m->mask.local_addr, 255, n);
	const int cidrs[] = {0, 128, 192, 224, 240, 248, 252, 254};
	if (n < 16) m->mask.local_addr.s6_addr[n] = cidrs[lip_mask % 8];
	return 0;
}
static int match_rip_handler(const char *s, struct skbox_config *cfg) {
	if (!s) return -1;
	if (cfg->state != SKBOX_CONFIG_TYPE_MAP) return -1;
	int rip_mask = atoi(s);
	struct skbox_map_list *m = &cfg->maps[cfg->curr_rule_or_map];
	if (rip_mask < 0 || rip_mask > 128) return -1;
	int n = rip_mask / 8;
	memset(&m->mask.remote_addr, 0, sizeof(struct in6_addr));
	memset(&m->mask.remote_addr, 255, n);
	const int cidrs[] = {0, 128, 192, 224, 240, 248, 252, 254};
	if (n < 16) m->mask.remote_addr.s6_addr[n] = cidrs[rip_mask % 8];
	return 0;
}
static int match_lport_handler(const char *s, struct skbox_config *cfg) {
	if (cfg->state != SKBOX_CONFIG_TYPE_MAP) return -1;
	struct skbox_map_list *m = &cfg->maps[cfg->curr_rule_or_map];
	m->mask.lport = 0xffff;
	return 0;
}
static int match_rport_handler(const char *s, struct skbox_config *cfg) {
	if (cfg->state != SKBOX_CONFIG_TYPE_MAP) return -1;
	struct skbox_map_list *m = &cfg->maps[cfg->curr_rule_or_map];
	m->mask.rport = 0xffff;
	return 0;
}
static struct config_token config_options[] = {
	{"default", set_default_handler}, //
	{"fail", jump_fail_handler}, //
	{"ip", local_ip_handler}, //
	{"jump-fd", jump_fd_handler}, //
	{"jump-map", jump_map_handler}, //
	{"jump-rule", jump_rule_handler}, //
	{"jump-unix", jump_unix_handler}, //
	{"map-set", map_set_handler}, //
	{"match-lip", match_lip_handler},
	{"match-lport", match_lport_handler},
	{"match-rip", match_rip_handler},
	{"match-rport", match_rport_handler},
	{"max-maps", max_maps_handler}, //
	{"max-rules", max_rules_handler}, //
	{"port", local_port_handler}, //
	{"rip", remote_ip_handler}, //
	{"rport", remote_port_handler}, //
	{"rule-set", rule_set_handler}, //
	{"size", size_handler}, //
};
static int parse_config_token(const char *token, struct skbox_config *global_config) {
	struct config_token d_token = {token, NULL};
	struct config_token *result_token = bsearch(&d_token, config_options,
			sizeof(config_options) / sizeof(config_options[0]), sizeof(struct config_token), compare_strings_before_colon);
	if (!result_token) return -1;
	const char *colon_brk = strchr(token, ':');
	if (colon_brk) colon_brk++;
	return result_token->token_handler(colon_brk, global_config);
}
struct skbox_config *skbox_parse_config(FILE *input_file) {
	struct skbox_config *result = calloc(sizeof(struct skbox_config), 1);
	if (!result) return NULL;
	int linenr = 0;
	while (1) {
		char *line = NULL;
		size_t linesize = 0;
		if (getline(&line, &linesize, input_file) < 0 || line == NULL) break;
		linenr++;
		if (linesize == 0) {free(line); continue;}
		if (line[0] == '#') {free(line); continue;}
		char *nlbrk = strchr(line, '\n');
		if (nlbrk) {
			if (nlbrk == line) {free(line); continue;}
			*nlbrk = 0;
		}
		result->continue_entry = 0;
		char *saveptr = NULL;
		for (char *token = strtok_r(line, " \t", &saveptr); token; token = strtok_r(NULL, " ", &saveptr)) {
			if (parse_config_token(token, result) < 0) {
				fprintf(stderr, "Syntax error on line %d, near '%s'\n", linenr, token);
				free(line);
				return NULL;
			}
		}
		free(line);
		continue;
	}
	return feof(input_file) ? result : NULL;
}
static struct skbox_ip_port_tuple *m_mask = NULL;
static int compare_tuples(const void *a, const void *b) {
	struct skbox_map_elem *a_map = (struct skbox_map_elem *) a;
	struct skbox_map_elem *b_map = (struct skbox_map_elem *) b;
	return skbox_compare_tuples(&a_map->match_pattern, &b_map->match_pattern, m_mask);
}
void skbox_sort_maps(struct skbox_config *config) {
	for (uint32_t i = 0; i < config->nr_maps; i++) {
		struct skbox_map_list *m = &config->maps[i];
		m_mask = &m->mask;
		qsort(m->items, m->nr_items, sizeof(struct skbox_map_elem), compare_tuples);
	}
}
