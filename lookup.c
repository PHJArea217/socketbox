#include "lookup.h"
static const uint32_t tuple_intsize = sizeof(struct skbox_ip_port_tuple) / sizeof(uint32_t);
int skbox_compare_tuples(
		const struct skbox_ip_port_tuple *left,
		const struct skbox_ip_port_tuple *right,
		const struct skbox_ip_port_tuple *mask) {
	uint32_t *l = (uint32_t *) left;
	uint32_t *r = (uint32_t *) right;
	uint32_t *m = (uint32_t *) mask;
	for (unsigned int i = 0; i < tuple_intsize; i++) {
		uint32_t lw = l[i] & m[i];
		uint32_t rw = r[i] & m[i];
		if (lw < rw) return -1;
		if (lw > rw) return 1;
	}
	return 0;
}
const struct skbox_action *skbox_find_action_for_map(const struct skbox_ip_port_tuple *this_socket, const struct skbox_map_list *map) {
	uint32_t lb = 0;
	uint32_t rb = map->nr_items;
	while (lb < rb) {
		uint32_t mb = lb + (rb - lb) / 2;
		const struct skbox_map_elem *mb_elem = &map->items[mb];
		int bsearch_res = skbox_compare_tuples(this_socket, &mb_elem->match_pattern, &map->mask);
		if (bsearch_res == 0) {
			return &mb_elem->action;
		} else if (bsearch_res < 0) {
			rb = mb;
		} else {
			lb = mb;
		}
	}
	return &map->default_action;
}
const struct skbox_action *skbox_find_action_for_list(const struct skbox_ip_port_tuple *this_socket, const struct skbox_rule_list *list) {
	for (uint32_t idx = 0; idx < list->nr_rules; idx++) {
		struct skbox_rule_elem *elem = &list->rules[idx];
		if (skbox_compare_tuples(this_socket, &elem->match_pattern, &elem->match_mask) == 0) {
			return &elem->action;
		}
	}
	return &list->default_action;
}
const struct skbox_action *skbox_iterative_lookup(const struct skbox_ip_port_tuple *this_socket, const struct skbox_rule_list *rules, uint32_t nr_rules, const struct skbox_map_list *maps, uint32_t nr_maps, int max_lookups) {
	const struct skbox_action current_action_d = {.type = SKBOX_ACTION_JUMP_RULE, .action = {.map_or_rule_id = 0}};
	const struct skbox_action *current_action = &current_action_d;
	for (int i = 0; i < max_lookups; i++) {
		const struct skbox_action *next_action = NULL;
		switch (current_action->type) {
			case SKBOX_ACTION_JUMP_MAP:
				;uint32_t mapid = current_action->action.map_or_rule_id;
				if (mapid >= nr_maps) goto fail;
				next_action = skbox_find_action_for_map(this_socket, &maps[mapid]);
				break;
			case SKBOX_ACTION_JUMP_RULE:
				;uint32_t ruleid = current_action->action.map_or_rule_id;
				if (ruleid >= nr_rules) goto fail;
				next_action = skbox_find_action_for_list(this_socket, &rules[ruleid]);
				break;
			default:
				goto fail;
		}
		switch(next_action->type) {
			case SKBOX_ACTION_JUMP_RULE:
			case SKBOX_ACTION_JUMP_MAP:
				current_action = next_action;
				break;
			case SKBOX_ACTION_FAIL:
			case SKBOX_ACTION_FD:
			case SKBOX_ACTION_SOCKET:
				return next_action;
			default:
				goto fail;
		}
	}
fail:
	return NULL;
}
