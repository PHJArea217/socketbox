#include "lookup.h"
#include <stdio.h>
struct skbox_config {
	struct skbox_map_list *maps;
	struct skbox_rule_list *rules;
	uint32_t nr_maps;
	uint32_t nr_rules;
	uint32_t curr_rule_or_map;
	uint16_t state; /* 0 = global, 1 = map, 2 = rule */
	uint16_t continue_entry;
};
struct skbox_config *skbox_parse_config(FILE *input_file);
void skbox_sort_maps(struct skbox_config *config);
