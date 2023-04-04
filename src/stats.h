#ifndef STATS_H
#define STATS_H

#include <stddef.h>

struct stats {
	size_t num_request;
	size_t num_halfopen;
};

void stats_read(struct stats *out_stats);

#endif /* STATS_H */
