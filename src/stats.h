#ifndef STATS_H
#define STATS_H

#include <stddef.h>
#include <stdint.h>

struct stats {
	uintmax_t num_request;
	size_t num_halfopen;
};

void stats_read(struct stats *out_stats);

#endif /* STATS_H */
