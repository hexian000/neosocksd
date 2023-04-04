#include "stats.h"
#include "forward.h"
#include "socks.h"
#include "http.h"

static void stats_add(struct stats *restrict a, const struct stats *restrict b)
{
	*a = (struct stats){
		.num_request = a->num_request + b->num_request,
		.num_halfopen = a->num_halfopen + b->num_halfopen,
	};
}

void stats_read(struct stats *restrict out_stats)
{
	*out_stats = (struct stats){ 0 };
	struct stats s;
	socks_read_stats(&s);
	stats_add(out_stats, &s);
	http_read_stats(&s);
	stats_add(out_stats, &s);
	forward_read_stats(&s);
	stats_add(out_stats, &s);
}
