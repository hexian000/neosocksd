#ifndef RESOLVER_H
#define RESOLVER_H

#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <stdbool.h>

struct ev_loop;
struct config;

struct resolver;

struct resolver_stats {
	uintmax_t num_query;
	uintmax_t num_success;
};

struct resolve_query;

void resolver_atexit_cb(void);

struct resolver *resolver_new(struct ev_loop *loop, const struct config *conf);
const struct resolver_stats *resolver_stats(struct resolver *r);
void resolver_free(struct resolver *r);

struct resolve_query *resolve_new(struct resolver *r, struct event_cb cb);
void resolve_start(
	struct resolve_query *restrict q, const char *name, const char *service,
	int family);
void resolve_cancel(struct resolve_query *q);
bool resolve_get(sockaddr_max_t *addr, const struct resolve_query *q);

#endif /* RESOLVER_H */
