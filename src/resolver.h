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

struct resolve_query {
	struct resolver *resolver;
	struct ev_watcher w_done;
	struct event_cb done_cb;
	bool ok : 1;
	sockaddr_max_t addr;
};

void resolver_atexit_cb(void);

struct resolver *resolver_new(struct ev_loop *loop, const struct config *conf);
const struct resolver_stats *resolver_stats(struct resolver *r);
void resolver_free(struct resolver *r);

void resolve_init(
	struct resolver *r, struct resolve_query *q, struct event_cb cb);
bool resolve_start(
	struct resolve_query *q, const char *name, const char *service,
	int family);
void resolve_cancel(struct resolve_query *q);
const struct sockaddr *resolve_get(const struct resolve_query *q);

#endif /* RESOLVER_H */
