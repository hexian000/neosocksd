#ifndef RESOLVER_H
#define RESOLVER_H

#include "conf.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>

#include <stddef.h>

struct sockaddr;
struct ev_loop;

/* RFC 1035: Section 2.3.4 */
#define FQDN_MAX_LENGTH ((size_t)(255))

struct domain_name {
	uint8_t len;
	char name[FQDN_MAX_LENGTH];
};

struct resolver {
	struct event_cb done_cb;
	struct ev_watcher watcher;
	int resolve_pf;
	int state;
	int err;
	sockaddr_max_t addr;
};

void resolver_init(
	struct resolver *r, int resolve_pf, const struct event_cb *cb);

bool resolver_start(
	struct resolver *r, struct ev_loop *loop,
	const struct domain_name *name);

void resolver_stop(struct resolver *r, struct ev_loop *loop);

const struct sockaddr *resolver_get(struct resolver *r);

#endif /* RESOLVER_H */
