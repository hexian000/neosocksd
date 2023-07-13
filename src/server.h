#ifndef SERVER_H
#define SERVER_H

#include "conf.h"

#include <ev.h>

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

struct server_stats {
	size_t num_halfopen;
	size_t num_sessions;
	uintmax_t num_request;
	uintmax_t num_rejected;
	ev_tstamp started;
};

struct server;

typedef void (*serve_fn)(
	struct server *h, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa);

struct server {
	const struct config *conf;
	struct ruleset *ruleset;
	struct server_stats *stats;

	serve_fn serve;
};

/* the listener binds to an address and accepts incoming connections */
struct listener {
	struct server *s;
	struct ev_io w_accept;
	struct ev_timer w_timer;
};

void listener_init(struct listener *l, struct server *s);
bool listener_start(
	struct listener *l, struct ev_loop *loop,
	const struct sockaddr *bindaddr);
void listener_stop(struct listener *l, struct ev_loop *loop);

#endif /* SERVER_H */
