#ifndef SERVER_H
#define SERVER_H

#include "conf.h"

#include <ev.h>

struct ruleset;
struct server;

typedef void (*serve_fn)(
	struct ev_loop *loop, struct server *s, const int accepted_fd,
	const struct sockaddr *accepted_sa);

/* the server binds to an address and serves any incoming request with serve_cb */
struct server {
	const struct config *conf;
	struct ruleset *ruleset;
	serve_fn serve_cb;
	struct ev_io w_accept;
	ev_tstamp uptime;
};

struct server *server_new(
	const struct sockaddr *bindaddr, const struct config *conf,
	struct ruleset *ruleset, serve_fn serve_cb);
void server_start(struct server *s, struct ev_loop *loop);
void server_stop(struct server *s, struct ev_loop *loop);
void server_free(struct server *s);

double server_get_uptime(struct server *s, ev_tstamp now);

#endif /* SERVER_H */
