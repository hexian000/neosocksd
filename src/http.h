#ifndef REST_H
#define REST_H

#include "server.h"
#include "ruleset.h"
#include "stats.h"

struct ev_loop;
struct server;

/* http_proxy_serve: implements serve_fn */
void http_proxy_serve(
	struct ev_loop *loop, struct server *s, int accepted_fd,
	const struct sockaddr *accepted_sa);

/* http_api_serve: implements serve_fn */
void http_api_serve(
	struct ev_loop *loop, struct server *s, int accepted_fd,
	const struct sockaddr *accepted_sa);

void http_read_stats(struct stats *out_stats);

#endif /* REST_H */
