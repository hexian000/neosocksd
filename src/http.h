#ifndef REST_H
#define REST_H

#include "ruleset.h"

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

size_t http_get_halfopen(void);

#endif /* REST_H */
