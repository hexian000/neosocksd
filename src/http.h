#ifndef HTTP_H
#define HTTP_H

#include "server.h"

struct dialreq;

/* http_proxy_serve: implements serve_fn */
void http_proxy_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

/* http_api_serve: implements serve_fn */
void http_api_serve(
	struct server *s, struct ev_loop *loop, int accepted_fd,
	const struct sockaddr *accepted_sa);

struct http_invoke_ctx;
struct http_invoke_ctx *http_invoke(
	struct ev_loop *loop, const struct config *conf, struct dialreq *req,
	const char *code, size_t len);

#endif /* HTTP_H */
