#ifndef HTTP_H
#define HTTP_H

#include "server.h"
#include "ruleset.h"

struct ev_loop;
struct sockaddr;

struct config;
struct dialreq;
struct server;
struct stats;

/* http_proxy_serve: implements serve_fn */
void http_proxy_serve(
	struct ev_loop *loop, struct server *s, int accepted_fd,
	const struct sockaddr *accepted_sa);

/* http_api_serve: implements serve_fn */
void http_api_serve(
	struct ev_loop *loop, struct server *s, int accepted_fd,
	const struct sockaddr *accepted_sa);

void http_read_stats(struct stats *out_stats);

struct http_invoke_ctx;
struct http_invoke_ctx *http_invoke(
	struct ev_loop *loop, const struct config *conf, struct dialreq *req,
	const char *code, size_t len);

#endif /* HTTP_H */
