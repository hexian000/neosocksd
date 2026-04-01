/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "proto/http.h"

#include <stddef.h>

struct config;
struct dialreq;
struct resolver;

struct ev_loop;

struct http_client_ctx;

struct http_client_cb {
	void (*func)(
		struct ev_loop *loop, void *data, const char *errmsg,
		size_t errlen, struct http_parser *parser, int fd);
	void *data;
};

struct http_client_ctx *http_client_new(
	struct ev_loop *loop, struct http_parsehdr_cb on_header,
	const struct http_client_cb *cb, const struct config *conf,
	struct resolver *resolver);

struct http_parser *http_client_parser(struct http_client_ctx *ctx);

void http_client_start(
	struct ev_loop *loop, struct http_client_ctx *ctx,
	const struct dialreq *req);

void http_client_start_fd(
	struct ev_loop *loop, struct http_client_ctx *ctx, int fd);

void http_client_cancel(struct ev_loop *loop, struct http_client_ctx *ctx);

#endif /* HTTP_CLIENT_H */
