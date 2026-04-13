/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include "dialer.h"
#include "proto/http.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>

struct config;
struct dialreq;
struct resolver;

enum http_client_state {
	STATE_CLIENT_INIT,
	STATE_CLIENT_CONNECT,
	STATE_CLIENT_REQUEST,
	STATE_CLIENT_RESPONSE,
};

struct http_client_cb {
	void (*func)(
		struct ev_loop *loop, void *data, const char *errmsg,
		size_t errlen, struct http_conn *conn);
	void *data;
};

struct http_client_ctx {
	struct ev_loop *loop;
	const struct config *conf;
	struct resolver *resolver;
	struct dialreq *dialreq;
	bool cache_retried;
	enum http_client_state state;
	struct http_client_cb cb;
	struct http_parsehdr_cb user_on_header;
	ev_timer w_timeout;
	ev_io w_socket;
	struct dialer dialer;
	struct http_conn conn;
};

void http_client_init(
	struct http_client_ctx *ctx, struct ev_loop *loop,
	struct http_parsehdr_cb on_header, const struct http_client_cb *cb,
	const struct config *conf, struct resolver *resolver);

/* Takes ownership of req. */
void http_client_do(
	struct ev_loop *loop, struct http_client_ctx *ctx, struct dialreq *req);

void http_client_cancel(struct ev_loop *loop, struct http_client_ctx *ctx);

#endif /* HTTP_CLIENT_H */
