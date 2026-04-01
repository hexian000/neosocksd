/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_client.h"

#include "conf.h"
#include "dialer.h"
#include "util.h"

#include "os/socket.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

enum http_client_state {
	STATE_CLIENT_INIT,
	STATE_CLIENT_CONNECT,
	STATE_CLIENT_REQUEST,
	STATE_CLIENT_RESPONSE,
};

struct http_client_ctx {
	struct gcbase gcbase;
	struct ev_loop *loop;
	const struct config *conf;
	struct resolver *resolver;
	enum http_client_state state;
	struct http_client_cb cb;
	ev_timer w_timeout;
	ev_io w_socket;
	struct dialer dialer;
	struct http_parser parser;
};
ASSERT_SUPER(struct gcbase, struct http_client_ctx, gcbase);

static void
http_client_stop(struct ev_loop *loop, struct http_client_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	switch (ctx->state) {
	case STATE_CLIENT_INIT:
		break;
	case STATE_CLIENT_CONNECT:
		dialer_cancel(&ctx->dialer, loop);
		break;
	case STATE_CLIENT_REQUEST:
	case STATE_CLIENT_RESPONSE:
		ev_io_stop(loop, &ctx->w_socket);
		break;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
}

static void http_client_finalize(struct gcbase *restrict obj)
{
	struct http_client_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct http_client_ctx, gcbase, obj);

	http_client_stop(ctx->loop, ctx);
	if (ctx->w_socket.fd != -1) {
		CLOSE_FD(ctx->w_socket.fd);
		ctx->w_socket.fd = -1;
	}
	VBUF_FREE(ctx->parser.cbuf);
}

static void finish_error(
	struct http_client_ctx *restrict ctx, const char *errmsg,
	const size_t errlen)
{
	if (ctx->cb.func != NULL) {
		ctx->cb.func(ctx->loop, ctx->cb.data, errmsg, errlen, NULL, -1);
	}
	gc_unref(&ctx->gcbase);
}

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_client_ctx *restrict ctx = watcher->data;
	const int ret = http_parser_recv(&ctx->parser);
	if (ret < 0) {
		finish_error(
			ctx, "error receiving response",
			sizeof("error receiving response") - 1);
		return;
	}
	if (ret > 0) {
		return;
	}

	if (ctx->parser.state != STATE_PARSE_OK) {
		finish_error(
			ctx, "error parsing response",
			sizeof("error parsing response") - 1);
		return;
	}

	http_client_stop(loop, ctx);
	ctx->state = STATE_CLIENT_INIT;

	int fd = watcher->fd;
	watcher->fd = -1;
	if (ctx->cb.func != NULL) {
		ctx->cb.func(loop, ctx->cb.data, NULL, 0, &ctx->parser, fd);
	}
	gc_unref(&ctx->gcbase);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_client_ctx *restrict ctx = watcher->data;
	const int ret = http_parser_send(&ctx->parser, watcher->fd);
	if (ret < 0) {
		const int err = errno;
		const char *errmsg = strerror(err);
		finish_error(ctx, errmsg, strlen(errmsg));
		return;
	}
	if (ret > 0) {
		return;
	}

	ev_io_stop(loop, watcher);
	ctx->state = STATE_CLIENT_RESPONSE;
	ctx->parser.fd = watcher->fd;
	ev_set_cb(watcher, recv_cb);
	ev_io_set(watcher, watcher->fd, EV_READ);
	ev_io_start(loop, watcher);
}

static void dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct http_client_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CLIENT_CONNECT);
	if (fd < 0) {
		const enum dialer_error err = ctx->dialer.err;
		const int syserr = ctx->dialer.syserr;
		if (syserr != 0) {
			LOGE_F("dialer: %s (%d) %s", dialer_strerror(err),
			       syserr, strerror(syserr));
		} else {
			LOGE_F("dialer: %s", dialer_strerror(err));
		}
		finish_error(
			ctx, "connection failed",
			sizeof("connection failed") - 1);
		return;
	}

	ctx->state = STATE_CLIENT_REQUEST;
	ev_io *restrict w_send = &ctx->w_socket;
	ev_set_cb(w_send, send_cb);
	w_send->data = ctx;
	ev_io_set(w_send, fd, EV_WRITE);
	ev_io_start(loop, w_send);
}

static void http_client_timeout_cb(
	struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_client_ctx *restrict ctx = watcher->data;
	UNUSED(loop);
	finish_error(ctx, "timeout", sizeof("timeout") - 1);
}

struct http_client_ctx *http_client_new(
	struct ev_loop *loop, const struct http_parsehdr_cb on_header,
	const struct http_client_cb *cb, const struct config *conf,
	struct resolver *resolver)
{
	struct http_client_ctx *restrict ctx =
		malloc(sizeof(struct http_client_ctx));
	if (ctx == NULL) {
		LOGOOM();
		return NULL;
	}
	ctx->loop = loop;
	ctx->conf = conf;
	ctx->resolver = resolver;
	ctx->state = STATE_CLIENT_INIT;
	ctx->cb = *cb;
	ev_timer_init(
		&ctx->w_timeout, http_client_timeout_cb, conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
	ev_io_init(&ctx->w_socket, NULL, -1, EV_NONE);
	ctx->w_socket.data = ctx;
	const struct dialer_cb dialer_cb_conf = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, &dialer_cb_conf);
	http_parser_init(&ctx->parser, -1, STATE_PARSE_RESPONSE, on_header);
	gc_register(&ctx->gcbase, http_client_finalize);
	return ctx;
}

struct http_parser *http_client_parser(struct http_client_ctx *ctx)
{
	return &ctx->parser;
}

void http_client_start(
	struct ev_loop *loop, struct http_client_ctx *ctx,
	const struct dialreq *req)
{
	ASSERT(ctx->state == STATE_CLIENT_INIT);
	ctx->state = STATE_CLIENT_CONNECT;
	ev_timer_start(loop, &ctx->w_timeout);
	dialer_do(&ctx->dialer, loop, req, ctx->conf, ctx->resolver);
}

void http_client_start_fd(
	struct ev_loop *loop, struct http_client_ctx *ctx, const int fd)
{
	ASSERT(ctx->state == STATE_CLIENT_INIT);
	ctx->parser.fd = fd;
	ctx->state = STATE_CLIENT_REQUEST;
	ev_timer_start(loop, &ctx->w_timeout);
	ev_io_init(&ctx->w_socket, send_cb, fd, EV_WRITE);
	ctx->w_socket.data = ctx;
	ev_io_start(loop, &ctx->w_socket);
}

void http_client_cancel(struct ev_loop *loop, struct http_client_ctx *ctx)
{
	UNUSED(loop);
	gc_unref(&ctx->gcbase);
}
