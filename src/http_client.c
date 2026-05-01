/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_client.h"

#include "conf.h"
#include "dialer.h"
#include "util.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>

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

static void http_client_cleanup(struct http_client_ctx *restrict ctx)
{
	http_client_stop(ctx->loop, ctx);
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;
	if (ctx->w_socket.fd != -1) {
		CLOSE_FD(ctx->w_socket.fd);
		ctx->w_socket.fd = -1;
	}
	VBUF_FREE(ctx->conn.cbuf);
	ctx->state = STATE_CLIENT_INIT;
}

static void finish_error(
	struct http_client_ctx *restrict ctx, const char *errmsg,
	const size_t errlen)
{
	struct ev_loop *const loop = ctx->loop;
	const struct http_client_cb cb = ctx->cb;
	http_client_cleanup(ctx);
	if (cb.func != NULL) {
		cb.func(loop, cb.data, errmsg, errlen, NULL);
	}
}

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_client_ctx *restrict ctx = watcher->data;
	const int ret = http_conn_recv(&ctx->conn);
	if (ret < 0) {
		finish_error(
			ctx, "error receiving response",
			sizeof("error receiving response") - 1);
		return;
	}
	if (ret > 0) {
		return;
	}

	if (ctx->conn.state != STATE_PARSE_OK) {
		finish_error(
			ctx, "error parsing response",
			sizeof("error parsing response") - 1);
		return;
	}

	http_client_stop(loop, ctx);
	ctx->state = STATE_CLIENT_INIT;

	int fd = watcher->fd;
	watcher->fd = -1;
	const char *conn = ctx->conn.hdr.connection;
	if (ctx->dialreq != NULL &&
	    (conn == NULL || strcasecmp(conn, "close") != 0) &&
	    ctx->conf->conn_cache) {
		conn_cache_put(loop, fd, ctx->dialreq);
	} else {
		if (ctx->dialreq != NULL && conn != NULL) {
			LOGV("server wants to close the connection, skip caching");
		}
		CLOSE_FD(fd);
	}
	const struct http_client_cb cb = ctx->cb;
	if (cb.func != NULL) {
		cb.func(loop, cb.data, NULL, 0, &ctx->conn);
	}
	http_client_cleanup(ctx);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_client_ctx *restrict ctx = watcher->data;
	const int ret = http_conn_send(&ctx->conn, watcher->fd);
	if (ret < 0) {
		const int err = errno;
		if (ctx->state == STATE_CLIENT_REQUEST && !ctx->cache_retried &&
		    IS_STALECONN_ERROR(err)) {
			ctx->cache_retried = true;
			ev_io_stop(loop, watcher);
			const int stale_fd = watcher->fd;
			ev_io_set(watcher, -1, EV_NONE);
			if (stale_fd != -1) {
				CLOSE_FD(stale_fd);
			}
			ctx->state = STATE_CLIENT_CONNECT;
			dialer_do(
				&ctx->dialer, loop, ctx->dialreq, ctx->conf,
				ctx->resolver);
			return;
		}
		const char *strerr = strerror(err);
		const size_t errlen = strlen(strerr);
		char errmsg[errlen + 1];
		memcpy(errmsg, strerr, errlen + 1);
		finish_error(ctx, errmsg, errlen);
		return;
	}
	if (ret > 0) {
		return;
	}

	ev_io_stop(loop, watcher);
	ctx->state = STATE_CLIENT_RESPONSE;
	ctx->conn.fd = watcher->fd;
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

static bool http_client_on_header(void *data, const char *key, char *value)
{
	struct http_client_ctx *restrict ctx = data;
	if (strcasecmp(key, "Connection") == 0) {
		ctx->conn.hdr.connection = value;
		return true;
	}
	if (ctx->user_on_header.func != NULL) {
		return ctx->user_on_header.func(
			ctx->user_on_header.ctx, key, value);
	}
	return true;
}

void http_client_init(
	struct http_client_ctx *restrict ctx, struct ev_loop *loop,
	const struct http_parsehdr_cb on_header,
	const struct http_client_cb *restrict cb, const struct config *conf,
	struct resolver *resolver)
{
	ctx->loop = loop;
	ctx->conf = conf;
	ctx->resolver = resolver;
	ctx->dialreq = NULL;
	ctx->cache_retried = false;
	ctx->state = STATE_CLIENT_INIT;
	ctx->cb = *cb;
	ctx->user_on_header = on_header;
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
	const struct http_parsehdr_cb hdr_cb = { http_client_on_header, ctx };
	http_conn_init(&ctx->conn, -1, STATE_PARSE_RESPONSE, hdr_cb);
}

static void http_client_start_fd(
	struct ev_loop *loop, struct http_client_ctx *ctx, const int fd)
{
	ASSERT(ctx->state == STATE_CLIENT_INIT);
	ctx->conn.fd = fd;
	ctx->state = STATE_CLIENT_REQUEST;
	ev_timer_start(loop, &ctx->w_timeout);
	ev_io_init(&ctx->w_socket, send_cb, fd, EV_WRITE);
	ctx->w_socket.data = ctx;
	ev_io_start(loop, &ctx->w_socket);
}

void http_client_do(
	struct ev_loop *loop, struct http_client_ctx *ctx,
	struct dialreq *restrict req)
{
	ASSERT(ctx->state == STATE_CLIENT_INIT);
	ctx->dialreq = req;
	ctx->cache_retried = false;
	if (ctx->conf->conn_cache) {
		const int fd = conn_cache_get(loop, req);
		if (fd != -1) {
			LOGV_F("http_client: reusing cached connection [fd:%d]",
			       fd);
			http_client_start_fd(loop, ctx, fd);
			return;
		}
	}
	ctx->state = STATE_CLIENT_CONNECT;
	ev_timer_start(loop, &ctx->w_timeout);
	dialer_do(&ctx->dialer, loop, req, ctx->conf, ctx->resolver);
}

void http_client_cancel(struct ev_loop *loop, struct http_client_ctx *ctx)
{
	UNUSED(loop);
	http_client_cleanup(ctx);
}
