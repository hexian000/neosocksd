/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_client.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "util.h"

#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <stddef.h>
#include <string.h>

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
		socket_close(ctx->w_socket.fd);
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

static bool response_is_interim(const struct http_conn *restrict conn)
{
	const char *const code = conn->msg.rsp.code;
	return code != NULL && strlen(code) == 3 && code[0] == '1' &&
	       '0' <= code[1] && code[1] <= '9' && '0' <= code[2] &&
	       code[2] <= '9';
}

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_client_ctx *restrict ctx = watcher->data;
	int ret = http_conn_recv(&ctx->conn);
	while (ret == 0 && ctx->conn.state == STATE_PARSE_OK &&
	       response_is_interim(&ctx->conn)) {
		/* RFC 9110 15.2: discard each interim header block and keep
		 * waiting for the final response, including bytes already read. */
		struct http_conn *restrict conn = &ctx->conn;
		const size_t consumed =
			(size_t)((unsigned char *)conn->next - conn->rbuf.data);
		const size_t remaining = conn->rbuf.len - consumed;
		memmove(conn->rbuf.data, conn->next, remaining);
		http_conn_init(
			conn, watcher->fd, STATE_PARSE_RESPONSE,
			conn->on_header, conn->byt_recv, conn->byt_sent);
		conn->rbuf.len = remaining;
		conn->rbuf.data[remaining] = '\0';
		ret = http_conn_parse(conn);
	}
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

	const int fd = watcher->fd;
	watcher->fd = -1;
	socket_close(fd);
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
	int err = 0;
	const int ret = http_conn_send(&ctx->conn, watcher->fd, &err);
	if (ret < 0) {
		/* Every request runs on its own freshly dialed connection, so
		 * a write error is no idle connection gone stale: report it
		 * rather than redial and resend. */
		const char *const strerr = strerror(err);
		/* copy into a fixed buffer with truncation rather than a VLA
		 * sized by locale-dependent strerror() output */
		char errmsg[256];
		size_t errlen = strlen(strerr);
		if (errlen > sizeof(errmsg) - 1) {
			errlen = sizeof(errmsg) - 1;
		}
		memcpy(errmsg, strerr, errlen);
		errmsg[errlen] = '\0';
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
		char errbuf[128];
		LOGE_F("dialer: %s",
		       dialer_errorstr(errbuf, sizeof(errbuf), &ctx->dialer));
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
	(void)loop;
	finish_error(ctx, "timeout", sizeof("timeout") - 1);
}

static bool http_client_on_header(void *data, const char *key, char *value)
{
	struct http_client_ctx *restrict ctx = data;
	/* Informational responses have no body regardless of framing fields
	 * (RFC 9112 6.3). Ignore their headers so they cannot frame a body or
	 * change the final response's representation metadata. */
	if (response_is_interim(&ctx->conn)) {
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
	const struct http_client_cb *restrict cb,
	const struct http_client_opts *restrict opts)
{
	const struct config *restrict conf = opts->conf;
	ctx->loop = loop;
	ctx->conf = conf;
	ctx->resolver = opts->resolver;
	ctx->dialreq = NULL;
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
	dialer_init(
		&ctx->dialer, &dialer_cb_conf, opts->dialer_byt_sent,
		opts->dialer_byt_recv);
	const struct http_parsehdr_cb hdr_cb = {
		.func = http_client_on_header,
		.ctx = ctx,
	};
	http_conn_init(
		&ctx->conn, -1, STATE_PARSE_RESPONSE, hdr_cb, opts->byt_recv,
		opts->byt_sent);
}

void http_client_do(
	struct http_client_ctx *ctx, struct ev_loop *loop,
	struct dialreq *restrict req)
{
	ASSERT(ctx->state == STATE_CLIENT_INIT);
	ctx->dialreq = req;
	ctx->state = STATE_CLIENT_CONNECT;
	ev_timer_start(loop, &ctx->w_timeout);
	dialer_do(&ctx->dialer, loop, req, ctx->conf, ctx->resolver, NULL);
}

void http_client_cancel(struct http_client_ctx *ctx, struct ev_loop *loop)
{
	(void)loop;
	http_client_cleanup(ctx);
}
