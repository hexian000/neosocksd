/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_server.h"
#include "conf.h"
#include "dialer.h"
#include "http_parser.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "transfer.h"
#include "util.h"

#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/object.h"
#include "utils/slog.h"

#include <ev.h>

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);

static void http_ctx_stop(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_REQUEST:
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		dialer_cancel(&ctx->dialer, loop);
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		stats->num_halfopen--;
		return;
	case STATE_CONNECTED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_halfopen--;
		break;
	case STATE_ESTABLISHED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_sessions--;
		break;
	}
	HTTP_CTX_LOG_F(INFO, ctx, "closed, %zu active", stats->num_sessions);
}

static void http_ctx_free(struct http_ctx *restrict ctx)
{
	if (ctx == NULL) {
		return;
	}
	assert(!ev_is_active(&ctx->w_timeout));
	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	session_del(&ctx->ss);
	free(ctx);
}

void http_ctx_close(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	HTTP_CTX_LOG_F(
		DEBUG, ctx, "close fd=%d state=%d", ctx->accepted_fd,
		ctx->state);
	http_ctx_stop(loop, ctx);
	http_ctx_free(ctx);
}

static void
http_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct http_ctx *restrict ctx =
		DOWNCAST(struct session, struct http_ctx, ss, ss);
	http_ctx_close(loop, ctx);
}

void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_ctx *restrict ctx = watcher->data;

	const int want = http_parser_recv(&ctx->parser);
	if (want < 0) {
		http_ctx_close(loop, ctx);
		return;
	}
	if (want > 0) {
		return;
	}
	switch (ctx->parser.state) {
	case STATE_PARSE_OK: {
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_request++;
		ctx->handle(loop, ctx);
		ctx->state = STATE_RESPONSE;
		ev_io_start(loop, &ctx->w_send);
	} break;
	case STATE_PARSE_ERROR:
		http_resp_errpage(&ctx->parser, ctx->parser.http_status);
		ctx->state = STATE_RESPONSE;
		ev_io_start(loop, &ctx->w_send);
		break;
	default:
		FAIL();
	}
}

void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	assert(ctx->state == STATE_RESPONSE || ctx->state == STATE_CONNECT);

	const unsigned char *buf = ctx->parser.wbuf.data + ctx->parser.wpos;
	size_t len = ctx->parser.wbuf.len - ctx->parser.wpos;
	int err = socket_send(watcher->fd, buf, &len);
	if (err != 0) {
		HTTP_CTX_LOG_F(ERROR, ctx, "send: %s", strerror(err));
		http_ctx_close(loop, ctx);
		return;
	}
	ctx->parser.wpos += len;
	if (ctx->parser.wpos < ctx->parser.wbuf.len) {
		return;
	}

	if (ctx->parser.cbuf != NULL) {
		const struct vbuffer *restrict cbuf = ctx->parser.cbuf;
		buf = cbuf->data + ctx->parser.cpos;
		len = cbuf->len - ctx->parser.cpos;
		err = socket_send(watcher->fd, buf, &len);
		if (err != 0) {
			HTTP_CTX_LOG_F(ERROR, ctx, "send: %s", strerror(err));
			http_ctx_close(loop, ctx);
			return;
		}
		ctx->parser.cpos += len;
		if (ctx->parser.cpos < cbuf->len) {
			return;
		}
	}

	if (ctx->state == STATE_CONNECT) {
		/* CONNECT proxy */
		http_ctx_hijack(loop, ctx);
		return;
	}
	/* Connection: close */
	http_ctx_close(loop, ctx);
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	assert(ctx->state == STATE_CONNECT);

	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		HTTP_CTX_LOG_F(
			ERROR, ctx, "unable to establish client connection: %s",
			strerror(ctx->dialer.syserr));
		http_resp_errpage(&ctx->parser, HTTP_BAD_GATEWAY);
		ev_io_start(loop, &ctx->w_send);
		return;
	}
	ctx->dialed_fd = fd;
	BUF_APPENDCONST(
		ctx->parser.wbuf,
		"HTTP/1.1 200 Connection established\r\n\r\n");
	ev_io_start(loop, &ctx->w_send);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_ctx *restrict ctx = watcher->data;
	http_ctx_close(loop, ctx);
}

static struct http_ctx *
http_ctx_new(struct server *restrict s, const int fd, http_handler_fn handler)
{
	struct http_ctx *restrict ctx = malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = s;
	ctx->state = STATE_INIT;
	ctx->handle = handler;
	ctx->accepted_fd = fd;
	ctx->dialed_fd = -1;

	{
		struct ev_timer *restrict w_timeout = &ctx->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, G.conf->timeout, 0.0);
		ev_set_priority(w_timeout, EV_MINPRI);
		w_timeout->data = ctx;
	}
	{
		struct ev_io *restrict w_recv = &ctx->w_recv;
		ev_io_init(w_recv, recv_cb, fd, EV_READ);
		w_recv->data = ctx;
	}
	{
		struct ev_io *restrict w_send = &ctx->w_send;
		ev_io_init(w_send, send_cb, fd, EV_WRITE);
		w_send->data = ctx;
	}
	const struct http_parsehdr_cb on_header = { NULL, NULL };
	http_parser_init(&ctx->parser, fd, STATE_PARSE_REQUEST, on_header);
	ctx->dialreq = NULL;
	const struct event_cb cb = {
		.cb = dialer_cb,
		.ctx = ctx,
	};
	dialer_init(&ctx->dialer, cb);
	ctx->ss.close = http_ss_close;
	session_add(&ctx->ss);
	return ctx;
}

static void http_ctx_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_start(loop, &ctx->w_timeout);

	ctx->state = STATE_REQUEST;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen++;
}

static void http_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa, http_handler_fn handler)
{
	struct http_ctx *restrict ctx = http_ctx_new(s, accepted_fd, handler);
	if (ctx == NULL) {
		LOGOOM();
		CLOSE_FD(accepted_fd);
		return;
	}
	(void)memcpy(
		&ctx->accepted_sa.sa, accepted_sa, getsocklen(accepted_sa));
	http_ctx_start(loop, ctx);
}

void http_proxy_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	http_serve(s, loop, accepted_fd, accepted_sa, http_handle_proxy);
}

void http_api_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	http_serve(s, loop, accepted_fd, accepted_sa, http_handle_api);
}
