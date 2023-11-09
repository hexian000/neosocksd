/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "http_impl.h"
#include "utils/minmax.h"
#include "utils/buffer.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "net/http.h"
#include "session.h"
#include "server.h"
#include "transfer.h"
#include "conf.h"
#include "dialer.h"
#include "util.h"

#include <ev.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

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
	case STATE_HEADER:
	case STATE_CONTENT:
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		dialer_cancel(&ctx->dialer, loop);
		free(ctx->dialreq);
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
	ctx->cbuf = VBUF_FREE(ctx->cbuf);
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
	http_ctx_close(loop, CAST(struct http_ctx, ss, ss));
}

void http_resp_errpage(struct http_ctx *restrict ctx, const uint16_t code)
{
	const size_t cap = ctx->wbuf.cap - ctx->wbuf.len;
	char *buf = (char *)(ctx->wbuf.data + ctx->wbuf.len);
	const int len = http_error(buf, cap, code);
	if (len <= 0) {
		/* can't generate error page, reply with code only */
		RESPHDR_WRITE(ctx->wbuf, code, "");
		return;
	}
	ctx->wbuf.len += len;
	LOGD_F("http: response error page %" PRIu16, code);
}

static bool reply_short(struct http_ctx *restrict ctx, const char *s)
{
	const size_t n = strlen(s);
	assert(n < 256);
	LOG_BIN_F(
		VERBOSE, s, n, "reply_short: fd=%d %zu bytes", ctx->accepted_fd,
		n);
	const ssize_t nsend = send(ctx->accepted_fd, s, n, 0);
	if (nsend < 0) {
		const int err = errno;
		HTTP_CTX_LOG_F(ERROR, ctx, "send: %s", strerror(err));
		return false;
	} else if ((size_t)nsend != n) {
		HTTP_CTX_LOG(ERROR, ctx, "send: short send");
		return false;
	}
	return true;
}

static bool
on_header(struct http_ctx *restrict ctx, const char *key, const char *value)
{
	HTTP_CTX_LOG_F(VERBOSE, ctx, "header \"%s: %s\"", key, value);
	if (strcasecmp(key, "Content-Length") == 0) {
		size_t content_length;
		if (sscanf(value, "%zu", &content_length) != 1) {
			http_resp_errpage(ctx, HTTP_BAD_REQUEST);
			return false;
		}
		if (strcmp(ctx->http.msg.req.method, "CONNECT") == 0) {
			http_resp_errpage(ctx, HTTP_BAD_REQUEST);
			return false;
		}
		if (content_length > HTTP_MAX_CONTENT) {
			http_resp_errpage(ctx, HTTP_ENTITY_TOO_LARGE);
			return false;
		}
		ctx->http.content_length = content_length;
	} else if (strcasecmp(key, "Expect") == 0) {
		if (strcasecmp(value, "100-continue") != 0) {
			http_resp_errpage(ctx, HTTP_EXPECTATION_FAILED);
			return false;
		}
		ctx->http.expect_continue = true;
	}
	return true;
}

static int parse_request(struct http_ctx *restrict ctx)
{
	switch (ctx->state) {
	case STATE_REQUEST:
	case STATE_HEADER:
	case STATE_CONTENT:
		break;
	case STATE_CONNECT:
		return -1;
	default:
		FAIL();
	}
	char *next = ctx->http.nxt;
	if (next == NULL) {
		next = (char *)ctx->rbuf.data;
		ctx->http.nxt = next;
	}
	struct http_message *restrict msg = &ctx->http.msg;
	if (ctx->state == STATE_REQUEST) {
		next = http_parse(next, msg);
		if (next == NULL) {
			HTTP_CTX_LOG(
				ERROR, ctx, "http: failed parsing request");
			return -1;
		} else if (next == ctx->http.nxt) {
			if (ctx->rbuf.len + 1 >= ctx->rbuf.cap) {
				http_resp_errpage(ctx, HTTP_ENTITY_TOO_LARGE);
				return 0;
			}
			return 1;
		}
		if (strncmp(msg->req.version, "HTTP/1.", 7) != 0) {
			HTTP_CTX_LOG_F(
				ERROR, ctx, "http: unsupported protocol %s",
				msg->req.version);
			return -1;
		}
		HTTP_CTX_LOG_F(
			VERBOSE, ctx, "request \"%s\" \"%s\" \"%s\"",
			msg->req.method, msg->req.url, msg->req.version);
		ctx->http.nxt = next;
		ctx->cbuf = NULL;
		ctx->state = STATE_HEADER;
	}
	while (ctx->state == STATE_HEADER) {
		char *key, *value;
		next = http_parsehdr(next, &key, &value);
		if (next == NULL) {
			HTTP_CTX_LOG(ERROR, ctx, "http: failed parsing header");
			return -1;
		} else if (next == ctx->http.nxt) {
			return 1;
		}
		ctx->http.nxt = next;
		if (key == NULL) {
			ctx->state = STATE_CONTENT;
			break;
		}

		/* save the header */
		if (!on_header(ctx, key, value)) {
			return 0;
		}
	}
	if (ctx->state == STATE_CONTENT && ctx->http.content_length > 0) {
		if (ctx->cbuf != NULL) {
			const size_t len = ctx->cbuf->len;
			if (len < ctx->http.content_length) {
				return 1;
			}
			ctx->cbuf->data[len] = '\0';
			return 0;
		}
		/* null terminated */
		ctx->cbuf = VBUF_NEW(ctx->http.content_length + 1);
		if (ctx->cbuf == NULL) {
			LOGOOM();
			return -1;
		}
		if (ctx->http.expect_continue) {
			if (!reply_short(ctx, "HTTP/1.1 100 Continue\r\n\r\n")) {
				return -1;
			}
		}
		const size_t offset =
			(unsigned char *)ctx->http.nxt - ctx->rbuf.data;
		const size_t len = ctx->rbuf.len - offset;
		memcpy(ctx->cbuf->data, ctx->http.nxt, len);
		ctx->cbuf->len = len;
		if (len < ctx->http.content_length) {
			return 1;
		}
		ctx->cbuf->data[len] = '\0';
	}
	return 0;
}

static int http_recv(struct http_ctx *restrict ctx)
{
	const int fd = ctx->accepted_fd;
	struct vbuffer *restrict rbuf = (struct vbuffer *)&ctx->rbuf;
	if (ctx->state == STATE_CONTENT) {
		rbuf = ctx->cbuf;
	}
	while (rbuf->len + 1 < rbuf->cap) {
		unsigned char *buf = rbuf->data + rbuf->len;
		const size_t n = rbuf->cap - rbuf->len - 1;
		const ssize_t nrecv = recv(fd, buf, n, 0);
		if (nrecv < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			HTTP_CTX_LOG_F(
				ERROR, ctx, "recv: fd=%d %s", fd,
				strerror(err));
			return -1;
		} else if (nrecv == 0) {
			/* connection is not established yet, we do not expect EOF here */
			HTTP_CTX_LOG_F(ERROR, ctx, "recv: fd=%d early EOF", fd);
			return -1;
		}
		rbuf->len += (size_t)nrecv;
	}
	rbuf->data[rbuf->len] = '\0';
	LOG_TXT_F(
		VERBOSE, rbuf->data, rbuf->len, "recv: fd=%d %zu bytes", fd,
		rbuf->len);
	return parse_request(ctx);
}

void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct http_ctx *restrict ctx = watcher->data;

	const int want = http_recv(ctx);
	if (want < 0) {
		http_ctx_close(loop, ctx);
		return;
	} else if (want > 0) {
		return;
	}
	ev_io_stop(loop, watcher);
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_request++;
	ctx->state = STATE_RESPONSE;
	ctx->handle(loop, ctx);
	if (ctx->state == STATE_RESPONSE) {
		ev_io_start(loop, &ctx->w_send);
	}
}

void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct http_ctx *restrict ctx = watcher->data;
	assert(ctx->state == STATE_RESPONSE || ctx->state == STATE_CONNECT);

	unsigned char *buf = ctx->wbuf.data;
	size_t len = ctx->wbuf.len;
	size_t nbsend = 0;
	while (len > 0) {
		const ssize_t nsend = send(watcher->fd, buf, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			HTTP_CTX_LOG_F(ERROR, ctx, "send: %s", strerror(err));
			http_ctx_close(loop, ctx);
			return;
		} else if (nsend == 0) {
			break;
		}
		buf += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	BUF_CONSUME(ctx->wbuf, nbsend);
	if (ctx->wbuf.len > 0) {
		return;
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
		HTTP_CTX_LOG(ERROR, ctx, "dialer failed");
		http_resp_errpage(ctx, HTTP_BAD_GATEWAY);
		ev_io_start(loop, &ctx->w_send);
		return;
	}
	ctx->dialed_fd = fd;
	BUF_APPENDCONST(
		ctx->wbuf, "HTTP/1.1 200 Connection established\r\n\r\n");
	ev_io_start(loop, &ctx->w_send);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
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
	ctx->http.nxt = NULL;
	ctx->http.content_length = 0;
	ctx->http.expect_continue = false;
	ctx->dialreq = NULL;
	struct event_cb cb = (struct event_cb){
		.cb = dialer_cb,
		.ctx = ctx,
	};
	dialer_init(&ctx->dialer, cb);
	ctx->cbuf = NULL;
	BUF_INIT(ctx->rbuf, 0);
	BUF_INIT(ctx->wbuf, 0);
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
