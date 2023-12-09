/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "http_impl.h"
#include "utils/minmax.h"
#include "utils/buffer.h"
#include "utils/slog.h"
#include "utils/debug.h"
#include "utils/object.h"
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
	case STATE_HANDLE:
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
	struct http_ctx *restrict ctx =
		DOWNCAST(struct session, struct http_ctx, ss, ss);
	http_ctx_close(loop, ctx);
}

void http_resp_errpage(struct http_ctx *restrict ctx, const uint16_t code)
{
	ctx->wbuf.len = 0;
	ctx->cbuf = VBUF_FREE(ctx->cbuf);
	const size_t cap = ctx->wbuf.cap - ctx->wbuf.len;
	char *buf = (char *)(ctx->wbuf.data + ctx->wbuf.len);
	const int len = http_error(buf, cap, code);
	if (len <= 0) {
		/* can't generate error page, reply with code only */
		RESPHDR_BEGIN(ctx->wbuf, code);
		RESPHDR_FINISH(ctx->wbuf);
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

static int
on_header(struct http_ctx *restrict ctx, const char *key, char *value)
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
		ctx->http.content_length = content_length;
	} else if (strcasecmp(key, "Content-Type") == 0) {
		ctx->http.content_type = value;
	} else if (strcasecmp(key, "Content-Encoding") == 0) {
		if (strcasecmp(value, "deflate") == 0) {
			ctx->http.content_encoding = CENCODING_DEFLATE;
			return true;
		}
		if (strcasecmp(value, "gzip") == 0) {
			ctx->http.content_encoding = CENCODING_GZIP;
			return true;
		}
		http_resp_errpage(ctx, HTTP_UNSUPPORTED_MEDIA_TYPE);
		return false;
	} else if (strcasecmp(key, "Accept-Encoding") == 0) {
		if (strcmp(value, "*") == 0) {
			ctx->http.accept_encoding = CENCODING_DEFLATE;
			return true;
		}
		char *suffix = strchr(value, ';');
		if (suffix != NULL) {
			*suffix = '\0';
		}
		for (char *token = strtok(value, ", "); token != NULL;
		     token = strtok(NULL, ", ")) {
			if (strcasecmp(token, "deflate") != 0) {
				ctx->http.accept_encoding = CENCODING_DEFLATE;
			}
		}
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
	char *next = ctx->http.nxt;
	if (next == NULL) {
		next = (char *)ctx->rbuf.data;
		ctx->http.nxt = next;
	}
	struct http_message *restrict msg = &ctx->http.msg;
	next = http_parse(next, msg);
	if (next == NULL) {
		HTTP_CTX_LOG(DEBUG, ctx, "http: failed parsing request");
		return -1;
	} else if (next == ctx->http.nxt) {
		if (ctx->rbuf.len + 1 >= ctx->rbuf.cap) {
			http_resp_errpage(ctx, HTTP_ENTITY_TOO_LARGE);
			ctx->state = STATE_RESPONSE;
			return 0;
		}
		return 1;
	}
	if (strncmp(msg->req.version, "HTTP/1.", 7) != 0) {
		HTTP_CTX_LOG_F(
			DEBUG, ctx, "http: unsupported protocol %s",
			msg->req.version);
		return -1;
	}
	HTTP_CTX_LOG_F(
		VERBOSE, ctx, "request \"%s\" \"%s\" \"%s\"", msg->req.method,
		msg->req.url, msg->req.version);
	ctx->http.nxt = next;
	ctx->state = STATE_HEADER;
	return 0;
}

static int parse_header(struct http_ctx *restrict ctx)
{
	char *next = ctx->http.nxt;
	for (;;) {
		char *key, *value;
		next = http_parsehdr(next, &key, &value);
		if (next == NULL) {
			HTTP_CTX_LOG(DEBUG, ctx, "http: failed parsing header");
			return -1;
		} else if (next == ctx->http.nxt) {
			return 1;
		}
		ctx->http.nxt = next;
		if (key == NULL) {
			ctx->cbuf = NULL;
			ctx->state = STATE_CONTENT;
			break;
		}

		/* save the header */
		if (!on_header(ctx, key, value)) {
			ctx->state = STATE_RESPONSE;
			return 0;
		}
	}
	return 0;
}

static int parse_content(struct http_ctx *restrict ctx)
{
	if (ctx->http.content_length > HTTP_MAX_CONTENT) {
		http_resp_errpage(ctx, HTTP_ENTITY_TOO_LARGE);
		ctx->state = STATE_RESPONSE;
		return 0;
	}
	if (ctx->cbuf == NULL) {
		ctx->cbuf = VBUF_NEW(ctx->http.content_length + 1);
		if (ctx->cbuf == NULL) {
			LOGOOM();
			return -1;
		}
		const size_t pos =
			(unsigned char *)ctx->http.nxt - ctx->rbuf.data;
		const size_t len = ctx->rbuf.len - pos;
		memcpy(ctx->cbuf->data, ctx->http.nxt, len);
		ctx->cbuf->len = len;
		if (ctx->http.expect_continue) {
			if (!reply_short(ctx, "HTTP/1.1 100 Continue\r\n\r\n")) {
				return -1;
			}
		}
	}
	if (ctx->cbuf->len < ctx->http.content_length) {
		return 1;
	}
	ctx->state = STATE_HANDLE;
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
	LOGV_F("recv: fd=%d total %zu bytes", fd, rbuf->len);

	for (;;) {
		int ret;
		switch (ctx->state) {
		case STATE_REQUEST:
			ret = parse_request(ctx);
			if (ret != 0) {
				return ret;
			}
			break;
		case STATE_HEADER:
			ret = parse_header(ctx);
			if (ret != 0) {
				return ret;
			}
			break;
		case STATE_CONTENT:
			return parse_content(ctx);
		default:
			return 0;
		}
	}
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
	if (ctx->state == STATE_HANDLE) {
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_request++;
		ctx->handle(loop, ctx);
		ctx->state = STATE_RESPONSE;
	}
	if (ctx->state == STATE_RESPONSE) {
		ev_io_start(loop, &ctx->w_send);
	}
}

static int
send_as_much(const int fd, const unsigned char *buf, size_t *restrict len)
{
	size_t nbsend = 0;
	size_t n = *len;
	while (n > 0) {
		const ssize_t nsend = send(fd, buf, n, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			*len = nbsend;
			return err;
		} else if (nsend == 0) {
			break;
		}
		buf += nsend;
		n -= nsend;
		nbsend += nsend;
	}
	*len = nbsend;
	return 0;
}

void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct http_ctx *restrict ctx = watcher->data;
	assert(ctx->state == STATE_RESPONSE || ctx->state == STATE_CONNECT);

	const unsigned char *buf = ctx->wbuf.data + ctx->wpos;
	size_t len = ctx->wbuf.len - ctx->wpos;
	const int err = send_as_much(watcher->fd, buf, &len);
	if (err != 0) {
		HTTP_CTX_LOG_F(ERROR, ctx, "send: %s", strerror(err));
		http_ctx_close(loop, ctx);
		return;
	}
	ctx->wpos += len;
	if (ctx->wpos < ctx->wbuf.len) {
		return;
	}

	if (ctx->cbuf != NULL) {
		const struct vbuffer *restrict cbuf = ctx->cbuf;
		buf = cbuf->data + ctx->cpos;
		len = cbuf->len - ctx->cpos;
		const int err = send_as_much(watcher->fd, buf, &len);
		if (err != 0) {
			HTTP_CTX_LOG_F(ERROR, ctx, "send: %s", strerror(err));
			http_ctx_close(loop, ctx);
			return;
		}
		ctx->cpos += len;
		if (ctx->cpos < cbuf->len) {
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
		HTTP_CTX_LOG(
			DEBUG, ctx, "unable to establish client connection");
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
	ctx->http = (struct httpreq){ 0 };
	ctx->dialreq = NULL;
	struct event_cb cb = (struct event_cb){
		.cb = dialer_cb,
		.ctx = ctx,
	};
	dialer_init(&ctx->dialer, cb);
	ctx->wpos = ctx->cpos = 0;
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
