/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_client.h"

#if WITH_RULESET

#include "conf.h"
#include "dialer.h"
#include "http_parser.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "io/stream.h"
#include "net/http.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* never rollback */
enum http_client_state {
	STATE_CLIENT_CONNECT,
	STATE_CLIENT_REQUEST,
	STATE_CLIENT_RESPONSE,
};

struct http_client_ctx {
	enum http_client_state state;
	struct http_client_cb invoke_cb;
	struct ev_timer w_timeout;
	struct dialreq *dialreq;
	struct dialer dialer;
	struct ev_io w_socket;
	struct http_parser parser;
};

static void http_client_close(
	struct ev_loop *restrict loop, struct http_client_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);
	if (ctx->state == STATE_CLIENT_CONNECT) {
		dialer_cancel(&ctx->dialer, loop);
		dialreq_free(ctx->dialreq);
	}
	if (ctx->state >= STATE_CLIENT_REQUEST) {
		ev_io_stop(loop, &ctx->w_socket);
		CLOSE_FD(ctx->w_socket.fd);
	}
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	free(ctx);
}

static void http_client_finish(
	struct ev_loop *loop, struct http_client_ctx *restrict ctx, bool ok,
	const void *data, const size_t len)
{
	if (ctx->invoke_cb.func != NULL) {
		ctx->invoke_cb.func(
			handle_make(ctx), loop, ctx->invoke_cb.ctx, ok, data,
			len);
		if (ok) {
			stream_close((struct stream *)data);
		}
	}
	http_client_close(loop, ctx);
}

#define HTTP_RETURN_ERROR(loop, ctx, msg)                                      \
	do {                                                                   \
		http_client_finish(                                            \
			(loop), (ctx), false, (msg ""), sizeof(msg) - 1);      \
		return;                                                        \
	} while (false)

static void
response_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_client_ctx *restrict ctx = watcher->data;
	int ret = http_parser_recv(&ctx->parser);
	if (ret < 0) {
		LOGD("error receiving response");
		HTTP_RETURN_ERROR(loop, ctx, "error receiving response");
	} else if (ret > 0) {
		return;
	}
	const struct http_message *restrict msg = &ctx->parser.msg;
	if (strcmp(msg->rsp.code, "200") != 0) {
		char buf[64];
		ret = snprintf(
			buf, sizeof(buf), "%s %s %s", msg->rsp.version,
			msg->rsp.code, msg->rsp.status);
		CHECK(ret > 0);
		http_client_finish(loop, ctx, false, buf, (size_t)ret);
		return;
	}
	if (!check_rpcall_mime(ctx->parser.hdr.content.type)) {
		HTTP_RETURN_ERROR(loop, ctx, "unsupported content-type");
	}
	struct stream *r = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (r == NULL) {
		LOGOOM();
		HTTP_RETURN_ERROR(loop, ctx, "out of memory");
	}
	http_client_finish(loop, ctx, true, r, 0);
}

static void
request_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	const int fd = watcher->fd;
	struct http_client_ctx *restrict ctx = watcher->data;
	struct http_parser *restrict p = &ctx->parser;
	const unsigned char *buf = p->wbuf.data + p->wpos;
	size_t len = p->wbuf.len - p->wpos;
	int err = socket_send(fd, buf, &len);
	if (err != 0) {
		const char *msg = strerror(err);
		http_client_finish(loop, ctx, false, msg, strlen(msg));
		return;
	}
	p->wpos += len;
	LOGV_F("send: fd=%d %zu/%zu bytes", fd, p->wpos, p->wbuf.len);
	if (p->wpos < p->wbuf.len) {
		return;
	}

	if (p->cbuf != NULL) {
		const struct vbuffer *restrict cbuf = p->cbuf;
		buf = cbuf->data + p->cpos;
		len = cbuf->len - p->cpos;
		err = socket_send(watcher->fd, buf, &len);
		if (err != 0) {
			const char *msg = strerror(err);
			http_client_finish(loop, ctx, false, msg, strlen(msg));
			return;
		}
		p->cpos += len;
		LOGV_F("send: fd=%d %zu/%zu bytes", fd, p->cpos, p->cbuf->len);
		if (p->cpos < cbuf->len) {
			return;
		}
		p->cbuf = VBUF_FREE(p->cbuf);
	}

	if (ctx->invoke_cb.func == NULL) {
		http_client_close(loop, ctx);
		return;
	}
	ev_io_stop(loop, watcher);

	ctx->state = STATE_CLIENT_RESPONSE;
	p->fd = fd;
	ev_io_set(watcher, fd, EV_READ);
	ev_set_cb(watcher, response_read_cb);
	ev_io_start(loop, watcher);
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct http_client_ctx *restrict ctx = data;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		LOGE_F("unable to establish client connection: %s",
		       strerror(ctx->dialer.syserr));
		HTTP_RETURN_ERROR(loop, ctx, "failed connecting to server");
	}
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	ctx->state = STATE_CLIENT_REQUEST;
	struct ev_io *restrict w_write = &ctx->w_socket;
	ev_io_init(w_write, request_write_cb, fd, EV_WRITE);
	w_write->data = ctx;
	ev_io_start(loop, w_write);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_client_ctx *restrict ctx = watcher->data;
	HTTP_RETURN_ERROR(loop, ctx, "timeout");
}

static bool make_request(
	struct http_parser *restrict p, const char *uri, const char *content,
	const size_t len)
{
	const enum content_encodings encoding =
		(len > RPCALL_COMPRESS_THRESHOLD) ? CENCODING_DEFLATE :
						    CENCODING_NONE;
	struct stream *s = content_writer(&p->cbuf, len, encoding);
	if (s == NULL) {
		return false;
	}
	size_t n = len;
	const int err1 = stream_write(s, content, &n);
	const int err2 = stream_close(s);
	if (p->cbuf == NULL || err1 != 0 || n != len || err2 != 0) {
		return false;
	}
	BUF_APPENDF(
		p->wbuf,
		"POST %s HTTP/1.1\r\n"
		"Accept: %s\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: %s\r\n"
		"Accept-Encoding: deflate\r\n",
		uri, MIME_RPCALL, VBUF_LEN(p->cbuf), MIME_RPCALL);
	const char *encoding_str = content_encoding_str[encoding];
	if (encoding_str != NULL) {
		BUF_APPENDF(p->wbuf, "Content-Encoding: %s\r\n", encoding_str);
	}
	BUF_APPENDCONST(p->wbuf, "\r\n");
	LOG_TXT_F(
		VERYVERBOSE, p->wbuf.data, p->wbuf.len,
		"request header: %zu bytes", p->wbuf.len);
	LOG_BIN_F(
		VERYVERBOSE, VBUF_DATA(p->cbuf), VBUF_LEN(p->cbuf),
		"request content: %zu bytes", VBUF_LEN(p->cbuf));
	return true;
}

handle_type http_client_do(
	struct ev_loop *loop, struct dialreq *req, const char *uri,
	const char *content, const size_t len, struct http_client_cb client_cb)
{
	CHECK(len <= INT_MAX);
	struct http_client_ctx *restrict ctx =
		malloc(sizeof(struct http_client_ctx));
	if (ctx == NULL) {
		LOGOOM();
		dialreq_free(req);
		return INVALID_HANDLE;
	}
	ctx->state = STATE_CLIENT_CONNECT;
	const struct http_parsehdr_cb on_header = { NULL, NULL };
	http_parser_init(&ctx->parser, -1, STATE_PARSE_RESPONSE, on_header);
	if (!make_request(&ctx->parser, uri, content, len)) {
		LOGOOM();
		http_client_close(loop, ctx);
		return INVALID_HANDLE;
	}
	ctx->invoke_cb = client_cb;
	ev_timer_init(&ctx->w_timeout, timeout_cb, G.conf->timeout, 0.0);
	ev_set_priority(&ctx->w_timeout, EV_MINPRI);
	ctx->w_timeout.data = ctx;
	ctx->dialreq = req;
	const struct event_cb cb = {
		.cb = dialer_cb,
		.ctx = ctx,
	};
	dialer_init(&ctx->dialer, cb);

	ev_timer_start(loop, &ctx->w_timeout);
	dialer_start(&ctx->dialer, loop, req);
	return handle_make(ctx);
}

void http_client_cancel(struct ev_loop *loop, const handle_type h)
{
	http_client_close(loop, handle_toptr(h));
}

#endif /* WITH_RULESET */
