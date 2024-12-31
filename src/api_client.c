/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_client.h"

#if WITH_RULESET

#include "conf.h"
#include "dialer.h"
#include "httputil.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "io/stream.h"
#include "net/http.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <strings.h>

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* never rollback */
enum api_client_state {
	STATE_CLIENT_CONNECT,
	STATE_CLIENT_REQUEST,
	STATE_CLIENT_RESPONSE,
};

struct api_client_ctx {
	struct session ss;
	enum api_client_state state;
	struct api_client_cb cb;
	struct ev_timer w_timeout;
	struct dialreq *dialreq;
	struct dialer dialer;
	struct ev_io w_socket;
	struct http_parser parser;
};
ASSERT_SUPER(struct session, struct api_client_ctx, ss);

static void api_client_close(
	struct ev_loop *restrict loop, struct api_client_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);
	if (ctx->state == STATE_CLIENT_CONNECT) {
		dialer_cancel(&ctx->dialer, loop);
	}
	if (ctx->dialreq != NULL) {
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
	}
	if (ctx->state >= STATE_CLIENT_REQUEST) {
		ev_io_stop(loop, &ctx->w_socket);
		CLOSE_FD(ctx->w_socket.fd);
	}
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	if (ctx->ss.close != NULL) {
		/* managed by session */
		session_del(&ctx->ss);
	}
	free(ctx);
}

static void
api_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct api_client_ctx *restrict ctx =
		DOWNCAST(struct session, struct api_client_ctx, ss, ss);
	api_client_close(loop, ctx);
}

static void api_client_finish(
	struct ev_loop *loop, struct api_client_ctx *restrict ctx, bool ok,
	const void *data, const size_t len)
{
	if (ctx->cb.func != NULL) {
		ctx->cb.func(ctx, loop, ctx->cb.data, ok, data, len);
	}
	if (ok) {
		stream_close((struct stream *)data);
	}
	api_client_close(loop, ctx);
}

#define API_RETURN_ERROR(loop, ctx, msg)                                       \
	do {                                                                   \
		api_client_finish(                                             \
			(loop), (ctx), false, (msg ""), sizeof(msg) - 1);      \
		return;                                                        \
	} while (false)

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct api_client_ctx *restrict ctx = watcher->data;
	int ret = http_parser_recv(&ctx->parser);
	if (ret < 0) {
		API_RETURN_ERROR(loop, ctx, "error receiving response");
	} else if (ret > 0) {
		return;
	}
	const struct http_message *restrict msg = &ctx->parser.msg;
	if (strcmp(msg->rsp.code, "200") == 0) {
		/* OK - get the results */
		if (!check_rpcall_mime(ctx->parser.hdr.content.type)) {
			API_RETURN_ERROR(loop, ctx, "unsupported content-type");
		}
	} else if (VBUF_LEN(ctx->parser.cbuf) > 0) {
		/* return content as error info */
		api_client_finish(
			loop, ctx, false, VBUF_DATA(ctx->parser.cbuf),
			VBUF_LEN(ctx->parser.cbuf));
		return;
	} else {
		/* HTTP error info */
		char buf[64];
		ret = snprintf(
			buf, sizeof(buf), "%s %s %s", msg->rsp.version,
			msg->rsp.code, msg->rsp.status);
		CHECK(ret > 0);
		api_client_finish(loop, ctx, false, buf, (size_t)ret);
		return;
	}
	struct stream *r = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (r == NULL) {
		LOGOOM();
		API_RETURN_ERROR(loop, ctx, "out of memory");
	}
	api_client_finish(loop, ctx, true, r, 0);
}

static void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	const int fd = watcher->fd;
	struct api_client_ctx *restrict ctx = watcher->data;
	struct http_parser *restrict p = &ctx->parser;
	const unsigned char *buf = p->wbuf.data + p->wpos;
	size_t len = p->wbuf.len - p->wpos;
	int err = socket_send(fd, buf, &len);
	if (err != 0) {
		const char *msg = strerror(err);
		api_client_finish(loop, ctx, false, msg, strlen(msg));
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
			api_client_finish(loop, ctx, false, msg, strlen(msg));
			return;
		}
		p->cpos += len;
		LOGV_F("send: fd=%d %zu/%zu bytes", fd, p->cpos, p->cbuf->len);
		if (p->cpos < cbuf->len) {
			return;
		}
		p->cbuf = VBUF_FREE(p->cbuf);
	}

	if (ctx->cb.func == NULL) {
		api_client_close(loop, ctx);
		return;
	}
	ev_io_stop(loop, watcher);

	ctx->state = STATE_CLIENT_RESPONSE;
	p->fd = fd;
	ev_io_set(watcher, fd, EV_READ);
	ev_set_cb(watcher, recv_cb);
	ev_io_start(loop, watcher);
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct api_client_ctx *restrict ctx = data;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		const int err = ctx->dialer.syserr;
		if (err != 0) {
			LOGD_F("unable to establish client connection: %s",
			       strerror(err));
		}
		API_RETURN_ERROR(loop, ctx, "failed connecting to server");
	}
	ASSERT(ctx->dialreq != NULL);
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	ctx->state = STATE_CLIENT_REQUEST;
	struct ev_io *restrict w_write = &ctx->w_socket;
	ev_io_init(w_write, send_cb, fd, EV_WRITE);
	w_write->data = ctx;
	ev_io_start(loop, w_write);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct api_client_ctx *restrict ctx = watcher->data;
	API_RETURN_ERROR(loop, ctx, "timeout");
}

static bool make_request(
	struct http_parser *restrict p, const char *uri, const char *content,
	const size_t len)
{
	const enum content_encodings encoding = CENCODING_DEFLATE;
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
		"Accept-Encoding: deflate\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: %s\r\n",
		uri, VBUF_LEN(p->cbuf), MIME_RPCALL);
	const char *encoding_str = content_encoding_str[encoding];
	if (encoding_str != NULL) {
		BUF_APPENDF(p->wbuf, "Content-Encoding: %s\r\n", encoding_str);
	}
	BUF_APPENDSTR(p->wbuf, "\r\n");
	LOG_TXT_F(
		VERYVERBOSE, (const char *)p->wbuf.data, p->wbuf.len,
		"request header: %zu bytes", p->wbuf.len);
	LOG_BIN_F(
		VERYVERBOSE, VBUF_DATA(p->cbuf), VBUF_LEN(p->cbuf),
		"request content: %zu bytes", VBUF_LEN(p->cbuf));
	return true;
}

static bool parse_header(void *ctx, const char *key, char *value)
{
	struct http_parser *restrict p =
		&((struct api_client_ctx *)ctx)->parser;

	/* hop-by-hop headers */
	if (strcasecmp(key, "Connection") == 0) {
		p->hdr.connection = strtrimspace(value);
		return true;
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		return parsehdr_transfer_encoding(p, value);
	}

	/* representation headers */
	if (strcasecmp(key, "Content-Length") == 0) {
		return parsehdr_content_length(p, value);
	}
	if (strcasecmp(key, "Content-Type") == 0) {
		p->hdr.content.type = strtrimspace(value);
		return true;
	}
	if (strcasecmp(key, "Content-Encoding") == 0) {
		return parsehdr_content_encoding(p, value);
	}

	LOGV_F("unknown http header: `%s' = `%s'", key, value);
	return true;
}

static struct api_client_ctx *api_client_do(
	struct ev_loop *loop, struct dialreq *req, const char *uri,
	const char *payload, const size_t len, struct api_client_cb client_cb)
{
	CHECK(len <= INT_MAX);
	struct api_client_ctx *restrict ctx =
		malloc(sizeof(struct api_client_ctx));
	if (ctx == NULL) {
		LOGOOM();
		dialreq_free(req);
		return NULL;
	}
	ctx->state = STATE_CLIENT_CONNECT;
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	http_parser_init(&ctx->parser, -1, STATE_PARSE_RESPONSE, on_header);
	if (!make_request(&ctx->parser, uri, payload, len)) {
		LOGOOM();
		api_client_close(loop, ctx);
		return NULL;
	}
	ctx->cb = client_cb;
	ev_timer_init(&ctx->w_timeout, timeout_cb, G.conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
	ctx->dialreq = req;
	const struct event_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, cb);
	if (ctx->cb.func != NULL) {
		/* managed by ruleset */
		ctx->ss.close = NULL;
	} else {
		/* managed by session */
		ctx->ss.close = api_ss_close;
		session_add(&ctx->ss);
	}

	ev_timer_start(loop, &ctx->w_timeout);
	dialer_start(&ctx->dialer, loop, req);
	if (client_cb.func == NULL) {
		return NULL;
	}
	return ctx;
}

void api_client_invoke(
	struct ev_loop *loop, struct dialreq *req, const char *payload,
	const size_t len)
{
	(void)api_client_do(
		loop, req, "/ruleset/invoke", payload, len,
		(struct api_client_cb){ NULL, NULL });
}

struct api_client_ctx *api_client_rpcall(
	struct ev_loop *loop, struct dialreq *req, const char *payload,
	const size_t len, const struct api_client_cb cb)
{
	ASSERT(cb.func != NULL);
	return api_client_do(loop, req, "/ruleset/rpcall", payload, len, cb);
}

void api_client_cancel(struct ev_loop *loop, struct api_client_ctx *ctx)
{
	api_client_close(loop, ctx);
}

#endif /* WITH_RULESET */
