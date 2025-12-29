/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
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
#include "utils/intcast.h"
#include "utils/slog.h"

#include <ev.h>
#include <strings.h>

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* State machine progression - never rollback to previous states */
enum api_client_state {
	STATE_CLIENT_INIT,
	STATE_CLIENT_CONNECT,
	STATE_CLIENT_REQUEST,
	STATE_CLIENT_RESPONSE,
	STATE_CLIENT_PROCESS,
};

struct api_client_ctx {
	struct session ss;
	enum api_client_state state;
	struct api_client_cb cb;
	ev_timer w_timeout;
	ev_io w_socket;
	ev_idle w_ruleset;
	struct dialreq *dialreq;
	struct dialer dialer;
	struct http_parser parser;
	struct {
		const char *errmsg;
		size_t errlen;
		struct stream *stream;
	} result;
};
ASSERT_SUPER(struct session, struct api_client_ctx, ss);

static void
api_client_stop(struct ev_loop *loop, struct api_client_ctx *restrict ctx)
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
	case STATE_CLIENT_PROCESS:
		ev_idle_stop(loop, &ctx->w_ruleset);
		break;
	default:
		FAIL();
	}
}

static void
api_client_close(struct ev_loop *loop, struct api_client_ctx *restrict ctx)
{
	api_client_stop(loop, ctx);
	if (ctx->w_socket.fd != -1) {
		CLOSE_FD(ctx->w_socket.fd);
	}
	if (ctx->result.stream != NULL) {
		stream_close(ctx->result.stream);
		ctx->result.stream = NULL;
	}

	if (ctx->ss.close != NULL) {
		/* managed by session */
		session_del(&ctx->ss);
	}
	dialreq_free(ctx->dialreq);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	free(ctx);
}

static void
api_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct api_client_ctx *restrict ctx =
		DOWNCAST(struct session, struct api_client_ctx, ss, ss);
	api_client_close(loop, ctx);
}

static void
process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct api_client_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_CLIENT_PROCESS);

	if (ctx->cb.func != NULL) {
		ctx->cb.func(
			ctx, loop, ctx->cb.data, ctx->result.errmsg,
			ctx->result.errlen, ctx->result.stream);
	}
	if (ctx->result.stream != NULL) {
		stream_close(ctx->result.stream);
		ctx->result.stream = NULL;
	}
	api_client_close(loop, ctx);
}

static void api_client_finish(
	struct ev_loop *loop, struct api_client_ctx *restrict ctx,
	const char *errmsg, const size_t errlen, struct stream *stream)
{
	ctx->result.errmsg = errmsg;
	ctx->result.errlen = errlen;
	ctx->result.stream = stream;

	api_client_stop(loop, ctx);
	ctx->state = STATE_CLIENT_PROCESS;
	ev_idle_start(loop, &ctx->w_ruleset);
}

#define API_RETURN_ERROR(loop, ctx, msg)                                       \
	do {                                                                   \
		api_client_finish(                                             \
			(loop), (ctx), (msg ""), sizeof(msg) - 1, NULL);       \
		return;                                                        \
	} while (false)

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct api_client_ctx *restrict ctx = watcher->data;
	int ret = http_parser_recv(&ctx->parser);
	if (ret < 0) {
		API_RETURN_ERROR(loop, ctx, "error receiving response");
	}
	if (ret > 0) {
		return;
	}
	const struct http_message *restrict msg = &ctx->parser.msg;
	uint16_t code = 0;
	{
		const uintmax_t status = strtoumax(msg->rsp.code, NULL, 10);
		if (UINTCAST_CHECK(code, status)) {
			code = status;
		}
	}
	if (code == HTTP_OK) {
		/* Success - validate content type for RPC response */
		if (!check_rpcall_mime(ctx->parser.hdr.content.type)) {
			API_RETURN_ERROR(loop, ctx, "unsupported content-type");
		}
	} else if (
		VBUF_LEN(ctx->parser.cbuf) > 0 &&
		check_rpcall_mime(ctx->parser.hdr.content.type)) {
		/* Server returned structured error in RPC format */
		api_client_finish(
			loop, ctx, VBUF_DATA(ctx->parser.cbuf),
			VBUF_LEN(ctx->parser.cbuf), NULL);
		return;
	} else {
		/* Generic HTTP error response */
		char buf[64];
		ret = snprintf(
			buf, sizeof(buf), "%s %s %s", msg->rsp.version,
			msg->rsp.code, msg->rsp.status);
		ASSERT(ret > 0);
		api_client_finish(loop, ctx, buf, (size_t)ret, NULL);
		return;
	}
	struct stream *r = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (r == NULL) {
		LOGOOM();
		API_RETURN_ERROR(loop, ctx, "out of memory");
	}
	api_client_finish(loop, ctx, NULL, 0, r);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
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
		api_client_finish(loop, ctx, msg, strlen(msg), NULL);
		return;
	}
	p->wpos += len;
	LOGV_F("send: fd=%d %zu/%zu bytes", fd, p->wpos, p->wbuf.len);
	if (p->wpos < p->wbuf.len) {
		return;
	}

	/* Send request body after headers are fully sent */
	if (p->cbuf != NULL) {
		const struct vbuffer *restrict cbuf = p->cbuf;
		buf = cbuf->data + p->cpos;
		len = cbuf->len - p->cpos;
		err = socket_send(fd, buf, &len);
		if (err != 0) {
			const char *msg = strerror(err);
			api_client_finish(loop, ctx, msg, strlen(msg), NULL);
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
		/* It's a fire-and-forget invoke call - no response expected */
		api_client_close(loop, ctx);
		return;
	}
	ev_io_stop(loop, watcher);

	/* Switch to receiving response */
	ctx->state = STATE_CLIENT_RESPONSE;
	p->fd = fd;
	ev_set_cb(watcher, recv_cb);
	ev_io_set(watcher, fd, EV_READ);
	ev_io_start(loop, watcher);
}

static void dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct api_client_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CLIENT_CONNECT);
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
	ev_io *restrict w_send = &ctx->w_socket;
	ev_set_cb(w_send, send_cb);
	w_send->data = ctx;
	ev_io_set(w_send, fd, EV_WRITE);
	ev_io_start(loop, w_send);
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct api_client_ctx *restrict ctx = watcher->data;
	API_RETURN_ERROR(loop, ctx, "timeout");
}

static bool make_request(
	struct http_parser *restrict p, const char *restrict uri,
	const void *restrict content, const size_t len)
{
	/* Compress large payloads to reduce traffic */
	const enum content_encodings encoding =
		(len < RPCALL_COMPRESS_THRESHOLD) ? CENCODING_NONE :
						    CENCODING_DEFLATE;
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
		p->hdr.connection = value;
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
		p->hdr.content.type = value;
		return true;
	}
	if (strcasecmp(key, "Content-Encoding") == 0) {
		return parsehdr_content_encoding(p, value);
	}

	LOGV_F("unknown http header: `%s' = `%s'", key, value);
	return true;
}

static bool api_client_do(
	struct ev_loop *loop, struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const char *restrict uri,
	const void *restrict payload, const size_t len,
	const struct api_client_cb *restrict in_cb)
{
	CHECK(len <= INT_MAX);
	struct api_client_ctx *restrict ctx =
		malloc(sizeof(struct api_client_ctx));
	if (ctx == NULL) {
		LOGOOM();
		dialreq_free(req);
		return false;
	}
	ctx->state = STATE_CLIENT_INIT;
	ctx->dialreq = req;
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	http_parser_init(&ctx->parser, -1, STATE_PARSE_RESPONSE, on_header);
	if (!make_request(&ctx->parser, uri, payload, len)) {
		LOGOOM();
		api_client_close(loop, ctx);
		return false;
	}
	ctx->cb = *in_cb;
	ev_timer_init(&ctx->w_timeout, timeout_cb, G.conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
	ev_idle_init(&ctx->w_ruleset, process_cb);
	ctx->w_ruleset.data = ctx;
	ev_io_init(&ctx->w_socket, NULL, -1, EV_NONE);
	ctx->w_socket.data = ctx;
	ctx->result.errmsg = NULL;
	ctx->result.errlen = 0;
	ctx->result.stream = NULL;
	const struct dialer_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, &cb);
	if (ctx->cb.func != NULL) {
		/* RPC call - lifecycle managed by ruleset callback */
		ctx->ss.close = NULL;
	} else {
		/* Invoke call - lifecycle managed by session system */
		ctx->ss.close = api_ss_close;
		session_add(&ctx->ss);
	}

	ev_timer_start(loop, &ctx->w_timeout);
	if (pctx != NULL) {
		*pctx = ctx;
	}
	ctx->state = STATE_CLIENT_CONNECT;
	dialer_do(&ctx->dialer, loop, req);
	return true;
}

void api_client_invoke(
	struct ev_loop *loop, struct dialreq *req, const void *payload,
	const size_t len)
{
	(void)api_client_do(
		loop, NULL, req, "/ruleset/invoke", payload, len,
		&(struct api_client_cb){ NULL, NULL });
}

bool api_client_rpcall(
	struct ev_loop *loop, struct api_client_ctx **pctx, struct dialreq *req,
	const void *payload, const size_t len, const struct api_client_cb *cb)
{
	ASSERT(cb->func != NULL);
	return api_client_do(
		loop, pctx, req, "/ruleset/rpcall", payload, len, cb);
}

void api_client_cancel(struct ev_loop *loop, struct api_client_ctx *ctx)
{
	api_client_close(loop, ctx);
}

#endif /* WITH_RULESET */
