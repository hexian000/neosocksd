/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "conf.h"
#include "session.h"
#include "util.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/slog.h"
#include "net/http.h"
#include "dialer.h"

#include <ev.h>
#include <strings.h>

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <string.h>

#define HTTP_MAX_ENTITY 8192
#define HTTP_MAX_CONTENT 4194304

/* never rollback */
enum http_client_state {
	STATE_INIT,
	STATE_CONNECT,
	STATE_REQUEST,
	STATE_RESPONSE,
	STATE_HEADER,
	STATE_CONTENT,
};

struct httprsp {
	struct http_message msg;
	char *nxt;
	size_t content_length;
	const char *content_type;
	const char *content_encoding;
};

struct http_client_ctx {
	int state;
	struct http_client_cb invoke_cb;
	struct ev_timer w_timeout;
	union {
		struct {
			struct dialreq *dialreq;
			struct dialer dialer;
		};
		struct {
			struct ev_io w_socket;
			struct httprsp http;
		};
	};
	struct vbuffer *rbuf, *wbuf;
};

static void http_client_close(
	struct ev_loop *restrict loop, struct http_client_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);
	if (ctx->state == STATE_CONNECT) {
		dialer_cancel(&ctx->dialer, loop);
	}
	if (ctx->state >= STATE_REQUEST) {
		ev_io_stop(loop, &ctx->w_socket);
		CLOSE_FD(ctx->w_socket.fd);
	}
	ctx->wbuf = VBUF_FREE(ctx->wbuf);
	if (ctx->state >= STATE_RESPONSE) {
		ctx->rbuf = VBUF_FREE(ctx->rbuf);
	}
	free(ctx);
}

static void http_client_finish(
	struct ev_loop *loop, struct http_client_ctx *restrict ctx, bool ok,
	const void *data, const size_t len)
{
	if (ctx->invoke_cb.func != NULL) {
		ctx->invoke_cb.func(
			TO_HANDLE(ctx), loop, ctx->invoke_cb.ctx, ok, data,
			len);
	}
	http_client_close(loop, ctx);
}

#define HTTP_CLIENT_ERROR(loop, ctx, msg)                                      \
	http_client_finish((loop), (ctx), false, (msg ""), sizeof(msg) - 1)

static void
request_write_cb(struct ev_loop *loop, struct http_client_ctx *restrict ctx)
{
	struct ev_io *restrict watcher = &ctx->w_socket;
	const int fd = ctx->w_socket.fd;
	struct vbuffer *restrict wbuf = ctx->wbuf;
	unsigned char *buf = wbuf->data;
	size_t len = wbuf->len;
	size_t nbsend = 0;
	while (len > 0) {
		const ssize_t nsend = send(fd, buf, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("send: %s", strerror(err));
			ev_io_stop(loop, watcher);
			ctx->wbuf = VBUF_FREE(wbuf);
			free(ctx);
			return;
		}
		buf += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	VBUF_CONSUME(wbuf, nbsend);
	if (wbuf->len > 0) {
		return;
	}

	if (ctx->invoke_cb.func == NULL) {
		http_client_close(loop, ctx);
		return;
	}
	ev_io_stop(loop, watcher);

	ctx->state = STATE_RESPONSE;
	ctx->rbuf = VBUF_NEW(HTTP_MAX_ENTITY);
	if (ctx->rbuf == NULL) {
		HTTP_CLIENT_ERROR(loop, ctx, "out of memory");
		return;
	}
	ctx->http = (struct httprsp){ 0 };
	ev_io_set(watcher, fd, EV_READ);
	ev_io_start(loop, watcher);
}

static bool on_header(
	struct http_client_ctx *restrict ctx, const char *key,
	const char *value)
{
	LOGV_F("header \"%s: %s\"", key, value);
	if (strcasecmp(key, "Content-Length") == 0) {
		size_t content_length;
		if (sscanf(value, "%zu", &content_length) != 1) {
			return false;
		}
		if (content_length > HTTP_MAX_CONTENT) {
			return false;
		}
		ctx->http.content_length = content_length;
	} else if (strcasecmp(key, "Content-Type") == 0) {
		ctx->http.content_type = value;
	} else if (strcasecmp(key, "Content-Encoding") == 0) {
		ctx->http.content_encoding = value;
	}
	return true;
}

static int parse_response(struct http_client_ctx *restrict ctx)
{
	switch (ctx->state) {
	case STATE_RESPONSE:
	case STATE_HEADER:
	case STATE_CONTENT:
		break;
	default:
		FAIL();
	}
	struct vbuffer *restrict rbuf = ctx->rbuf;
	assert(rbuf->len < rbuf->cap);
	rbuf->data[rbuf->len] = '\0';
	char *next = ctx->http.nxt;
	if (next == NULL) {
		next = (char *)rbuf->data;
		ctx->http.nxt = next;
	}
	struct http_message *restrict msg = &ctx->http.msg;
	if (ctx->state == STATE_RESPONSE) {
		next = http_parse(next, msg);
		if (next == NULL) {
			LOGD("http: failed parsing response");
			return -1;
		} else if (next == ctx->http.nxt) {
			if (rbuf->len + 1 >= rbuf->cap) {
				LOGD("http: response too large");
				return -1;
			}
			return 1;
		}
		if (strncmp(msg->rsp.version, "HTTP/1.", 7) != 0) {
			LOGD_F("http: unsupported protocol %s",
			       msg->req.version);
			return -1;
		}
		LOGV_F("request \"%s\" \"%s\" \"%s\"", msg->req.method,
		       msg->req.url, msg->req.version);
		ctx->http.nxt = next;
		ctx->state = STATE_HEADER;
	}
	while (ctx->state == STATE_HEADER) {
		char *key, *value;
		next = http_parsehdr(next, &key, &value);
		if (next == NULL) {
			LOGD("http: failed parsing header");
			return -1;
		} else if (next == ctx->http.nxt) {
			return 1;
		}
		ctx->http.nxt = next;
		if (key == NULL) {
			if (ctx->http.content_type == NULL ||
			    strcasecmp(ctx->http.content_type, MIME_RPCALL) !=
				    0) {
				LOGD_F("rpcall: invalid content type \"%s\"",
				       ctx->http.content_type);
				return -1;
			}
			ctx->state = STATE_CONTENT;
			break;
		}
		if (!on_header(ctx, key, value)) {
			LOGD_F("http: invalid header \"%s: %s\"", key, value);
			return -1;
		}
	}
	if (ctx->state == STATE_CONTENT) {
		const size_t offset =
			(size_t)((unsigned char *)next - rbuf->data);
		size_t cap = HTTP_MAX_ENTITY + HTTP_MAX_CONTENT;
		if (ctx->http.content_length > 0) {
			if (rbuf->len >= offset + ctx->http.content_length) {
				return 0;
			}
			cap = offset + ctx->http.content_length + 1;
		} else {
			LOGW("rpcall: no content length");
		}
		if (rbuf->len < cap) {
			ctx->rbuf = rbuf = VBUF_RESERVE(rbuf, cap);
		}
		if (rbuf->cap <= rbuf->len) {
			LOGE_F("http_client: buffer is full (%zu/%zu)",
			       rbuf->len, rbuf->cap);
			return -1;
		}
		return 1;
	}
	return 0;
}

static void
response_read_cb(struct ev_loop *loop, struct http_client_ctx *restrict ctx)
{
	bool eof = false;
	const int fd = ctx->w_socket.fd;
	struct vbuffer *restrict rbuf = ctx->rbuf;
	while (rbuf->len + 1 < rbuf->cap) {
		unsigned char *buf = rbuf->data + rbuf->len;
		const size_t n = rbuf->cap - rbuf->len - 1;
		const ssize_t nrecv = recv(fd, buf, n, 0);
		if (nrecv < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				return;
			}
			const char *s = strerror(err);
			http_client_finish(loop, ctx, false, s, strlen(s));
			return;
		} else if (nrecv == 0) {
			eof = true;
			break;
		}
		rbuf->len += (size_t)nrecv;
	}
	LOG_TXT_F(
		VERBOSE, rbuf->data, rbuf->len, "recv: fd=%d %zu bytes", fd,
		rbuf->len);

	const int ret = parse_response(ctx);
	if (ret < 0) {
		HTTP_CLIENT_ERROR(loop, ctx, "invalid response");
		return;
	} else if (ret > 0 && eof) {
		HTTP_CLIENT_ERROR(loop, ctx, "early EOF");
		return;
	}
	const char *code = ctx->http.msg.rsp.code;
	const void *content = ctx->http.nxt;
	size_t len = ctx->http.content_length;
	if (len == 0) {
		len = ctx->rbuf->len - ((unsigned char *)ctx->http.nxt -
					(unsigned char *)ctx->rbuf->data);
	}
	LOG_BIN_F(VERBOSE, content, len, "content: %zu bytes", len);
	if (strcmp(code, "200") == 0) {
		http_client_finish(loop, ctx, true, content, len);
		return;
	}
	if (strcmp(code, "500") == 0) {
		http_client_finish(loop, ctx, false, content, len);
		return;
	}
	char buf[64];
	len = snprintf(
		buf, sizeof(buf), "%s %s %s", ctx->http.msg.rsp.version, code,
		ctx->http.msg.rsp.status);
	http_client_finish(loop, ctx, false, buf, len);
}

static void socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct http_client_ctx *restrict ctx = watcher->data;
	if (revents & EV_WRITE) {
		request_write_cb(loop, ctx);
	}
	if (revents & EV_READ) {
		response_read_cb(loop, ctx);
	}
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct http_client_ctx *restrict ctx = data;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		HTTP_CLIENT_ERROR(loop, ctx, "failed connecting to server");
		return;
	}
	dialreq_free(ctx->dialreq);

	ctx->state = STATE_REQUEST;
	struct ev_io *restrict w_write = &ctx->w_socket;
	ev_io_init(w_write, socket_cb, fd, EV_WRITE);
	w_write->data = ctx;
	ev_io_start(loop, w_write);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct http_client_ctx *restrict ctx = watcher->data;
	HTTP_CLIENT_ERROR(loop, ctx, "timeout");
}

handle_t http_client_do(
	struct ev_loop *loop, struct dialreq *req, const char *uri,
	const char *content, const size_t len, struct http_client_cb client_cb)
{
	CHECK(len <= INT_MAX);
	struct http_client_ctx *restrict ctx =
		malloc(sizeof(struct http_client_ctx));
	if (ctx == NULL) {
		LOGOOM();
		free(req);
		return INVALID_HANDLE;
	}
	ctx->wbuf = VBUF_APPENDF(
		NULL,
		"POST %s HTTP/1.1\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %zu\r\n"
		"\r\n"
		"%.*s",
		uri, MIME_RPCALL, len, (int)len, content);
	if (ctx->wbuf == NULL) {
		LOGOOM();
		free(req);
		free(ctx);
		return INVALID_HANDLE;
	}
	ev_timer_init(&ctx->w_timeout, timeout_cb, G.conf->timeout, 0.0);
	ev_set_priority(&ctx->w_timeout, EV_MINPRI);
	ctx->w_timeout.data = ctx;
	ev_timer_start(loop, &ctx->w_timeout);
	ctx->state = STATE_CONNECT;
	ctx->invoke_cb = client_cb;
	struct event_cb cb = (struct event_cb){
		.cb = dialer_cb,
		.ctx = ctx,
	};
	dialer_init(&ctx->dialer, cb);
	ctx->dialreq = req;
	LOG_TXT_F(
		VERBOSE, ctx->wbuf->data, ctx->wbuf->len, "http_invoke: api=%s",
		uri);
	dialer_start(&ctx->dialer, loop, req);
	return TO_HANDLE(ctx);
}

void http_client_cancel(struct ev_loop *loop, const handle_t h)
{
	http_client_close(loop, TO_POINTER(h));
}
