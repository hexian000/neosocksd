/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_impl.h"
#include "utils/buffer.h"
#include "dialer.h"

#include <limits.h>
#include <stdlib.h>

struct http_invoke_ctx {
	struct ev_loop *loop;
	union {
		struct {
			struct dialreq *dialreq;
			struct dialer dialer;
		};
		struct {
			struct ev_io w_write;
		};
	};
	struct vbuffer *wbuf;
};

static void
request_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct http_invoke_ctx *restrict ctx = watcher->data;
	struct vbuffer *restrict wbuf = ctx->wbuf;
	unsigned char *buf = wbuf->data;
	size_t len = wbuf->len;
	size_t nbsend = 0;
	while (len > 0) {
		const ssize_t nsend = send(watcher->fd, buf, len, 0);
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

	ev_io_stop(loop, watcher);
	ctx->wbuf = VBUF_FREE(wbuf);
	free(ctx);
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct http_invoke_ctx *restrict ctx = data;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		LOGE("invoke: dialer failed");
		ctx->wbuf = VBUF_FREE(ctx->wbuf);
		free(ctx);
		return;
	}
	dialreq_free(ctx->dialreq);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_init(w_write, request_write_cb, fd, EV_WRITE);
	w_write->data = ctx;
	ev_io_start(loop, w_write);
}

void http_invoke(
	struct ev_loop *loop, struct dialreq *req, const char *code,
	const size_t len)
{
	CHECK(len <= INT_MAX);
	struct http_invoke_ctx *restrict ctx =
		malloc(sizeof(struct http_invoke_ctx));
	if (ctx == NULL) {
		LOGOOM();
		free(req);
		return;
	}
	ctx->wbuf = VBUF_APPENDF(
		NULL,
		"POST /ruleset/invoke HTTP/1.1\r\n"
		"Content-Length: %zu\r\n"
		"\r\n"
		"%.*s",
		len, (int)len, code);
	if (ctx->wbuf == NULL) {
		LOGOOM();
		free(req);
		free(ctx);
		return;
	}
	struct event_cb cb = (struct event_cb){
		.cb = dialer_cb,
		.ctx = ctx,
	};
	dialer_init(&ctx->dialer, cb);
	ctx->dialreq = req;
	LOGV_F("http_invoke:\n%.*s", (int)ctx->wbuf->len, ctx->wbuf->data);
	dialer_start(&ctx->dialer, loop, req);
}
