/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_client.h"

#if WITH_RULESET

#include "conf.h"
#include "dialer.h"
#include "http_client.h"
#include "proto/http.h"
#include "server.h"
#include "util.h"

#include "io/stream.h"
#include "meta/class.h"
#include "meta/intcast.h"
#include "meta/minmax.h"
#include "net/http.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

struct api_client_ctx {
	struct gcbase gcbase;
	struct ev_loop *loop;
	struct api_client_cb cb;
	ev_idle w_process;
	struct http_client_ctx hctx;
	struct {
		const char *errmsg;
		size_t errlen;
		struct stream *stream;
		struct vbuffer *content;
	} result;
};
ASSERT_SUPER(struct gcbase, struct api_client_ctx, gcbase);

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

static bool parse_header(void *ctx, const char *key, char *value)
{
	struct api_client_ctx *restrict c = ctx;
	ASSERT(c->hctx.state != STATE_CLIENT_INIT);
	struct http_conn *restrict p = &c->hctx.conn;

	/* hop-by-hop headers */
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

	LOGVV_F("unknown http header: `%s' = `%s'", key, value);
	return true;
}

static void
api_client_stop(struct ev_loop *loop, struct api_client_ctx *restrict ctx)
{
	if (ctx->hctx.state != STATE_CLIENT_INIT) {
		http_client_cancel(&ctx->hctx, loop);
	}
	ev_idle_stop(loop, &ctx->w_process);
}

static void api_client_finish(
	struct ev_loop *loop, struct api_client_ctx *restrict ctx,
	const char *errmsg, const size_t errlen, struct stream *stream)
{
	/* A caller with a callback reads errmsg == NULL as success and then
	 * consumes the stream, so it must never be handed both as NULL. Only a
	 * fire-and-forget invoke (no callback) may finish with neither. */
	ASSERT(errmsg != NULL || stream != NULL || ctx->cb.func == NULL);
	ctx->result.errmsg = errmsg;
	ctx->result.errlen = errlen;
	ctx->result.stream = stream;

	api_client_stop(loop, ctx);
	ev_idle_start(loop, &ctx->w_process);
}

#define API_RETURN_ERROR(loop, ctx, msg)                                       \
	do {                                                                   \
		api_client_finish(                                             \
			(loop), (ctx), (msg ""), sizeof(msg) - 1, NULL);       \
		return;                                                        \
	} while (false)

/* Copy a completion error message into ctx-owned storage, then defer the
 * result. The message may point into the caller's stack frame (http_client.c's
 * strerror-based write-error path builds it in a stack buffer), which unwinds
 * before the deferred process_cb reads it; storing it in result.content keeps
 * it valid until then, mirroring the structured-error path. */
static void api_client_finish_errmsg(
	struct ev_loop *loop, struct api_client_ctx *restrict ctx,
	const char *restrict errmsg, const size_t errlen)
{
	struct vbuffer *emsg = VBUF_NEW(errlen);
	if (emsg != NULL) {
		VBUF_APPEND(emsg, errmsg, errlen);
	}
	if (VBUF_HAS_OOM(emsg)) {
		LOGOOM();
		VBUF_FREE(emsg);
		API_RETURN_ERROR(loop, ctx, "out of memory");
	}
	ctx->result.content = emsg;
	api_client_finish(loop, ctx, VBUF_DATA(emsg), VBUF_LEN(emsg), NULL);
}

static void on_http_client_done(
	struct ev_loop *loop, void *data, const char *errmsg,
	const size_t errlen, struct http_conn *conn)
{
	struct api_client_ctx *restrict ctx = data;

	if (errmsg != NULL) {
		api_client_finish_errmsg(loop, ctx, errmsg, errlen);
		return;
	}
	ASSERT(conn != NULL);
	/* http_conn frames only Content-Length bodies; a chunked response parses
	 * OK with cbuf == NULL and its body left unconsumed in rbuf (see
	 * http_conn_recv). This path consumes cbuf directly and cannot dechunk, so
	 * report an error rather than silently deliver an empty body. A stock
	 * neosocksd peer never sends one (always Content-Length + Connection:
	 * close), but a compatible/custom peer might. */
	if (conn->hdr.transfer.encoding == TENCODING_CHUNKED) {
		API_RETURN_ERROR(loop, ctx, "chunked response not supported");
	}
	struct vbuffer *content = conn->cbuf;
	conn->cbuf = NULL;

	const struct http_message *restrict msg = &conn->msg;
	uint_fast16_t code = 0;
	{
		const uintmax_t status = strtoumax(msg->rsp.code, NULL, 10);
		if (UINTCAST_CHECK(code, status)) {
			code = (uint_fast16_t)status;
		}
	}
	if (BETWEEN(code, 200, 299)) {
		/* invoke: 2xx with empty body is success */
		if (ctx->cb.func == NULL &&
		    (content == NULL || VBUF_LEN(content) == 0)) {
			api_client_finish(loop, ctx, NULL, 0, NULL);
			return;
		}
		/* rpcall: validate content type */
		if (!check_rpcall_mime(conn->hdr.content.type)) {
			VBUF_FREE(content);
			API_RETURN_ERROR(loop, ctx, "unsupported content-type");
		}
	} else {
		if (content != NULL && VBUF_LEN(content) > 0 &&
		    check_rpcall_mime(conn->hdr.content.type)) {
			/* Server returned structured error in RPC format */
			ctx->result.content = content;
			api_client_finish(
				loop, ctx, VBUF_DATA(content),
				VBUF_LEN(content), NULL);
			return;
		}
		/* Generic HTTP error response */
		VBUF_RESERVE(content, 64);
		if (content == NULL) {
			LOGOOM();
			API_RETURN_ERROR(loop, ctx, "out of memory");
		}
		VBUF_RESET(content);
		VBUF_APPENDF(
			content, "%s %s %s", msg->rsp.version, msg->rsp.code,
			msg->rsp.status);
		if (VBUF_HAS_OOM(content)) {
			LOGOOM();
			VBUF_FREE(content);
			API_RETURN_ERROR(loop, ctx, "out of memory");
		}
		ctx->result.content = content;
		api_client_finish(
			loop, ctx, VBUF_DATA(content), VBUF_LEN(content), NULL);
		return;
	}

	if (LOGLEVEL(VERBOSE)) {
		FORMAT_BYTES(clen, content != NULL ? VBUF_LEN(content) : 0);
		LOGV_F("response: content %s", clen);
	}

	/* Content-Length: 0 leaves content unallocated; io_memreader() requires
	 * a non-NULL buffer even for a zero-length read, so substitute "". */
	struct stream *r = content_reader(
		content != NULL ? VBUF_DATA(content) : "",
		content != NULL ? VBUF_LEN(content) : 0,
		conn->hdr.content.encoding);
	if (r == NULL) {
		LOGOOM();
		VBUF_FREE(content);
		API_RETURN_ERROR(loop, ctx, "out of memory");
	}

	ctx->result.content = content;
	api_client_finish(loop, ctx, NULL, 0, r);
}

static bool make_request(
	struct http_conn *restrict p, const char *restrict uri,
	const void *restrict content, const size_t len)
{
	/* Compress large payloads to reduce traffic */
	enum content_encodings encoding = CENCODING_NONE;
	if (len >= RPCALL_COMPRESS_THRESHOLD) {
		encoding = CENCODING_DEFLATE;
	}
	struct stream *s = content_writer(&p->cbuf, len, encoding);
	if (s == NULL) {
		/* content_writer may have reserved p->cbuf before the stream
		 * wrapper itself failed to allocate */
		LOGOOM();
		VBUF_FREE(p->cbuf);
		return false;
	}
	size_t n = len;
	const int err1 = stream_write(s, content, &n);
	const int err2 = stream_close(s);
	if (p->cbuf == NULL) {
		LOGOOM();
		return false;
	}
	if (err1 != 0 || err2 != 0 || n != len) {
		/* a codec error, not necessarily an allocation failure */
		LOGE_F("api request: cannot build content, "
		       "write error %d, close error %d, %zu of %zu bytes",
		       err1, err2, n, len);
		VBUF_FREE(p->cbuf);
		return false;
	}
	BUF_APPENDF(
		p->wbuf,
		"POST %s HTTP/1.1\r\n"
		"Accept-Encoding: deflate\r\n"
		"Connection: close\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: %s\r\n",
		uri, VBUF_LEN(p->cbuf), MIME_RPCALL);
	const char *encoding_str = http_content_encoding_str[encoding];
	if (encoding_str != NULL) {
		BUF_APPENDF(p->wbuf, "Content-Encoding: %s\r\n", encoding_str);
	}
	BUF_APPENDSTR(p->wbuf, "\r\n");
	LOG_TXT_F(
		VERYVERBOSE, (const char *)p->wbuf.data, p->wbuf.len, 0,
		"request header: %zu bytes", p->wbuf.len);
	LOG_BIN_F(
		VERYVERBOSE, VBUF_DATA(p->cbuf), VBUF_LEN(p->cbuf), 0,
		"request content: %zu bytes", VBUF_LEN(p->cbuf));
	return true;
}

/* Close a stream on a best-effort cleanup path, logging at debug level when the
 * close reports an error that is non-actionable here. */
static void close_stream(struct stream *restrict s)
{
	const int err = stream_close(s);
	if (err != 0) {
		LOGD_F("stream_close: error %d", err);
	}
}

static void
process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct api_client_ctx *restrict ctx = watcher->data;

	if (ctx->cb.func != NULL) {
		ctx->cb.func(
			ctx, loop, ctx->cb.data, ctx->result.errmsg,
			ctx->result.errlen, ctx->result.stream);
	} else if (ctx->result.errmsg != NULL) {
		LOGW_F("api invoke: %.*s", (int)ctx->result.errlen,
		       ctx->result.errmsg);
	}
	if (ctx->result.stream != NULL) {
		close_stream(ctx->result.stream);
		ctx->result.stream = NULL;
	}
	VBUF_FREE(ctx->result.content);

	gc_unref(&ctx->gcbase);
}

static void api_client_finalize(struct gcbase *restrict obj)
{
	struct api_client_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct api_client_ctx, gcbase, obj);

	api_client_stop(ctx->loop, ctx);
	if (ctx->result.stream != NULL) {
		close_stream(ctx->result.stream);
		ctx->result.stream = NULL;
	}
	VBUF_FREE(ctx->result.content);
}

static bool api_client_do(
	struct ev_loop *loop, struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const char *restrict uri,
	const void *restrict payload, const size_t len,
	const struct api_client_cb *restrict in_cb,
	const struct config *restrict conf, struct resolver *restrict resolver,
	struct server_stats *restrict stats)
{
	struct api_client_ctx *restrict ctx =
		malloc(sizeof(struct api_client_ctx));
	if (ctx == NULL) {
		LOGOOM();
		dialreq_free(req);
		return false;
	}
	ctx->loop = loop;
	ctx->result.errmsg = NULL;
	ctx->result.errlen = 0;
	ctx->result.stream = NULL;
	ctx->result.content = NULL;
	const struct http_parsehdr_cb on_header = {
		.func = parse_header,
		.ctx = ctx,
	};
	const struct http_client_cb hcb = {
		.func = on_http_client_done,
		.data = ctx,
	};
	http_client_init(
		&ctx->hctx, loop, on_header, &hcb, conf, resolver,
		stats != NULL ? &stats->api_client_byt_recv : NULL,
		stats != NULL ? &stats->api_client_byt_send : NULL,
		stats != NULL ? &stats->byt_dial_send : NULL,
		stats != NULL ? &stats->byt_dial_recv : NULL);
	if (!make_request(&ctx->hctx.conn, uri, payload, len)) {
		/* make_request logs its own specific cause */
		dialreq_free(req);
		free(ctx);
		return false;
	}
	/* count only requests that are actually issued (make_request can fail
	 * building/compressing the body before anything is sent) */
	if (stats != NULL) {
		stats->num_api_client_request++;
	}
	ctx->cb = *in_cb;
	ev_idle_init(&ctx->w_process, process_cb);
	ctx->w_process.data = ctx;
	gc_register(&ctx->gcbase, api_client_finalize);
	if (pctx != NULL) {
		*pctx = ctx;
	}
	http_client_do(&ctx->hctx, loop, req);
	return true;
}

void api_client_invoke(
	struct ev_loop *restrict loop, struct dialreq *restrict req,
	const void *restrict payload, const size_t len,
	const struct config *restrict conf, struct resolver *restrict resolver,
	struct server_stats *restrict stats)
{
	(void)api_client_do(
		loop, NULL, req, "/ruleset/invoke", payload, len,
		&(struct api_client_cb){
			.func = NULL,
			.data = NULL,
		},
		conf, resolver, stats);
}

bool api_client_rpcall(
	struct ev_loop *restrict loop, struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const void *restrict payload,
	const size_t len, const struct api_client_cb *restrict cb,
	const struct config *restrict conf, struct resolver *restrict resolver,
	struct server_stats *restrict stats)
{
	ASSERT(cb->func != NULL);
	return api_client_do(
		loop, pctx, req, "/ruleset/rpcall", payload, len, cb, conf,
		resolver, stats);
}

void api_client_cancel(
	struct ev_loop *restrict loop, struct api_client_ctx *restrict ctx)
{
	(void)loop;
	gc_unref(&ctx->gcbase);
}

#endif /* WITH_RULESET */
