/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_client.h"

#if WITH_RULESET

#include "conf.h"
#include "dialer.h"
#include "http_client.h"
#include "proto/http.h"
#include "util.h"

#include "io/stream.h"
#include "net/http.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/gc.h"
#include "utils/intcast.h"
#include "utils/slog.h"

#include <ev.h>
#include <strings.h>

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct api_client_ctx {
	struct gcbase gcbase;
	struct ev_loop *loop;
	const struct config *conf;
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

static void
api_client_stop(struct ev_loop *loop, struct api_client_ctx *restrict ctx)
{
	if (ctx->hctx.state != STATE_CLIENT_INIT) {
		http_client_cancel(loop, &ctx->hctx);
	}
	ev_idle_stop(loop, &ctx->w_process);
}

static void api_client_finalize(struct gcbase *restrict obj)
{
	struct api_client_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct api_client_ctx, gcbase, obj);

	api_client_stop(ctx->loop, ctx);
	if (ctx->result.stream != NULL) {
		stream_close(ctx->result.stream);
		ctx->result.stream = NULL;
	}
	VBUF_FREE(ctx->result.content);
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
		stream_close(ctx->result.stream);
		ctx->result.stream = NULL;
	}
	VBUF_FREE(ctx->result.content);

	gc_unref(&ctx->gcbase);
}

static void api_client_finish(
	struct ev_loop *loop, struct api_client_ctx *restrict ctx,
	const char *errmsg, const size_t errlen, struct stream *stream)
{
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

static void on_http_client_done(
	struct ev_loop *loop, void *data, const char *errmsg,
	const size_t errlen, struct http_parser *parser)
{
	struct api_client_ctx *restrict ctx = data;

	if (errmsg != NULL) {
		api_client_finish(loop, ctx, errmsg, errlen, NULL);
		return;
	}
	ASSERT(parser != NULL);
	struct vbuffer *content = parser->cbuf;
	parser->cbuf = NULL;

	const struct http_message *restrict msg = &parser->msg;
	uint16_t code = 0;
	{
		const uintmax_t status = strtoumax(msg->rsp.code, NULL, 10);
		if (UINTCAST_CHECK(code, status)) {
			code = status;
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
		if (!check_rpcall_mime(parser->hdr.content.type)) {
			VBUF_FREE(content);
			API_RETURN_ERROR(loop, ctx, "unsupported content-type");
		}
	} else if (
		content != NULL && VBUF_LEN(content) > 0 &&
		check_rpcall_mime(parser->hdr.content.type)) {
		/* Server returned structured error in RPC format */
		ctx->result.content = content;
		api_client_finish(
			loop, ctx, VBUF_DATA(content), VBUF_LEN(content), NULL);
		return;
	} else {
		/* Generic HTTP error response */
		VBUF_RESERVE(content, 64);
		if (content == NULL) {
			LOGOOM();
			VBUF_FREE(content);
			api_client_finish(loop, ctx, NULL, 0, NULL);
			return;
		}
		VBUF_RESET(content);
		VBUF_APPENDF(
			content, "%s %s %s", msg->rsp.version, msg->rsp.code,
			msg->rsp.status);
		if (VBUF_HAS_OOM(content)) {
			LOGOOM();
			VBUF_FREE(content);
			api_client_finish(loop, ctx, NULL, 0, NULL);
			return;
		}
		ctx->result.content = content;
		api_client_finish(
			loop, ctx, VBUF_DATA(content), VBUF_LEN(content), NULL);
		return;
	}

	if (LOGLEVEL(VERBOSE)) {
		FORMAT_BYTES(clen, VBUF_LEN(content));
		LOGV_F("response: content %s", clen);
	}

	struct stream *r = content_reader(
		VBUF_DATA(content), VBUF_LEN(content),
		parser->hdr.content.encoding);
	if (r == NULL) {
		LOGOOM();
		VBUF_FREE(content);
		API_RETURN_ERROR(loop, ctx, "out of memory");
	}

	ctx->result.content = content;
	api_client_finish(loop, ctx, NULL, 0, r);
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
		"Connection: keep-alive\r\n"
		"Content-Length: %zu\r\n"
		"Content-Type: %s\r\n",
		uri, VBUF_LEN(p->cbuf), MIME_RPCALL);
	const char *encoding_str = content_encoding_str[encoding];
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

static bool parse_header(void *ctx, const char *key, char *value)
{
	struct api_client_ctx *restrict c = ctx;
	ASSERT(c->hctx.state != STATE_CLIENT_INIT);
	struct http_parser *restrict p = &c->hctx.parser;

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

static bool api_client_do(
	struct ev_loop *loop, struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const char *restrict uri,
	const void *restrict payload, const size_t len,
	const struct api_client_cb *restrict in_cb,
	const struct config *restrict conf, struct resolver *restrict resolver)
{
	struct api_client_ctx *restrict ctx =
		malloc(sizeof(struct api_client_ctx));
	if (ctx == NULL) {
		LOGOOM();
		dialreq_free(req);
		return false;
	}
	ctx->loop = loop;
	ctx->conf = conf;
	ctx->result.errmsg = NULL;
	ctx->result.errlen = 0;
	ctx->result.stream = NULL;
	ctx->result.content = NULL;
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	const struct http_client_cb hcb = {
		.func = on_http_client_done,
		.data = ctx,
	};
	http_client_init(&ctx->hctx, loop, on_header, &hcb, conf, resolver);
	if (!make_request(&ctx->hctx.parser, uri, payload, len)) {
		LOGOOM();
		dialreq_free(req);
		free(ctx);
		return false;
	}
	ctx->cb = *in_cb;
	ev_idle_init(&ctx->w_process, process_cb);
	ctx->w_process.data = ctx;
	gc_register(&ctx->gcbase, api_client_finalize);
	if (pctx != NULL) {
		*pctx = ctx;
	}
	http_client_do(loop, &ctx->hctx, req);
	return true;
}

void api_client_invoke(
	struct ev_loop *restrict loop, struct dialreq *restrict req,
	const void *restrict payload, const size_t len,
	const struct config *restrict conf, struct resolver *restrict resolver)
{
	(void)api_client_do(
		loop, NULL, req, "/ruleset/invoke", payload, len,
		&(struct api_client_cb){ NULL, NULL }, conf, resolver);
}

bool api_client_rpcall(
	struct ev_loop *restrict loop, struct api_client_ctx **restrict pctx,
	struct dialreq *restrict req, const void *restrict payload,
	const size_t len, const struct api_client_cb *restrict cb,
	const struct config *restrict conf, struct resolver *restrict resolver)
{
	ASSERT(cb->func != NULL);
	return api_client_do(
		loop, pctx, req, "/ruleset/rpcall", payload, len, cb, conf,
		resolver);
}

void api_client_cancel(
	struct ev_loop *restrict loop, struct api_client_ctx *restrict ctx)
{
	UNUSED(loop);
	gc_unref(&ctx->gcbase);
}

#endif /* WITH_RULESET */
