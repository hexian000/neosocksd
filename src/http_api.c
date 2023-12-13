/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_server.h"
#include "http_parser.h"
#include "io/stream.h"
#include "net/http.h"
#include "net/url.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/posixtime.h"
#include "utils/slog.h"
#include "resolver.h"
#include "ruleset.h"
#include "server.h"

#include <strings.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RESPHDR_CPLAINTEXT(buf)                                                \
	BUF_APPENDCONST(                                                       \
		(buf), "Content-Type: text/plain; charset=utf-8\r\n"           \
		       "X-Content-Type-Options: nosniff\r\n")

#define RESPHDR_CTYPE(buf, type)                                               \
	BUF_APPENDF((buf), "Content-Type: %s\r\n", (type))

#define RESPHDR_CLENGTH(buf, len)                                              \
	BUF_APPENDF((buf), "Content-Length: %zu\r\n", (len))

#define RESPHDR_CENCODING(buf, encoding)                                       \
	BUF_APPENDF((buf), "Content-Encoding: %s\r\n", (encoding))

#define RESPHDR_NOCACHE(buf)                                                   \
	BUF_APPENDCONST((buf), "Cache-Control: no-store\r\n")

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

static void server_stats(
	struct buffer *restrict buf, const struct server *restrict s,
	const double uptime)
{
	const struct server_stats *restrict stats = &s->stats;
	const struct listener_stats *restrict lstats = &s->l.stats;
	const struct resolver_stats *restrict resolv_stats =
		resolver_stats(G.resolver);
	const time_t server_time = time(NULL);

	char timestamp[32];
	(void)strftime(
		timestamp, sizeof(timestamp), "%FT%T%z",
		localtime(&server_time));
	char str_uptime[16];
	(void)format_duration(
		str_uptime, sizeof(str_uptime), make_duration(uptime));

	FORMAT_BYTES(xfer_up, (double)stats->byt_up);
	FORMAT_BYTES(xfer_down, (double)stats->byt_down);

	const double uptime_hrs = uptime / 3600.0;
	const double avgreq_hrs = (double)(stats->num_request) / uptime_hrs;
	const double avgresolv_hrs =
		(double)(resolv_stats->num_query) / uptime_hrs;
	FORMAT_BYTES(avgbw_up, ((double)stats->byt_up) / uptime_hrs);
	FORMAT_BYTES(avgbw_down, ((double)stats->byt_down) / uptime_hrs);

	BUF_APPENDF(
		*buf,
		"Server Time         : %s\n"
		"Uptime              : %s\n"
		"Num Sessions        : %zu (+%zu)\n"
		"Conn Accepts        : %ju (+%ju)\n"
		"Requests            : %ju (+%ju), %.1f/hrs\n"
		"Name Resolves       : %ju (+%ju), %.1f/hrs\n"
		"Traffic             : Up %s, Down %s\n"
		"Avg Bandwidth       : Up %s/hrs, Down %s/hrs\n",
		timestamp, str_uptime, stats->num_sessions, stats->num_halfopen,
		lstats->num_serve, lstats->num_accept - lstats->num_serve,
		stats->num_success, stats->num_request - stats->num_success,
		avgreq_hrs, resolv_stats->num_success,
		resolv_stats->num_query - resolv_stats->num_success,
		avgresolv_hrs, xfer_up, xfer_down, avgbw_up, avgbw_down);

#if WITH_RULESET
	if (G.ruleset != NULL) {
		struct ruleset_vmstats vmstats;
		ruleset_vmstats(G.ruleset, &vmstats);
		char heap_total[16];
		(void)format_iec_bytes(
			heap_total, sizeof(heap_total),
			(double)vmstats.byt_allocated);
		BUF_APPENDF(
			*buf,
			"Ruleset Memory      : %s (%zu objects)\n"
			"Async Routines      : %zu\n",
			heap_total, vmstats.num_object, vmstats.num_routine);
	}
#endif
}

static void server_stats_stateful(
	struct buffer *restrict buf, const struct server *restrict s,
	const double dt)
{
	const struct server_stats *restrict stats = &s->stats;
	const struct listener_stats *restrict lstats = &s->l.stats;

	static struct {
		uintmax_t num_request;
		uintmax_t xfer_up, xfer_down;
		uintmax_t num_accept;
		uintmax_t num_reject;
	} last = { 0 };

	FORMAT_BYTES(xfer_rate_up, (double)(stats->byt_up - last.xfer_up) / dt);
	FORMAT_BYTES(
		xfer_rate_down,
		(double)(stats->byt_down - last.xfer_down) / dt);

	const uintmax_t num_reject = lstats->num_accept - lstats->num_serve;
	const double accept_rate =
		(double)(lstats->num_accept - last.num_accept) / dt;
	const double reject_rate = (double)(num_reject - last.num_reject) / dt;

	const double request_rate =
		(double)(stats->num_request - last.num_request) / dt;

	BUF_APPENDF(
		*buf,
		"Accept Rate         : %.1f/s (%+.1f/s)\n"
		"Request Rate        : %.1f/s\n"
		"Bandwidth           : Up %s/s, Down %s/s\n",
		accept_rate, reject_rate, request_rate, xfer_rate_up,
		xfer_rate_down);

	last.num_request = stats->num_request;
	last.xfer_up = stats->byt_up;
	last.xfer_down = stats->byt_down;
	last.num_accept = lstats->num_accept;
	last.num_reject = num_reject;
}
#undef FORMAT_BYTES

static void http_handle_stats(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	struct url *restrict uri)
{
	const struct http_message *restrict msg = &ctx->parser.msg;
	bool banner = true;
	while (uri->query != NULL) {
		char *key, *value;
		if (!url_query_component(&uri->query, &key, &value)) {
			http_resp_errpage(&ctx->parser, HTTP_BAD_REQUEST);
			return;
		}
		if (strcmp(key, "banner") == 0) {
			if (strcmp(value, "no") == 0) {
				banner = false;
			}
		}
	}

	const enum content_encodings encoding =
		(ctx->parser.hdr.accept_encoding == CENCODING_DEFLATE) ?
			CENCODING_DEFLATE :
			CENCODING_NONE;
	bool stateless;
	if (strcmp(msg->req.method, "GET") == 0) {
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_NOCACHE(ctx->parser.wbuf);
		stateless = true;
	} else if (strcmp(msg->req.method, "POST") == 0) {
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		stateless = false;
	} else {
		http_resp_errpage(&ctx->parser, HTTP_METHOD_NOT_ALLOWED);
		return;
	}
	struct stream *w = content_writer(&ctx->parser.cbuf, 0, encoding);
	if (w == NULL) {
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	/* borrow the read buffer */
	struct buffer *restrict buf = (struct buffer *)&ctx->parser.rbuf;
	buf->len = 0;

	if (banner) {
		BUF_APPENDCONST(
			*buf, PROJECT_NAME " " PROJECT_VER "\n"
					   "  " PROJECT_HOMEPAGE "\n\n");
	}

	const ev_tstamp now = ev_now(loop);
	const double uptime = ev_now(loop) - ctx->s->stats.started;
	server_stats(buf, ctx->s->data, uptime);

	if (stateless) {
		size_t n = buf->len;
		const int werr = stream_write(w, buf->data, &n);
		const int cerr = stream_close(w);
		if (werr != 0 || n < buf->len || cerr != 0) {
			LOGE_F("stream error: %d, %zu, %d", werr, n, cerr);
			http_resp_errpage(
				&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		}
		return;
	}
	static ev_tstamp last = TSTAMP_NIL;
	const double dt = (last == TSTAMP_NIL) ? uptime : now - last;
	last = now;

	server_stats_stateful(buf, ctx->s->data, dt);

	size_t n = buf->len;
	int err = stream_write(w, buf->data, &n);
	if (n < buf->len || err != 0) {
		LOGE_F("stream_write error: %d, %zu/%zu", err, n, buf->len);
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

#if WITH_RULESET
	if (G.ruleset != NULL) {
		const char header[] = "\n"
				      "Ruleset Stats\n"
				      "================\n";
		const char *s = ruleset_stats(G.ruleset, dt);
		if (s == NULL) {
			s = ruleset_error(G.ruleset);
		}
		n = sizeof(header) - 1;
		err = stream_write(w, header, &n);
		if (n < sizeof(header) - 1 || err != 0) {
			LOGE_F("stream_write error: %d, %zu/%zu", err, n,
			       sizeof(header) - 1);
			http_resp_errpage(
				&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
		const size_t len = strlen(s);
		n = len;
		err = stream_write(w, s, &n);
		if (n < len || err != 0) {
			LOGE_F("stream_write error: %d, %zu/%zu", err, n, len);
			http_resp_errpage(
				&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}
#endif

	err = stream_close(w);
	if (err != 0) {
		LOGE_F("stream_close error: %d", err);
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const char *encoding_str = content_encoding_str[encoding];
	if (encoding_str != NULL) {
		RESPHDR_CENCODING(ctx->parser.wbuf, encoding_str);
	}
	RESPHDR_CLENGTH(ctx->parser.wbuf, VBUF_LEN(ctx->parser.cbuf));
	RESPHDR_FINISH(ctx->parser.wbuf);
}

static bool http_leafnode_check(
	struct http_ctx *restrict ctx, const struct url *restrict uri,
	const char *method, const bool require_content)
{
	if (uri->path != NULL) {
		http_resp_errpage(&ctx->parser, HTTP_NOT_FOUND);
		return false;
	}
	const struct http_message *restrict msg = &ctx->parser.msg;
	if (method != NULL && strcmp(msg->req.method, method) != 0) {
		http_resp_errpage(&ctx->parser, HTTP_METHOD_NOT_ALLOWED);
		return false;
	}
	if (require_content && ctx->parser.hdr.content.length == 0) {
		http_resp_errpage(&ctx->parser, HTTP_LENGTH_REQUIRED);
		return false;
	}
	return true;
}

#if WITH_RULESET
static void
handle_ruleset_rpcall(struct http_ctx *restrict ctx, struct ruleset *ruleset)
{
	char *mime_type = ctx->parser.hdr.content.type;
	if (!check_rpcall_mime(mime_type)) {
		LOGD("rpcall: invalid content type");
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_BAD_REQUEST);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_FINISH(ctx->parser.wbuf);
		return;
	}
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const void *result;
	size_t resultlen;
	const bool ok = ruleset_rpcall(ruleset, reader, &result, &resultlen);
	stream_close(reader);
	if (!ok) {
		const char *err = ruleset_error(ruleset);
		LOGW_F("ruleset rpcall: %s", err);
		const size_t len = strlen(err);
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CTYPE(ctx->parser.wbuf, MIME_RPCALL);
		RESPHDR_CLENGTH(ctx->parser.wbuf, len);
		RESPHDR_FINISH(ctx->parser.wbuf);
		ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
		BUF_APPEND(ctx->parser.wbuf, err, len);
		return;
	}
	const enum content_encodings encoding =
		(ctx->parser.hdr.accept_encoding == CENCODING_DEFLATE) &&
				(resultlen > HTTP_MAX_ENTITY) ?
			CENCODING_DEFLATE :
			CENCODING_NONE;
	struct stream *w =
		content_writer(&ctx->parser.cbuf, resultlen, encoding);
	size_t n = resultlen;
	int err = stream_write(w, result, &n);
	if (n != resultlen || err != 0) {
		LOGW_F("stream_write: error %d", err);
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	err = stream_close(w);
	if (err != 0) {
		LOGW_F("stream_close: error %d", err);
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_CTYPE(ctx->parser.wbuf, MIME_RPCALL);
	const char *encoding_str = content_encoding_str[encoding];
	if (encoding_str != NULL) {
		RESPHDR_CENCODING(ctx->parser.wbuf, encoding_str);
	}
	RESPHDR_CLENGTH(ctx->parser.wbuf, VBUF_LEN(ctx->parser.cbuf));
	RESPHDR_FINISH(ctx->parser.wbuf);
}

static void
handle_ruleset_invoke(struct http_ctx *restrict ctx, struct ruleset *ruleset)
{
	const int64_t start = clock_monotonic();
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const bool ok = ruleset_invoke(ruleset, reader);
	stream_close(reader);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	if (!ok) {
		const char *err = ruleset_error(ruleset);
		LOGW_F("ruleset invoke: %s", err);
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_FINISH(ctx->parser.wbuf);
		BUF_APPENDSTR(ctx->parser.wbuf, err);
		BUF_APPENDCONST(ctx->parser.wbuf, "\n");
		return;
	}
	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_FINISH(ctx->parser.wbuf);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	char timecost[16];
	(void)format_duration(
		timecost, sizeof(timecost),
		make_duration_nanos(clock_monotonic() - start));
	BUF_APPENDF(ctx->parser.wbuf, "Time Cost           : %s\n", timecost);
}

static void handle_ruleset_update(
	struct http_ctx *restrict ctx, struct ruleset *ruleset,
	const char *module)
{
	const int64_t start = clock_monotonic();
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const bool ok = ruleset_update(ruleset, module, reader);
	stream_close(reader);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	if (!ok) {
		const char *err = ruleset_error(ruleset);
		LOGW_F("ruleset update: %s", err);
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_FINISH(ctx->parser.wbuf);
		BUF_APPENDSTR(ctx->parser.wbuf, err);
		BUF_APPENDCONST(ctx->parser.wbuf, "\n");
		return;
	}
	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_FINISH(ctx->parser.wbuf);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	char timecost[16];
	(void)format_duration(
		timecost, sizeof(timecost),
		make_duration_nanos(clock_monotonic() - start));
	BUF_APPENDF(ctx->parser.wbuf, "Time Cost           : %s\n", timecost);
}

static void
handle_ruleset_gc(struct http_ctx *restrict ctx, struct ruleset *ruleset)
{
	const int64_t start = clock_monotonic();
	ruleset_gc(ruleset);
	struct ruleset_vmstats vmstats;
	ruleset_vmstats(ruleset, &vmstats);
	char livemem[16];
	(void)format_iec_bytes(
		livemem, sizeof(livemem), (double)vmstats.byt_allocated);
	char timecost[16];
	(void)format_duration(
		timecost, sizeof(timecost),
		make_duration_nanos(clock_monotonic() - start));
	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
	RESPHDR_FINISH(ctx->parser.wbuf);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	BUF_APPENDF(
		ctx->parser.wbuf,
		"Num Live Objects    : %zu\n"
		"Async Routines      : %zu\n"
		"Ruleset Live Memory : %s\n"
		"Time Cost           : %s\n",
		vmstats.num_object, vmstats.num_routine, livemem, timecost);
}

static void http_handle_ruleset(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	struct url *restrict uri)
{
	UNUSED(loop);
	struct ruleset *ruleset = G.ruleset;
	if (ruleset == NULL) {
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_FINISH(ctx->parser.wbuf);
		BUF_APPENDCONST(
			ctx->parser.wbuf,
			"ruleset not enabled, restart with -r\n");
		return;
	}

	char *segment;
	if (!url_path_segment(&uri->path, &segment)) {
		http_resp_errpage(&ctx->parser, HTTP_NOT_FOUND);
		return;
	}
	if (strcmp(segment, "rpcall") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		handle_ruleset_rpcall(ctx, ruleset);
		return;
	}
	if (strcmp(segment, "invoke") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		handle_ruleset_invoke(ctx, ruleset);
		return;
	}
	if (strcmp(segment, "update") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		const char *module = NULL;
		while (uri->query != NULL) {
			char *key, *value;
			if (!url_query_component(&uri->query, &key, &value)) {
				http_resp_errpage(
					&ctx->parser, HTTP_BAD_REQUEST);
				return;
			}
			if (strcmp(key, "module") == 0) {
				module = value;
			}
		}
		handle_ruleset_update(ctx, ruleset, module);
		return;
	}
	if (strcmp(segment, "gc") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", false)) {
			return;
		}
		handle_ruleset_gc(ctx, ruleset);
		return;
	}

	http_resp_errpage(&ctx->parser, HTTP_NOT_FOUND);
}
#endif

void http_handle_api(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->parser.msg;
	HTTP_CTX_LOG_F(DEBUG, ctx, "http: api \"%s\"", msg->req.url);
	struct url uri;
	if (!url_parse(msg->req.url, &uri)) {
		HTTP_CTX_LOG(WARNING, ctx, "failed parsing url");
		http_resp_errpage(&ctx->parser, HTTP_BAD_REQUEST);
		return;
	}
	char *segment;
	if (!url_path_segment(&uri.path, &segment)) {
		http_resp_errpage(&ctx->parser, HTTP_BAD_REQUEST);
		return;
	}
	if (strcmp(segment, "healthy") == 0) {
		if (!http_leafnode_check(ctx, &uri, NULL, false)) {
			return;
		}
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
		RESPHDR_FINISH(ctx->parser.wbuf);
		return;
	}
	if (strcmp(segment, "stats") == 0) {
		if (!http_leafnode_check(ctx, &uri, NULL, false)) {
			return;
		}
		http_handle_stats(loop, ctx, &uri);
		return;
	}
#if WITH_RULESET
	if (strcmp(segment, "ruleset") == 0) {
		http_handle_ruleset(loop, ctx, &uri);
		return;
	}
#endif
	http_resp_errpage(&ctx->parser, HTTP_NOT_FOUND);
}
