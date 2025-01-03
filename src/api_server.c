/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_server.h"

#include "conf.h"
#include "dialer.h"
#include "httputil.h"
#include "resolver.h"
#include "ruleset.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "util.h"

#include "io/io.h"
#include "io/stream.h"
#include "net/http.h"
#include "net/mime.h"
#include "net/url.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/slog.h"

#include <ev.h>
#include <strings.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* never rollback */
enum api_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_YIELD,
	STATE_RESPONSE,
};

struct api_ctx {
	struct session ss;
	struct server *s;
	enum api_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	struct ev_timer w_timeout;
	struct ev_io w_recv, w_send;
#if WITH_RULESET
	struct ruleset_state *rpcstate;
#endif
	struct dialreq *dialreq;
	struct http_parser parser;
};
ASSERT_SUPER(struct session, struct api_ctx, ss);

#define API_CTX_LOG_F(level, ctx, format, ...)                                 \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char caddr[64];                                                \
		format_sa(caddr, sizeof(caddr), &(ctx)->accepted_sa.sa);       \
		LOG_F(level, "[%d] %s: " format, (ctx)->accepted_fd, caddr,    \
		      __VA_ARGS__);                                            \
	} while (0)
#define API_CTX_LOG(level, ctx, message)                                       \
	API_CTX_LOG_F(level, ctx, "%s", message)

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

#define FORMAT_SI(name, value)                                                 \
	char name[16];                                                         \
	(void)format_si_prefix(name, sizeof(name), (value))

#define FORMAT_DURATION(name, value)                                           \
	char name[16];                                                         \
	(void)format_duration(name, sizeof(name), (value))

#if WITH_RULESET
bool check_rpcall_mime(char *s)
{
	if (s == NULL) {
		return false;
	}
	char *type, *subtype;
	s = mime_parse(s, &type, &subtype);
	if (s == NULL || strcmp(type, MIME_RPCALL_TYPE) != 0 ||
	    strcmp(subtype, MIME_RPCALL_SUBTYPE) != 0) {
		return false;
	}
	const char *version = NULL;
	char *key, *value;
	for (;;) {
		s = mime_parseparam(s, &key, &value);
		if (s == NULL) {
			return false;
		}
		if (key == NULL) {
			break;
		}
		if (strcmp(key, "version") == 0) {
			version = value;
		}
	}
	return version != NULL && strcmp(version, MIME_RPCALL_VERSION) == 0;
}

static void
append_memstats(struct buffer *restrict buf, const struct ruleset_vmstats *vm)
{
	FORMAT_BYTES(allocated, (double)vm->byt_allocated);
	FORMAT_SI(objects, (double)vm->num_object);

	const int memlimit_mb = G.conf->memlimit;
	if (memlimit_mb > 0) {
		FORMAT_BYTES(memlimit, ((double)memlimit_mb) * 0x1p20);
		BUF_APPENDF(
			*buf, "%-20s: %s < %s (%s objects)\n",
			"Ruleset Allocated", allocated, memlimit, objects);
	} else {
		BUF_APPENDF(
			*buf, "%-20s: %s (%s objects)\n", "Ruleset Allocated",
			allocated, objects);
	}
}
#endif

static void server_stats(
	struct buffer *restrict buf, const struct server *restrict api,
	const double uptime)
{
	const struct server_stats *restrict apistats = &api->stats;
	const struct server *restrict s = api->data;
	const struct server_stats *restrict stats = &s->stats;
	const struct listener_stats *restrict lstats = &s->l.stats;
	const struct resolver_stats *restrict resolv_stats =
		resolver_stats(G.resolver);
	const time_t server_time = time(NULL);

	char timestamp[32];
	(void)strftime(
		timestamp, sizeof(timestamp), "%FT%T%z",
		localtime(&server_time));
	FORMAT_DURATION(str_uptime, make_duration(uptime));
	FORMAT_BYTES(xfer_up, (double)stats->byt_up);
	FORMAT_BYTES(xfer_down, (double)stats->byt_down);

	BUF_APPENDF(
		*buf,
		"Server Time         : %s\n"
		"Uptime              : %s\n"
		"Num Sessions        : %zu (+%zu)\n"
		"Conn Accepts        : %ju (+%ju)\n"
		"Requests            : %ju (+%ju)\n"
		"API Requests        : %ju (+%ju)\n"
		"Name Resolves       : %ju (+%ju)\n"
		"Traffic             : Up %s, Down %s\n",
		timestamp, str_uptime, stats->num_sessions, stats->num_halfopen,
		lstats->num_serve, lstats->num_accept - lstats->num_serve,
		stats->num_success, stats->num_request - stats->num_success,
		apistats->num_success,
		apistats->num_request - apistats->num_success,
		resolv_stats->num_success,
		resolv_stats->num_query - resolv_stats->num_success, xfer_up,
		xfer_down);

#if WITH_RULESET
	const struct ruleset *r = G.ruleset;
	if (r != NULL) {
		struct ruleset_vmstats vmstats;
		ruleset_vmstats(r, &vmstats);
		append_memstats(buf, &vmstats);
	}
#endif
}

static void server_stats_stateful(
	struct buffer *restrict buf, const struct server *restrict api,
	const double dt)
{
	const struct server_stats *restrict apistats = &api->stats;
	const struct server *restrict s = api->data;
	const struct server_stats *restrict stats = &s->stats;
	const struct listener_stats *restrict lstats = &s->l.stats;

	static struct {
		uintmax_t xfer_up, xfer_down;
		uintmax_t num_accept;
		uintmax_t num_reject;
		uintmax_t num_request;
		uintmax_t num_api_request;
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
	const double api_request_rate =
		(double)(apistats->num_request - last.num_api_request) / dt;

	char load_str[16] = "(unknown)";
	const double load = thread_load();
	if (load >= 0) {
		(void)snprintf(
			load_str, sizeof(load_str), "%.03f%%", load * 100);
	}

	BUF_APPENDF(
		*buf,
		"Accept Rate         : %.1f/s (%+.1f/s)\n"
		"Request Rate        : %.1f/s\n"
		"API Request Rate    : %.1f/s\n"
		"Bandwidth           : Up %s/s, Down %s/s\n"
		"Server Load         : %s\n",
		accept_rate, reject_rate, request_rate, api_request_rate,
		xfer_rate_up, xfer_rate_down, load_str);

	last.xfer_up = stats->byt_up;
	last.xfer_down = stats->byt_down;
	last.num_accept = lstats->num_accept;
	last.num_reject = num_reject;
	last.num_request = stats->num_request;
	last.num_api_request = apistats->num_request;
}

static bool parse_bool(const char *s)
{
	return strcmp(s, "1") == 0 || strcmp(s, "y") == 0 ||
	       strcmp(s, "yes") == 0 || strcmp(s, "on") == 0 ||
	       strcmp(s, "t") == 0 || strcmp(s, "true") == 0;
}

static bool http_handle_stats(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	struct url *restrict uri)
{
	bool nobanner = false;
	bool server = true;
#if WITH_RULESET
	const char *query = NULL;
#endif
	while (uri->query != NULL) {
		struct url_query_component comp;
		if (!url_query_component(&uri->query, &comp)) {
			http_resp_errpage(&ctx->parser, HTTP_BAD_REQUEST);
			return false;
		}
		if (strcmp(comp.key, "nobanner") == 0) {
			nobanner = parse_bool(comp.value);
		} else if (strcmp(comp.key, "server") == 0) {
			server = parse_bool(comp.value);
		}
#if WITH_RULESET
		else if (strcmp(comp.key, "q") == 0) {
			query = comp.value;
		}
#endif
	}

	const struct http_message *restrict msg = &ctx->parser.msg;
	bool stateless;
	if (strcmp(msg->req.method, "GET") == 0) {
		stateless = true;
	} else if (strcmp(msg->req.method, "POST") == 0) {
		stateless = false;
	} else {
		http_resp_errpage(&ctx->parser, HTTP_METHOD_NOT_ALLOWED);
		return false;
	}

	const enum content_encodings encoding =
		(ctx->parser.hdr.accept_encoding == CENCODING_DEFLATE) ?
			CENCODING_DEFLATE :
			CENCODING_NONE;
	struct stream *w =
		content_writer(&ctx->parser.cbuf, IO_BUFSIZE, encoding);
	if (w == NULL) {
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return false;
	}
	/* borrow the read buffer */
	struct buffer *restrict buf = (struct buffer *)&ctx->parser.rbuf;
	buf->len = 0;

	if (!nobanner) {
		BUF_APPENDSTR(
			*buf, PROJECT_NAME " " PROJECT_VER "\n"
					   "  " PROJECT_HOMEPAGE "\n\n");
	}

	const ev_tstamp now = ev_now(loop);
	const double uptime = now - ctx->s->stats.started;
	static ev_tstamp last = TSTAMP_NIL;
	const double dt = (last == TSTAMP_NIL) ? uptime : now - last;
	if (server) {
		server_stats(buf, ctx->s, uptime);
		if (!stateless) {
			last = now;
			server_stats_stateful(buf, ctx->s, dt);
		}

		size_t n = buf->len;
		int err = stream_write(w, buf->data, &n);
		if (n < buf->len || err != 0) {
			LOGE_F("stream_write error: %d, %zu/%zu", err, n,
			       buf->len);
			http_resp_errpage(
				&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
			return false;
		}
	}

#if WITH_RULESET
	struct ruleset *ruleset = G.ruleset;
	if (!stateless && ruleset != NULL) {
		size_t len;
		const char *s = ruleset_stats(ruleset, dt, query, &len);
		if (s == NULL) {
			s = ruleset_geterror(ruleset, &len);
		}
		size_t n = len;
		int err = stream_write(w, s, &n);
		if (n < len || err != 0) {
			LOGE_F("stream_write error: %d, %zu/%zu", err, n, len);
			http_resp_errpage(
				&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
			return false;
		}
	}
#endif

	int err = stream_close(w);
	if (err != 0) {
		LOGE_F("stream_close error: %d", err);
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return false;
	}

	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
	if (stateless) {
		RESPHDR_NOCACHE(ctx->parser.wbuf);
	}
	const char *encoding_str = content_encoding_str[encoding];
	if (encoding_str != NULL) {
		RESPHDR_CENCODING(ctx->parser.wbuf, encoding_str);
	}
	RESPHDR_CLENGTH(ctx->parser.wbuf, VBUF_LEN(ctx->parser.cbuf));
	RESPHDR_FINISH(ctx->parser.wbuf);
	return true;
}

static bool restapi_check(
	struct api_ctx *restrict ctx, const struct url *restrict uri,
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
	if (require_content && !ctx->parser.hdr.content.has_length) {
		http_resp_errpage(&ctx->parser, HTTP_LENGTH_REQUIRED);
		return false;
	}
	return true;
}

#if WITH_RULESET
static void rpcall_return(void *data, const char *result, size_t resultlen)
{
	struct api_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_YIELD);
	ctx->rpcstate = NULL;
	ctx->state = STATE_RESPONSE;
	ev_io_start(ctx->s->loop, &ctx->w_send);

	if (result == NULL) {
		const char err[] = "rpcall is closed";
		const size_t errlen = sizeof(err) - 1;
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CTYPE(ctx->parser.wbuf, MIME_RPCALL);
		RESPHDR_CLENGTH(ctx->parser.wbuf, errlen);
		RESPHDR_FINISH(ctx->parser.wbuf);
		ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
		BUF_APPEND(ctx->parser.wbuf, err, errlen);
		return;
	}
	LOG_TXT(VERYVERBOSE, result, resultlen, "rpcall_return");
	const enum content_encodings encoding =
		(ctx->parser.hdr.accept_encoding != CENCODING_DEFLATE) ?
			CENCODING_NONE :
			CENCODING_DEFLATE;
	struct stream *writer =
		content_writer(&ctx->parser.cbuf, resultlen, encoding);
	if (writer == NULL) {
		LOGOOM();
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	size_t n = resultlen;
	int err = stream_write(writer, result, &n);
	if (err != 0) {
		LOGW_F("stream_write: error %d, %zu/%zu", err, n, resultlen);
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	err = stream_close(writer);
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

static bool
handle_ruleset_rpcall(struct api_ctx *restrict ctx, struct ruleset *r)
{
	char *mime_type = ctx->parser.hdr.content.type;
	if (!check_rpcall_mime(mime_type)) {
		LOGD("rpcall: invalid content type");
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_BAD_REQUEST);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_FINISH(ctx->parser.wbuf);
		return false;
	}
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return false;
	}
	ctx->state = STATE_YIELD;
	struct ruleset_state *rpcstate = ruleset_rpcall(
		r, reader,
		(struct rpcall_cb){
			.func = rpcall_return,
			.data = ctx,
		});
	stream_close(reader);
	if (rpcstate == NULL) {
		/* no callback */
		ctx->state = STATE_RESPONSE;
		size_t len;
		const char *err = ruleset_geterror(r, &len);
		LOGW_F("ruleset rpcall: %s", err);
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CTYPE(ctx->parser.wbuf, MIME_RPCALL);
		RESPHDR_CLENGTH(ctx->parser.wbuf, len);
		RESPHDR_FINISH(ctx->parser.wbuf);
		ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
		BUF_APPEND(ctx->parser.wbuf, err, len);
		return false;
	}
	if (ctx->state == STATE_YIELD) {
		/* rpcall_return is not called yet */
		ctx->rpcstate = rpcstate;
	}
	return true;
}

static bool handle_ruleset_invoke(
	struct ev_loop *loop, struct api_ctx *restrict ctx, struct ruleset *r)
{
	const ev_tstamp start = ev_now(loop);
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return false;
	}
	const bool ok = ruleset_invoke(r, reader);
	stream_close(reader);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	if (!ok) {
		size_t len;
		const char *err = ruleset_geterror(r, &len);
		LOGW_F("ruleset invoke: %s", err);
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_FINISH(ctx->parser.wbuf);
		BUF_APPEND(ctx->parser.wbuf, err, len);
		BUF_APPENDSTR(ctx->parser.wbuf, "\n");
		return false;
	}
	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
	RESPHDR_FINISH(ctx->parser.wbuf);
	const ev_tstamp end = ev_time();
	FORMAT_DURATION(timecost, make_duration(end - start));
	BUF_APPENDF(ctx->parser.wbuf, "Time Cost           : %s\n", timecost);
	return true;
}

static bool handle_ruleset_update(
	struct ev_loop *loop, struct api_ctx *restrict ctx, struct ruleset *r,
	const char *module, const char *chunkname)
{
	const ev_tstamp start = ev_now(loop);
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->parser.cbuf), VBUF_LEN(ctx->parser.cbuf),
		ctx->parser.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return false;
	}
	const bool ok = ruleset_update(r, module, chunkname, reader);
	stream_close(reader);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	if (!ok) {
		size_t len;
		const char *err = ruleset_geterror(r, &len);
		LOGW_F("ruleset update: %s", err);
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_FINISH(ctx->parser.wbuf);
		BUF_APPEND(ctx->parser.wbuf, err, len);
		BUF_APPENDSTR(ctx->parser.wbuf, "\n");
		return false;
	}
	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
	RESPHDR_FINISH(ctx->parser.wbuf);
	const ev_tstamp end = ev_time();
	FORMAT_DURATION(timecost, make_duration(end - start));
	BUF_APPENDF(ctx->parser.wbuf, "Time Cost           : %s\n", timecost);
	return true;
}

static bool handle_ruleset_gc(
	struct ev_loop *loop, struct api_ctx *restrict ctx, struct ruleset *r)
{
	const ev_tstamp start = ev_now(loop);
	struct ruleset_vmstats before;
	ruleset_vmstats(r, &before);
	const bool ok = ruleset_gc(r);
	if (!ok) {
		size_t len;
		const char *err = ruleset_geterror(r, &len);
		LOGW_F("ruleset gc: %s", err);
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
		RESPHDR_FINISH(ctx->parser.wbuf);
		BUF_APPEND(ctx->parser.wbuf, err, len);
		BUF_APPENDSTR(ctx->parser.wbuf, "\n");
		return false;
	}
	struct ruleset_vmstats vmstats;
	ruleset_vmstats(r, &vmstats);
	FORMAT_BYTES(allocated, (double)vmstats.byt_allocated);
	FORMAT_SI(objects, (double)vmstats.num_object);
	const ev_tstamp end = ev_time();
	FORMAT_DURATION(timecost, make_duration(end - start));
	RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
	RESPHDR_CPLAINTEXT(ctx->parser.wbuf);
	RESPHDR_FINISH(ctx->parser.wbuf);
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);

	FORMAT_BYTES(
		freed_bytes,
		(double)((intmax_t)vmstats.byt_allocated - (intmax_t)before.byt_allocated));
	FORMAT_SI(
		freed_objects,
		(double)((intmax_t)vmstats.num_object - (intmax_t)before.num_object));
	BUF_APPENDF(
		ctx->parser.wbuf, "%-20s: %s (%s objects)\n", "Difference",
		freed_bytes, freed_objects);
	append_memstats((struct buffer *)&ctx->parser.wbuf, &vmstats);
	BUF_APPENDF(ctx->parser.wbuf, "Time Cost           : %s\n", timecost);
	return true;
}

static bool http_handle_ruleset(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	struct url *restrict uri)
{
	struct ruleset *ruleset = G.ruleset;
	if (ruleset == NULL) {
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_FINISH(ctx->parser.wbuf);
		BUF_APPENDSTR(
			ctx->parser.wbuf,
			"ruleset not enabled, restart with -r\n");
		return false;
	}

	char *segment;
	if (!url_path_segment(&uri->path, &segment)) {
		http_resp_errpage(&ctx->parser, HTTP_NOT_FOUND);
		return false;
	}
	if (strcmp(segment, "rpcall") == 0) {
		if (!restapi_check(ctx, uri, "POST", true)) {
			return false;
		}
		return handle_ruleset_rpcall(ctx, ruleset);
	}
	if (strcmp(segment, "invoke") == 0) {
		if (!restapi_check(ctx, uri, "POST", true)) {
			return false;
		}
		return handle_ruleset_invoke(loop, ctx, ruleset);
	}
	if (strcmp(segment, "update") == 0) {
		if (!restapi_check(ctx, uri, "POST", true)) {
			return false;
		}
		const char *module = NULL;
		const char *chunkname = NULL;
		while (uri->query != NULL) {
			struct url_query_component comp;
			if (!url_query_component(&uri->query, &comp)) {
				http_resp_errpage(
					&ctx->parser, HTTP_BAD_REQUEST);
				return false;
			}
			if (strcmp(comp.key, "module") == 0) {
				module = comp.value;
			} else if (strcmp(comp.key, "chunkname") == 0) {
				chunkname = comp.value;
			}
		}
		return handle_ruleset_update(
			loop, ctx, ruleset, module, chunkname);
	}
	if (strcmp(segment, "gc") == 0) {
		if (!restapi_check(ctx, uri, "POST", false)) {
			return false;
		}
		return handle_ruleset_gc(loop, ctx, ruleset);
	}

	http_resp_errpage(&ctx->parser, HTTP_NOT_FOUND);
	return false;
}
#endif

static bool api_handle(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->parser.msg;
	API_CTX_LOG_F(
		DEBUG, ctx, "http: api `%s', content %zu bytes", msg->req.url,
		ctx->parser.hdr.content.length);
	struct url uri;
	if (!url_parse(msg->req.url, &uri)) {
		API_CTX_LOG(WARNING, ctx, "failed parsing url");
		http_resp_errpage(&ctx->parser, HTTP_BAD_REQUEST);
		return false;
	}
	char *segment;
	if (!url_path_segment(&uri.path, &segment)) {
		http_resp_errpage(&ctx->parser, HTTP_BAD_REQUEST);
		return false;
	}
	if (strcmp(segment, "healthy") == 0) {
		if (!restapi_check(ctx, &uri, NULL, false)) {
			return false;
		}
		RESPHDR_BEGIN(ctx->parser.wbuf, HTTP_OK);
		RESPHDR_FINISH(ctx->parser.wbuf);
		return true;
	}
	if (strcmp(segment, "stats") == 0) {
		if (!restapi_check(ctx, &uri, NULL, false)) {
			return false;
		}
		return http_handle_stats(loop, ctx, &uri);
	}
#if WITH_RULESET
	if (strcmp(segment, "ruleset") == 0) {
		return http_handle_ruleset(loop, ctx, &uri);
	}
#endif
	http_resp_errpage(&ctx->parser, HTTP_NOT_FOUND);
	return false;
}

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);

static void api_ctx_stop(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);
#if WITH_RULESET
	if (ctx->rpcstate != NULL) {
		ruleset_cancel(ctx->rpcstate);
		ctx->rpcstate = NULL;
	}
#endif

	struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_REQUEST:
	case STATE_YIELD:
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		break;
	}
	API_CTX_LOG_F(DEBUG, ctx, "closed, %zu active", stats->num_sessions);
}

static void api_ctx_close(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	API_CTX_LOG_F(VERBOSE, ctx, "close, state=%d", ctx->state);
	api_ctx_stop(loop, ctx);

	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	session_del(&ctx->ss);
	free(ctx);
}

static void
api_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct api_ctx *restrict ctx =
		DOWNCAST(struct session, struct api_ctx, ss, ss);
	api_ctx_close(loop, ctx);
}

void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct api_ctx *restrict ctx = watcher->data;

	const int want = http_parser_recv(&ctx->parser);
	if (want < 0) {
		api_ctx_close(loop, ctx);
		return;
	}
	if (want > 0) {
		return;
	}
	ev_io_stop(loop, watcher);
	switch (ctx->parser.state) {
	case STATE_PARSE_OK: {
		ctx->s->stats.num_request++;
		const bool ok = api_handle(loop, ctx);
		if (ok) {
			ctx->s->stats.num_success++;
		}
	} break;
	case STATE_PARSE_ERROR:
		http_resp_errpage(&ctx->parser, ctx->parser.http_status);
		break;
	default:
		FAIL();
	}
	switch (ctx->state) {
	case STATE_YIELD:
		break;
	case STATE_REQUEST:
		ctx->state = STATE_RESPONSE;
		/* fallthrough */
	case STATE_RESPONSE:
		ev_io_start(loop, &ctx->w_send);
		break;
	default:
		FAIL();
	}
}

void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct api_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE);

	const int fd = watcher->fd;
	const unsigned char *buf = ctx->parser.wbuf.data + ctx->parser.wpos;
	size_t len = ctx->parser.wbuf.len - ctx->parser.wpos;
	int err = socket_send(fd, buf, &len);
	if (err != 0) {
		API_CTX_LOG_F(
			WARNING, ctx, "send: fd=%d %s", fd, strerror(err));
		api_ctx_close(loop, ctx);
		return;
	}
	ctx->parser.wpos += len;
	if (ctx->parser.wpos < ctx->parser.wbuf.len) {
		return;
	}

	if (ctx->parser.cbuf != NULL) {
		const struct vbuffer *restrict cbuf = ctx->parser.cbuf;
		buf = cbuf->data + ctx->parser.cpos;
		len = cbuf->len - ctx->parser.cpos;
		err = socket_send(watcher->fd, buf, &len);
		if (err != 0) {
			API_CTX_LOG_F(
				WARNING, ctx, "send: fd=%d %s", fd,
				strerror(err));
			api_ctx_close(loop, ctx);
			return;
		}
		ctx->parser.cpos += len;
		if (ctx->parser.cpos < cbuf->len) {
			return;
		}
	}

	/* Connection: close */
	api_ctx_close(loop, ctx);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct api_ctx *restrict ctx = watcher->data;
	api_ctx_close(loop, ctx);
}

static bool parse_header(void *ctx, const char *key, char *value)
{
	struct http_parser *restrict p = &((struct api_ctx *)ctx)->parser;

	/* hop-by-hop headers */
	if (strcasecmp(key, "Connection") == 0) {
		p->hdr.connection = strtrimspace(value);
		return true;
	}
	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(p, value);
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

	/* request headers */
	if (strcasecmp(key, "Accept-Encoding") == 0) {
		return parsehdr_accept_encoding(p, value);
	}
	if (strcasecmp(key, "Expect") == 0) {
		value = strtrimspace(value);
		if (strcasecmp(value, "100-continue") != 0) {
			p->http_status = HTTP_EXPECTATION_FAILED;
			return false;
		}
		p->expect_continue = true;
		return true;
	}

	LOGV_F("unknown http header: `%s' = `%s'", key, value);
	return true;
}

static struct api_ctx *api_ctx_new(struct server *restrict s, const int fd)
{
	struct api_ctx *restrict ctx = malloc(sizeof(struct api_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = s;
	ctx->state = STATE_INIT;
	ctx->accepted_fd = fd;
	ctx->dialed_fd = -1;

	{
		struct ev_timer *restrict w_timeout = &ctx->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, G.conf->timeout, 0.0);
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
#if WITH_RULESET
	ctx->rpcstate = NULL;
#endif
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	http_parser_init(&ctx->parser, fd, STATE_PARSE_REQUEST, on_header);
	ctx->ss.close = api_ss_close;
	session_add(&ctx->ss);
	return ctx;
}

static void api_ctx_start(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_start(loop, &ctx->w_timeout);

	ctx->state = STATE_REQUEST;
}

void api_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct api_ctx *restrict ctx = api_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		CLOSE_FD(accepted_fd);
		return;
	}
	copy_sa(&ctx->accepted_sa.sa, accepted_sa);
	api_ctx_start(loop, ctx);
}
