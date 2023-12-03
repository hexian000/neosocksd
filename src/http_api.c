/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "http_impl.h"
#include "net/http.h"
#include "net/url.h"
#include "utils/formats.h"
#include "utils/posixtime.h"
#include "utils/slog.h"
#include "resolver.h"
#include "ruleset.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RESPHDR_CONTENTTEXT(buf)                                               \
	BUF_APPENDCONST(                                                       \
		(buf), "Content-Type: text/plain; charset=utf-8\r\n"           \
		       "X-Content-Type-Options: nosniff\r\n")

#define RESPHDR_CONTENTTYPE(buf, type)                                         \
	BUF_APPENDF((buf), "Content-Type: %s\r\n", (type))

#define RESPHDR_CONTENTLENGTH(buf, len)                                        \
	BUF_APPENDF((buf), "Content-Length: %zu\r\n", (len))

#define RESPHDR_NOCACHE(buf)                                                   \
	BUF_APPENDCONST((buf), "Cache-Control: no-store\r\n")

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

static void server_stats(
	struct http_ctx *restrict ctx, const struct server *restrict s,
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
		ctx->wbuf,
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
			ctx->wbuf,
			"Ruleset Memory      : %s (%zu objects)\n"
			"Async Routines      : %zu\n",
			heap_total, vmstats.num_object, vmstats.num_routines);
	}
#endif
}

static void server_stats_stateful(
	struct http_ctx *restrict ctx, const struct server *restrict s,
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
		ctx->wbuf,
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
	const struct http_message *restrict msg = &ctx->http.msg;
	bool banner = true;
	while (uri->query != NULL) {
		char *key, *value;
		if (!url_query_component(&uri->query, &key, &value)) {
			http_resp_errpage(ctx, HTTP_BAD_REQUEST);
			return;
		}
		if (strcmp(key, "banner") == 0) {
			if (strcmp(value, "no") == 0) {
				banner = false;
			}
		}
	}

	bool stateless;
	if (strcmp(msg->req.method, "GET") == 0) {
		RESPHDR_BEGIN(ctx->wbuf, HTTP_OK);
		RESPHDR_CONTENTTEXT(ctx->wbuf);
		RESPHDR_NOCACHE(ctx->wbuf);
		RESPHDR_FINISH(ctx->wbuf);
		stateless = true;
	} else if (strcmp(msg->req.method, "POST") == 0) {
		RESPHDR_BEGIN(ctx->wbuf, HTTP_OK);
		RESPHDR_CONTENTTEXT(ctx->wbuf);
		RESPHDR_FINISH(ctx->wbuf);
		stateless = false;
	} else {
		http_resp_errpage(ctx, HTTP_METHOD_NOT_ALLOWED);
		return;
	}

	if (banner) {
		BUF_APPENDCONST(
			ctx->wbuf, PROJECT_NAME " " PROJECT_VER "\n"
						"  " PROJECT_HOMEPAGE "\n\n");
	}

	const ev_tstamp now = ev_now(loop);
	const double uptime = ev_now(loop) - ctx->s->stats.started;
	server_stats(ctx, ctx->s->data, uptime);

	if (stateless) {
		return;
	}
	static ev_tstamp last = TSTAMP_NIL;
	const double dt = (last == TSTAMP_NIL) ? uptime : now - last;
	last = now;

	server_stats_stateful(ctx, ctx->s->data, dt);
#if WITH_RULESET
	if (G.ruleset != NULL) {
		const char *str = ruleset_stats(G.ruleset, dt);
		BUF_APPENDF(
			ctx->wbuf,
			"\n"
			"Ruleset Stats\n"
			"================\n"
			"%s\n",
			str != NULL ? str : ruleset_error(G.ruleset));
	}
#endif
}

static bool http_leafnode_check(
	struct http_ctx *restrict ctx, const struct url *restrict uri,
	const char *method, const bool require_content)
{
	if (uri->path != NULL) {
		http_resp_errpage(ctx, HTTP_NOT_FOUND);
		return false;
	}
	const struct http_message *restrict msg = &ctx->http.msg;
	if (method != NULL && strcmp(msg->req.method, method) != 0) {
		http_resp_errpage(ctx, HTTP_METHOD_NOT_ALLOWED);
		return false;
	}
	if (require_content && ctx->cbuf == NULL) {
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return false;
	}
	return true;
}

#if WITH_RULESET
static void http_handle_ruleset(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	struct url *restrict uri)
{
	UNUSED(loop);
	struct ruleset *ruleset = G.ruleset;
	if (ruleset == NULL) {
		RESPHDR_BEGIN(ctx->wbuf, HTTP_INTERNAL_SERVER_ERROR);
		RESPHDR_FINISH(ctx->wbuf);
		BUF_APPENDF(
			ctx->wbuf, "%s",
			"ruleset not enabled, restart with -r\n");
		return;
	}

	char *segment;
	if (!url_path_segment(&uri->path, &segment)) {
		http_resp_errpage(ctx, HTTP_NOT_FOUND);
		return;
	}
	if (strcmp(segment, "invoke") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		const char *code = (const char *)ctx->cbuf->data;
		const size_t len = ctx->http.content_length;
		LOG_TXT_F(
			VERBOSE, code, len, "api: ruleset invoke %zu bytes",
			len);
		const bool ok = ruleset_invoke(ruleset, code, len);
		if (!ok) {
			const char *err = ruleset_error(ruleset);
			LOGW_F("ruleset invoke: %s", err);
			RESPHDR_BEGIN(ctx->wbuf, HTTP_INTERNAL_SERVER_ERROR);
			RESPHDR_CONTENTTEXT(ctx->wbuf);
			RESPHDR_FINISH(ctx->wbuf);
			BUF_APPENDSTR(ctx->wbuf, err);
			BUF_APPENDCONST(ctx->wbuf, "\n");
			return;
		}
		RESPHDR_BEGIN(ctx->wbuf, HTTP_OK);
		RESPHDR_FINISH(ctx->wbuf);
		return;
	} else if (strcmp(segment, "update") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		const char *module = NULL;
		while (uri->query != NULL) {
			char *key, *value;
			if (!url_query_component(&uri->query, &key, &value)) {
				http_resp_errpage(ctx, HTTP_BAD_REQUEST);
				return;
			}
			if (strcmp(key, "module") == 0) {
				module = value;
			}
		}
		const char *code = (const char *)ctx->cbuf->data;
		const size_t len = ctx->http.content_length;
		LOG_TXT(VERBOSE, code, len, "api: ruleset update");
		const bool ok = ruleset_update(ruleset, module, code, len);
		if (!ok) {
			const char *err = ruleset_error(ruleset);
			LOGW_F("ruleset update: %s", err);
			RESPHDR_BEGIN(ctx->wbuf, HTTP_INTERNAL_SERVER_ERROR);
			RESPHDR_CONTENTTEXT(ctx->wbuf);
			RESPHDR_FINISH(ctx->wbuf);
			BUF_APPENDSTR(ctx->wbuf, err);
			BUF_APPENDCONST(ctx->wbuf, "\n");
			return;
		}
		RESPHDR_BEGIN(ctx->wbuf, HTTP_OK);
		RESPHDR_FINISH(ctx->wbuf);
		return;
	} else if (strcmp(segment, "gc") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", false)) {
			return;
		}
		const int64_t start = clock_monotonic();
		ruleset_gc(ruleset);
		struct ruleset_vmstats mem;
		ruleset_vmstats(ruleset, &mem);
		char livemem[16];
		(void)format_iec_bytes(
			livemem, sizeof(livemem), (double)mem.byt_allocated);
		char timecost[16];
		(void)format_duration(
			timecost, sizeof(timecost),
			make_duration_nanos(clock_monotonic() - start));
		RESPHDR_BEGIN(ctx->wbuf, HTTP_OK);
		RESPHDR_CONTENTTEXT(ctx->wbuf);
		RESPHDR_FINISH(ctx->wbuf);
		BUF_APPENDF(
			ctx->wbuf,
			"Num Live Object     : %zu\n"
			"Ruleset Live Memory : %s\n"
			"Time Cost           : %s\n",
			mem.num_object, livemem, timecost);
		return;
	} else if (strcmp(segment, "rpcall") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		if (ctx->http.content_type == NULL ||
		    strcasecmp(ctx->http.content_type, MIME_RPCALL) != 0) {
			LOGD_F("rpcall: invalid content type \"%s\"",
			       ctx->http.content_type);
			RESPHDR_BEGIN(ctx->wbuf, HTTP_BAD_REQUEST);
			RESPHDR_CONTENTTEXT(ctx->wbuf);
			RESPHDR_FINISH(ctx->wbuf);
			return;
		}
		if (ctx->http.content_encoding != NULL) {
			LOGD_F("rpcall: invalid content encoding \"%s\"",
			       ctx->http.content_encoding);
			RESPHDR_BEGIN(ctx->wbuf, HTTP_BAD_REQUEST);
			RESPHDR_CONTENTTEXT(ctx->wbuf);
			RESPHDR_FINISH(ctx->wbuf);
			return;
		}
		const char *code = (const char *)ctx->cbuf->data;
		size_t len = ctx->http.content_length;
		LOG_TXT_F(
			VERBOSE, code, len, "api: ruleset rpcall %zu bytes",
			len);
		const char *result;
		const bool ok =
			ruleset_rpcall(ruleset, code, len, &result, &len);
		if (!ok) {
			const char *err = ruleset_error(ruleset);
			LOGW_F("ruleset rpcall: %s", err);
			len = strlen(err);
			RESPHDR_BEGIN(ctx->wbuf, HTTP_INTERNAL_SERVER_ERROR);
			RESPHDR_CONTENTTYPE(ctx->wbuf, MIME_RPCALL);
			RESPHDR_CONTENTLENGTH(ctx->wbuf, len);
			RESPHDR_FINISH(ctx->wbuf);
			BUF_APPEND(ctx->wbuf, err, len);
			return;
		}
		RESPHDR_BEGIN(ctx->wbuf, HTTP_OK);
		RESPHDR_CONTENTTYPE(ctx->wbuf, MIME_RPCALL);
		RESPHDR_CONTENTLENGTH(ctx->wbuf, len);
		RESPHDR_FINISH(ctx->wbuf);
		LOG_BIN_F(
			VERBOSE, result, len,
			"api: ruleset rpcall result %zu bytes", len);
		BUF_APPENDSTR(ctx->wbuf, result);
		BUF_APPENDCONST(ctx->wbuf, "\n");
		return;
	}

	http_resp_errpage(ctx, HTTP_NOT_FOUND);
}
#endif

void http_handle_api(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->http.msg;
	HTTP_CTX_LOG_F(DEBUG, ctx, "http: api \"%s\"", msg->req.url);
	struct url uri;
	if (!url_parse(msg->req.url, &uri)) {
		HTTP_CTX_LOG(WARNING, ctx, "failed parsing url");
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return;
	}
	char *segment;
	if (!url_path_segment(&uri.path, &segment)) {
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return;
	}
	if (strcmp(segment, "healthy") == 0) {
		if (!http_leafnode_check(ctx, &uri, NULL, false)) {
			return;
		}
		RESPHDR_BEGIN(ctx->wbuf, HTTP_OK);
		RESPHDR_FINISH(ctx->wbuf);
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
	http_resp_errpage(ctx, HTTP_NOT_FOUND);
}
