#include "http_impl.h"
#include "net/url.h"
#include "utils/formats.h"
#include "utils/slog.h"
#include "ruleset.h"

static void handle_ruleset_stats(struct http_ctx *restrict ctx, const double dt)
{
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset == NULL) {
		return;
	}
	const size_t heap_bytes = ruleset_memused(ruleset);
	char heap_total[16];
	(void)format_iec_bytes(
		heap_total, sizeof(heap_total), (double)heap_bytes);
	BUF_APPENDF(ctx->wbuf, "Ruleset Memory      : %s\n", heap_total);
	const char *str = ruleset_stats(ruleset, dt);
	if (str == NULL) {
		return;
	}
	BUF_APPENDF(
		ctx->wbuf,
		"\n"
		"Ruleset Stats\n"
		"================\n"
		"%s\n",
		str);
}

static void http_handle_stats(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	struct url *restrict uri)
{
	struct http_message *restrict hdr = &ctx->http_msg;
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
	if (strcmp(hdr->req.method, "GET") == 0) {
		RESPHDR_GET(ctx->wbuf, HTTP_OK);
		stateless = true;
	} else if (strcmp(hdr->req.method, "POST") == 0) {
		RESPHDR_POST(ctx->wbuf, HTTP_OK);
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

	const struct server *restrict s_ = ctx->s->data;
	const struct server_stats *restrict stats = &s_->stats;
	const struct listener_stats *restrict lstats = &s_->l.stats;
	const ev_tstamp now = ev_now(loop);
	const double uptime = now - stats->started;
	const time_t server_time = time(NULL);

	char timestamp[32];
	(void)strftime(
		timestamp, sizeof(timestamp), "%FT%T%z",
		localtime(&server_time));
	char str_uptime[16];
	(void)format_duration(
		str_uptime, sizeof(str_uptime), make_duration(uptime));

	const uintmax_t num_reject = lstats->num_accept - lstats->num_serve;

#define FORMAT_BYTES(name, value)                                              \
	char name[16];                                                         \
	(void)format_iec_bytes(name, sizeof(name), (value))

	FORMAT_BYTES(xfer_up, (double)stats->byt_up);
	FORMAT_BYTES(xfer_down, (double)stats->byt_down);

	BUF_APPENDF(
		ctx->wbuf,
		"Server Time         : %s\n"
		"Uptime              : %s\n"
		"Num Sessions        : %zu (+%zu)\n"
		"Listener Accepts    : %ju (+%ju rejected)\n"
		"Requests            : %ju (+%ju)\n"
		"Traffic             : Up %s, Down %s\n",
		timestamp, str_uptime, stats->num_sessions, stats->num_halfopen,
		lstats->num_serve, num_reject, stats->num_success,
		stats->num_request - stats->num_success, xfer_up, xfer_down);

	if (stateless) {
		return;
	}

	static struct {
		uintmax_t num_success;
		uintmax_t xfer_up, xfer_down;
		uintmax_t num_accept;
		uintmax_t num_reject;
		ev_tstamp tstamp;
	} last = { .tstamp = TSTAMP_NIL };

	const double dt =
		(last.tstamp == TSTAMP_NIL) ? uptime : now - last.tstamp;

	FORMAT_BYTES(xfer_rate_up, (double)(stats->byt_up - last.xfer_up) / dt);
	FORMAT_BYTES(
		xfer_rate_down,
		(double)(stats->byt_down - last.xfer_down) / dt);

	const double accept_rate =
		(double)(lstats->num_accept - last.num_accept) / dt;
	const double reject_rate = (double)(num_reject - last.num_reject) / dt;

	const double success_rate =
		(double)(stats->num_success - last.num_success) / dt;

	BUF_APPENDF(
		ctx->wbuf,
		"Incoming Conns      : %.1f/s (%+.1f/s rejected)\n"
		"Request Success     : %.1f/s\n"
		"Bandwidth           : Up %s/s, Down %s/s\n",
		accept_rate, reject_rate, success_rate, xfer_rate_up,
		xfer_rate_down);

	last.num_success = stats->num_success;
	last.xfer_up = stats->byt_up;
	last.xfer_down = stats->byt_down;
	last.num_accept = lstats->num_accept;
	last.num_reject = num_reject;
	last.tstamp = now;

#undef FORMAT_BYTES

	handle_ruleset_stats(ctx, dt);
}

static bool http_leafnode_check(
	struct http_ctx *restrict ctx, struct url *restrict uri,
	const char *method, const bool require_content)
{
	if (uri->path != NULL) {
		http_resp_errpage(ctx, HTTP_NOT_FOUND);
		return false;
	}
	const struct http_message *restrict hdr = &ctx->http_msg;
	if (method != NULL && strcmp(hdr->req.method, method) != 0) {
		http_resp_errpage(ctx, HTTP_METHOD_NOT_ALLOWED);
		return false;
	}
	if (require_content && ctx->content == NULL) {
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return false;
	}
	return true;
}

static void http_handle_ruleset(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	struct url *restrict uri)
{
	UNUSED(loop);
	struct ruleset *ruleset = ctx->s->ruleset;
	if (ruleset == NULL) {
		RESPHDR_POST(ctx->wbuf, HTTP_INTERNAL_SERVER_ERROR);
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
		const char *code = (const char *)ctx->content;
		const size_t len = ctx->content_length;
		LOG_TXT(LOG_LEVEL_VERBOSE, code, len, "api: ruleset invoke");
		const char *err = ruleset_invoke(ruleset, code, len);
		if (err != NULL) {
			RESPHDR_POST(ctx->wbuf, HTTP_INTERNAL_SERVER_ERROR);
			BUF_APPENDSTR(ctx->wbuf, err);
			return;
		}
		RESPHDR_WRITE(ctx->wbuf, HTTP_OK, "");
		return;
	}
	if (strcmp(segment, "update") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		const char *code = (const char *)ctx->content;
		const size_t len = ctx->content_length;
		LOG_TXT(LOG_LEVEL_VERBOSE, code, len, "api: ruleset update");
		const char *err = ruleset_load(ruleset, code, len);
		if (err != NULL) {
			RESPHDR_POST(ctx->wbuf, HTTP_INTERNAL_SERVER_ERROR);
			BUF_APPENDSTR(ctx->wbuf, err);
			return;
		}
		RESPHDR_WRITE(ctx->wbuf, HTTP_OK, "");
		return;
	}
	if (strcmp(segment, "gc") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", false)) {
			return;
		}
		ruleset_gc(ruleset);
		const size_t livemem = ruleset_memused(ruleset);
		char buf[16];
		(void)format_iec_bytes(buf, sizeof(buf), (double)livemem);
		RESPHDR_POST(ctx->wbuf, HTTP_OK);
		BUF_APPENDF(ctx->wbuf, "Ruleset Live Memory: %s\n", buf);
		return;
	}

	http_resp_errpage(ctx, HTTP_NOT_FOUND);
}

void http_handle_api(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict hdr = &ctx->http_msg;
	struct url uri;
	if (!url_parse(hdr->req.url, &uri)) {
		HTTP_CTX_LOG(LOG_LEVEL_WARNING, ctx, "failed parsing url");
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
		RESPHDR_WRITE(ctx->wbuf, HTTP_OK, "");
		return;
	}
	if (strcmp(segment, "stats") == 0) {
		if (!http_leafnode_check(ctx, &uri, NULL, false)) {
			return;
		}
		http_handle_stats(loop, ctx, &uri);
		return;
	}
	if (strcmp(segment, "ruleset") == 0) {
		http_handle_ruleset(loop, ctx, &uri);
		return;
	}
	http_resp_errpage(ctx, HTTP_NOT_FOUND);
}
