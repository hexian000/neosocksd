/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "api_server.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "resolver.h"
#include "ruleset.h"
#include "server.h"
#include "util.h"

#include "io/io.h"
#include "io/memory.h"
#include "io/stream.h"
#include "net/http.h"
#include "net/mime.h"
#include "net/url.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/arraysize.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/formats.h"
#include "utils/gc.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

/* State machine progression - never rollback to previous states */
enum api_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_PROCESS,
	STATE_RESPONSE,
};

struct api_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum api_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	ev_timer w_timeout;
	ev_io w_recv, w_send;
#if WITH_RULESET
	ev_idle w_process;
	struct ruleset_callback rpcreturn;
	struct ruleset_state *rpcstate;
#endif
	struct dialreq *dialreq;
	struct http_conn conn;
	struct url uri;
	bool keepalive : 1;
};
ASSERT_SUPER(struct gcbase, struct api_ctx, gcbase);

#define API_CTX_LOG_F(level, ctx, format, ...)                                 \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char caddr[64];                                                \
		sa_format(caddr, sizeof(caddr), &(ctx)->accepted_sa.sa);       \
		LOG_F(level, "[fd:%d] %s: " format, (ctx)->accepted_fd, caddr, \
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
#endif

static int comp_intleast64(const void *a, const void *b)
{
	const int_least64_t va = *(const int_least64_t *)a;
	const int_least64_t vb = *(const int_least64_t *)b;
	if (va < vb) {
		return -1;
	}
	if (va > vb) {
		return 1;
	}
	return 0;
}

struct percentiles {
	int_least64_t p50, p90, p99, pmax;
};

static struct percentiles calc_percentiles(
	const size_t num_stats, const size_t num_samples,
	const int_least64_t *stats)
{
	const size_t n = MIN(num_stats, num_samples);
	int_least64_t samples[n];
	for (size_t i = 0; i < n; i++) {
		const size_t idx =
			(num_samples + num_stats - i - 1) % num_stats;
		samples[i] = stats[idx];
	}
	qsort(samples, n, sizeof(int_least64_t), comp_intleast64);
	const int i50 = (int)floor((double)n * 0.50);
	const int i90 = (int)floor((double)n * 0.90);
	const int i99 = (int)floor((double)n * 0.99);
	return (struct percentiles){
		.p50 = samples[i50],
		.p90 = samples[i90],
		.p99 = samples[i99],
		.pmax = samples[n - 1],
	};
}

#if WITH_RULESET
static void append_vmstats(
	struct stream *restrict w, const struct ruleset_vmstats *vm,
	const struct config *restrict conf)
{
	FORMAT_BYTES(allocated, (double)vm->byt_allocated);
	FORMAT_SI(objects, (double)vm->num_object);

	const int memlimit_mb = conf->memlimit;
	if (memlimit_mb > 0) {
		FORMAT_BYTES(memlimit, ((double)memlimit_mb) * 0x1p20);
		(void)io_bufprintf(
			w, "%-20s: %s < %s (%s objects)\n", "Ruleset Allocated",
			allocated, memlimit, objects);
	} else {
		(void)io_bufprintf(
			w, "%-20s: %s (%s objects)\n", "Ruleset Allocated",
			allocated, objects);
	}
	(void)io_bufprintf(
		w, "%-20s: %zu (peak %zu)\n", "Ruleset Threads",
		vm->num_thread_active, vm->num_thread_peak);

	if (vm->num_events == 0) {
		(void)io_bufprintf(
			w, "%-20s: %s\n", "Ruleset Events", "(never)");
		return;
	}

	const struct percentiles p = calc_percentiles(
		ARRAY_SIZE(vm->event_ns), vm->num_events, vm->event_ns);
	FORMAT_DURATION(p50_str, make_duration_nanos(p.p50));
	FORMAT_DURATION(p90_str, make_duration_nanos(p.p90));
	FORMAT_DURATION(p99_str, make_duration_nanos(p.p99));
	FORMAT_DURATION(pmax_str, make_duration_nanos(p.pmax));
	(void)io_bufprintf(
		w, "%-20s: P50=%s P90=%s P99=%s MAX=%s\n", "Ruleset Events",
		p50_str, p90_str, p99_str, pmax_str);
}

#endif

static double process_load(void)
{
	static struct {
		struct timespec monotime, cputime;
		bool set;
	} last = { .set = false };
	double load = -1;
	struct timespec monotime, cputime;
	if (!clock_monotonic(&monotime)) {
		return load;
	}
	if (!clock_process(&cputime)) {
		return load;
	}
	if (last.set) {
		const int_least64_t total =
			TIMESPEC_DIFF(monotime, last.monotime);
		const int_least64_t busy = TIMESPEC_DIFF(cputime, last.cputime);
		if (busy > 0 && total > 0) {
			load = (double)busy / (double)total;
		}
	}
	last.monotime = monotime;
	last.cputime = cputime;
	last.set = true;
	return load;
}

static void server_stats_stateful(
	struct stream *restrict w, const struct server *restrict api,
	const double dt)
{
	const struct server *restrict s = api->data;
	struct server_stats agg;
	server_stats(s, &agg);

	/* Static counters for rate calculation between calls */
	static struct {
		uint_least64_t xfer_up, xfer_down;
		uint_least64_t num_accept;
		uint_least64_t num_reject;
		uint_least64_t num_request;
		uint_least64_t num_api_request;
		uint_least64_t num_reject_ruleset;
		uint_least64_t num_reject_timeout;
		uint_least64_t num_reject_upstream;
	} last = { 0 };

	FORMAT_BYTES(xfer_rate_up, (double)(agg.byt_up - last.xfer_up) / dt);
	FORMAT_BYTES(
		xfer_rate_down, (double)(agg.byt_down - last.xfer_down) / dt);

	const uint_least64_t num_reject = agg.num_accept - agg.num_serve;
	const double accept_rate =
		(double)(agg.num_accept - last.num_accept) / dt;
	const double reject_rate = (double)(num_reject - last.num_reject) / dt;
	const double request_rate =
		(double)(agg.num_request - last.num_request) / dt;
	const double api_request_rate =
		(double)(api->stats.num_api_request - last.num_api_request) /
		dt;
	const double reject_ruleset_rate =
		(double)(agg.num_reject_ruleset - last.num_reject_ruleset) / dt;
	const double reject_timeout_rate =
		(double)(agg.num_reject_timeout - last.num_reject_timeout) / dt;
	const double reject_upstream_rate =
		(double)(agg.num_reject_upstream - last.num_reject_upstream) /
		dt;

	char load_str[16] = "(unknown)";
	const double load = process_load();
	if (load >= 0) {
		(void)snprintf(
			load_str, sizeof(load_str), "%.03f%%", load * 100);
	}
	FORMAT_DURATION(dt_str, make_duration(dt));

	(void)io_bufprintf(
		w,
		"Accept Rate         : %.1f/s (%+.1f/s)\n"
		"Request Rate        : %.1f/s (API%+.1f/s)\n"
		"Reject Rate         : ruleset=%.1f/s, timeout=%.1f/s, upstream=%.1f/s\n"
		"Throughput          : Up %s/s, Down %s/s\n"
		"Server Load         : %s (last %s)\n",
		accept_rate, reject_rate, request_rate, api_request_rate,
		reject_ruleset_rate, reject_timeout_rate, reject_upstream_rate,
		xfer_rate_up, xfer_rate_down, load_str, dt_str);

	last.xfer_up = agg.byt_up;
	last.xfer_down = agg.byt_down;
	last.num_accept = agg.num_accept;
	last.num_reject = num_reject;
	last.num_request = agg.num_request;
	last.num_api_request = api->stats.num_api_request;
	last.num_reject_ruleset = agg.num_reject_ruleset;
	last.num_reject_timeout = agg.num_reject_timeout;
	last.num_reject_upstream = agg.num_reject_upstream;
}

static void append_server_stats(
	struct stream *restrict w, const struct server *restrict api,
	const int_fast64_t uptime, const double dt, const bool runtime)
{
	const struct server_stats *restrict apistats = &api->stats;
	const struct server *restrict s = api->data;
	struct server_stats agg;
	server_stats(s, &agg);
	const struct resolver_stats *restrict resolv_stats =
		resolver_stats(s->resolver);

	const time_t server_time = time(NULL);
	char timestamp[32] = "(unknown)";
	if (server_time != (time_t)-1) {
		(void)format_rfc3339(
			timestamp, sizeof(timestamp), server_time, false);
	}
	FORMAT_DURATION(str_uptime, make_duration_nanos(uptime));
	FORMAT_BYTES(xfer_up, (double)agg.byt_up);
	FORMAT_BYTES(xfer_down, (double)agg.byt_down);
	FORMAT_BYTES(hs_crx, (double)agg.byt_client_recv);
	FORMAT_BYTES(hs_ctx, (double)agg.byt_client_send);
	FORMAT_BYTES(hs_drx, (double)agg.byt_dial_recv);
	FORMAT_BYTES(hs_dtx, (double)agg.byt_dial_send);
	FORMAT_BYTES(api_recv, (double)apistats->api_byt_recv);
	FORMAT_BYTES(api_send, (double)apistats->api_byt_send);

	(void)io_bufprintf(
		w,
		"Server Time         : %s\n"
		"Uptime              : %s\n"
		"Num Sessions        : %zu (+%zu) peak=%zu\n"
		"Num Rejected        : ruleset=%" PRIuLEAST64
		", timeout=%" PRIuLEAST64 ", upstream=%" PRIuLEAST64 "\n"
		"Conn Accepts        : %" PRIuLEAST64 " (+%" PRIuLEAST64 ")\n"
		"Name Resolves       : %" PRIuLEAST64 " (+%" PRIuLEAST64 ")\n"
		"Requests            : %" PRIuLEAST64 " (+%" PRIuLEAST64
		"), Rx %s, Tx %s\n"
		"API Requests        : %" PRIuLEAST64 " (+%" PRIuLEAST64
		"), Rx %s, Tx %s\n"
		"Handshake Dial      : Rx %s, Tx %s\n"
		"Traffic             : Up %s, Down %s\n",
		/* Server Time, Uptime */
		timestamp, str_uptime,
		/* Num Sessions */
		agg.num_sessions, agg.num_halfopen, agg.num_sessions_peak,
		/* Num Rejected */
		agg.num_reject_ruleset, agg.num_reject_timeout,
		agg.num_reject_upstream,
		/* Conn Accepts */
		agg.num_serve, agg.num_accept - agg.num_serve,
		/* Name Resolves */
		resolv_stats->num_success,
		resolv_stats->num_query - resolv_stats->num_success,
		/* Requests */
		agg.num_success, agg.num_request - agg.num_success, hs_crx,
		hs_ctx,
		/* API Requests */
		apistats->num_api_success,
		apistats->num_api_request - apistats->num_api_success, api_recv,
		api_send,
		/* Handshake Dial */
		hs_drx, hs_dtx,
		/* Traffic */
		xfer_up, xfer_down);

#if WITH_RULESET
	{
		FORMAT_BYTES(cli_recv, (double)agg.api_client_byt_recv);
		FORMAT_BYTES(cli_send, (double)agg.api_client_byt_send);
		(void)io_bufprintf(
			w,
			"API Client          : %" PRIuLEAST64
			" reqs, Rx %s, Tx %s\n",
			agg.num_api_client_request, cli_recv, cli_send);
	}
#endif

#if WITH_RULESET
	const struct ruleset *ruleset = s->ruleset;
	if (ruleset != NULL && runtime) {
		struct ruleset_vmstats vmstats;
		ruleset_vmstats(ruleset, &vmstats);
		append_vmstats(w, &vmstats, s->conf);
	}
#else
	UNUSED(runtime);
#endif

	if (agg.num_connects > 0) {
		const struct percentiles p = calc_percentiles(
			ARRAY_SIZE(agg.connect_ns), agg.num_connects,
			agg.connect_ns);
		FORMAT_DURATION(p50_str, make_duration_nanos(p.p50));
		FORMAT_DURATION(p90_str, make_duration_nanos(p.p90));
		FORMAT_DURATION(p99_str, make_duration_nanos(p.p99));
		FORMAT_DURATION(pmax_str, make_duration_nanos(p.pmax));
		(void)io_bufprintf(
			w, "%-20s: P50=%s P90=%s P99=%s MAX=%s\n",
			"Connect Latency", p50_str, p90_str, p99_str, pmax_str);
	} else {
		(void)io_bufprintf(
			w, "%-20s: %s\n", "Connect Latency", "(never)");
	}

	if (dt > 0) {
		server_stats_stateful(w, api, dt);
	}
}

static bool parse_bool(const char *s)
{
	return strcmp(s, "1") == 0 || strcmp(s, "y") == 0 ||
	       strcmp(s, "yes") == 0 || strcmp(s, "on") == 0 ||
	       strcmp(s, "t") == 0 || strcmp(s, "true") == 0;
}

static void
send_response(struct ev_loop *loop, struct api_ctx *restrict ctx, const bool ok)
{
	ASSERT(ctx->conn.wbuf.len > 0);
	if (ok) {
		ctx->s->stats.num_api_success++;
	}
	ctx->state = STATE_RESPONSE;
	ev_io_start(loop, &ctx->w_send);
}

static void send_errpage(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	const uint_fast16_t code)
{
	ASSERT(4 <= (code / 100) && (code / 100) <= 5);
	ctx->keepalive = false;
	http_resp_errpage(&ctx->conn, code);
	send_response(loop, ctx, false);
}

static void
http_handle_stats(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	struct {
		bool nobanner : 1;
		bool server : 1;
		bool runtime : 1;
	} opt = { false, true, false };
#if WITH_RULESET
	const char *query = NULL;
#endif
	while (ctx->uri.query != NULL) {
		struct url_query_component comp;
		if (!url_query_component(&ctx->uri.query, &comp)) {
			send_errpage(loop, ctx, HTTP_BAD_REQUEST);
			return;
		}
		if (strcmp(comp.key, "nobanner") == 0) {
			opt.nobanner = parse_bool(comp.value);
		} else if (strcmp(comp.key, "server") == 0) {
			opt.server = parse_bool(comp.value);
		} else if (strcmp(comp.key, "runtime") == 0) {
			opt.runtime = parse_bool(comp.value);
		}
#if WITH_RULESET
		else if (strcmp(comp.key, "q") == 0) {
			query = comp.value;
		}
#endif
	}

	const struct http_message *restrict msg = &ctx->conn.msg;
	bool stateless;
	if (strcmp(msg->req.method, "GET") == 0) {
		stateless = true;
	} else if (strcmp(msg->req.method, "POST") == 0) {
		stateless = false;
	} else {
		send_errpage(loop, ctx, HTTP_METHOD_NOT_ALLOWED);
		return;
	}

	/* Use compression if client supports it */
	const enum content_encodings encoding =
		(ctx->conn.hdr.accept_encoding == CENCODING_DEFLATE) ?
			CENCODING_DEFLATE :
			CENCODING_NONE;
	struct stream *w = io_bufwriter(
		content_writer(&ctx->conn.cbuf, IO_BUFSIZE, encoding),
		IO_BUFSIZE);
	if (w == NULL) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	if (!opt.nobanner) {
		(void)io_bufprintf(
			w, "%s %s\n  %s\n\n", PROJECT_NAME, PROJECT_VER,
			PROJECT_HOMEPAGE);
	}

	const int_least64_t now = (int_least64_t)clock_monotonic_ns();
	const int_least64_t uptime = now - ctx->s->stats.started;
	/* Track time between stateful requests for rate calculations */
	static struct {
		int_least64_t tstamp;
		bool is_set : 1;
	} last = { .is_set = false };
	double dt = 0.0;
	if (!stateless) {
		dt = (double)(last.is_set ? now - last.tstamp : uptime) * 1e-9;
		last.is_set = true;
		last.tstamp = now;
	}
	if (opt.server) {
		append_server_stats(w, ctx->s, uptime, dt, opt.runtime);
	}

#if WITH_RULESET
	struct ruleset *ruleset = ctx->s->ruleset;
	if (!stateless && ruleset != NULL) {
		size_t len;
		const char *s = ruleset_stats(ruleset, dt, query, &len);
		if (s == NULL) {
			s = ruleset_geterror(ruleset, &len);
		}
		size_t n = len;
		const int err = stream_write(w, s, &n);
		if (n < len || err != 0) {
			LOGE_F("stream_write: error %d, %zu/%zu", err, n, len);
			(void)stream_close(w);
			send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}
#endif

	const int err = stream_close(w);
	if (err != 0) {
		LOGE_F("stream_close: error %d", err);
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	RESPHDR_BEGIN(ctx->conn.wbuf, HTTP_OK);
	if (ctx->keepalive) {
		RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
	} else {
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
	}
	RESPHDR_CPLAINTEXT(ctx->conn.wbuf);
	if (stateless) {
		RESPHDR_NOCACHE(ctx->conn.wbuf);
	}
	const char *encoding_str = http_content_encoding_str[encoding];
	if (encoding_str != NULL) {
		RESPHDR_CENCODING(ctx->conn.wbuf, encoding_str);
	}
	RESPHDR_CLENGTH(ctx->conn.wbuf, VBUF_LEN(ctx->conn.cbuf));
	RESPHDR_FINISH(ctx->conn.wbuf);
	send_response(loop, ctx, true);
}

static bool restapi_check(
	struct ev_loop *loop, struct api_ctx *restrict ctx, const char *method,
	const bool require_content)
{
	if (ctx->uri.path != NULL) {
		send_errpage(loop, ctx, HTTP_NOT_FOUND);
		return false;
	}
	const struct http_message *restrict msg = &ctx->conn.msg;
	if (method != NULL && strcmp(msg->req.method, method) != 0) {
		send_errpage(loop, ctx, HTTP_METHOD_NOT_ALLOWED);
		return false;
	}
	if (require_content && !ctx->conn.hdr.content.has_length) {
		send_errpage(loop, ctx, HTTP_LENGTH_REQUIRED);
		return false;
	}
	return true;
}

#if WITH_RULESET
static void send_errmsg(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	const uint_fast16_t code, const char *msg, const size_t len)
{
	if ((code / 100) >= 4) {
		ctx->keepalive = false;
	}
	VBUF_FREE(ctx->conn.cbuf);
	RESPHDR_BEGIN(ctx->conn.wbuf, code);
	if (ctx->keepalive) {
		RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
	} else {
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
	}
	RESPHDR_CPLAINTEXT(ctx->conn.wbuf);
	RESPHDR_CLENGTH(ctx->conn.wbuf, len);
	RESPHDR_FINISH(ctx->conn.wbuf);
	BUF_APPEND(ctx->conn.wbuf, msg, len);
	send_response(loop, ctx, 1 <= (code / 100) && (code / 100) <= 3);
}

#define SEND_ERRSTR(loop, ctx, str)                                            \
	send_errmsg(                                                           \
		(loop), (ctx), HTTP_INTERNAL_SERVER_ERROR, ("" str),           \
		sizeof(str) - 1)

/* Asynchronous callback for RPC call completion */
static void
rpcall_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct api_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->rpcstate = NULL;
	if (ctx->rpcreturn.rpcall.result == NULL) {
		SEND_ERRSTR(loop, ctx, "rpcall did not return");
		return;
	}
	const char *result = ctx->rpcreturn.rpcall.result;
	const size_t resultlen = ctx->rpcreturn.rpcall.resultlen;
	if (LOGLEVEL(VERBOSE)) {
		FORMAT_BYTES(clen, ctx->rpcreturn.rpcall.resultlen);
		API_CTX_LOG_F(VERBOSE, ctx, "api response: content %s", clen);
		LOG_TXT(VERYVERBOSE, result, resultlen, "rpcall result:");
	}
	/* Compress response if client supports it and payload is large enough */
	const enum content_encodings encoding =
		(ctx->conn.hdr.accept_encoding != CENCODING_DEFLATE) ||
				(resultlen < RPCALL_COMPRESS_THRESHOLD) ?
			CENCODING_NONE :
			CENCODING_DEFLATE;
	struct stream *writer =
		content_writer(&ctx->conn.cbuf, resultlen, encoding);
	if (writer == NULL) {
		LOGOOM();
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	size_t n = resultlen;
	int err = stream_write(writer, result, &n);
	if (err != 0) {
		LOGW_F("stream_write: error %d, %zu/%zu", err, n, resultlen);
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	err = stream_close(writer);
	if (err != 0) {
		LOGW_F("stream_close: error %d", err);
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	RESPHDR_BEGIN(ctx->conn.wbuf, HTTP_OK);
	if (ctx->keepalive) {
		RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
	} else {
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
	}
	RESPHDR_CTYPE(ctx->conn.wbuf, MIME_RPCALL);
	const char *encoding_str = http_content_encoding_str[encoding];
	if (encoding_str != NULL) {
		RESPHDR_CENCODING(ctx->conn.wbuf, encoding_str);
	}
	RESPHDR_CLENGTH(ctx->conn.wbuf, VBUF_LEN(ctx->conn.cbuf));
	RESPHDR_FINISH(ctx->conn.wbuf);
	send_response(loop, ctx, true);
}

static void handle_ruleset_rpcall(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	struct ruleset *ruleset)
{
	char *mime_type = ctx->conn.hdr.content.type;
	if (!check_rpcall_mime(mime_type)) {
		LOGD("rpcall: incompatible content type");
		send_errpage(loop, ctx, HTTP_BAD_REQUEST);
		return;
	}
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->conn.cbuf), VBUF_LEN(ctx->conn.cbuf),
		ctx->conn.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	ctx->state = STATE_PROCESS;
	const bool ok = ruleset_rpcall(
		ruleset, &ctx->rpcstate, reader, &ctx->rpcreturn);
	stream_close(reader);
	if (!ok) {
		/* Synchronous error - no async callback will be invoked */
		size_t len;
		const char *err = ruleset_geterror(ruleset, &len);
		LOGW_F("ruleset rpcall: %s", err);
		send_errmsg(loop, ctx, HTTP_INTERNAL_SERVER_ERROR, err, len);
		return;
	}
}

static void handle_ruleset_invoke(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	struct ruleset *ruleset)
{
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->conn.cbuf), VBUF_LEN(ctx->conn.cbuf),
		ctx->conn.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const bool ok = ruleset_invoke(ruleset, reader);
	stream_close(reader);
	VBUF_FREE(ctx->conn.cbuf);
	if (!ok) {
		size_t len;
		const char *err = ruleset_geterror(ruleset, &len);
		LOGW_F("ruleset invoke: %s", err);
		send_errmsg(loop, ctx, HTTP_INTERNAL_SERVER_ERROR, err, len);
		return;
	}
	RESPHDR_BEGIN(ctx->conn.wbuf, HTTP_OK);
	if (ctx->keepalive) {
		RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
	} else {
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
	}
	RESPHDR_CLENGTH(ctx->conn.wbuf, 0);
	RESPHDR_FINISH(ctx->conn.wbuf);
	send_response(loop, ctx, true);
}

static void handle_ruleset_update(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	struct ruleset *ruleset, const char *module, const char *chunkname)
{
	const int_fast64_t start = clock_monotonic_ns();
	struct stream *reader = content_reader(
		VBUF_DATA(ctx->conn.cbuf), VBUF_LEN(ctx->conn.cbuf),
		ctx->conn.hdr.content.encoding);
	if (reader == NULL) {
		LOGOOM();
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	const bool ok = ruleset_update(ruleset, module, chunkname, reader);
	stream_close(reader);
	VBUF_FREE(ctx->conn.cbuf);
	if (!ok) {
		size_t len;
		const char *err = ruleset_geterror(ruleset, &len);
		LOGW_F("ruleset update: %s", err);
		send_errmsg(loop, ctx, HTTP_INTERNAL_SERVER_ERROR, err, len);
		return;
	}
	const int_fast64_t end = clock_monotonic_ns();
	{
		FORMAT_DURATION(timecost, make_duration_nanos(end - start));
		char body[64];
		const int bodylen = snprintf(
			body, sizeof(body), "Time Cost           : %s\n",
			timecost);
		RESPHDR_BEGIN(ctx->conn.wbuf, HTTP_OK);
		if (ctx->keepalive) {
			RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
		} else {
			RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
		}
		RESPHDR_CPLAINTEXT(ctx->conn.wbuf);
		RESPHDR_CLENGTH(ctx->conn.wbuf, (size_t)bodylen);
		RESPHDR_FINISH(ctx->conn.wbuf);
		BUF_APPEND(ctx->conn.wbuf, body, (size_t)bodylen);
	}
	send_response(loop, ctx, true);
}

static void handle_ruleset_gc(
	struct ev_loop *loop, struct api_ctx *restrict ctx,
	struct ruleset *ruleset)
{
	struct ruleset_vmstats before;
	ruleset_vmstats(ruleset, &before);
	const int_fast64_t start = clock_monotonic_ns();
	const bool ok = ruleset_gc(ruleset);
	if (!ok) {
		size_t len;
		const char *err = ruleset_geterror(ruleset, &len);
		LOGW_F("ruleset gc: %s", err);
		send_errmsg(loop, ctx, HTTP_INTERNAL_SERVER_ERROR, err, len);
		return;
	}
	const int_fast64_t end = clock_monotonic_ns();
	struct ruleset_vmstats vmstats;
	ruleset_vmstats(ruleset, &vmstats);

	struct stream *w = io_bufwriter(
		content_writer(&ctx->conn.cbuf, IO_BUFSIZE, CENCODING_NONE),
		IO_BUFSIZE);
	if (w == NULL) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	{
		FORMAT_BYTES(
			freed_bytes, (double)((intmax_t)vmstats.byt_allocated -
					      (intmax_t)before.byt_allocated));
		FORMAT_SI(
			freed_objects, (double)((intmax_t)vmstats.num_object -
						(intmax_t)before.num_object));
		(void)io_bufprintf(
			w, "%-20s: %s (%s objects)\n", "Difference",
			freed_bytes, freed_objects);
	}
	append_vmstats(w, &vmstats, ctx->s->conf);
	{
		FORMAT_DURATION(timecost, make_duration_nanos(end - start));
		(void)io_bufprintf(w, "Time Cost           : %s\n", timecost);
	}
	{
		const int err = stream_close(w);
		if (err != 0) {
			LOGE_F("stream_close: error %d", err);
			send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
	}
	RESPHDR_BEGIN(ctx->conn.wbuf, HTTP_OK);
	if (ctx->keepalive) {
		RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
	} else {
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
	}
	RESPHDR_CPLAINTEXT(ctx->conn.wbuf);
	RESPHDR_CLENGTH(ctx->conn.wbuf, VBUF_LEN(ctx->conn.cbuf));
	RESPHDR_FINISH(ctx->conn.wbuf);
	send_response(loop, ctx, true);
}

static void
process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct api_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	struct ruleset *ruleset = ctx->s->ruleset;
	ASSERT(ruleset != NULL);

	char *segment;
	if (!url_path_segment(&ctx->uri.path, &segment)) {
		send_errpage(loop, ctx, HTTP_NOT_FOUND);
		return;
	}
	if (strcmp(segment, "rpcall") == 0) {
		if (!restapi_check(loop, ctx, "POST", true)) {
			return;
		}
		handle_ruleset_rpcall(loop, ctx, ruleset);
		return;
	}
	if (strcmp(segment, "invoke") == 0) {
		if (!restapi_check(loop, ctx, "POST", true)) {
			return;
		}
		handle_ruleset_invoke(loop, ctx, ruleset);
		return;
	}
	if (strcmp(segment, "update") == 0) {
		if (!restapi_check(loop, ctx, "POST", true)) {
			return;
		}
		const char *module = NULL;
		const char *chunkname = NULL;
		while (ctx->uri.query != NULL) {
			struct url_query_component comp;
			if (!url_query_component(&ctx->uri.query, &comp)) {
				send_errpage(loop, ctx, HTTP_BAD_REQUEST);
				return;
			}
			if (strcmp(comp.key, "module") == 0) {
				module = comp.value;
			} else if (strcmp(comp.key, "chunkname") == 0) {
				chunkname = comp.value;
			}
		}
		handle_ruleset_update(loop, ctx, ruleset, module, chunkname);
		return;
	}
	if (strcmp(segment, "gc") == 0) {
		if (!restapi_check(loop, ctx, "POST", false)) {
			return;
		}
		handle_ruleset_gc(loop, ctx, ruleset);
		return;
	}

	send_errpage(loop, ctx, HTTP_NOT_FOUND);
}

static void
http_handle_ruleset(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	if (ctx->s->ruleset == NULL) {
		SEND_ERRSTR(loop, ctx, "ruleset is not enabled on the server");
		return;
	}

	ev_idle_start(loop, &ctx->w_process);
}
#endif /* WITH_RULESET */

static void
http_handle_metrics(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->conn.msg;
	if (strcmp(msg->req.method, "GET") != 0) {
		send_errpage(loop, ctx, HTTP_METHOD_NOT_ALLOWED);
		return;
	}

	const struct server_stats *restrict apistats = &ctx->s->stats;
	const struct server *restrict s = ctx->s->data;
	struct server_stats agg;
	server_stats(s, &agg);
	const struct resolver_stats *restrict resolv_stats =
		resolver_stats(s->resolver);

	const double uptime =
		(double)(clock_monotonic_ns() - ctx->s->stats.started) * 1e-9;
	struct timespec cpu_ts = { 0 };
	const bool have_cpu = clock_process(&cpu_ts);

	const enum content_encodings encoding =
		(ctx->conn.hdr.accept_encoding == CENCODING_DEFLATE) ?
			CENCODING_DEFLATE :
			CENCODING_NONE;
	struct stream *w = io_bufwriter(
		content_writer(&ctx->conn.cbuf, IO_BUFSIZE, encoding),
		IO_BUFSIZE);
	if (w == NULL) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

/* name: metric name suffix (prefix "neosocksd_" is added automatically);
 * type: "gauge"/"counter"/etc.;
 * help: description; fmt: printf format for the value(s); ...: value(s). */
/* Emit HELP + TYPE header only (use once before multiple metric lines) */
#define APPEND_METRIC_HDR(name, type, help)                                    \
	(void)io_bufprintf(                                                    \
		w,                                                             \
		"# HELP neosocksd_%s %s\n"                                     \
		"# TYPE neosocksd_%s %s\n",                                    \
		name, help, name, type)

/* Emit one metric line without HELP/TYPE */
#define APPEND_METRIC(name, fmt, ...)                                          \
	(void)io_bufprintf(w, "neosocksd_%s " fmt "\n", name, __VA_ARGS__)

/* Emit one labeled metric line without HELP/TYPE */
#define APPEND_METRIC_L(name, labels, fmt, ...)                                \
	(void)io_bufprintf(                                                    \
		w, "neosocksd_%s{" labels "} " fmt "\n", name, __VA_ARGS__)

	/* Gauges */
	APPEND_METRIC_HDR(
		"sessions_active", "gauge", "Number of active proxy sessions.");
	APPEND_METRIC("sessions_active", "%zu", agg.num_sessions);
	APPEND_METRIC_HDR(
		"sessions_peak", "gauge",
		"Peak concurrent proxy sessions since start.");
	APPEND_METRIC("sessions_peak", "%zu", agg.num_sessions_peak);
	APPEND_METRIC_HDR(
		"halfopen_connections", "gauge",
		"Connections in handshake/ruleset/dial phase.");
	APPEND_METRIC("halfopen_connections", "%zu", agg.num_halfopen);
	APPEND_METRIC_HDR(
		"uptime_seconds", "gauge", "Seconds since server start.");
	APPEND_METRIC("uptime_seconds", "%g", uptime);

	/* Counters */
	if (have_cpu) {
		APPEND_METRIC_HDR(
			"process_cpu_seconds_total", "counter",
			"Total CPU time consumed by the process.");
		APPEND_METRIC(
			"process_cpu_seconds_total", "%g",
			(double)TIMESPEC_NANO(cpu_ts) * 1e-9);
	}
	APPEND_METRIC_HDR(
		"connections_accepted_total", "counter",
		"Connections accepted by the listener.");
	APPEND_METRIC(
		"connections_accepted_total", "%" PRIuLEAST64, agg.num_accept);
	APPEND_METRIC_HDR(
		"connections_served_total", "counter",
		"Connections upgraded to proxy sessions.");
	APPEND_METRIC(
		"connections_served_total", "%" PRIuLEAST64, agg.num_serve);
	APPEND_METRIC_HDR(
		"requests_total", "counter", "Total proxy requests processed.");
	APPEND_METRIC("requests_total", "%" PRIuLEAST64, agg.num_request);
	APPEND_METRIC_HDR(
		"requests_success_total", "counter",
		"Proxy requests completed successfully.");
	APPEND_METRIC(
		"requests_success_total", "%" PRIuLEAST64, agg.num_success);
	APPEND_METRIC_HDR(
		"rejects_ruleset_total", "counter",
		"Connections rejected by the ruleset.");
	APPEND_METRIC(
		"rejects_ruleset_total", "%" PRIuLEAST64,
		agg.num_reject_ruleset);
	APPEND_METRIC_HDR(
		"rejects_timeout_total", "counter",
		"Connections timed out before becoming active.");
	APPEND_METRIC(
		"rejects_timeout_total", "%" PRIuLEAST64,
		agg.num_reject_timeout);
	APPEND_METRIC_HDR(
		"rejects_upstream_total", "counter",
		"Connections failed during upstream dial.");
	APPEND_METRIC(
		"rejects_upstream_total", "%" PRIuLEAST64,
		agg.num_reject_upstream);
	APPEND_METRIC_HDR(
		"dns_queries_total", "counter", "DNS queries issued.");
	APPEND_METRIC(
		"dns_queries_total", "%" PRIuLEAST64, resolv_stats->num_query);
	APPEND_METRIC_HDR(
		"dns_success_total", "counter",
		"DNS queries resolved successfully.");
	APPEND_METRIC(
		"dns_success_total", "%" PRIuLEAST64,
		resolv_stats->num_success);
	APPEND_METRIC_HDR(
		"api_requests_total", "counter", "API requests received.");
	APPEND_METRIC(
		"api_requests_total", "%" PRIuLEAST64,
		apistats->num_api_request);
	APPEND_METRIC_HDR(
		"api_requests_success_total", "counter",
		"API requests completed successfully.");
	APPEND_METRIC(
		"api_requests_success_total", "%" PRIuLEAST64,
		apistats->num_api_success);
	APPEND_METRIC_HDR(
		"uplink_bytes_total", "counter",
		"Total bytes of proxied payload sent to upstream.");
	APPEND_METRIC("uplink_bytes_total", "%" PRIuLEAST64, agg.byt_up);
	APPEND_METRIC_HDR(
		"downlink_bytes_total", "counter",
		"Total bytes of proxied payload received from upstream.");
	APPEND_METRIC("downlink_bytes_total", "%" PRIuLEAST64, agg.byt_down);
	/* neosocksd_protocol_bytes_total: per-module protocol overhead */
	APPEND_METRIC_HDR(
		"protocol_bytes_total", "counter",
		"Total bytes of protocol overhead, by direction and module.");
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "rx", "api_server", apistats->api_byt_recv);
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "tx", "api_server", apistats->api_byt_send);
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "rx", "proxy_server", agg.byt_client_recv);
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "tx", "proxy_server", agg.byt_client_send);
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "rx", "proxy_client", agg.byt_dial_recv);
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "tx", "proxy_client", agg.byt_dial_send);
#if WITH_RULESET
	APPEND_METRIC_HDR(
		"api_client_requests_total", "counter",
		"API client requests issued by the ruleset.");
	APPEND_METRIC(
		"api_client_requests_total", "%" PRIuLEAST64,
		agg.num_api_client_request);
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "rx", "api_client", agg.api_client_byt_recv);
	APPEND_METRIC_L(
		"protocol_bytes_total", "direction=\"%s\",module=\"%s\"",
		"%" PRIuLEAST64, "tx", "api_client", agg.api_client_byt_send);
#endif

	/* Connect latency summary */
	if (agg.num_connects > 0) {
		const struct percentiles p = calc_percentiles(
			ARRAY_SIZE(agg.connect_ns), agg.num_connects,
			agg.connect_ns);
		APPEND_METRIC_HDR(
			"connect_latency_seconds", "summary",
			"Connection establishment latency.");
		APPEND_METRIC_L(
			"connect_latency_seconds", "quantile=\"%s\"", "%g",
			"0.5", (double)p.p50 * 1e-9);
		APPEND_METRIC_L(
			"connect_latency_seconds", "quantile=\"%s\"", "%g",
			"0.9", (double)p.p90 * 1e-9);
		APPEND_METRIC_L(
			"connect_latency_seconds", "quantile=\"%s\"", "%g",
			"0.99", (double)p.p99 * 1e-9);
		APPEND_METRIC(
			"connect_latency_seconds_count", "%zu",
			agg.num_connects);
	}

#if WITH_RULESET
	{
		struct ruleset_vmstats vmstats = { 0 };
		const struct ruleset *restrict ruleset = s->ruleset;
		if (ruleset != NULL) {
			ruleset_vmstats(ruleset, &vmstats);
		}
		APPEND_METRIC_HDR(
			"lua_memory_bytes", "gauge",
			"Bytes allocated by the Lua VM.");
		APPEND_METRIC("lua_memory_bytes", "%zu", vmstats.byt_allocated);
		APPEND_METRIC_HDR(
			"lua_objects", "gauge", "Number of live Lua objects.");
		APPEND_METRIC("lua_objects", "%zu", vmstats.num_object);
		APPEND_METRIC_HDR(
			"lua_threads_active", "gauge",
			"Lua coroutines currently dispatched.");
		APPEND_METRIC(
			"lua_threads_active", "%zu", vmstats.num_thread_active);
		APPEND_METRIC_HDR(
			"lua_threads_peak", "gauge",
			"Peak concurrent dispatched Lua coroutines since start.");
		APPEND_METRIC(
			"lua_threads_peak", "%zu", vmstats.num_thread_peak);
	}
	{
		struct ruleset *restrict ruleset = s->ruleset;
		if (ruleset != NULL) {
			size_t len;
			const char *m = ruleset_metrics(ruleset, &len);
			if (m != NULL) {
				size_t n = len;
				const int werr = stream_write(w, m, &n);
				if (n < len || werr != 0) {
					LOGE_F("stream_write: error %d, %zu/%zu",
					       werr, n, len);
					(void)stream_close(w);
					send_errpage(
						loop, ctx,
						HTTP_INTERNAL_SERVER_ERROR);
					return;
				}
			}
		}
	}
#endif /* WITH_RULESET */
#undef APPEND_METRIC_HDR
#undef APPEND_METRIC
#undef APPEND_METRIC_L

	const int err = stream_close(w);
	if (err != 0) {
		LOGE_F("stream_close: error %d", err);
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}

	RESPHDR_BEGIN(ctx->conn.wbuf, HTTP_OK);
	if (ctx->keepalive) {
		RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
	} else {
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
	}
	RESPHDR_NOCACHE(ctx->conn.wbuf);
	RESPHDR_CTYPE(
		ctx->conn.wbuf, "text/plain; version=0.0.4; charset=utf-8");
	const char *encoding_str = http_content_encoding_str[encoding];
	if (encoding_str != NULL) {
		RESPHDR_CENCODING(ctx->conn.wbuf, encoding_str);
	}
	RESPHDR_CLENGTH(ctx->conn.wbuf, VBUF_LEN(ctx->conn.cbuf));
	RESPHDR_FINISH(ctx->conn.wbuf);
	send_response(loop, ctx, true);
}

static void api_handle(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->conn.msg;
	if (LOGLEVEL(VERBOSE)) {
		FORMAT_BYTES(clen, ctx->conn.hdr.content.length);
		API_CTX_LOG_F(
			VERBOSE, ctx, "api request `%s': content %s",
			msg->req.url, clen);
	}
	if (!url_parse(msg->req.url, &ctx->uri)) {
		API_CTX_LOG(WARNING, ctx, "failed parsing url");
		send_errpage(loop, ctx, HTTP_BAD_REQUEST);
		return;
	}
	char *segment;
	if (!url_path_segment(&ctx->uri.path, &segment)) {
		send_errpage(loop, ctx, HTTP_BAD_REQUEST);
		return;
	}
	if (strcmp(segment, "healthy") == 0) {
		if (!restapi_check(loop, ctx, NULL, false)) {
			return;
		}
		RESPHDR_BEGIN(ctx->conn.wbuf, HTTP_OK);
		if (ctx->keepalive) {
			RESPHDR_CONN_KEEPALIVE(ctx->conn.wbuf);
		} else {
			RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
		}
		RESPHDR_CLENGTH(ctx->conn.wbuf, 0);
		RESPHDR_FINISH(ctx->conn.wbuf);
		send_response(loop, ctx, true);
		return;
	}
	if (strcmp(segment, "stats") == 0) {
		if (!restapi_check(loop, ctx, NULL, false)) {
			return;
		}
		http_handle_stats(loop, ctx);
		return;
	}
	if (strcmp(segment, "metrics") == 0) {
		if (!restapi_check(loop, ctx, NULL, false)) {
			return;
		}
		http_handle_metrics(loop, ctx);
		return;
	}
#if WITH_RULESET
	if (strcmp(segment, "ruleset") == 0) {
		http_handle_ruleset(loop, ctx);
		return;
	}
#endif
	send_errpage(loop, ctx, HTTP_NOT_FOUND);
}

static void api_ctx_stop(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	const struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_REQUEST:
		ev_io_stop(loop, &ctx->w_recv);
		break;
	case STATE_PROCESS:
#if WITH_RULESET
		ev_idle_stop(loop, &ctx->w_process);
		if (ctx->rpcstate != NULL) {
			ruleset_cancel(loop, ctx->rpcstate);
			ctx->rpcstate = NULL;
		}
#endif
		break;
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_send);
		break;
	}
	API_CTX_LOG_F(
		VERYVERBOSE, ctx, "closed, %zu active api",
		stats->num_sessions);
}

static void api_ctx_finalize(struct gcbase *restrict obj)
{
	struct api_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct api_ctx, gcbase, obj);
	API_CTX_LOG_F(VERYVERBOSE, ctx, "closing, state=%d", ctx->state);

	api_ctx_stop(ctx->s->loop, ctx);
	if (ctx->accepted_fd != -1) {
		SOCKET_CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		SOCKET_CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	VBUF_FREE(ctx->conn.cbuf);
}

static bool parse_header(void *ctx, const char *key, char *value)
{
	struct http_conn *restrict p = &((struct api_ctx *)ctx)->conn;

	/* hop-by-hop headers */
	if (strcasecmp(key, "Connection") == 0) {
		p->hdr.connection = value;
		return true;
	}
	if (strcasecmp(key, "TE") == 0) {
		/* Record chunked TE if offered; ignore unsupported tokens —
		 * the API server is an endpoint, not an intermediary, so it
		 * must not reject clients that advertise encodings it does not
		 * support (e.g. Prometheus sending "TE: trailers"). */
		(void)parsehdr_accept_te(p, value);
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

	/* request headers */
	if (strcasecmp(key, "Accept-Encoding") == 0) {
		return parsehdr_accept_encoding(p, value);
	}
	if (strcasecmp(key, "Expect") == 0) {
		return parsehdr_expect(p, value);
	}

	LOGVV_F("unknown http header: `%s' = `%s'", key, value);
	return true;
}

/* Returns true when HTTP/1.1 and the client did not request Connection: close */
static bool api_should_keepalive(const struct api_ctx *restrict ctx)
{
	const char *version = ctx->conn.msg.req.version;
	if (strncmp(version, "HTTP/1.1", 8) != 0) {
		return false;
	}
	const char *conn = ctx->conn.hdr.connection;
	return conn == NULL || strcasecmp(conn, "close") != 0;
}

/* Reset parser and state machine for reuse on the same TCP connection */
static void api_ctx_reset(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	VBUF_FREE(ctx->conn.cbuf);
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	http_conn_init(
		&ctx->conn, ctx->accepted_fd, STATE_PARSE_REQUEST, on_header,
		&ctx->s->stats.api_byt_recv, &ctx->s->stats.api_byt_send);
	ctx->uri = (struct url){ 0 };
	ctx->keepalive = false;
	ctx->state = STATE_REQUEST;
	ev_timer_again(loop, &ctx->w_timeout);
	ev_io_start(loop, &ctx->w_recv);
}

void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct api_ctx *restrict ctx = watcher->data;

	const int want = http_conn_recv(&ctx->conn);
	if (want < 0) {
		gc_unref(&ctx->gcbase);
		return;
	}
	if (want > 0) {
		return;
	}
	ctx->state = STATE_PROCESS;
	ev_io_stop(loop, watcher);

	switch (ctx->conn.state) {
	case STATE_PARSE_OK: {
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_api_request++;
		ctx->keepalive = api_should_keepalive(ctx);
	} break;
	case STATE_PARSE_ERROR:
		send_errpage(loop, ctx, ctx->conn.http_status);
		return;
	default:
		FAILMSGF("unexpected http parser state: %d", ctx->conn.state);
	}

	api_handle(loop, ctx);
}

void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct api_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE);

	const int fd = watcher->fd;
	{
		const unsigned char *buf = ctx->conn.wbuf.data + ctx->conn.wpos;
		size_t len = ctx->conn.wbuf.len - ctx->conn.wpos;
		const int err = socket_send(fd, buf, &len);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				return;
			}
			API_CTX_LOG_F(
				WARNING, ctx, "send: (%d) %s", err,
				strerror(err));
			gc_unref(&ctx->gcbase);
			return;
		}
		ctx->conn.wpos += len;
		*ctx->conn.byt_sent += (uint_least64_t)len;
		if (ctx->conn.wpos < ctx->conn.wbuf.len) {
			return;
		}
	}

	/* Send response body after headers are fully sent */
	if (ctx->conn.cbuf != NULL) {
		const unsigned char *buf;
		size_t len;
		VBUF_VIEW(buf, len, ctx->conn.cbuf, ctx->conn.cpos);
		const int err = socket_send(fd, buf, &len);
		if (err != 0) {
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == ENOBUFS || err == ENOMEM) {
				return;
			}
			API_CTX_LOG_F(
				WARNING, ctx, "send: (%d) %s", err,
				strerror(err));
			gc_unref(&ctx->gcbase);
			return;
		}
		ctx->conn.cpos += len;
		*ctx->conn.byt_sent += (uint_least64_t)len;
		if (ctx->conn.cpos < VBUF_LEN(ctx->conn.cbuf)) {
			return;
		}
	}

	/* Reuse or close the connection based on keep-alive negotiation */
	if (ctx->keepalive) {
		ev_io_stop(loop, watcher);
		api_ctx_reset(loop, ctx);
		return;
	}
	gc_unref(&ctx->gcbase);
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	struct api_ctx *restrict ctx = watcher->data;
	gc_unref(&ctx->gcbase);
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

	ev_timer_init(&ctx->w_timeout, timeout_cb, 0.0, s->conf->timeout);
	ctx->w_timeout.data = ctx;
	ev_io_init(&ctx->w_recv, recv_cb, fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(&ctx->w_send, send_cb, fd, EV_WRITE);
	ctx->w_send.data = ctx;
#if WITH_RULESET
	ev_idle_init(&ctx->w_process, process_cb);
	ctx->w_process.data = ctx;
	ev_init(&ctx->rpcreturn.w_finish, rpcall_cb);
	ctx->rpcreturn.w_finish.data = ctx;
	ctx->rpcreturn.forward = NULL;
	ctx->rpcstate = NULL;
#endif
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	http_conn_init(
		&ctx->conn, fd, STATE_PARSE_REQUEST, on_header,
		&s->stats.api_byt_recv, &s->stats.api_byt_send);
	gc_register(&ctx->gcbase, api_ctx_finalize);
	return ctx;
}

static void api_ctx_start(struct ev_loop *loop, struct api_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_again(loop, &ctx->w_timeout);

	ctx->state = STATE_REQUEST;
}

void api_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct api_ctx *restrict ctx = api_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		SOCKET_CLOSE_FD(accepted_fd);
		return;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	api_ctx_start(loop, ctx);
}
