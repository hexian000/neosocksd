/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "net/http.h"
#include "net/url.h"
#include "server.h"
#include "utils/minmax.h"
#include "utils/buffer.h"
#include "utils/formats.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "ruleset.h"
#include "transfer.h"
#include "dialer.h"
#include "util.h"

#include <ev.h>
#include <stdint.h>
#include <strings.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

static void
http_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);

#define HTTP_MAX_HEADER_COUNT 256
#define HTTP_MAX_ENTITY 8192

struct http_ctx;

typedef void (*http_handler_fn)(struct ev_loop *loop, struct http_ctx *ctx);

struct http_hdr_item {
	const char *key, *value;
};

enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_HEADER,
	STATE_CONTENT,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct http_ctx {
	struct server *s;
	http_handler_fn on_request;
	int accepted_fd, dialed_fd;
	enum http_state state;
	sockaddr_max_t accepted_sa;
	struct ev_timer w_timeout;
	union {
		struct {
			struct ev_io w_read, w_write;
			struct http_message http_msg;
			char *http_nxt;
			struct http_hdr_item http_hdr[HTTP_MAX_HEADER_COUNT];
			size_t http_hdr_num, content_length;
			unsigned char *content;
			struct dialer dialer;
			struct {
				BUFFER_HDR;
				unsigned char data[HTTP_MAX_ENTITY];
			} rbuf, wbuf;
		};
		struct { /* connected */
			struct transfer uplink, downlink;
		};
	};
};

#define HTTP_CTX_LOG_F(level, ctx, format, ...)                                \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char laddr[64];                                                \
		format_sa(&(ctx)->accepted_sa.sa, laddr, sizeof(laddr));       \
		LOG_F(level, "\"%s\": " format, laddr, __VA_ARGS__);           \
	} while (0)
#define HTTP_CTX_LOG(level, ctx, message)                                      \
	HTTP_CTX_LOG_F(level, ctx, "%s", message)

static void http_ctx_stop(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_REQUEST:
	case STATE_HEADER:
	case STATE_CONTENT:
		ev_io_stop(loop, &ctx->w_read);
		ev_io_stop(loop, &ctx->w_write);
		stats->num_halfopen--;
		/* fallthrough */
	case STATE_CONNECT:
		dialer_stop(&ctx->dialer, loop);
		return;
	case STATE_CONNECTED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_halfopen--;
		break;
	case STATE_ESTABLISHED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_sessions--;
		break;
	}
	HTTP_CTX_LOG_F(
		LOG_LEVEL_INFO, ctx, "closed, %zu active", stats->num_sessions);
}

static void http_ctx_free(struct http_ctx *restrict ctx)
{
	if (ctx != NULL) {
		(void)close(ctx->w_read.fd);
	}
	if (ctx->accepted_fd != -1) {
		(void)close(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		(void)close(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	free(ctx);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	if (ctx->uplink.state == XFER_CLOSED ||
	    ctx->downlink.state == XFER_CLOSED) {
		http_ctx_stop(loop, ctx);
		http_ctx_free(ctx);
		return;
	}
	if (ctx->state == STATE_CONNECTED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		ctx->state = STATE_ESTABLISHED;
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		HTTP_CTX_LOG_F(
			LOG_LEVEL_INFO, ctx, "established, %zu active",
			stats->num_sessions);
		ev_timer_stop(loop, &ctx->w_timeout);
		return;
	}
}

static void
http_resphdr_init(struct http_ctx *restrict ctx, const uint16_t code)
{
	char date_str[32];
	const int date_len = (int)http_date(date_str, sizeof(date_str));
	const char *status = http_status(code);
	ctx->wbuf.len = 0;
	BUF_APPENDF(
		ctx->wbuf,
		"HTTP/1.0 %" PRIu16 " %s\r\n"
		"Date: %.*s\r\n"
		"Connection: close\r\n",
		code, status ? status : "", date_len, date_str);
}

#define RESPHDR_ADD(ctx, key, value)                                           \
	BUF_APPENDCONST((ctx)->wbuf, key ": " value "\r\n")

#define RESPHDR_END(ctx) BUF_APPENDCONST((ctx)->wbuf, "\r\n")

#define RESPHDR_TXT(ctx, code)                                                 \
	do {                                                                   \
		http_resphdr_init((ctx), (code));                              \
		RESPHDR_ADD(ctx, "Content-Type", "text/plain; charset=utf-8"); \
		RESPHDR_ADD(ctx, "X-Content-Type-Options", "nosniff");         \
		RESPHDR_END(ctx);                                              \
	} while (0)

static void
http_resp_errpage(struct http_ctx *restrict ctx, const uint16_t code)
{
	const size_t cap = ctx->wbuf.cap - ctx->wbuf.len;
	char *buf = (char *)(ctx->wbuf.data + ctx->wbuf.len);
	const int len = http_error(buf, cap, code);
	if (len <= 0) {
		/* can't generate error page, reply with code only */
		http_resphdr_init(ctx, code);
		RESPHDR_END(ctx);
		return;
	}
	ctx->wbuf.len += len;
	LOGV_F("http: response error page %" PRIu16, code);
}

static void
http_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct http_ctx *restrict ctx = watcher->data;
	unsigned char *buf = ctx->rbuf.data + ctx->rbuf.len;
	size_t cap =
		ctx->rbuf.cap - ctx->rbuf.len - 1; /* for null-terminator */
	const ssize_t nrecv = recv(watcher->fd, buf, cap, 0);
	if (nrecv < 0) {
		const int err = errno;
		if (IS_TRANSIENT_ERROR(err)) {
			return;
		}
		LOGE_F("recv: %s", strerror(err));
		http_ctx_stop(loop, ctx);
		http_ctx_free(ctx);
		return;
	} else if (nrecv == 0) {
		http_ctx_stop(loop, ctx);
		http_ctx_free(ctx);
		return;
	}
	ctx->rbuf.len += nrecv;
	cap -= nrecv;

	ctx->rbuf.data[ctx->rbuf.len] = '\0';
	char *next = ctx->http_nxt;
	if (next == NULL) {
		next = (char *)ctx->rbuf.data;
		ctx->http_nxt = next;
	}
	struct ev_io *restrict w_write = &ctx->w_write;
	struct http_message *restrict hdr = &ctx->http_msg;
	if (ctx->state == STATE_REQUEST) {
		next = http_parse(next, hdr);
		if (next == NULL) {
			LOGE("http: invalid request");
			http_ctx_stop(loop, ctx);
			http_ctx_free(ctx);
			return;
		} else if (next == ctx->http_nxt) {
			if (cap == 0) {
				ev_io_stop(loop, watcher);
				http_resp_errpage(ctx, HTTP_ENTITY_TOO_LARGE);
				ev_io_start(loop, w_write);
				return;
			}
			return;
		}
		if (strncmp(hdr->req.version, "HTTP/1.", 7) != 0) {
			LOGE_F("http: unsupported protocol %s",
			       hdr->req.version);
			http_ctx_stop(loop, ctx);
			http_ctx_free(ctx);
			return;
		}
		LOGV_F("http: request %s %s %s", hdr->req.method, hdr->req.url,
		       hdr->req.version);
		ctx->http_nxt = next;
		ctx->http_hdr_num = 0;
		ctx->content = NULL;
		ctx->state = STATE_HEADER;
	}
	while (ctx->state == STATE_HEADER) {
		char *key, *value;
		next = http_parsehdr(next, &key, &value);
		if (next == NULL) {
			LOGE("http: invalid header");
			http_ctx_stop(loop, ctx);
			http_ctx_free(ctx);
			return;
		} else if (next == ctx->http_nxt) {
			return;
		}
		ctx->http_nxt = next;
		if (key == NULL) {
			ctx->state = STATE_CONTENT;
			break;
		}

		/* save the header */
		const size_t num = ctx->http_hdr_num;
		if (num >= HTTP_MAX_HEADER_COUNT) {
			LOGE("http: too many headers");
			http_ctx_stop(loop, ctx);
			http_ctx_free(ctx);
			return;
		}
		ctx->http_hdr[num] = (struct http_hdr_item){
			.key = key,
			.value = value,
		};
		ctx->http_hdr_num = num + 1;
		if (strcasecmp(key, "Content-Length") == 0) {
			if (sscanf(value, "%zu", &ctx->content_length) != 1) {
				ev_io_stop(loop, watcher);
				http_resp_errpage(ctx, HTTP_BAD_REQUEST);
				ev_io_start(loop, w_write);
				return;
			}
			/* indicates that there is content */
			ctx->content = ctx->rbuf.data;
		}
		LOGV_F("http: header %s: %s", key, value);
	}
	if (ctx->content != NULL) {
		/* use inline buffer */
		ctx->content = (unsigned char *)ctx->http_nxt;
		assert(ctx->content > ctx->rbuf.data);
		const size_t offset = ctx->content - ctx->rbuf.data;
		const size_t want = ctx->content_length + 1;
		const size_t content_cap = ctx->rbuf.cap - offset;
		if (want > content_cap) {
			/* no enough buffer */
			ev_io_stop(loop, watcher);
			http_resp_errpage(ctx, HTTP_ENTITY_TOO_LARGE);
			ev_io_start(loop, w_write);
			return;
		}
		const size_t len = ctx->rbuf.len - offset;
		if (len < ctx->content_length) {
			return;
		}
		ctx->content[ctx->content_length] = '\0';
	}

	/* HTTP/1.0 only, stop reading */
	ev_io_stop(loop, watcher);
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_request++;
	ctx->on_request(loop, ctx);

	if (ctx->wbuf.len > 0) {
		ev_io_start(loop, w_write);
	}
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	struct ev_io *restrict w_write = &ctx->w_write;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		LOGE_F("dialer: %s", dialer_strerror(&ctx->dialer));
		http_resp_errpage(ctx, HTTP_BAD_GATEWAY);
		ev_io_start(loop, w_write);
		return;
	}
	ev_timer_stop(loop, &ctx->w_timeout);
	ctx->dialed_fd = fd;

	ctx->state = STATE_CONNECTED;
	BUF_APPENDF(
		ctx->wbuf, "HTTP/1.0 %" PRIu16 " %s\r\n\r\n", HTTP_OK,
		http_status(HTTP_OK));
	ev_io_init(w_write, http_write_cb, ctx->accepted_fd, EV_WRITE);
	w_write->data = ctx;
	ev_io_start(loop, w_write);
}

static void http_hijack(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_read);
	ev_io_stop(loop, &ctx->w_write);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);

	const struct config *restrict conf = ctx->s->conf;
	struct server_stats *restrict stats = &ctx->s->stats;
	if (conf->proto_timeout) {
		ev_timer_start(loop, w_timeout);
	} else {
		ctx->state = STATE_ESTABLISHED;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		HTTP_CTX_LOG_F(
			LOG_LEVEL_INFO, ctx, "established, %zu active",
			stats->num_sessions);
	}

	struct event_cb cb = {
		.cb = xfer_state_cb,
		.ctx = ctx,
	};
	transfer_init(
		&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static void
http_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct http_ctx *restrict ctx = watcher->data;
	unsigned char *buf = ctx->wbuf.data;
	size_t len = ctx->wbuf.len;
	size_t nbsend = 0;
	while (len > 0) {
		const ssize_t nsend = send(watcher->fd, buf, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("send: %s", strerror(err));
			http_ctx_stop(loop, ctx);
			http_ctx_free(ctx);
			return;
		}
		buf += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	BUF_CONSUME(ctx->wbuf, nbsend);
	if (ctx->wbuf.len > 0) {
		return;
	}

	if (ctx->state == STATE_CONNECTED) {
		http_hijack(loop, ctx);
		return;
	}
	/* HTTP/1.0 only, close after serve */
	http_ctx_stop(loop, ctx);
	http_ctx_free(ctx);
}

static void
http_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct http_ctx *restrict ctx = watcher->data;
	http_ctx_stop(loop, ctx);
	http_ctx_free(ctx);
}

static struct http_ctx *
http_ctx_new(struct server *restrict h, const int fd, http_handler_fn handler)
{
	struct http_ctx *restrict ctx = malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = h;
	ctx->accepted_fd = fd;
	ctx->dialed_fd = -1;
	ctx->on_request = handler;
	ctx->state = STATE_INIT;
	BUF_INIT(ctx->rbuf, HTTP_MAX_ENTITY);
	BUF_INIT(ctx->wbuf, HTTP_MAX_ENTITY);
	ctx->http_nxt = NULL;

	const struct config *restrict conf = h->conf;

	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_init(w_timeout, http_timeout_cb, conf->timeout, 0.0);
	w_timeout->data = ctx;
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_init(w_read, http_read_cb, fd, EV_READ);
	w_read->data = ctx;
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_init(w_write, http_write_cb, fd, EV_WRITE);
	w_write->data = ctx;

	dialer_init(
		&ctx->dialer, conf,
		&(struct event_cb){
			.cb = dialer_cb,
			.ctx = ctx,
		});
	return ctx;
}

static void http_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_start(loop, w_read);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_start(loop, w_timeout);

	ctx->state = STATE_REQUEST;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen++;
}

static bool proxy_dial(
	struct http_ctx *restrict ctx, struct ev_loop *loop,
	const char *addr_str)
{
	struct server *restrict h = ctx->s;
	struct ruleset *ruleset = h->ruleset;

	struct dialreq *req = NULL;
	if (ruleset == NULL) {
		struct dialaddr addr;
		if (!dialaddr_set(&addr, addr_str, strlen(addr_str))) {
			return false;
		}
		req = dialreq_new(&addr, 0);
	} else {
		req = ruleset_resolve(ruleset, addr_str);
	}

	if (req == NULL) {
		return false;
	}
	if (!dialer_start(&ctx->dialer, loop, req)) {
		return false;
	}
	ctx->state = STATE_CONNECT;
	return true;
}

static void
http_handle_proxy(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_message *restrict hdr = &ctx->http_msg;
	if (strcmp(hdr->req.method, "CONNECT") != 0) {
		http_resp_errpage(ctx, HTTP_BAD_REQUEST);
		return;
	}
	HTTP_CTX_LOG_F(
		LOG_LEVEL_DEBUG, ctx, "http: CONNECT \"%s\"", hdr->req.url);

	if (!proxy_dial(ctx, loop, hdr->req.url)) {
		http_resp_errpage(ctx, HTTP_BAD_GATEWAY);
		return;
	}
}

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
	bool stateless;
	if (strcmp(hdr->req.method, "GET") == 0) {
		stateless = true;
	} else if (strcmp(hdr->req.method, "POST") == 0) {
		stateless = false;
	} else {
		http_resp_errpage(ctx, HTTP_METHOD_NOT_ALLOWED);
		return;
	}
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

	http_resphdr_init(ctx, HTTP_OK);
	RESPHDR_ADD(ctx, "Content-Type", "text/plain; charset=utf-8");
	RESPHDR_ADD(ctx, "X-Content-Type-Options", "nosniff");
	if (stateless) {
		RESPHDR_ADD(ctx, "Cache-Control", "no-store");
	}
	RESPHDR_END(ctx);
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
		"Listener Accepts    : %ju (%ju rejected)\n"
		"Requests            : %ju (+%ju)\n"
		"Traffic (up/down)   : %s / %s\n",
		timestamp, str_uptime, stats->num_sessions, stats->num_halfopen,
		lstats->num_serve, num_reject, stats->num_success,
		stats->num_request - stats->num_success, xfer_up, xfer_down);

	if (stateless) {
		return;
	}

	static struct {
		uintmax_t num_request;
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

	const double successful_rate =
		(double)(stats->num_success - last.num_success) / dt;
	const double unsuccessful_rate =
		(double)((stats->num_request - last.num_request) - (stats->num_success - last.num_success)) /
		dt;

	BUF_APPENDF(
		ctx->wbuf,
		"Listener Accepts    : %.1f/s (%.1f reject/s)\n"
		"Requests            : %.1f/s (%+.1f/s)\n"
		"Traffic (up/down)   : %s/s / %s/s\n",
		accept_rate, reject_rate, successful_rate, unsuccessful_rate,
		xfer_rate_up, xfer_rate_down);

	last.num_request = stats->num_request;
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
		RESPHDR_TXT(ctx, HTTP_INTERNAL_SERVER_ERROR);
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
		LOGV_F("api: ruleset invoke\n%s", code);
		const char *err = ruleset_invoke(ruleset, code, len);
		if (err != NULL) {
			RESPHDR_TXT(ctx, HTTP_INTERNAL_SERVER_ERROR);
			BUF_APPENDSTR(ctx->wbuf, err);
			return;
		}
		http_resphdr_init(ctx, HTTP_OK);
		RESPHDR_END(ctx);
		return;
	}
	if (strcmp(segment, "update") == 0) {
		if (!http_leafnode_check(ctx, uri, "POST", true)) {
			return;
		}
		const char *code = (const char *)ctx->content;
		const size_t len = ctx->content_length;
		LOGV_F("api: ruleset update\n%s", code);
		const char *err = ruleset_load(ruleset, code, len);
		if (err != NULL) {
			RESPHDR_TXT(ctx, HTTP_INTERNAL_SERVER_ERROR);
			BUF_APPENDSTR(ctx->wbuf, err);
			return;
		}
		http_resphdr_init(ctx, HTTP_OK);
		RESPHDR_END(ctx);
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
		RESPHDR_TXT(ctx, HTTP_OK);
		BUF_APPENDF(ctx->wbuf, "Ruleset Live Memory: %s\n", buf);
		return;
	}

	http_resp_errpage(ctx, HTTP_NOT_FOUND);
}

static void http_handle_api(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict hdr = &ctx->http_msg;
	struct url uri;
	LOGV_F("api: serve uri \"%s\"", hdr->req.url);
	if (!url_parse(hdr->req.url, &uri)) {
		LOGW("api: failed parsing url");
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
		http_resphdr_init(ctx, HTTP_OK);
		RESPHDR_END(ctx);
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

static void http_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa, http_handler_fn handler)
{
	struct http_ctx *restrict ctx = http_ctx_new(s, accepted_fd, handler);
	if (ctx == NULL) {
		LOGOOM();
		(void)close(accepted_fd);
		return;
	}
	(void)memcpy(
		&ctx->accepted_sa.sa, accepted_sa, getsocklen(accepted_sa));
	http_start(loop, ctx);
}

void http_proxy_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	http_serve(s, loop, accepted_fd, accepted_sa, http_handle_proxy);
}

void http_api_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	http_serve(s, loop, accepted_fd, accepted_sa, http_handle_api);
}

struct http_invoke_ctx {
	struct dialer dialer;
	struct ev_loop *loop;
	struct ev_io w_write;
	const struct config *conf;
	struct vbuffer *wbuf;
};

static void
request_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct http_invoke_ctx *restrict ctx = watcher->data;
	unsigned char *buf = ctx->wbuf->data;
	size_t len = ctx->wbuf->len;
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
			VBUF_FREE(ctx->wbuf);
			free(ctx);
			return;
		}
		buf += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	VBUF_CONSUME(ctx->wbuf, nbsend);
	if (ctx->wbuf->len > 0) {
		return;
	}

	ev_io_stop(loop, watcher);
	VBUF_FREE(ctx->wbuf);
	free(ctx);
}

static void invoke_cb(struct ev_loop *loop, void *data)
{
	struct http_invoke_ctx *restrict ctx = data;
	struct ev_io *restrict w_write = &ctx->w_write;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		LOGE_F("invoke: %s", dialer_strerror(&ctx->dialer));
		ev_io_start(loop, w_write);
		return;
	}
	ev_io_init(w_write, request_write_cb, fd, EV_WRITE);
	w_write->data = ctx;
	ev_io_start(loop, w_write);
}

struct http_invoke_ctx *http_invoke(
	struct ev_loop *loop, const struct config *conf, struct dialreq *req,
	const char *code, const size_t len)
{
	CHECK(len <= INT_MAX);
	struct http_invoke_ctx *restrict ctx =
		malloc(sizeof(struct http_invoke_ctx));
	if (ctx == NULL) {
		LOGOOM();
		return NULL;
	}
	ctx->wbuf = VBUF_APPENDF(
		NULL,
		"POST /ruleset/invoke HTTP/1.0\r\n"
		"Content-Length: %zu\r\n"
		"\r\n"
		"%.*s",
		len, (int)len, code);
	if (ctx->wbuf == NULL) {
		LOGOOM();
		free(ctx);
		return NULL;
	}
	LOGV_F("http_invoke:\n%.*s", (int)ctx->wbuf->len, ctx->wbuf->data);
	dialer_init(
		&ctx->dialer, conf,
		&(struct event_cb){
			.cb = invoke_cb,
			.ctx = ctx,
		});
	dialer_start(&ctx->dialer, loop, req);
	return ctx;
}
