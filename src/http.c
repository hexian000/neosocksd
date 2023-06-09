/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "net/http.h"
#include "net/url.h"
#include "utils/minmax.h"
#include "utils/buffer.h"
#include "utils/formats.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "ruleset.h"
#include "transfer.h"
#include "dialer.h"
#include "stats.h"
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

static struct stats stats = { 0 };

struct http_ctx;

typedef void (*http_handler)(struct ev_loop *loop, struct http_ctx *ctx);

struct http_hdr_item {
	const char *key, *value;
};

struct http_ctx {
	int accepted_fd, dialed_fd;
	http_handler handler;
	bool is_connected;
	union {
		struct {
			struct server *server;
			struct ev_io w_read, w_write;
			struct ev_timer w_timeout;
			enum {
				HTTPSTATE_REQUEST,
				HTTPSTATE_HEADER,
				HTTPSTATE_CONTENT,
				HTTPSTATE_GATEWAY,
			} http_state;
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

static void http_stop(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	if (ctx->is_connected) {
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		return;
	}
	dialer_stop(&ctx->dialer, loop);
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_stop(loop, w_read);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_stop(loop, w_write);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);
	stats.num_halfopen--;
}

static void http_free(struct http_ctx *restrict ctx)
{
	if (ctx != NULL) {
		(void)close(ctx->w_read.fd);
	}
	free(ctx);
}

static void xfer_done_cb(struct ev_loop *loop, void *ctx)
{
	http_stop(loop, ctx);
	http_free(ctx);
}

static void
http_resphdr_init(struct http_ctx *restrict ctx, const uint16_t code)
{
	char date_str[32];
	const int date_len = (int)http_date(date_str, sizeof(date_str));
	const char *status = http_status(code);
	ctx->wbuf.len = 0;
	(void)buf_appendf(
		&ctx->wbuf,
		"HTTP/1.0 %" PRIu16 " %s\r\n"
		"Date: %.*s\r\n"
		"Connection: close\r\n",
		code, status ? status : "", date_len, date_str);
}

#define RESPHDR_ADD(ctx, key, value)                                           \
	BUF_APPENDCONST(&(ctx)->wbuf, key ": " value "\r\n")

#define RESPHDR_END(ctx) BUF_APPENDCONST(&(ctx)->wbuf, "\r\n")

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
		http_stop(loop, ctx);
		http_free(ctx);
		return;
	} else if (nrecv == 0) {
		http_stop(loop, ctx);
		http_free(ctx);
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
	if (ctx->http_state == HTTPSTATE_REQUEST) {
		next = http_parse(next, hdr);
		if (next == NULL) {
			LOGE("http: invalid request");
			http_stop(loop, ctx);
			http_free(ctx);
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
			http_stop(loop, ctx);
			http_free(ctx);
			return;
		}
		LOGV_F("http: request %s %s %s", hdr->req.method, hdr->req.url,
		       hdr->req.version);
		ctx->http_nxt = next;
		ctx->http_hdr_num = 0;
		ctx->content = NULL;
		ctx->http_state = HTTPSTATE_HEADER;
	}
	while (ctx->http_state == HTTPSTATE_HEADER) {
		char *key, *value;
		next = http_parsehdr(next, &key, &value);
		if (next == NULL) {
			LOGE("http: invalid header");
			http_stop(loop, ctx);
			http_free(ctx);
			return;
		} else if (next == ctx->http_nxt) {
			return;
		}
		ctx->http_nxt = next;
		if (key == NULL) {
			ctx->http_state = HTTPSTATE_CONTENT;
			break;
		}

		/* save the header */
		const size_t num = ctx->http_hdr_num;
		if (num >= HTTP_MAX_HEADER_COUNT) {
			LOGE("http: too many headers");
			http_stop(loop, ctx);
			http_free(ctx);
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
	stats.num_request++;
	ctx->handler(loop, ctx);

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
		const int err = ctx->dialer.err;
		LOGD_F("dialer failed: %s", strerror(err));
		http_resp_errpage(ctx, HTTP_BAD_GATEWAY);
		ev_io_start(loop, w_write);
		return;
	}
	ev_timer_stop(loop, &ctx->w_timeout);
	ctx->dialed_fd = fd;

	ctx->http_state = HTTPSTATE_GATEWAY;
	(void)buf_appendf(
		&ctx->wbuf, "HTTP/1.0 %" PRIu16 " %s\r\n\r\n", HTTP_OK,
		http_status(HTTP_OK));
	ev_io_init(w_write, http_write_cb, ctx->accepted_fd, EV_WRITE);
	w_write->data = ctx;
	ev_io_start(loop, w_write);
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
			http_stop(loop, ctx);
			http_free(ctx);
			return;
		}
		buf += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	buf_consume(&ctx->wbuf, nbsend);
	if (ctx->wbuf.len > 0) {
		return;
	}

	if (ctx->http_state == HTTPSTATE_GATEWAY) {
		http_stop(loop, ctx);
		ctx->is_connected = true;
		struct event_cb cb = {
			.cb = xfer_done_cb,
			.ctx = ctx,
		};
		transfer_init(
			&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd);
		transfer_init(
			&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd);
		transfer_start(loop, &ctx->uplink);
		transfer_start(loop, &ctx->downlink);
		return;
	}
	/* HTTP/1.0 only, close after serve */
	http_stop(loop, ctx);
	http_free(ctx);
}

static void
http_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	struct http_ctx *restrict ctx = watcher->data;
	http_stop(loop, ctx);
	http_free(ctx);
}

static struct http_ctx *
http_new(const int fd, struct server *restrict s, http_handler handler)
{
	struct http_ctx *restrict ctx = malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->accepted_fd = fd;
	ctx->dialed_fd = -1;
	ctx->handler = handler;
	ctx->is_connected = false;
	ctx->server = s;
	buf_init(&ctx->rbuf, HTTP_MAX_ENTITY);
	buf_init(&ctx->wbuf, HTTP_MAX_ENTITY);
	ctx->http_state = HTTPSTATE_REQUEST;
	ctx->http_nxt = NULL;
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_init(w_timeout, http_timeout_cb, s->conf->timeout, 0.0);
	w_timeout->data = ctx;
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_init(w_read, http_read_cb, fd, EV_READ);
	w_read->data = ctx;
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_init(w_write, http_write_cb, fd, EV_WRITE);
	w_write->data = ctx;
	dialer_init(
		&ctx->dialer, s->conf,
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
	stats.num_halfopen++;
}

static bool proxy_dial(
	struct http_ctx *restrict ctx, struct ev_loop *loop,
	const char *addr_str)
{
	struct server *restrict s = ctx->server;
	struct ruleset *ruleset = s->ruleset;

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
	LOGI_F("http: CONNECT %s", hdr->req.url);

	if (!proxy_dial(ctx, loop, hdr->req.url)) {
		http_resp_errpage(ctx, HTTP_BAD_GATEWAY);
		return;
	}
}

static void handle_ruleset_stats(struct http_ctx *restrict ctx, const double dt)
{
	struct ruleset *restrict ruleset = ctx->server->ruleset;
	if (ruleset == NULL) {
		return;
	}
	const size_t heap_bytes = ruleset_memused(ruleset);
	char heap_total[16];
	(void)format_iec_bytes(
		heap_total, sizeof(heap_total), (double)heap_bytes);
	(void)buf_appendf(
		&ctx->wbuf,
		""
		"Ruleset Memory  : %s\n",
		heap_total);
	const char *str = ruleset_stats(ruleset, dt);
	if (str == NULL) {
		return;
	}
	(void)buf_appendf(
		&ctx->wbuf,
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
			&ctx->wbuf, "" PROJECT_NAME " " PROJECT_VER "\n"
				    "  " PROJECT_HOMEPAGE "\n\n");
	}

	const ev_tstamp now = ev_now(loop);
	const double uptime = server_get_uptime(ctx->server, now);
	const time_t server_time = time(NULL);
	struct stats total;
	stats_read(&total);

	const uintmax_t num_request = total.num_request;

	const size_t num_halfopen = total.num_halfopen;
	const size_t num_active = transfer_get_active() / 2u;

	const uintmax_t xfer_bytes = transfer_get_bytes();
	char timestamp[32];
	(void)strftime(
		timestamp, sizeof(timestamp), "%FT%T%z",
		localtime(&server_time));
	char xfer_total[16];
	(void)format_iec_bytes(
		xfer_total, sizeof(xfer_total), (double)xfer_bytes);

	char str_uptime[16];
	(void)format_duration(
		str_uptime, sizeof(str_uptime), make_duration(uptime));

	(void)buf_appendf(
		&ctx->wbuf,
		""
		"Server Time     : %s\n"
		"Uptime          : %s\n"
		"Active          : %zu (+%zu)\n"
		"Transferred     : %s\n"
		"Total Requests  : %ju\n",
		timestamp, str_uptime, num_active, num_halfopen, xfer_total,
		num_request);

	if (stateless) {
		return;
	}

	static struct {
		uintmax_t num_request;
		uintmax_t xfer_bytes;
		ev_tstamp tstamp;
	} last = { .tstamp = TSTAMP_NIL };
	const double dt =
		(last.tstamp == TSTAMP_NIL) ? uptime : now - last.tstamp;
	last.tstamp = now;

	char xfer_rate[16];
	(void)format_iec_bytes(
		xfer_rate, sizeof(xfer_rate),
		(double)(xfer_bytes - last.xfer_bytes) / dt);
	last.xfer_bytes = xfer_bytes;

	const double request_rate =
		(double)(num_request - last.num_request) / dt;
	last.num_request = num_request;

	(void)buf_appendf(
		&ctx->wbuf,
		""
		"Traffic         : %s/s\n"
		"Requests        : %.1lf/s\n",
		xfer_rate, request_rate);

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
	struct server *restrict s = ctx->server;
	struct ruleset *ruleset = s->ruleset;
	if (ruleset == NULL) {
		RESPHDR_TXT(ctx, HTTP_INTERNAL_SERVER_ERROR);
		(void)buf_appendf(
			&ctx->wbuf, "%s",
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
			BUF_APPENDSTR(&ctx->wbuf, err);
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
			BUF_APPENDSTR(&ctx->wbuf, err);
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
		(void)buf_appendf(&ctx->wbuf, "Ruleset Live Memory: %s\n", buf);
		return;
	}

	http_resp_errpage(ctx, HTTP_NOT_FOUND);
}

static void
http_handle_restapi(struct ev_loop *loop, struct http_ctx *restrict ctx)
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

void http_proxy_serve(
	struct ev_loop *loop, struct server *s, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	UNUSED(accepted_sa);
	struct http_ctx *restrict ctx =
		http_new(accepted_fd, s, http_handle_proxy);
	if (ctx == NULL) {
		LOGOOM();
		(void)close(accepted_fd);
		return;
	}
	http_start(loop, ctx);
}

void http_api_serve(
	struct ev_loop *loop, struct server *s, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	UNUSED(accepted_sa);
	struct http_ctx *restrict ctx =
		http_new(accepted_fd, s, http_handle_restapi);
	if (ctx == NULL) {
		LOGOOM();
		(void)close(accepted_fd);
		return;
	}
	http_start(loop, ctx);
}

void http_read_stats(struct stats *restrict out_stats)
{
	*out_stats = stats;
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
			vbuf_free(ctx->wbuf);
			free(ctx);
			return;
		}
		buf += nsend;
		len -= nsend;
		nbsend += nsend;
	}
	buf_consume(ctx->wbuf, nbsend);
	if (ctx->wbuf->len > 0) {
		return;
	}

	ev_io_stop(loop, watcher);
	vbuf_free(ctx->wbuf);
	free(ctx);
}

static void invoke_cb(struct ev_loop *loop, void *data)
{
	struct http_invoke_ctx *restrict ctx = data;
	struct ev_io *restrict w_write = &ctx->w_write;
	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		LOGD("dielr err");
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
	dialer_init(
		&ctx->dialer, conf,
		&(struct event_cb){
			.cb = invoke_cb,
			.ctx = ctx,
		});
	ctx->wbuf = vbuf_appendf(
		NULL,
		"POST /ruleset/invoke HTTP/1.0\r\n"
		"Content-Length: %zu\r\n"
		"\r\n"
		"%.*s",
		len, (int)len, code);
	if (ctx->wbuf == NULL) {
		LOGOOM();
		dialer_stop(&ctx->dialer, loop);
		free(ctx);
		return NULL;
	}
	LOGV_F("http_invoke:\n%.*s", (int)ctx->wbuf->len, ctx->wbuf->data);
	dialer_start(&ctx->dialer, loop, req);
	return ctx;
}
