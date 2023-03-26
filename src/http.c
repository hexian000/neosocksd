/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http.h"
#include "net/http.h"
#include "net/url.h"
#include "utils/buffer.h"
#include "utils/formats.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "dialer.h"
#include "ruleset.h"
#include "transfer.h"
#include "socks.h"
#include "forward.h"
#include "util.h"
#include "server.h"

#include <ev.h>

#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <sys/socket.h>

#include <assert.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <inttypes.h>

static void
http_read_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_write_cb(struct ev_loop *loop, struct ev_io *watcher, int revents);
static void
http_timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents);

#define HTTP_MAX_HEADER_COUNT 256
#define HTTP_MAX_ENTITY 8192

static size_t http_num_halfopen = 0;

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
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_stop(loop, w_read);
	struct ev_io *restrict w_write = &ctx->w_write;
	ev_io_stop(loop, w_write);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_stop(loop, w_timeout);
	http_num_halfopen--;
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

static void http_write_error(struct http_ctx *restrict ctx, const uint16_t code)
{
	LOGV_F("http: response HTTP %" PRIu16, code);
	const size_t cap = ctx->wbuf.cap - ctx->wbuf.len;
	char *buf = (char *)(ctx->wbuf.data + ctx->wbuf.len);
	ctx->wbuf.len += http_error(buf, cap, code);
}

static void
http_write_rsphdr(struct http_ctx *restrict ctx, const uint16_t code)
{
	char date_str[32];
	const int date_len = (int)http_date(date_str, sizeof(date_str));
	(void)buf_appendf(
		&ctx->wbuf,
		"HTTP/1.0 %" PRIu16 " %s\r\n"
		"Date: %.*s\r\n"
		"Connection: close\r\n"
		"Content-type: text/plain\r\n\r\n",
		code, http_status(code), date_len, date_str);
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
		if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR ||
		    err == ENOMEM) {
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
				http_write_error(ctx, HTTP_ENTITY_TOO_LARGE);
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
		ctx->content_length = 0;
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
				http_write_error(ctx, HTTP_BAD_REQUEST);
				ev_io_start(loop, w_write);
				return;
			}
			if (ctx->content_length > ctx->rbuf.cap) {
				ev_io_stop(loop, watcher);
				http_write_error(ctx, HTTP_ENTITY_TOO_LARGE);
				ev_io_start(loop, w_write);
				return;
			}
		}
		LOGV_F("http: header %s: %s", key, value);
	}
	if ((char *)(ctx->rbuf.data + ctx->rbuf.len) <
	    ctx->http_nxt + ctx->content_length) {
		if ((char *)(ctx->rbuf.data + ctx->rbuf.cap) <
		    ctx->http_nxt + ctx->content_length + 1) {
			ev_io_stop(loop, watcher);
			http_write_error(ctx, HTTP_ENTITY_TOO_LARGE);
			ev_io_start(loop, w_write);
		}
		return;
	}
	ctx->http_nxt[ctx->content_length] = '\0';

	/* HTTP/1.0 only, stop reading */
	ev_io_stop(loop, watcher);
	ctx->handler(loop, ctx);

	if (ctx->wbuf.len > 0) {
		struct ev_io *restrict w_write = &ctx->w_write;
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
		http_write_error(ctx, HTTP_BAD_GATEWAY);
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
	size_t nbsend = 0;
	size_t len = ctx->wbuf.len;
	while (len > 0) {
		const ssize_t nsend = send(watcher->fd, buf, len, 0);
		if (nsend < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK ||
			    err == EINTR || err == ENOMEM) {
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
	return ctx;
}

static void http_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct ev_io *restrict w_read = &ctx->w_read;
	ev_io_start(loop, w_read);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_start(loop, w_timeout);
	http_num_halfopen++;
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
	dialer_init(
		&ctx->dialer, s->conf,
		&(struct event_cb){
			.cb = dialer_cb,
			.ctx = ctx,
		});
	dialer_start(&ctx->dialer, loop, req);
	return true;
}

static void
http_handle_proxy(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_message *restrict hdr = &ctx->http_msg;
	if (strcasecmp(hdr->req.method, "CONNECT") != 0) {
		http_write_error(ctx, HTTP_BAD_REQUEST);
		return;
	}

	if (!proxy_dial(ctx, loop, hdr->req.url)) {
		http_write_error(ctx, HTTP_BAD_GATEWAY);
		return;
	}
}

static void http_handle_stats(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	struct url *restrict uri)
{
	UNUSED(uri);
	const struct http_message *restrict hdr = &ctx->http_msg;
	if (strcasecmp(hdr->req.method, "GET") != 0) {
		http_write_error(ctx, HTTP_BAD_REQUEST);
		return;
	}
	http_write_rsphdr(ctx, HTTP_OK);

	const ev_tstamp now = ev_now(loop);
	static size_t last_xfer_bytes = 0;
	static ev_tstamp last = TSTAMP_NIL;
	const double dt = (last == TSTAMP_NIL) ? 1.0 : now - last;
	{
		const time_t server_time = time(NULL);
		const size_t num_halfopen = socks_get_halfopen() +
					    http_get_halfopen() +
					    forward_get_halfopen();
		const size_t num_active = transfer_get_active() / 2u;
		const size_t xfer_bytes = transfer_get_bytes();
		char timestamp[32];
		(void)strftime(
			timestamp, sizeof(timestamp), "%FT%T%z",
			localtime(&server_time));
		char xfer_total[16];
		(void)format_iec(xfer_total, sizeof(xfer_total), xfer_bytes);
		char xfer_rate[16];
		(void)format_iec(
			xfer_rate, sizeof(xfer_rate),
			(size_t)round(
				(double)(xfer_bytes - last_xfer_bytes) / dt));
		char uptime[16];
		(void)format_duration_seconds(
			uptime, sizeof(uptime),
			make_duration(server_get_uptime(ctx->server, now)));
		(void)buf_appendf(
			&ctx->wbuf,
			"" PROJECT_NAME " " PROJECT_VER "\n"
			"  " PROJECT_HOMEPAGE "\n\n"
			"Server Time     : %s\n"
			"Uptime          : %s\n"
			"Active          : %zu (+%zu)\n"
			"Transferred     : %s\n"
			"Traffic         : %s/s\n",
			timestamp, uptime, num_active, num_halfopen, xfer_total,
			xfer_rate);

		last_xfer_bytes = xfer_bytes;
	}

	struct server *restrict s = ctx->server;
	struct ruleset *ruleset = s->ruleset;
	if (ruleset) {
		const size_t heap_bytes = ruleset_memused(ruleset);
		char heap_total[16];
		(void)format_iec(heap_total, sizeof(heap_total), heap_bytes);
		(void)buf_appendf(
			&ctx->wbuf,
			""
			"Ruleset Memory  : %s\n",
			heap_total);
	}

	last = now;
}

static void http_handle_ruleset(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	struct url *restrict uri)
{
	UNUSED(loop);
	const struct http_message *restrict hdr = &ctx->http_msg;
	if (uri->query == NULL) {
		http_write_error(ctx, HTTP_BAD_REQUEST);
		return;
	}
	struct server *restrict s = ctx->server;
	struct ruleset *ruleset = s->ruleset;
	if (ruleset == NULL) {
		http_write_rsphdr(ctx, HTTP_INTERNAL_SERVER_ERROR);
		(void)buf_appendf(
			&ctx->wbuf, "%s",
			"ruleset not enabled, restart with -r\n");
		return;
	}

	if (strcmp(uri->query, "gc") == 0) {
		if (strcasecmp(hdr->req.method, "POST") != 0) {
			http_write_error(ctx, HTTP_METHOD_NOT_ALLOWED);
			return;
		}
		ruleset_gc(ruleset);
		http_write_rsphdr(ctx, HTTP_OK);
		return;
	}

	if (strcmp(uri->query, "update") == 0) {
		if (strcasecmp(hdr->req.method, "POST") != 0) {
			http_write_error(ctx, HTTP_METHOD_NOT_ALLOWED);
			return;
		}
		LOGV_F("api: ruleset update\n%s", ctx->http_nxt);
		if (!ruleset_load(ruleset, ctx->http_nxt)) {
			http_write_error(ctx, HTTP_INTERNAL_SERVER_ERROR);
			return;
		}
		http_write_rsphdr(ctx, HTTP_OK);
		return;
	}

	http_write_rsphdr(ctx, HTTP_NOT_FOUND);
}

static void
http_handle_restapi(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict hdr = &ctx->http_msg;
	struct url uri;
	LOGV_F("api: serve uri \"%s\"", hdr->req.url);
	if (!url_parse(hdr->req.url, &uri)) {
		LOGW("api: failed parsing url");
		http_write_error(ctx, HTTP_BAD_REQUEST);
		return;
	}
	if (strcmp(uri.path, "stats") == 0) {
		http_handle_stats(loop, ctx, &uri);
		return;
	}
	if (strcmp(uri.path, "ruleset") == 0) {
		http_handle_ruleset(loop, ctx, &uri);
		return;
	}
	if (strcmp(uri.path, "healthy") == 0) {
		http_write_rsphdr(ctx, HTTP_OK);
		return;
	}
	http_write_error(ctx, HTTP_NOT_FOUND);
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

size_t http_get_halfopen(void)
{
	return http_num_halfopen;
}
