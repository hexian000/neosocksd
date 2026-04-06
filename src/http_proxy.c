/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
#include "proto/domain.h"
#include "proto/http.h"
#include "ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "codec/base64.h"
#include "net/http.h"
#include "net/url.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>
#include <strings.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct http_ctx;

/* never rollback */
enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_PROCESS,
	STATE_RESPONSE,
	STATE_CONNECT,
	STATE_FORWARD,
	/* relaying upstream HTTP response before returning conn to cache */
	STATE_RELAY_HDR,
	STATE_RELAY_BODY,
	STATE_ESTABLISHED,
	STATE_BIDIRECTIONAL,
};

struct server;

struct http_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum http_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	int_least64_t accepted_ns;
	ev_timer w_timeout;
	union {
		/* state < STATE_CONNECTED */
		struct {
			ev_io w_recv, w_send;
#if WITH_RULESET
			ev_idle w_process;
			struct ruleset_callback ruleset_callback;
			struct ruleset_state *ruleset_state;
#endif
			struct dialreq *dialreq;
			struct dialer dialer;
			struct http_conn conn;
			size_t relay_content_length; /* SIZE_MAX = unknown */
			size_t relay_body_read;
			bool relay_can_cache : 1;
		};
		/* state >= STATE_CONNECTED */
		struct {
			struct transfer uplink, downlink;
		};
	};
};
ASSERT_SUPER(struct gcbase, struct http_ctx, gcbase);

static int format_status(
	char *restrict s, const size_t maxlen,
	const struct http_ctx *restrict ctx)
{
	char caddr[64];
	sa_format(caddr, sizeof(caddr), &ctx->accepted_sa.sa);
	if (ctx->state != STATE_CONNECT && ctx->state != STATE_FORWARD) {
		return snprintf(
			s, maxlen, "[fd:%d] %s", ctx->accepted_fd, caddr);
	}
	return snprintf(
		s, maxlen, "[fd:%d] %s -> `%s'", ctx->accepted_fd, caddr,
		ctx->conn.msg.req.url);
}

#define HTTP_CTX_LOG_F(level, ctx, format, ...)                                \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char status_str[256];                                          \
		const int nstatus =                                            \
			format_status(status_str, sizeof(status_str), (ctx));  \
		ASSERT(nstatus > 0);                                           \
		LOG_F(level, "%.*s: " format, nstatus, status_str,             \
		      __VA_ARGS__);                                            \
	} while (0)
#define HTTP_CTX_LOG(level, ctx, message)                                      \
	HTTP_CTX_LOG_F(level, ctx, "%s", message)

static void send_response(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ctx->state = STATE_RESPONSE;
	ev_io_start(loop, &ctx->w_send);
}

static void send_errpage(
	struct ev_loop *loop, struct http_ctx *restrict ctx,
	const uint_fast16_t code)
{
	ASSERT(4 <= (code / 100) && (code / 100) <= 5);
	http_resp_errpage(&ctx->conn, code);
	send_response(loop, ctx);
}

static void http_ctx_stop(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_REQUEST:
		ev_io_stop(loop, &ctx->w_recv);
		stats->num_halfopen--;
		return;
	case STATE_PROCESS:
#if WITH_RULESET
		ev_idle_stop(loop, &ctx->w_process);
		if (ctx->ruleset_state != NULL) {
			ruleset_cancel(loop, ctx->ruleset_state);
			ctx->ruleset_state = NULL;
		}
#endif
		stats->num_halfopen--;
		return;
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		dialer_cancel(&ctx->dialer, loop);
		stats->num_halfopen--;
		return;
	case STATE_FORWARD:
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_RELAY_HDR:
	case STATE_RELAY_BODY:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_ESTABLISHED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_halfopen--;
		return;
	case STATE_BIDIRECTIONAL:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_sessions--;
		break;
	}
	HTTP_CTX_LOG_F(VERBOSE, ctx, "closed, %zu active", stats->num_sessions);
}

static void http_ctx_finalize(struct gcbase *restrict obj)
{
	struct http_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct http_ctx, gcbase, obj);
	HTTP_CTX_LOG_F(VERBOSE, ctx, "closing state=%d", ctx->state);

	http_ctx_stop(ctx->s->loop, ctx);
	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;
	VBUF_FREE(ctx->conn.cbuf);
}

/* Parse "host:port" from an absolute HTTP URL into buf.
 * Port defaults to 80 when absent.  Returns false on failure. */
static bool parse_hostport(
	char *restrict buf, const size_t bufcap, const char *restrict url)
{
	const size_t urllen = strlen(url);
	if (urllen >= bufcap) {
		return false;
	}
	memcpy(buf, url, urllen + 1);
	struct url parsed;
	if (!url_parse(buf, &parsed) || parsed.scheme == NULL ||
	    strcmp(parsed.scheme, "http") != 0 || parsed.host == NULL ||
	    parsed.host[0] == '\0') {
		return false;
	}
	const size_t hlen = strlen(parsed.host);
	memmove(buf, parsed.host, hlen + 1);
	/* append :80 if port absent */
	const char *portcheck = (buf[0] == '[') ? strchr(buf, ']') : buf;
	if (portcheck == NULL || strchr(portcheck, ':') == NULL) {
		if (hlen + 3 >= bufcap) {
			return false;
		}
		memcpy(buf + hlen, ":80", 4);
	}
	return true;
}

static struct dialreq *
make_dialreq(struct http_ctx *restrict ctx, const char *restrict addr_str)
{
	struct dialreq *req = dialreq_new(ctx->s->basereq, 0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	if (!dialaddr_parse(&req->addr, addr_str, strlen(addr_str))) {
		dialreq_free(req);
		return NULL;
	}
	return req;
}

static void http_connect(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	if (ctx->dialreq == NULL) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	HTTP_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	dialer_do(
		&ctx->dialer, loop, ctx->dialreq, ctx->s->conf,
		ctx->s->resolver);
}

/* Parse the target host:port for a plain HTTP request.
 * Tries the absolute URL first, then falls back to the Host header. */
static bool parse_req_target(
	char *restrict buf, const size_t bufcap,
	const struct http_ctx *restrict ctx)
{
	const char *url = ctx->conn.msg.req.url;
	if (parse_hostport(buf, bufcap, url)) {
		return true;
	}
	/* fall back to Host header */
	const char *host = ctx->conn.hdr.host;
	if (host == NULL) {
		return false;
	}
	const size_t hlen = strlen(host);
	if (hlen >= bufcap) {
		return false;
	}
	memcpy(buf, host, hlen + 1);
	/* append :80 if port absent */
	const char *portcheck = (buf[0] == '[') ? strchr(buf, ']') : buf;
	if (portcheck == NULL || strchr(portcheck, ':') == NULL) {
		if (hlen + 3 >= bufcap) {
			return false;
		}
		memcpy(buf + hlen, ":80", 4);
	}
	return true;
}

static void mark_ready(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;
	stats->num_sessions++;
	if (stats->num_sessions > stats->num_sessions_peak) {
		stats->num_sessions_peak = stats->num_sessions;
	}
	stats->num_success++;
	{
		const int_fast64_t elapsed =
			clock_monotonic_ns() - ctx->accepted_ns;
		stats->connect_ns[stats->num_connects % CONNECT_HIST_SIZE] =
			elapsed;
		stats->num_connects++;
	}
	HTTP_CTX_LOG_F(
		DEBUG, ctx, "ready, %zu active sessions", stats->num_sessions);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	if (ctx->uplink.state == XFER_FINISHED &&
	    ctx->downlink.state == XFER_FINISHED) {
		gc_unref(&ctx->gcbase);
		return;
	}
	if (ctx->state == STATE_ESTABLISHED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		mark_ready(loop, ctx);
		return;
	}
}

static void http_ctx_hijack(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	/* cleanup before state change */
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	if (ctx->s->conf->bidir_timeout) {
		ctx->state = STATE_ESTABLISHED;
	} else {
		mark_ready(loop, ctx);
	}

	const struct transfer_state_cb cb = {
		.func = xfer_state_cb,
		.data = ctx,
	};
	struct server_stats *restrict stats = &ctx->s->stats;
	transfer_init(
		&ctx->uplink, &cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up, true, ctx->s->conf->pipe);
	transfer_init(
		&ctx->downlink, &cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down, false, ctx->s->conf->pipe);

	HTTP_CTX_LOG_F(
		DEBUG, ctx,
		"transfer start: uplink [%d->%d], downlink [%d->%d]",
		ctx->accepted_fd, ctx->dialed_fd, ctx->dialed_fd,
		ctx->accepted_fd);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

/* Scan raw header bytes for Content-Length and Connection header values.
 * `hdr_end` points just past the \r\n\r\n separator.
 * On return, `*out_len` is the parsed Content-Length (SIZE_MAX if absent),
 * and `*out_can_cache` is true unless "Connection: close" was found. */
static void scan_relay_headers(
	const char *restrict hdr_end, const char *restrict data, size_t datalen,
	size_t *restrict out_len, bool *restrict out_can_cache)
{
	*out_len = SIZE_MAX;
	*out_can_cache = true;

	/* skip the response status line */
	const char *p = (const char *)memchr(data, '\n', datalen);
	if (p == NULL) {
		return;
	}
	p++;

	while (p < hdr_end) {
		const char *eol =
			(const char *)memchr(p, '\n', (size_t)(hdr_end - p));
		if (eol == NULL) {
			break;
		}
		const char *colon =
			(const char *)memchr(p, ':', (size_t)(eol - p));
		if (colon == NULL) {
			p = eol + 1;
			continue;
		}
		const size_t klen = (size_t)(colon - p);
		const char *val = colon + 1;
		while (val < eol && (*val == ' ' || *val == '\t')) {
			val++;
		}
		/* strip trailing \r */
		const char *vend = eol;
		if (vend > val && *(vend - 1) == '\r') {
			vend--;
		}
		const size_t vlen = (size_t)(vend - val);

		if (klen == CONSTSTRLEN("Content-Length") &&
		    strncasecmp(p, "Content-Length", klen) == 0) {
			char tmp[32];
			if (vlen < sizeof(tmp)) {
				memcpy(tmp, val, vlen);
				tmp[vlen] = '\0';
				char *end;
				const uintmax_t v = strtoumax(tmp, &end, 10);
				if (*end == '\0' && v <= SIZE_MAX) {
					*out_len = (size_t)v;
				}
			}
		} else if (
			klen == CONSTSTRLEN("Connection") &&
			strncasecmp(p, "Connection", klen) == 0 &&
			vlen == CONSTSTRLEN("close") &&
			strncasecmp(val, "close", vlen) == 0) {
			*out_can_cache = false;
		}

		p = eol + 1;
	}
}

static void relay_finish(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);
	if (ctx->relay_can_cache) {
		if (ctx->s->conf->conn_cache) {
			conn_cache_put(loop, ctx->dialed_fd, ctx->dialreq);
		} else {
			CLOSE_FD(ctx->dialed_fd);
		}
		ctx->dialed_fd = -1;
	}
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;
	gc_unref(&ctx->gcbase);
}

static void
relay_recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RELAY_HDR || ctx->state == STATE_RELAY_BODY);

	struct http_conn *restrict p = &ctx->conn;
	/* read into rbuf from dialed_fd */
	const size_t space = p->rbuf.cap - p->rbuf.len;
	if (space == 0) {
		/* buffer full; flush wbuf first by waiting for send */
		ev_io_stop(loop, watcher);
		return;
	}
	size_t n = space;
	const int ret =
		socket_recv(ctx->dialed_fd, p->rbuf.data + p->rbuf.len, &n);
	if (ret != 0) {
		const int err = errno;
		HTTP_CTX_LOG_F(
			WARNING, ctx, "relay recv: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	if (n == 0) {
		/* upstream EOF */
		if (ctx->state == STATE_RELAY_HDR) {
			/* headers never completed */
			gc_unref(&ctx->gcbase);
			return;
		}
		/* upstream EOF: flush any remaining rbuf bytes to client */
		if (p->rbuf.len > 0) {
			BUF_APPEND(p->wbuf, p->rbuf.data, p->rbuf.len);
			BUF_RESET(p->rbuf);
		}
		if (p->wbuf.len > p->wpos) {
			ev_io_start(loop, &ctx->w_send);
		}
		/* stop reading; relay_send_cb will call relay_finish */
		ev_io_stop(loop, watcher);
		ctx->relay_can_cache = false;
		ctx->state = STATE_RELAY_BODY; /* sentinel: trigger finish */
		/* If nothing left to send, finish immediately */
		if (p->wbuf.len == p->wpos) {
			relay_finish(loop, ctx);
		}
		return;
	}

	p->rbuf.len += n;

	if (ctx->state == STATE_RELAY_HDR) {
		/* Search for end-of-headers marker */
		const char *raw = (const char *)p->rbuf.data;
		const size_t rawlen = p->rbuf.len;
		const char *hdr_end = NULL;
		for (size_t i = 0; i + 3 < rawlen; i++) {
			if (raw[i] == '\r' && raw[i + 1] == '\n' &&
			    raw[i + 2] == '\r' && raw[i + 3] == '\n') {
				hdr_end = raw + i + 4;
				break;
			}
		}
		if (hdr_end == NULL) {
			/* headers incomplete; forward what we have */
			BUF_APPEND(p->wbuf, p->rbuf.data, p->rbuf.len);
			p->rbuf.len = 0;
			BUF_RESET(p->rbuf);
			if (p->wbuf.len > p->wpos) {
				ev_io_start(loop, &ctx->w_send);
			}
			return;
		}
		/* headers complete: scan for Content-Length / Connection */
		size_t content_length;
		bool can_cache;
		scan_relay_headers(
			hdr_end, raw, rawlen, &content_length, &can_cache);
		ctx->relay_content_length = content_length;
		ctx->relay_can_cache = can_cache;

		/* count body bytes already buffered */
		const size_t body_so_far = rawlen - (size_t)(hdr_end - raw);
		ctx->relay_body_read = body_so_far;

		/* forward everything in rbuf to client */
		BUF_APPEND(p->wbuf, p->rbuf.data, rawlen);
		BUF_RESET(p->rbuf);
		if (p->wbuf.len > p->wpos) {
			ev_io_start(loop, &ctx->w_send);
		}

		if (content_length != SIZE_MAX &&
		    body_so_far >= content_length) {
			/* body already complete */
			ev_io_stop(loop, watcher);
			if (p->wbuf.len == p->wpos) {
				relay_finish(loop, ctx);
			}
			/* else relay_send_cb will finish when wbuf drained */
			return;
		}
		ctx->state = STATE_RELAY_BODY;
		return;
	}

	/* STATE_RELAY_BODY: forward newly received bytes */
	const size_t chunk = p->rbuf.len;
	ctx->relay_body_read += chunk;
	BUF_APPEND(p->wbuf, p->rbuf.data, chunk);
	BUF_RESET(p->rbuf);
	if (p->wbuf.len > p->wpos) {
		ev_io_start(loop, &ctx->w_send);
	}

	const size_t clen = ctx->relay_content_length;
	if (clen != SIZE_MAX && ctx->relay_body_read >= clen) {
		/* body complete */
		ev_io_stop(loop, watcher);
		if (p->wbuf.len == p->wpos) {
			relay_finish(loop, ctx);
		}
		/* else relay_send_cb will finish */
	}
}

static void
relay_send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RELAY_HDR || ctx->state == STATE_RELAY_BODY);

	struct http_conn *restrict p = &ctx->conn;
	const unsigned char *buf = p->wbuf.data + p->wpos;
	size_t len = p->wbuf.len - p->wpos;
	const int ret = socket_send(ctx->accepted_fd, buf, &len);
	if (ret != 0) {
		const int err = errno;
		HTTP_CTX_LOG_F(
			WARNING, ctx, "relay send: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	p->wpos += len;
	if (p->wpos < p->wbuf.len) {
		return;
	}
	/* wbuf fully sent; reset positions */
	BUF_RESET(p->wbuf);
	p->wpos = 0;
	ev_io_stop(loop, watcher);

	/* If recv is still active, wbuf was just drained between two recv
	 * callbacks — nothing to do, wait for more data. */
	if (ev_is_active(&ctx->w_recv)) {
		return;
	}
	/* recv is not active; determine why */
	const size_t clen = ctx->relay_content_length;
	if (clen != SIZE_MAX && ctx->relay_body_read >= clen) {
		/* body complete */
		relay_finish(loop, ctx);
		return;
	}
	if (!ctx->relay_can_cache) {
		/* upstream closed the connection (EOF) */
		relay_finish(loop, ctx);
		return;
	}
	/* recv was paused because rbuf was full; resume reading */
	ev_io_start(loop, &ctx->w_recv);
}

static void
http_ctx_relay_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;
	BUF_RESET(p->rbuf);
	BUF_RESET(p->wbuf);
	p->wpos = 0;

	ctx->relay_content_length = SIZE_MAX;
	ctx->relay_body_read = 0;
	ctx->relay_can_cache = true; /* updated after header scan */
	ctx->state = STATE_RELAY_HDR;

	ev_io_init(&ctx->w_recv, relay_recv_cb, ctx->dialed_fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(&ctx->w_send, relay_send_cb, ctx->accepted_fd, EV_WRITE);
	ctx->w_send.data = ctx;
	ev_io_start(loop, &ctx->w_recv);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE || ctx->state == STATE_FORWARD);

	const int ret = http_conn_send(&ctx->conn, watcher->fd);
	if (ret < 0) {
		const int err = errno;
		HTTP_CTX_LOG_F(
			WARNING, ctx, "socket_send: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	if (ret > 0) {
		return;
	}
	if (ctx->state == STATE_FORWARD) {
		/* request fully forwarded */
		ev_io_stop(loop, &ctx->w_send);
		if (ctx->s->conf->conn_cache) {
			/* relay the upstream response, then maybe cache conn */
			http_ctx_relay_start(loop, ctx);
			return;
		}
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		mark_ready(loop, ctx);
		const struct transfer_state_cb cb = {
			.func = xfer_state_cb,
			.data = ctx,
		};
		struct server_stats *restrict stats = &ctx->s->stats;
		transfer_init(
			&ctx->uplink, &cb, ctx->accepted_fd, ctx->dialed_fd,
			&stats->byt_up, true, ctx->s->conf->pipe);
		transfer_init(
			&ctx->downlink, &cb, ctx->dialed_fd, ctx->accepted_fd,
			&stats->byt_down, false, ctx->s->conf->pipe);
		HTTP_CTX_LOG_F(
			DEBUG, ctx,
			"transfer start: uplink [%d->%d], downlink [%d->%d]",
			ctx->accepted_fd, ctx->dialed_fd, ctx->dialed_fd,
			ctx->accepted_fd);
		transfer_start(loop, &ctx->uplink);
		transfer_start(loop, &ctx->downlink);
		return;
	}
	/* Connection: close */
	gc_unref(&ctx->gcbase);
}

/* After a successful dial for a proxy_pass request, wire w_send to the
 * upstream fd and start draining the buffered forwarded request. */
static void
http_ctx_forward(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ctx->state = STATE_FORWARD;
	ev_io_init(&ctx->w_send, send_cb, ctx->dialed_fd, EV_WRITE);
	ctx->w_send.data = ctx;
	ev_io_start(loop, &ctx->w_send);
}

#if WITH_RULESET
static void
ruleset_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->dialreq = ctx->ruleset_callback.request.req;
	ctx->ruleset_state = NULL;
	if (ctx->dialreq == NULL) {
		ctx->s->stats.num_reject_ruleset++;
		send_errpage(loop, ctx, HTTP_FORBIDDEN);
		return;
	}
	if (strcmp(ctx->conn.msg.req.method, "CONNECT") != 0 &&
	    ctx->s->conf->conn_cache) {
		const int fd = conn_cache_get(loop, ctx->dialreq);
		if (fd != -1) {
			LOGV_F("http_proxy: reusing cached connection [fd:%d]",
			       fd);
			ctx->dialed_fd = fd;
			http_ctx_forward(loop, ctx);
			return;
		}
	}
	http_connect(loop, ctx);
}

static void parse_proxy_auth(
	unsigned char *buf, const size_t bufsize, const char **username,
	const char **password, const char *authtype, const char *credentials)
{
	if (authtype == NULL || credentials == NULL) {
		return;
	}
	if (strcmp(authtype, "Basic") != 0) {
		return;
	}
	size_t dstlen = bufsize - 1;
	if (!base64_decode(
		    buf, &dstlen, (const unsigned char *)credentials,
		    strlen(credentials))) {
		return;
	}
	char *s = (char *)buf;
	s[dstlen] = '\0';
	char *sep = strchr(s, ':');
	if (sep == NULL) {
		return;
	}
	*sep = '\0';
	*username = s;
	*password = sep + 1;
}

static void
process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct http_ctx *restrict ctx = watcher->data;
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	ASSERT(ruleset != NULL);
	ASSERT(ctx->state == STATE_PROCESS);

	unsigned char buf[512];
	const char *username = NULL;
	const char *password = NULL;
	parse_proxy_auth(
		buf, sizeof(buf), &username, &password,
		ctx->conn.hdr.proxy_authorization.type,
		ctx->conn.hdr.proxy_authorization.credentials);
	if (ctx->s->conf->auth_required &&
	    (username == NULL || password == NULL)) {
		RESPHDR_BEGIN(
			ctx->conn.wbuf, HTTP_PROXY_AUTHENTICATION_REQUIRED);
		RESPHDR_CONN_CLOSE(ctx->conn.wbuf);
		BUF_APPENDSTR(ctx->conn.wbuf, "Proxy-Authenticate: Basic\r\n");
		RESPHDR_FINISH(ctx->conn.wbuf);
		send_response(loop, ctx);
		return;
	}

	const char *addr_str;
	char hostport[FQDN_MAX_LENGTH + sizeof(":65535")];
	if (strcmp(ctx->conn.msg.req.method, "CONNECT") == 0) {
		addr_str = ctx->conn.msg.req.url;
	} else {
		if (!parse_req_target(hostport, sizeof(hostport), ctx)) {
			send_errpage(loop, ctx, HTTP_BAD_REQUEST);
			return;
		}
		addr_str = hostport;
	}
	const bool ok = ruleset_resolve(
		ruleset, &ctx->ruleset_state, addr_str, username, password,
		&ctx->ruleset_callback);
	if (!ok) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
}
#endif

/* For proxy_pass requests: write the forwarded request line into wbuf
 * on the first header callback (before any header is forwarded). */
static void build_pass_req(struct http_conn *restrict p)
{
	const char *method = p->msg.req.method;
	const char *version = p->msg.req.version;
	const size_t urllen = strlen(p->msg.req.url);
	if (urllen + 1 < HTTP_MAX_ENTITY) {
		char urlbuf[urllen + 1];
		memcpy(urlbuf, p->msg.req.url, sizeof(urlbuf));
		struct url parsed;
		if (url_parse(urlbuf, &parsed) && parsed.scheme != NULL &&
		    strcmp(parsed.scheme, "http") == 0) {
			(void)BUF_APPENDF(p->wbuf, "%s /", method);
			if (parsed.path != NULL && *parsed.path != '\0') {
				(void)BUF_APPENDF(p->wbuf, "%s", parsed.path);
			}
			if (parsed.query != NULL) {
				(void)BUF_APPENDF(p->wbuf, "?%s", parsed.query);
			}
			(void)BUF_APPENDF(p->wbuf, " %s\r\n", version);
			return;
		}
	}
	/* fallback: forward URL as-is */
	(void)BUF_APPENDF(
		p->wbuf, "%s %s %s\r\n", method, p->msg.req.url, version);
}

static void http_proxy_pass(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;

	/* ensure the request line was written (no headers case) */
	if (p->wbuf.len == 0) {
		build_pass_req(p);
	}
	/* keep upstream connection alive when conn_cache is enabled
	 * so we can return it to the cache after the response */
	if (ctx->s->conf->conn_cache) {
		BUF_APPENDSTR(p->wbuf, "\r\n");
	} else {
		BUF_APPENDSTR(p->wbuf, "Connection: close\r\n\r\n");
	}

	/* forward any body bytes already buffered in rbuf */
	{
		const size_t overread =
			p->rbuf.len -
			(size_t)((unsigned char *)p->next - p->rbuf.data);
		if (overread > 0) {
			BUF_APPEND(p->wbuf, (unsigned char *)p->next, overread);
		}
	}

	HTTP_CTX_LOG_F(
		VERBOSE, ctx, "http: %s `%s'", p->msg.req.method,
		p->msg.req.url);

#if WITH_RULESET
	const struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif
	{
		char hostport[FQDN_MAX_LENGTH + sizeof(":65535")];
		if (!parse_req_target(hostport, sizeof(hostport), ctx)) {
			send_errpage(loop, ctx, HTTP_BAD_REQUEST);
			return;
		}
		ctx->dialreq = make_dialreq(ctx, hostport);
	}
	if (ctx->dialreq != NULL && ctx->s->conf->conn_cache) {
		const int fd = conn_cache_get(loop, ctx->dialreq);
		if (fd != -1) {
			LOGV_F("http_proxy: reusing cached connection [fd:%d]",
			       fd);
			ctx->dialed_fd = fd;
			http_ctx_forward(loop, ctx);
			return;
		}
	}
	http_connect(loop, ctx);
}

static void
http_proxy_handle(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->conn.msg;
	if (strcmp(msg->req.method, "CONNECT") != 0) {
		http_proxy_pass(loop, ctx);
		return;
	}

	const char *addr_str = ctx->conn.msg.req.url;
	HTTP_CTX_LOG_F(VERBOSE, ctx, "http: CONNECT `%s'", addr_str);
#if WITH_RULESET
	const struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif

	ctx->dialreq = make_dialreq(ctx, addr_str);
	http_connect(loop, ctx);
}

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_ctx *restrict ctx = watcher->data;

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
		stats->num_request++;
	} break;
	case STATE_PARSE_ERROR:
		send_errpage(loop, ctx, ctx->conn.http_status);
		return;
	default:
		FAILMSGF("unexpected http parser state: %d", ctx->conn.state);
	}

	http_proxy_handle(loop, ctx);
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_ctx *restrict ctx = watcher->data;
	ctx->s->stats.num_reject_timeout++;
	gc_unref(&ctx->gcbase);
}

static void dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct http_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	if (fd < 0) {
		const enum dialer_error err = ctx->dialer.err;
		const int syserr = ctx->dialer.syserr;
		if (syserr != 0) {
			HTTP_CTX_LOG_F(
				ERROR, ctx, "dialer: %s (%d) %s",
				dialer_strerror(err), syserr, strerror(syserr));
		} else {
			HTTP_CTX_LOG_F(
				ERROR, ctx, "dialer: %s", dialer_strerror(err));
		}
		ctx->s->stats.num_reject_upstream++;
		send_errpage(loop, ctx, HTTP_BAD_GATEWAY);
		return;
	}
	HTTP_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	ctx->dialed_fd = fd;

	if (strcmp(ctx->conn.msg.req.method, "CONNECT") == 0) {
		/* CONNECT tunnel: send 200 and hijack the connection */
		if (!http_resp_established(&ctx->conn)) {
			gc_unref(&ctx->gcbase);
			return;
		}
		http_ctx_hijack(loop, ctx);
	} else {
		/* plain HTTP: forward the buffered request to upstream */
		http_ctx_forward(loop, ctx);
	}
}

static bool parse_header(void *data, const char *key, char *value)
{
	struct http_ctx *restrict ctx = (struct http_ctx *)data;
	struct http_conn *restrict p = &ctx->conn;
	const bool is_connect = (strcmp(p->msg.req.method, "CONNECT") == 0);

	/* hop-by-hop headers: handle but never forward */
	if (strcasecmp(key, "Connection") == 0) {
		return parsehdr_connection(p, value);
	}
	if (strcasecmp(key, "Keep-Alive") == 0) {
		return true;
	}
	if (strcasecmp(key, "Proxy-Authorization") == 0) {
		char *sep = strchr(value, ' ');
		if (sep == NULL) {
			return false;
		}
		*sep = '\0';
		p->hdr.proxy_authorization.type = value;
		p->hdr.proxy_authorization.credentials = sep + 1;
		return true;
	}
	if (strcasecmp(key, "Proxy-Connection") == 0) {
		return true;
	}
	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(p, value);
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		if (!parsehdr_transfer_encoding(p, value)) {
			return false;
		}
		if (!is_connect &&
		    p->hdr.transfer.encoding == TENCODING_CHUNKED) {
			if (p->wbuf.len == 0) {
				build_pass_req(p);
			}
			BUF_APPENDSTR(
				p->wbuf, "Transfer-Encoding: chunked\r\n");
		}
		return true;
	}
	if (strcasecmp(key, "Upgrade") == 0) {
		return true;
	}
	if (strcasecmp(key, "Trailers") == 0) {
		return true;
	}

	if (is_connect) {
		/* CONNECT: only parse Authorization for auth check; ignore rest */
		if (strcasecmp(key, "Authorization") == 0) {
			char *sep = strchr(value, ' ');
			if (sep == NULL) {
				return false;
			}
			*sep = '\0';
			p->hdr.authorization.type = value;
			p->hdr.authorization.credentials = sep + 1;
		}
		return true;
	}

	/* proxy_pass: build forwarded request in wbuf */
	/* skip headers listed in Connection (dynamic hop-by-hop) */
	{
		const size_t keylen = strlen(key);
		const char *tok;
		size_t toklen;
		for (const char *next = parsehdr_connection_token(
			     p->hdr.connection, &tok, &toklen);
		     tok != NULL;
		     next = parsehdr_connection_token(next, &tok, &toklen)) {
			if (toklen == keylen &&
			    strncasecmp(tok, key, keylen) == 0) {
				return true;
			}
		}
	}
	if (p->wbuf.len == 0) {
		build_pass_req(p);
	}

	if (strcasecmp(key, "Host") == 0) {
		p->hdr.host = value;
		(void)BUF_APPENDF(p->wbuf, "Host: %s\r\n", value);
		return true;
	}
	if (strcasecmp(key, "Authorization") == 0) {
		char *sep = strchr(value, ' ');
		if (sep == NULL) {
			return false;
		}
		*sep = '\0';
		p->hdr.authorization.type = value;
		p->hdr.authorization.credentials = sep + 1;
		/* reconstruct for forwarding */
		(void)BUF_APPENDF(
			p->wbuf, "Authorization: %s %s\r\n",
			p->hdr.authorization.type,
			p->hdr.authorization.credentials);
		return true;
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		(void)BUF_APPENDF(p->wbuf, "Content-Length: %s\r\n", value);
		return true;
	}
	if (strcasecmp(key, "Content-Type") == 0) {
		p->hdr.content.type = value;
		(void)BUF_APPENDF(p->wbuf, "Content-Type: %s\r\n", value);
		return true;
	}
	/* forward all other end-to-end headers */
	(void)BUF_APPENDF(p->wbuf, "%s: %s\r\n", key, value);
	return true;
}

static struct http_ctx *http_ctx_new(struct server *restrict s, const int fd)
{
	struct http_ctx *restrict ctx = malloc(sizeof(struct http_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = s;
	ctx->state = STATE_INIT;
	ctx->accepted_fd = fd;
	ctx->dialed_fd = -1;

	ev_timer_init(&ctx->w_timeout, timeout_cb, s->conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
	ev_io_init(&ctx->w_recv, recv_cb, fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(&ctx->w_send, send_cb, fd, EV_WRITE);
	ctx->w_send.data = ctx;
#if WITH_RULESET
	ev_idle_init(&ctx->w_process, process_cb);
	ctx->w_process.data = ctx;
	ev_init(&ctx->ruleset_callback.w_finish, ruleset_cb);
	ctx->ruleset_callback.w_finish.data = ctx;
	ctx->ruleset_state = NULL;
#endif
	ctx->dialreq = NULL;
	const struct dialer_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, &cb);
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	http_conn_init(&ctx->conn, fd, STATE_PARSE_REQUEST, on_header);

	gc_register(&ctx->gcbase, http_ctx_finalize);
	return ctx;
}

static void http_ctx_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_start(loop, &ctx->w_timeout);

	ctx->accepted_ns = clock_monotonic_ns();
	ctx->state = STATE_REQUEST;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen++;
}

void http_proxy_serve(
	struct server *s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct http_ctx *restrict ctx = http_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		CLOSE_FD(accepted_fd);
		return;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	http_ctx_start(loop, ctx);
}
