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
#include "utils/arraysize.h"
#include "utils/ascii.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>
#include <strings.h>

#include <errno.h>
#include <inttypes.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
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
	STATE_RELAY_REQBODY,
	STATE_RELAY_RSPHDR,
	STATE_RELAY_RSPBODY,
	STATE_BIDIRECTIONAL,
};

struct server;

struct http_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum http_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	intmax_t accepted_ns;
	ev_timer w_timeout;
	union {
		/* state < STATE_BIDIRECTIONAL */
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
			size_t req_content_length;
			struct http_body req_body_inspector;
			struct http_body rsp_body_inspector;
			enum transfer_encodings relay_downstream_body_te;
			/* cached target hostport for proxy_pass requests */
			char req_target[FQDN_MAX_LENGTH + sizeof(":65535")];
			/* offset into rbuf already scanned for CRLFCRLF */
			size_t relay_hdr_scanned;
			bool relay_can_cache : 1;
			bool req_content_length_known : 1;
			bool req_conn_cache_capable : 1;
			bool req_client_keep_alive : 1;
			/* request has body bytes after the header section */
			bool req_has_body : 1;
			/* Connection header contains "close" token */
			bool req_conn_token_close : 1;
			/* true when current forward uses a cached upstream fd */
			bool fwd_cached_fd : 1;
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
	case STATE_RELAY_REQBODY:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_RELAY_RSPHDR:
	case STATE_RELAY_RSPBODY:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_BIDIRECTIONAL:
		/* transfer_ctx is self-owned; nothing to do */
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
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

	if (ctx->state < STATE_BIDIRECTIONAL) {
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		VBUF_FREE(ctx->conn.cbuf);
	}
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

/* Parse the target host:port for a plain HTTP request.
 * Tries the absolute URL first, then falls back to the Host header.
 * The result is written into ctx->req_target and also copied to buf
 * when buf != NULL. */
static bool parse_req_target(
	char *restrict buf, const size_t bufcap, struct http_ctx *restrict ctx)
{
	/* return cached result when already computed */
	if (ctx->req_target[0] != '\0') {
		if (buf != NULL) {
			const size_t n = strlen(ctx->req_target);
			if (n >= bufcap) {
				return false;
			}
			memcpy(buf, ctx->req_target, n + 1);
		}
		return true;
	}
	const char *url = ctx->conn.msg.req.url;
	const size_t cap = sizeof(ctx->req_target);
	if (parse_hostport(ctx->req_target, cap, url)) {
		if (buf != NULL) {
			const size_t n = strlen(ctx->req_target);
			if (n >= bufcap) {
				ctx->req_target[0] = '\0';
				return false;
			}
			memcpy(buf, ctx->req_target, n + 1);
		}
		return true;
	}
	/* fall back to Host header */
	const char *host = ctx->conn.hdr.host;
	if (host == NULL) {
		return false;
	}
	const size_t hlen = strlen(host);
	if (hlen >= cap) {
		return false;
	}
	memcpy(ctx->req_target, host, hlen + 1);
	/* append :80 if port absent */
	const char *portcheck = (ctx->req_target[0] == '[') ?
					strchr(ctx->req_target, ']') :
					ctx->req_target;
	if (portcheck == NULL || strchr(portcheck, ':') == NULL) {
		if (hlen + 3 >= cap) {
			ctx->req_target[0] = '\0';
			return false;
		}
		memcpy(ctx->req_target + hlen, ":80", 4);
	}
	if (buf != NULL) {
		const size_t n = strlen(ctx->req_target);
		if (n >= bufcap) {
			ctx->req_target[0] = '\0';
			return false;
		}
		memcpy(buf, ctx->req_target, n + 1);
	}
	return true;
}

static void http_ctx_hijack(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	/* cleanup before state change */
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;
	VBUF_FREE(ctx->conn.cbuf);

	const int acc_fd = ctx->accepted_fd, dial_fd = ctx->dialed_fd;
	ctx->accepted_fd = ctx->dialed_fd = -1;
	/*
	 * Transition to STATE_BIDIRECTIONAL before transfer_start so that
	 * http_ctx_stop becomes a no-op if gc_unref is called below.
	 */
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;
	HTTP_CTX_LOG_F(
		DEBUG, ctx, "transfer start: [%d<->%d]", acc_fd, dial_fd);
	/*
	 * Increment num_sessions before transfer_start so the xfer thread's
	 * decrement can never precede our increment. Undo on OOM.
	 */
#if WITH_THREADS
	const size_t cur =
		atomic_fetch_add_explicit(
			&ctx->s->num_sessions, 1, memory_order_relaxed) +
		1;
#else
	const size_t cur = ++ctx->s->num_sessions;
#endif
	if (!transfer_serve(
		    ctx->s->xfer, acc_fd, dial_fd,
		    &(struct transfer_opts){
			    .byt_up = &ctx->s->byt_up,
			    .byt_down = &ctx->s->byt_down,
#if WITH_SPLICE
			    .use_splice = ctx->s->conf->pipe,
#endif
			    .num_sessions = &ctx->s->num_sessions,
		    })) {
#if WITH_THREADS
		atomic_fetch_sub_explicit(
			&ctx->s->num_sessions, 1, memory_order_relaxed);
#else
		ctx->s->num_sessions--;
#endif
		LOGOOM();
		CLOSE_FD(acc_fd);
		CLOSE_FD(dial_fd);
		gc_unref(&ctx->gcbase);
		return;
	}
	if (cur > stats->num_sessions_peak) {
		stats->num_sessions_peak = cur;
	}
	stats->num_success++;
	{
		const int_fast64_t elapsed =
			clock_monotonic_ns() - ctx->accepted_ns;
		stats->connect_ns
			[stats->num_connects % ARRAY_SIZE(stats->connect_ns)] =
			elapsed;
		stats->num_connects++;
	}
	HTTP_CTX_LOG_F(DEBUG, ctx, "ready, %zu active sessions", cur);
	gc_unref(&ctx->gcbase);
}

static bool append_encoded_body(
	struct http_ctx *restrict ctx, const unsigned char *restrict data,
	const size_t len, const enum transfer_encodings te,
	const bool final_chunk)
{
	struct http_conn *restrict p = &ctx->conn;
	if (te == TENCODING_NONE) {
		if (p->wbuf.cap - p->wbuf.len < len) {
			return false;
		}
		BUF_APPEND(p->wbuf, data, len);
		return true;
	}
	if (te != TENCODING_CHUNKED) {
		return false;
	}
	if (final_chunk) {
		if (p->wbuf.cap - p->wbuf.len < CONSTSTRLEN("0\r\n\r\n")) {
			return false;
		}
		BUF_APPENDSTR(p->wbuf, "0\r\n\r\n");
		return true;
	}
	if (len == 0) {
		return true;
	}
	if (p->wbuf.cap - p->wbuf.len < len + 32u) {
		return false;
	}
	(void)BUF_APPENDF(p->wbuf, "%zx\r\n", len);
	BUF_APPEND(p->wbuf, data, len);
	BUF_APPENDSTR(p->wbuf, "\r\n");
	return true;
}

static bool relay_body_data_cb(
	void *restrict data, const unsigned char *restrict buf,
	const size_t len)
{
	struct http_ctx *restrict ctx = data;
	return append_encoded_body(
		ctx, buf, len, ctx->relay_downstream_body_te, false);
}

static bool relay_setup_headers(
	struct http_ctx *restrict ctx, const char *restrict raw,
	const char *restrict hdr_end)
{
	struct http_conn *restrict p = &ctx->conn;
	const char *line_end =
		(const char *)memchr(raw, '\n', (size_t)(hdr_end - raw));
	if (line_end == NULL) {
		return false;
	}
	BUF_APPEND(p->wbuf, raw, (size_t)(line_end - raw + 1));

	int status_code = 502;
	{
		const char *sp1 = strchr(raw, ' ');
		if (sp1 != NULL) {
			status_code = (int)strtol(sp1 + 1, NULL, 10);
		}
	}

	bool has_upstream_chunked = false;
	bool has_upstream_length = false;
	size_t upstream_length = 0;
	bool conn_close = false;

	for (const char *cur = line_end + 1; cur < hdr_end;) {
		const char *eol = (const char *)memchr(
			cur, '\n', (size_t)(hdr_end - cur));
		if (eol == NULL) {
			break;
		}
		const char *line = cur;
		cur = eol + 1;
		if (line == eol || (line + 1 == eol && line[0] == '\r')) {
			break;
		}
		const char *colon =
			(const char *)memchr(line, ':', (size_t)(eol - line));
		if (colon == NULL) {
			continue;
		}
		const size_t klen = (size_t)(colon - line);
		const char *val = colon + 1;
		while (val < eol && (*val == ' ' || *val == '\t')) {
			val++;
		}
		const char *vend = eol;
		if (vend > val && vend[-1] == '\r') {
			vend--;
		}
		const size_t vlen = (size_t)(vend - val);

		if (klen == CONSTSTRLEN("Transfer-Encoding") &&
		    strncasecmp(line, "Transfer-Encoding", klen) == 0) {
			char tmp[64];
			if (vlen < sizeof(tmp)) {
				memcpy(tmp, val, vlen);
				tmp[vlen] = '\0';
				for (size_t i = 0; i < vlen; i++) {
					const unsigned char c =
						(unsigned char)tmp[i];
					if (c >= 'A' && c <= 'Z') {
						tmp[i] = (char)(c | 0x20u);
					}
				}
				if (strstr(tmp, "chunked") != NULL) {
					has_upstream_chunked = true;
				}
			}
			continue;
		}
		if (klen == CONSTSTRLEN("Content-Length") &&
		    strncasecmp(line, "Content-Length", klen) == 0) {
			char tmp[32];
			if (vlen < sizeof(tmp)) {
				memcpy(tmp, val, vlen);
				tmp[vlen] = '\0';
				char *end;
				const uintmax_t n = strtoumax(tmp, &end, 10);
				if (*end == '\0' && n <= SIZE_MAX) {
					has_upstream_length = true;
					upstream_length = (size_t)n;
				}
			}
			continue;
		}
		if (klen == CONSTSTRLEN("Connection") &&
		    strncasecmp(line, "Connection", klen) == 0) {
			char tmp[128];
			if (vlen < sizeof(tmp)) {
				memcpy(tmp, val, vlen);
				tmp[vlen] = '\0';
				const char *tok;
				size_t toklen;
				for (const char *next =
					     parsehdr_connection_token(
						     tmp, &tok, &toklen);
				     tok != NULL;
				     next = parsehdr_connection_token(
					     next, &tok, &toklen)) {
					if (toklen == CONSTSTRLEN("close") &&
					    strncasecmp(tok, "close", toklen) ==
						    0) {
						conn_close = true;
						break;
					}
				}
			}
			continue;
		}
		if ((klen == CONSTSTRLEN("Keep-Alive") &&
		     strncasecmp(line, "Keep-Alive", klen) == 0) ||
		    (klen == CONSTSTRLEN("Proxy-Connection") &&
		     strncasecmp(line, "Proxy-Connection", klen) == 0) ||
		    (klen == CONSTSTRLEN("Trailer") &&
		     strncasecmp(line, "Trailer", klen) == 0) ||
		    (klen == CONSTSTRLEN("Trailers") &&
		     strncasecmp(line, "Trailers", klen) == 0) ||
		    (klen == CONSTSTRLEN("Upgrade") &&
		     strncasecmp(line, "Upgrade", klen) == 0) ||
		    (klen == CONSTSTRLEN("TE") &&
		     strncasecmp(line, "TE", klen) == 0)) {
			continue;
		}
		BUF_APPEND(p->wbuf, line, klen);
		BUF_APPENDSTR(p->wbuf, ": ");
		BUF_APPEND(p->wbuf, val, vlen);
		BUF_APPENDSTR(p->wbuf, "\r\n");
	}

	ctx->relay_can_cache = !conn_close;
	const bool no_body = (strcmp(ctx->conn.msg.req.method, "HEAD") == 0) ||
			     (100 <= status_code && status_code < 200) ||
			     (status_code == 204 || status_code == 304);

	if (no_body) {
		http_body_init(&ctx->rsp_body_inspector, HTTP_BODY_NONE, 0);
		ctx->relay_downstream_body_te = TENCODING_NONE;
	} else if (has_upstream_chunked) {
		http_body_init(&ctx->rsp_body_inspector, HTTP_BODY_CHUNKED, 0);
		ctx->relay_downstream_body_te = TENCODING_CHUNKED;
	} else if (has_upstream_length) {
		http_body_init(
			&ctx->rsp_body_inspector, HTTP_BODY_CONTENT_LENGTH,
			upstream_length);
		ctx->relay_downstream_body_te = TENCODING_NONE;
	} else {
		http_body_init(&ctx->rsp_body_inspector, HTTP_BODY_EOF, 0);
		ctx->relay_downstream_body_te = TENCODING_CHUNKED;
		ctx->relay_can_cache = false;
	}

	if (has_upstream_length &&
	    ctx->relay_downstream_body_te == TENCODING_NONE) {
		(void)BUF_APPENDF(
			p->wbuf, "Content-Length: %zu\r\n", upstream_length);
	}
	if (ctx->relay_downstream_body_te == TENCODING_CHUNKED) {
		BUF_APPENDSTR(p->wbuf, "Transfer-Encoding: chunked\r\n");
	}
	if (ctx->relay_can_cache && ctx->req_client_keep_alive) {
		BUF_APPENDSTR(p->wbuf, "Connection: keep-alive\r\n\r\n");
	} else {
		BUF_APPENDSTR(p->wbuf, "Connection: close\r\n\r\n");
	}
	return true;
}

static void relay_finish(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);
	if (ctx->relay_can_cache && ctx->req_client_keep_alive) {
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
	ASSERT(ctx->state == STATE_RELAY_RSPHDR ||
	       ctx->state == STATE_RELAY_RSPBODY);

	struct http_conn *restrict p = &ctx->conn;
	/* Pause reading if wbuf cannot accommodate a full recv to prevent
	 * truncation. relay_send_cb will restart reading once wbuf drains. */
	const size_t free = p->wbuf.cap - p->wbuf.len;
	if (free <= 64u) {
		ev_io_stop(loop, watcher);
		return;
	}
	size_t n = p->rbuf.cap - p->rbuf.len;
	if (n == 0) {
		/* response headers exceed buffer capacity */
		gc_unref(&ctx->gcbase);
		return;
	}
	if (n > free - 64u) {
		n = free - 64u;
	}
	const int err =
		socket_recv(ctx->dialed_fd, p->rbuf.data + p->rbuf.len, &n);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return;
		}
		HTTP_CTX_LOG_F(
			WARNING, ctx, "relay recv: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	if (n == 0) {
		/* upstream EOF */
		if (ctx->state == STATE_RELAY_RSPHDR) {
			/* headers never completed */
			gc_unref(&ctx->gcbase);
			return;
		}
		if (p->rbuf.len > 0) {
			const struct http_body_data_cb cb = {
				.func = relay_body_data_cb,
				.ctx = ctx,
			};
			if (!http_body_consume(
				    &ctx->rsp_body_inspector, p->rbuf.data,
				    p->rbuf.len, cb)) {
				gc_unref(&ctx->gcbase);
				return;
			}
			BUF_RESET(p->rbuf);
		}
		if (!http_body_finish(&ctx->rsp_body_inspector)) {
			gc_unref(&ctx->gcbase);
			return;
		}
		if (ctx->relay_downstream_body_te == TENCODING_CHUNKED &&
		    !append_encoded_body(
			    ctx, NULL, 0, ctx->relay_downstream_body_te,
			    true)) {
			gc_unref(&ctx->gcbase);
			return;
		}
		if (p->wbuf.len > p->wpos) {
			ev_io_start(loop, &ctx->w_send);
		}
		ev_io_stop(loop, watcher);
		if (ctx->rsp_body_inspector.mode == HTTP_BODY_EOF) {
			ctx->relay_can_cache = false;
		}
		if (p->wbuf.len == p->wpos) {
			relay_finish(loop, ctx);
		}
		return;
	}

	p->rbuf.len += n;

	if (ctx->state == STATE_RELAY_RSPHDR) {
		/* Incremental scan for end-of-headers marker.
		 * Back up 3 bytes so a split CRLFCRLF is not missed. */
		const char *raw = (const char *)p->rbuf.data;
		const size_t rawlen = p->rbuf.len;
		const size_t start = ctx->relay_hdr_scanned > 3u ?
					     ctx->relay_hdr_scanned - 3u :
					     0;
		const char *hdr_end = NULL;
		for (size_t i = start; i + 3 < rawlen; i++) {
			if (raw[i] == '\r' && raw[i + 1] == '\n' &&
			    raw[i + 2] == '\r' && raw[i + 3] == '\n') {
				hdr_end = raw + i + 4;
				break;
			}
		}
		ctx->relay_hdr_scanned = rawlen;
		if (hdr_end == NULL) {
			return;
		}

		if (!relay_setup_headers(ctx, raw, hdr_end)) {
			gc_unref(&ctx->gcbase);
			return;
		}

		const size_t body_so_far = rawlen - (size_t)(hdr_end - raw);
		if (body_so_far > 0) {
			const struct http_body_data_cb cb = {
				.func = relay_body_data_cb,
				.ctx = ctx,
			};
			if (!http_body_consume(
				    &ctx->rsp_body_inspector,
				    (const unsigned char *)hdr_end, body_so_far,
				    cb)) {
				gc_unref(&ctx->gcbase);
				return;
			}
		}
		BUF_RESET(p->rbuf);
		if (ctx->rsp_body_inspector.done) {
			if (ctx->relay_downstream_body_te ==
				    TENCODING_CHUNKED &&
			    !append_encoded_body(
				    ctx, NULL, 0, ctx->relay_downstream_body_te,
				    true)) {
				gc_unref(&ctx->gcbase);
				return;
			}
			ev_io_stop(loop, watcher);
		}
		if (p->wbuf.len > p->wpos) {
			ev_io_start(loop, &ctx->w_send);
		}
		ctx->state = STATE_RELAY_RSPBODY;
		return;
	}

	/* STATE_RELAY_BODY: decode + re-encode body bytes */
	const struct http_body_data_cb cb = {
		.func = relay_body_data_cb,
		.ctx = ctx,
	};
	if (!http_body_consume(
		    &ctx->rsp_body_inspector, p->rbuf.data, p->rbuf.len, cb)) {
		gc_unref(&ctx->gcbase);
		return;
	}
	BUF_RESET(p->rbuf);
	if (p->wbuf.len > p->wpos) {
		ev_io_start(loop, &ctx->w_send);
	}
	if (ctx->rsp_body_inspector.done) {
		if (ctx->relay_downstream_body_te == TENCODING_CHUNKED &&
		    !append_encoded_body(
			    ctx, NULL, 0, ctx->relay_downstream_body_te,
			    true)) {
			gc_unref(&ctx->gcbase);
			return;
		}
		ev_io_stop(loop, watcher);
		if (p->wbuf.len == p->wpos) {
			relay_finish(loop, ctx);
		}
	}
}

static void
relay_send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RELAY_RSPHDR ||
	       ctx->state == STATE_RELAY_RSPBODY);

	struct http_conn *restrict p = &ctx->conn;
	const unsigned char *buf = p->wbuf.data + p->wpos;
	size_t len = p->wbuf.len - p->wpos;
	const int err = socket_send(ctx->accepted_fd, buf, &len);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
		    err == ENOMEM) {
			return;
		}
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
	if (ctx->rsp_body_inspector.done) {
		relay_finish(loop, ctx);
		return;
	}
	/* recv was paused because wbuf was full; resume reading */
	ev_io_start(loop, &ctx->w_recv);
}

static void
http_ctx_relay_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;
	BUF_RESET(p->rbuf);
	BUF_RESET(p->wbuf);
	p->wpos = 0;

	ctx->relay_can_cache = true; /* updated after header scan */
	ctx->relay_downstream_body_te = TENCODING_NONE;
	ctx->relay_hdr_scanned = 0;
	http_body_init(&ctx->rsp_body_inspector, HTTP_BODY_NONE, 0);
	ctx->state = STATE_RELAY_RSPHDR;

	ev_io_init(&ctx->w_recv, relay_recv_cb, ctx->dialed_fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(&ctx->w_send, relay_send_cb, ctx->accepted_fd, EV_WRITE);
	ctx->w_send.data = ctx;
	ev_io_start(loop, &ctx->w_recv);
}

static void
pass_req_body_send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RELAY_REQBODY);

	struct http_conn *restrict p = &ctx->conn;
	const unsigned char *buf = p->wbuf.data + p->wpos;
	size_t len = p->wbuf.len - p->wpos;
	const int err = socket_send(ctx->dialed_fd, buf, &len);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK || err == ENOBUFS ||
		    err == ENOMEM) {
			return;
		}
		HTTP_CTX_LOG_F(
			WARNING, ctx, "req body send: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	p->wpos += len;
	if (p->wpos < p->wbuf.len) {
		return;
	}

	BUF_RESET(p->wbuf);
	p->wpos = 0;
	ev_io_stop(loop, watcher);

	if (ctx->req_body_inspector.done) {
		http_ctx_relay_start(loop, ctx);
		return;
	}

	if (!ev_is_active(&ctx->w_recv)) {
		ev_io_start(loop, &ctx->w_recv);
	}
}

static bool body_discard_cb(
	void *restrict data, const unsigned char *restrict buf,
	const size_t len)
{
	UNUSED(data);
	UNUSED(buf);
	UNUSED(len);
	return true;
}

static bool req_consume_body_bytes(
	struct http_ctx *restrict ctx, const unsigned char *restrict data,
	const size_t len)
{
	if (len == 0) {
		return true;
	}
	struct http_conn *restrict p = &ctx->conn;
	if (p->wbuf.cap - p->wbuf.len < len) {
		return false;
	}
	BUF_APPEND(p->wbuf, data, len);
	const struct http_body_data_cb cb = {
		.func = body_discard_cb,
		.ctx = ctx,
	};
	if (!http_body_consume(&ctx->req_body_inspector, data, len, cb)) {
		return false;
	}
	return true;
}

static void
pass_req_body_recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RELAY_REQBODY);

	if (ctx->req_body_inspector.done) {
		ev_io_stop(loop, watcher);
		http_ctx_relay_start(loop, ctx);
		return;
	}

	struct http_conn *restrict p = &ctx->conn;
	const size_t free = p->wbuf.cap - p->wbuf.len;
	if (free <= 64u) {
		ev_io_stop(loop, watcher);
		return;
	}

	size_t n = p->rbuf.cap;
	if (n > free - 64u) {
		n = free - 64u;
	}
	if (ctx->req_body_inspector.mode == HTTP_BODY_CONTENT_LENGTH) {
		const size_t remain = ctx->req_body_inspector.content_length -
				      ctx->req_body_inspector.consumed;
		if (n > remain) {
			n = remain;
		}
	}
	const int err = socket_recv(ctx->accepted_fd, p->rbuf.data, &n);
	if (err != 0) {
		if (err == EAGAIN || err == EWOULDBLOCK) {
			return;
		}
		HTTP_CTX_LOG_F(
			WARNING, ctx, "req body recv: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	if (n == 0) {
		if (ctx->req_body_inspector.mode == HTTP_BODY_EOF) {
			if (!http_body_finish(&ctx->req_body_inspector)) {
				gc_unref(&ctx->gcbase);
				return;
			}
			ev_io_stop(loop, watcher);
			if (p->wbuf.len > p->wpos) {
				ev_io_start(loop, &ctx->w_send);
			} else {
				http_ctx_relay_start(loop, ctx);
			}
			return;
		}
		gc_unref(&ctx->gcbase);
		return;
	}

	p->rbuf.len = n;
	if (!req_consume_body_bytes(ctx, p->rbuf.data, n)) {
		gc_unref(&ctx->gcbase);
		return;
	}
	BUF_RESET(p->rbuf);
	if (p->wbuf.len > p->wpos) {
		ev_io_start(loop, &ctx->w_send);
	}

	if (ctx->req_body_inspector.done) {
		ev_io_stop(loop, watcher);
	}
}

static void http_ctx_pass_req_body_start(
	struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ASSERT(ctx->req_conn_cache_capable);
	ASSERT(ctx->req_has_body);
	ASSERT(!ctx->req_body_inspector.done);
	ctx->state = STATE_RELAY_REQBODY;

	struct http_conn *restrict p = &ctx->conn;
	BUF_RESET(p->rbuf);
	BUF_RESET(p->wbuf);
	p->wpos = 0;

	ev_io_init(
		&ctx->w_recv, pass_req_body_recv_cb, ctx->accepted_fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(
		&ctx->w_send, pass_req_body_send_cb, ctx->dialed_fd, EV_WRITE);
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
		if (ctx->state == STATE_FORWARD && ctx->fwd_cached_fd &&
		    (err == ECONNRESET || err == EPIPE || err == ECONNABORTED ||
		     err == ENOTCONN || err == EBADF)) {
			ctx->fwd_cached_fd = false;
			ev_io_stop(loop, &ctx->w_send);
			ev_io_set(&ctx->w_send, -1, EV_NONE);
			if (ctx->dialed_fd != -1) {
				CLOSE_FD(ctx->dialed_fd);
				ctx->dialed_fd = -1;
			}
			if (ctx->dialreq == NULL) {
				gc_unref(&ctx->gcbase);
				return;
			}
			ctx->state = STATE_CONNECT;
			dialer_do(
				&ctx->dialer, loop, ctx->dialreq, ctx->s->conf,
				ctx->s->resolver);
			return;
		}
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
		if (ctx->s->conf->conn_cache && ctx->req_conn_cache_capable &&
		    ctx->req_has_body && !ctx->req_body_inspector.done) {
			http_ctx_pass_req_body_start(loop, ctx);
			return;
		}
		if (ctx->s->conf->conn_cache && ctx->req_conn_cache_capable) {
			/* relay the upstream response, then maybe cache conn */
			http_ctx_relay_start(loop, ctx);
			return;
		}
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		VBUF_FREE(ctx->conn.cbuf);
		{
			const int acc_fd = ctx->accepted_fd,
				  dial_fd = ctx->dialed_fd;
			ctx->accepted_fd = ctx->dialed_fd = -1;
			ctx->state = STATE_BIDIRECTIONAL;
			ev_timer_stop(loop, &ctx->w_timeout);
			struct server_stats *restrict stats = &ctx->s->stats;
			stats->num_halfopen--;
			HTTP_CTX_LOG_F(
				DEBUG, ctx, "transfer start: [%d<->%d]", acc_fd,
				dial_fd);
#if WITH_THREADS
			const size_t cur = atomic_fetch_add_explicit(
						   &ctx->s->num_sessions, 1,
						   memory_order_relaxed) +
					   1;
#else
			const size_t cur = ++ctx->s->num_sessions;
#endif
			if (!transfer_serve(
				    ctx->s->xfer, acc_fd, dial_fd,
				    &(struct transfer_opts){
					    .byt_up = &ctx->s->byt_up,
					    .byt_down = &ctx->s->byt_down,
#if WITH_SPLICE
					    .use_splice = ctx->s->conf->pipe,
#endif
					    .num_sessions =
						    &ctx->s->num_sessions,
				    })) {
#if WITH_THREADS
				atomic_fetch_sub_explicit(
					&ctx->s->num_sessions, 1,
					memory_order_relaxed);
#else
				ctx->s->num_sessions--;
#endif
				LOGOOM();
				CLOSE_FD(acc_fd);
				CLOSE_FD(dial_fd);
				gc_unref(&ctx->gcbase);
				return;
			}
			if (cur > stats->num_sessions_peak) {
				stats->num_sessions_peak = cur;
			}
			stats->num_success++;
			{
				const int_fast64_t elapsed =
					clock_monotonic_ns() - ctx->accepted_ns;
				stats->connect_ns
					[stats->num_connects %
					 ARRAY_SIZE(stats->connect_ns)] =
					elapsed;
				stats->num_connects++;
			}
			HTTP_CTX_LOG_F(
				DEBUG, ctx, "ready, %zu active sessions", cur);
			gc_unref(&ctx->gcbase);
		}
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
	    ctx->req_conn_cache_capable) {
		const int fd = conn_cache_get(loop, ctx->dialreq);
		if (fd != -1) {
			LOGV_F("http_proxy: reusing cached connection [fd:%d]",
			       fd);
			ctx->dialed_fd = fd;
			ctx->fwd_cached_fd = true;
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
		BUF_APPENDSTR(
			ctx->conn.wbuf,
			"Proxy-Authenticate: Basic realm=\"proxy\"\r\n");
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
static void build_pass_req(struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;
	const char *method = p->msg.req.method;
	const char *version = p->msg.req.version;
	const size_t urllen = strlen(p->msg.req.url);
	if (urllen + 1 < HTTP_MAX_ENTITY) {
		char urlbuf[urllen + 1];
		memcpy(urlbuf, p->msg.req.url, sizeof(urlbuf));
		struct url parsed;
		if (url_parse(urlbuf, &parsed) && parsed.scheme != NULL &&
		    strcmp(parsed.scheme, "http") == 0 && parsed.host != NULL &&
		    parsed.host[0] != '\0') {
			/* cache hostport into ctx->req_target */
			const size_t hlen = strlen(parsed.host);
			const size_t cap = sizeof(ctx->req_target);
			if (hlen < cap) {
				memcpy(ctx->req_target, parsed.host, hlen + 1);
				const char *pc =
					(ctx->req_target[0] == '[') ?
						strchr(ctx->req_target, ']') :
						ctx->req_target;
				if (pc != NULL && strchr(pc, ':') == NULL &&
				    hlen + 3 < cap) {
					memcpy(ctx->req_target + hlen, ":80",
					       4);
				}
			}
			/* build forwarded request line in one call */
			const char *path =
				(parsed.path != NULL && *parsed.path != '\0') ?
					parsed.path :
					"";
			if (parsed.query != NULL) {
				(void)BUF_APPENDF(
					p->wbuf, "%s /%s?%s %s\r\n", method,
					path, parsed.query, version);
			} else {
				(void)BUF_APPENDF(
					p->wbuf, "%s /%s %s\r\n", method, path,
					version);
			}
			(void)BUF_APPENDF(
				p->wbuf, "Via: %s neosocksd\r\n", version + 5);
			return;
		}
	}
	/* fallback: forward URL as-is */
	(void)BUF_APPENDF(
		p->wbuf, "%s %s %s\r\n", method, p->msg.req.url, version);
	(void)BUF_APPENDF(p->wbuf, "Via: %s neosocksd\r\n", version + 5);
}

static bool req_connection_is_close(const struct http_ctx *restrict ctx)
{
	return ctx->req_conn_token_close;
}

static bool req_is_conn_cache_capable(const struct http_ctx *restrict ctx)
{
	const struct http_conn *restrict p = &ctx->conn;
	if (!ctx->s->conf->conn_cache) {
		return false;
	}
	if (!ctx->req_client_keep_alive) {
		return false;
	}
	if (!ctx->req_has_body) {
		return true;
	}
	if (ctx->req_content_length_known ||
	    p->hdr.transfer.encoding == TENCODING_CHUNKED) {
		return true;
	}
	return false;
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

static void http_proxy_pass(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;
	const size_t overread =
		p->rbuf.len - (size_t)((unsigned char *)p->next - p->rbuf.data);
	ctx->req_client_keep_alive = !req_connection_is_close(ctx);
	ctx->req_conn_cache_capable = req_is_conn_cache_capable(ctx);
	if (!ctx->req_has_body) {
		http_body_init(&ctx->req_body_inspector, HTTP_BODY_NONE, 0);
	} else if (
		ctx->req_content_length_known &&
		p->hdr.transfer.encoding == TENCODING_NONE) {
		http_body_init(
			&ctx->req_body_inspector, HTTP_BODY_CONTENT_LENGTH,
			ctx->req_content_length);
	} else if (p->hdr.transfer.encoding == TENCODING_CHUNKED) {
		http_body_init(&ctx->req_body_inspector, HTTP_BODY_CHUNKED, 0);
	} else {
		http_body_init(&ctx->req_body_inspector, HTTP_BODY_NONE, 0);
	}

	/* ensure the request line was written (no headers case) */
	if (p->wbuf.len == 0) {
		build_pass_req(ctx);
	}
	if (p->hdr.transfer.encoding == TENCODING_CHUNKED) {
		BUF_APPENDSTR(p->wbuf, "Transfer-Encoding: chunked\r\n");
	} else if (ctx->req_content_length_known) {
		(void)BUF_APPENDF(
			p->wbuf, "Content-Length: %zu\r\n",
			ctx->req_content_length);
	}

	/* keep upstream connection alive when conn_cache path is enabled */
	if (ctx->req_conn_cache_capable) {
		BUF_APPENDSTR(p->wbuf, "\r\n");
	} else {
		BUF_APPENDSTR(p->wbuf, "Connection: close\r\n\r\n");
	}

	/* forward any body bytes already buffered in rbuf */
	if (overread > 0) {
		if (ctx->req_has_body) {
			if (!req_consume_body_bytes(
				    ctx, (unsigned char *)p->next, overread)) {
				send_errpage(loop, ctx, HTTP_BAD_REQUEST);
				return;
			}
		} else {
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
	if (ctx->dialreq != NULL && ctx->req_conn_cache_capable) {
		const int fd = conn_cache_get(loop, ctx->dialreq);
		if (fd != -1) {
			LOGV_F("http_proxy: reusing cached connection [fd:%d]",
			       fd);
			ctx->dialed_fd = fd;
			ctx->fwd_cached_fd = true;
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

	/* RFC 7230 §3.2.6 / RFC 9112 §2.2: validate field name (tchar only)
	 * and field value (no CTL except HTAB, no DEL). */
	for (const unsigned char *c = (const unsigned char *)key; *c != '\0';
	     c++) {
		const unsigned char ch = *c;
		if (!isalnum(ch) && !strchr("!#$%&'*+-.^_`|~", ch)) {
			return false;
		}
	}
	for (const unsigned char *c = (const unsigned char *)value; *c != '\0';
	     c++) {
		const unsigned char ch = *c;
		/* RFC 9110 §5.5 field-value: VCHAR / SP / HTAB / obs-text */
		if (iscntrl(ch) && ch != '\t') {
			return false;
		}
	}

	/* hop-by-hop headers: handle but never forward */
	if (strcasecmp(key, "Connection") == 0) {
		if (!parsehdr_connection(p, value)) {
			return false;
		}
		/* scan tokens once and cache the "close" flag */
		const char *tok;
		size_t toklen;
		for (const char *next = parsehdr_connection_token(
			     p->hdr.connection, &tok, &toklen);
		     tok != NULL;
		     next = parsehdr_connection_token(next, &tok, &toklen)) {
			if (toklen == CONSTSTRLEN("close") &&
			    strncasecmp(tok, "close", toklen) == 0) {
				ctx->req_conn_token_close = true;
				break;
			}
		}
		return true;
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
		/* fall back to Proxy-Connection for legacy HTTP/1.0 clients */
		if (p->hdr.connection == NULL) {
			parsehdr_connection(p, value);
		}
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
			/* RFC 9112 §6.3: CL+TE coexistence must be rejected */
			if (ctx->req_content_length_known) {
				return false;
			}
			ctx->req_has_body = true;
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
		build_pass_req(ctx);
	}

	if (strcasecmp(key, "Host") == 0) {
		p->hdr.host = value;
		BUF_APPENDSTR(p->wbuf, "Host: ");
		BUF_APPEND(p->wbuf, value, strlen(value));
		BUF_APPENDSTR(p->wbuf, "\r\n");
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
		BUF_APPENDSTR(p->wbuf, "Authorization: ");
		BUF_APPEND(
			p->wbuf, p->hdr.authorization.type,
			strlen(p->hdr.authorization.type));
		BUF_APPENDSTR(p->wbuf, " ");
		BUF_APPEND(
			p->wbuf, p->hdr.authorization.credentials,
			strlen(p->hdr.authorization.credentials));
		BUF_APPENDSTR(p->wbuf, "\r\n");
		return true;
	}
	if (strcasecmp(key, "Content-Length") == 0) {
		/* RFC 9112 §6.3: reject duplicate CL or CL+TE:chunked conflict */
		if (ctx->req_content_length_known ||
		    p->hdr.transfer.encoding == TENCODING_CHUNKED) {
			return false;
		}
		/* require bare decimal digits; no sign, prefix, or list */
		if ((unsigned char)value[0] < '0' ||
		    (unsigned char)value[0] > '9') {
			return false;
		}
		char *end;
		const uintmax_t cl = strtoumax(value, &end, 10);
		while (*end == ' ' || *end == '\t') {
			end++;
		}
		if (*end != '\0' || cl > (uintmax_t)SIZE_MAX) {
			return false;
		}
		ctx->req_content_length = (size_t)cl;
		ctx->req_content_length_known = true;
		if (ctx->req_content_length > 0) {
			ctx->req_has_body = true;
		}
		return true;
	}
	if (strcasecmp(key, "Content-Type") == 0) {
		p->hdr.content.type = value;
		BUF_APPENDSTR(p->wbuf, "Content-Type: ");
		BUF_APPEND(p->wbuf, value, strlen(value));
		BUF_APPENDSTR(p->wbuf, "\r\n");
		return true;
	}
	if (strcasecmp(key, "Expect") == 0) {
		/* Expect: 100-continue means the client has a request body */
		if (strcasecmp(value, "100-continue") == 0) {
			ctx->req_has_body = true;
			p->expect_continue = true;
		}
		BUF_APPENDSTR(p->wbuf, "Expect: ");
		BUF_APPEND(p->wbuf, value, strlen(value));
		BUF_APPENDSTR(p->wbuf, "\r\n");
		return true;
	}
	/* forward all other end-to-end headers */
	{
		const size_t klen = strlen(key);
		const size_t vlen = strlen(value);
		BUF_APPEND(p->wbuf, key, klen);
		BUF_APPENDSTR(p->wbuf, ": ");
		BUF_APPEND(p->wbuf, value, vlen);
		BUF_APPENDSTR(p->wbuf, "\r\n");
	}
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
	ctx->req_content_length = 0;
	http_body_init(&ctx->req_body_inspector, HTTP_BODY_NONE, 0);
	http_body_init(&ctx->rsp_body_inspector, HTTP_BODY_NONE, 0);
	ctx->relay_downstream_body_te = TENCODING_NONE;
	ctx->req_content_length_known = false;
	ctx->req_conn_cache_capable = false;
	ctx->req_client_keep_alive = false;
	ctx->req_has_body = false;
	ctx->req_conn_token_close = false;
	ctx->fwd_cached_fd = false;
	ctx->req_target[0] = '\0';
	ctx->relay_hdr_scanned = 0;
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
