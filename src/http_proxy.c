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
#include "os/socket.h"
#include "utils/arraysize.h"
#include "utils/ascii.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

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
#include <strings.h>

struct http_ctx;

/* never rollback */
enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_PROCESS,
	STATE_RESPONSE,
	STATE_CONNECT,
	STATE_ESTABLISHED,
	STATE_FORWARD,
	STATE_BIDIRECTIONAL,
};

/* maximum number of forwarded end-to-end headers */
enum { PROXY_MAX_HEADERS = 100 };

struct server;

struct http_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum http_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
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
			/* end-to-end headers recorded for forwarding */
			struct {
				const char *key;
				char *value;
			} fwd_hdr[PROXY_MAX_HEADERS];
			size_t num_fwd_hdr;
			/* dial target hostport for proxy_pass requests */
			char req_target[FQDN_MAX_LENGTH + sizeof(":65535")];
			bool req_content_length_known : 1;
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
	if (ctx->state < STATE_CONNECT || STATE_FORWARD < ctx->state) {
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
	case STATE_ESTABLISHED:
	case STATE_FORWARD:
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
		SOCKET_CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		SOCKET_CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	if (ctx->state < STATE_BIDIRECTIONAL) {
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		VBUF_FREE(ctx->conn.cbuf);
	}
}

/* Transitions ctx to STATE_BIDIRECTIONAL and starts bidirectional transfer
 * between ctx->accepted_fd and ctx->dialed_fd. Handles session counters and
 * always calls gc_unref before returning. The caller must stop any active
 * watchers and release dialreq / cbuf before calling this. */
static void
http_ctx_start_transfer(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const int acc_fd = ctx->accepted_fd, dial_fd = ctx->dialed_fd;
	ctx->accepted_fd = ctx->dialed_fd = -1;
	/*
	 * Transition to STATE_BIDIRECTIONAL before transfer_start so that
	 * http_ctx_stop becomes a no-op if gc_unref is called below.
	 */
	struct server_stats *restrict stats = &ctx->s->stats;
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);
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
		SOCKET_CLOSE_FD(acc_fd);
		SOCKET_CLOSE_FD(dial_fd);
		gc_unref(&ctx->gcbase);
		return;
	}
	if (cur > stats->num_sessions_peak) {
		stats->num_sessions_peak = cur;
	}
	stats->num_success++;
	HTTP_CTX_LOG_F(DEBUG, ctx, "ready, %zu active sessions", cur);
	gc_unref(&ctx->gcbase);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE ||
	       ctx->state == STATE_ESTABLISHED || ctx->state == STATE_FORWARD);

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
	if (ctx->state == STATE_ESTABLISHED || ctx->state == STATE_FORWARD) {
		/* CONNECT response / forwarded request fully sent */
		ev_io_stop(loop, &ctx->w_send);
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		VBUF_FREE(ctx->conn.cbuf);
		http_ctx_start_transfer(loop, ctx);
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
		ctx->s->resolver, ctx->s);
}

/* commit a connected upstream: for CONNECT queue the 200 response, otherwise
 * replay the buffered request to the upstream; takes ownership of @p fd */
static void
http_commit(struct ev_loop *loop, struct http_ctx *restrict ctx, const int fd)
{
	HTTP_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	ctx->dialed_fd = fd;

	if (strcmp(ctx->conn.msg.req.method, "CONNECT") == 0) {
		/* CONNECT tunnel: queue the 200 response */
		ASSERT(ctx->conn.wbuf.len == 0);
		BUF_APPENDSTR(
			ctx->conn.wbuf,
			"HTTP/1.1 200 Connection established\r\n\r\n");
		ctx->state = STATE_ESTABLISHED;
		ev_io_start(loop, &ctx->w_send);
		return;
	}
	/* plain HTTP: forward the buffered request to upstream */
	http_ctx_forward(loop, ctx);
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
		/* the ruleset gave up: reject by policy (403) */
		ctx->s->stats.num_reject_ruleset++;
		send_errpage(loop, ctx, HTTP_FORBIDDEN);
		return;
	}
	http_connect(loop, ctx);
}

/* await.forward() commit hook */
static void http_forward_commit(
	struct ev_loop *loop, struct ruleset_callback *restrict cb,
	const int fd)
{
	struct http_ctx *restrict ctx = cb->w_finish.data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->ruleset_state = NULL;
	http_commit(loop, ctx, fd);
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
	if (strcmp(ctx->conn.msg.req.method, "CONNECT") == 0) {
		addr_str = ctx->conn.msg.req.url;
	} else {
		/* filled by build_forward_req() before w_process was started */
		ASSERT(ctx->req_target[0] != '\0');
		addr_str = ctx->req_target;
	}
	const bool ok = ruleset_resolve(
		ruleset, &ctx->ruleset_state, addr_str, username, password,
		&ctx->ruleset_callback);
	if (!ok) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
}
#endif /* WITH_RULESET */

/* Normalize "host[:port]" into buf, appending ":80" when the port is
 * absent. Returns false when buf is too small or host is malformed. */
static bool hostport_normalize(
	char *restrict buf, const size_t cap, const char *restrict host)
{
	const size_t hlen = strlen(host);
	if (hlen >= cap) {
		return false;
	}
	memcpy(buf, host, hlen + 1);
	const char *portcheck = (buf[0] == '[') ? strchr(buf, ']') : buf;
	if (portcheck == NULL) {
		return false;
	}
	if (strchr(portcheck, ':') != NULL) {
		return true;
	}
	if (hlen + 3 >= cap) {
		return false;
	}
	memcpy(buf + hlen, ":80", 4);
	return true;
}

/* Append a string to wbuf, failing instead of truncating. */
static bool fwd_append(struct http_conn *restrict p, const char *restrict s)
{
	const size_t n = strlen(s);
	if (n > p->wbuf.cap - p->wbuf.len) {
		return false;
	}
	BUF_APPEND(p->wbuf, s, n);
	return true;
}

/* Checks whether the Connection header value lists the given field name. */
static bool
connection_lists(const char *restrict connection, const char *restrict key)
{
	const size_t keylen = strlen(key);
	const char *tok;
	size_t toklen;
	for (const char *next =
		     parsehdr_connection_token(connection, &tok, &toklen);
	     tok != NULL;
	     next = parsehdr_connection_token(next, &tok, &toklen)) {
		if (toklen == keylen && strncasecmp(tok, key, keylen) == 0) {
			return true;
		}
	}
	return false;
}

/* Rebuild the client request in wbuf for forwarding to the upstream and
 * normalize the dial target into ctx->req_target. Any overread body bytes
 * are moved to cbuf. Returns 0 on success or an HTTP status on failure. */
static uint_fast16_t build_forward_req(struct http_ctx *restrict ctx)
{
	struct http_conn *restrict p = &ctx->conn;
	const char *method = p->msg.req.method;
	const char *version = p->msg.req.version;

	/* RFC 9112 §3.2.2: a proxy accepts absolute-form only */
	const size_t urllen = strlen(p->msg.req.url);
	ASSERT(urllen < HTTP_MAX_ENTITY);
	char urlbuf[urllen + 1];
	memcpy(urlbuf, p->msg.req.url, urllen + 1);
	struct url parsed;
	if (!url_parse(urlbuf, &parsed) || parsed.scheme == NULL ||
	    strcmp(parsed.scheme, "http") != 0 || parsed.host == NULL ||
	    parsed.host[0] == '\0') {
		return HTTP_BAD_REQUEST;
	}
	if (!hostport_normalize(
		    ctx->req_target, sizeof(ctx->req_target), parsed.host)) {
		return HTTP_BAD_REQUEST;
	}

	/* request line, origin-form */
	const char *path = (parsed.path != NULL) ? parsed.path : "";
	bool ok = fwd_append(p, method) && fwd_append(p, " /") &&
		  fwd_append(p, path);
	if (parsed.query != NULL) {
		ok = ok && fwd_append(p, "?") && fwd_append(p, parsed.query);
	}
	ok = ok && fwd_append(p, " ") && fwd_append(p, version) &&
	     fwd_append(p, "\r\n");
	/* RFC 9112 §3.2.2: regenerate Host from the request target */
	ok = ok && fwd_append(p, "Host: ") && fwd_append(p, parsed.host) &&
	     fwd_append(p, "\r\n");
	/* end-to-end headers, except those listed in Connection */
	for (size_t i = 0; ok && i < ctx->num_fwd_hdr; i++) {
		const char *key = ctx->fwd_hdr[i].key;
		if (connection_lists(p->hdr.connection, key)) {
			continue;
		}
		ok = fwd_append(p, key) && fwd_append(p, ": ") &&
		     fwd_append(p, ctx->fwd_hdr[i].value) &&
		     fwd_append(p, "\r\n");
	}
	/* RFC 9110 §7.6.3: append our Via entry after any client Via */
	ok = ok && fwd_append(p, "Via: ") && fwd_append(p, version + 5) &&
	     fwd_append(p, " neosocksd\r\n");
	if (p->hdr.transfer.encoding == TENCODING_CHUNKED) {
		ok = ok && fwd_append(p, "Transfer-Encoding: chunked\r\n");
	} else if (ctx->req_content_length_known) {
		char cl[sizeof("Content-Length: \r\n") + 20];
		(void)snprintf(
			cl, sizeof(cl), "Content-Length: %zu\r\n",
			ctx->req_content_length);
		ok = ok && fwd_append(p, cl);
	}
	/* always close upstream after request to keep proxy stateless */
	ok = ok && fwd_append(p, "Connection: close\r\n\r\n");
	if (!ok) {
		return HTTP_ENTITY_TOO_LARGE;
	}

	/* move any body bytes already buffered into cbuf */
	const size_t overread =
		p->rbuf.len - (size_t)((unsigned char *)p->next - p->rbuf.data);
	if (overread > 0) {
		ASSERT(p->cbuf == NULL);
		p->cbuf = VBUF_NEW(overread);
		if (p->cbuf == NULL) {
			LOGOOM();
			return HTTP_INTERNAL_SERVER_ERROR;
		}
		VBUF_APPEND(p->cbuf, p->next, overread);
	}
	return 0;
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
	const uint_fast16_t code = build_forward_req(ctx);
	if (code != 0) {
		send_errpage(loop, ctx, code);
		return;
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
	ctx->dialreq = make_dialreq(ctx, ctx->req_target);
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
	http_commit(loop, ctx, fd);
}

/* Handles proxy_pass-specific header processing for parse_header().
 * Called when the request is not CONNECT and all hop-by-hop headers have
 * already been handled by parse_header(). Validates and records end-to-end
 * headers for the later rebuild in build_forward_req(). */
static bool parse_header_proxy_pass(
	struct http_ctx *restrict ctx, struct http_conn *restrict p,
	const char *key, char *value)
{
	if (strcasecmp(key, "Host") == 0) {
		/* reject duplicate Host to avoid request smuggling */
		if (p->hdr.host != NULL) {
			return false;
		}
		p->hdr.host = value;
		/* not recorded: Host is regenerated from the request target */
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
		/* not recorded: the canonical value is emitted at rebuild */
		return true;
	}
	if (strcasecmp(key, "Expect") == 0 &&
	    strcasecmp(value, "100-continue") == 0) {
		/* Expect: 100-continue means the client has a request body */
		p->expect_continue = true;
	}
	/* record all other end-to-end headers for forwarding */
	if (ctx->num_fwd_hdr >= ARRAY_SIZE(ctx->fwd_hdr)) {
		p->http_status = HTTP_ENTITY_TOO_LARGE;
		return false;
	}
	ctx->fwd_hdr[ctx->num_fwd_hdr].key = key;
	ctx->fwd_hdr[ctx->num_fwd_hdr].value = value;
	ctx->num_fwd_hdr++;
	return true;
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
	return parse_header_proxy_pass(ctx, p, key, value);
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
	ctx->ruleset_callback.forward = http_forward_commit;
	ctx->ruleset_state = NULL;
#endif
	ctx->dialreq = NULL;
	ctx->req_content_length = 0;
	ctx->req_content_length_known = false;
	ctx->num_fwd_hdr = 0;
	ctx->req_target[0] = '\0';
	const struct dialer_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(
		&ctx->dialer, &cb, &s->stats.byt_dial_send,
		&s->stats.byt_dial_recv);
	const struct http_parsehdr_cb on_header = { parse_header, ctx };
	http_conn_init(
		&ctx->conn, fd, STATE_PARSE_REQUEST, on_header,
		&s->stats.byt_client_recv, &s->stats.byt_client_send);

	gc_register(&ctx->gcbase, http_ctx_finalize);
	return ctx;
}

static void http_ctx_start(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_io_start(loop, &ctx->w_recv);
	ev_timer_start(loop, &ctx->w_timeout);

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
		SOCKET_CLOSE_FD(accepted_fd);
		return;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	http_ctx_start(loop, ctx);
}
