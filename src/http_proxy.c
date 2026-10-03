/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
#include "proto/http.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "util.h"

#include "codec/base64.h"
#include "meta/class.h"
#include "net/http.h"
#include "os/socket.h"
#include "utils/buffer.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* never rollback */
enum http_state {
	STATE_INIT,
	STATE_REQUEST,
	STATE_PROCESS,
	STATE_RESPONSE,
	STATE_CONNECT,
	STATE_ESTABLISHED,
	/* CONNECT raw relay (transfer-engine owned) */
	STATE_BIDIRECTIONAL,
};

struct http_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum http_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	struct dialaddr addr;
	ev_timer w_timeout;
	ev_io w_recv, w_send;
#if WITH_RULESET
	ev_idle w_process;
	struct ruleset_callback ruleset_callback;
	struct ruleset_state *ruleset_state;
#endif
	struct dialreq *dialreq;
	struct dialer dialer;
	struct http_conn conn;
};
ASSERT_SUPER(struct gcbase, struct http_ctx, gcbase);

/* Upper bound (excluding NUL) on the prefix format_fd() builds. */
#define FD_PREFIX_STRLEN                                                       \
	(CONSTSTRLEN("[fd:] ") + CONSTSTRLEN("-2147483648") /* max int fd */)

/* The fd-correlation prefix, empty when there is no descriptor left to name:
 * the transfer hand-off moves the accepted fd out of the context, and the
 * number it held may since have been reused by another connection. */
static const char *
format_fd(char *restrict buf, const size_t maxlen, const int fd)
{
	if (fd < 0) {
		return "";
	}
	const int n = snprintf(buf, maxlen, "[fd:%d] ", fd);
	ASSERT(n > 0 && (size_t)n < maxlen);
	(void)n;
	return buf;
}

static int format_status(
	char *restrict s, const size_t maxlen,
	const struct http_ctx *restrict ctx, const int fd)
{
	char fdstr[FD_PREFIX_STRLEN + 1];
	const char *const prefix = format_fd(fdstr, sizeof(fdstr), fd);
	char caddr[64];
	sa_format(caddr, sizeof(caddr), &ctx->accepted_sa.sa);
	if (ctx->state < STATE_CONNECT || STATE_ESTABLISHED < ctx->state) {
		return snprintf(s, maxlen, "%s%s", prefix, caddr);
	}
	return snprintf(
		s, maxlen, "%s%s -> `%s'", prefix, caddr,
		ctx->conn.msg.req.url);
}

/* Log with an explicit fd for the correlation prefix, for the hand-off path
 * that has already moved the accepted fd out of the context. */
#define HTTP_FD_LOG_F(level, ctx, fd, format, ...)                             \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char status_str[256];                                          \
		const int nstatus = format_status(                             \
			status_str, sizeof(status_str), (ctx), (fd));          \
		ASSERT(nstatus > 0);                                           \
		LOG_F(level, "%.*s: " format, nstatus, status_str,             \
		      __VA_ARGS__);                                            \
	} while (0)
#define HTTP_CTX_LOG_F(level, ctx, format, ...)                                \
	HTTP_FD_LOG_F(level, ctx, (ctx)->accepted_fd, format, __VA_ARGS__)
#define HTTP_CTX_LOG(level, ctx, message)                                      \
	HTTP_CTX_LOG_F(level, ctx, "%s", message)

#if WITH_RULESET
/* Release the ruleset work the context still owes. A start that failed may
 * have published its state anyway, and a request that completed in this same
 * loop sweep leaves w_finish pending with a delivered dialreq; neither is tied
 * to a context state, so every path that stops expecting the callback releases
 * both. */
static void cancel_ruleset(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	if (ctx->ruleset_state != NULL) {
		ruleset_cancel(loop, ctx->ruleset_state);
		ctx->ruleset_state = NULL;
	}
	ruleset_request_cancel(loop, &ctx->ruleset_callback);
}
#endif /* WITH_RULESET */

static void http_ctx_stop(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);
#if WITH_RULESET
	cancel_ruleset(loop, ctx);
#endif

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
#endif /* WITH_RULESET */
		stats->num_halfopen--;
		return;
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		dialer_cancel(&ctx->dialer, loop);
		stats->num_halfopen--;
		return;
	case STATE_ESTABLISHED:
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
		socket_close(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		socket_close(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	if (ctx->state < STATE_BIDIRECTIONAL) {
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		VBUF_FREE(ctx->conn.cbuf);
	}
}

/* Start bidirectional transfer; always calls gc_unref.
 * Caller must stop watchers and release dialreq/cbuf first. */
static void
http_ctx_start_transfer(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const int acc_fd = ctx->accepted_fd, dial_fd = ctx->dialed_fd;
	ctx->accepted_fd = ctx->dialed_fd = -1;
	/* Enter STATE_BIDIRECTIONAL before server_commit_session(): on failure
	 * it gc_unref()s the context, and the finalizer must then treat it as
	 * handed off rather than decrement num_halfopen a second time or free
	 * the released dialreq again. */
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);
	ctx->s->stats.num_halfopen--;
	HTTP_FD_LOG_F(
		DEBUG, ctx, acc_fd, "transfer start: [%d<->%d]", acc_fd,
		dial_fd);
	const size_t cur =
		server_commit_session(ctx->s, &ctx->gcbase, acc_fd, dial_fd);
	if (cur == 0) {
		return;
	}
	HTTP_FD_LOG_F(DEBUG, ctx, acc_fd, "ready, %zu active sessions", cur);
	gc_unref(&ctx->gcbase);
}

/* Bytes already buffered past the parsed request/headers (e.g. from a
 * TCP-fast-open client that didn't wait for a reply before sending
 * payload). */
static size_t readahead_len(const struct http_conn *restrict p)
{
	return p->rbuf.len - (size_t)((unsigned char *)p->next - p->rbuf.data);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE || ctx->state == STATE_ESTABLISHED);

	int err = 0;
	const int ret = http_conn_send(&ctx->conn, watcher->fd, &err);
	if (ret < 0) {
		HTTP_CTX_LOG_F(
			WARNING, ctx, "socket_send: (%d) %s", err,
			strerror(err));
		gc_unref(&ctx->gcbase);
		return;
	}
	if (ret > 0) {
		return;
	}
	switch (ctx->state) {
	case STATE_ESTABLISHED: {
		/* CONNECT 200 fully sent: a CONNECT tunnel has no cbuf salvage
		 * step, so replay any pipelined client bytes to the upstream now,
		 * while both fds are still valid, then start the raw relay. */
		ev_io_stop(loop, &ctx->w_send);
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		const size_t readahead = readahead_len(&ctx->conn);
		if (readahead > 0 && !forward_readahead(
					     ctx->dialed_fd, ctx->conn.next,
					     readahead, &ctx->s->byt_up)) {
			HTTP_CTX_LOG(
				WARNING, ctx,
				"failed to forward pipelined bytes to upstream");
			gc_unref(&ctx->gcbase);
			return;
		}
		VBUF_FREE(ctx->conn.cbuf);
		http_ctx_start_transfer(loop, ctx);
		return;
	}
	case STATE_RESPONSE:
		/* a locally-generated response (error page) was fully sent */
		gc_unref(&ctx->gcbase);
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
}

/* commit a connected upstream: queue the CONNECT 200 response and start
 * draining it to the client; takes ownership of @p fd */
static void
http_commit(struct ev_loop *loop, struct http_ctx *restrict ctx, const int fd)
{
	HTTP_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	ctx->dialed_fd = fd;
	ASSERT(ctx->conn.wbuf.len == 0);
	BUF_APPENDSTR(
		ctx->conn.wbuf, "HTTP/1.1 200 Connection established\r\n\r\n");
	ctx->state = STATE_ESTABLISHED;
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
	/* every caller resolves ctx->dialreq (and its error code) first */
	ASSERT(ctx->dialreq != NULL);
	HTTP_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	dialer_do(
		&ctx->dialer, loop, ctx->dialreq, ctx->s->conf,
		ctx->s->resolver, ctx->s);
}

static void
http_connect_direct(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	struct dialreq *req = dialreq_new(ctx->s->basereq, 0);
	if (req == NULL) {
		LOGOOM();
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	dialaddr_copy(&req->addr, &ctx->addr);
	ctx->dialreq = req;
	http_connect(loop, ctx);
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
	unsigned char *buf, const size_t bufsize,
	struct ruleset_credentials *restrict creds, const char *authtype,
	const char *credentials)
{
	if (authtype == NULL || credentials == NULL) {
		return;
	}
	/* RFC 9110 §11.1: the authentication scheme token is case-insensitive */
	if (!http_token_equal(authtype, "Basic")) {
		return;
	}
	size_t dstlen = bufsize - 1;
	if (!base64_decode(
		    buf, &dstlen, (const unsigned char *)credentials,
		    strlen(credentials))) {
		return;
	}
	/* RFC 7617 §2 forbids control characters in the user-id and the
	 * password, so a null byte makes the credentials malformed */
	if (memchr(buf, '\0', dstlen) != NULL) {
		return;
	}
	char *const s = (char *)buf;
	s[dstlen] = '\0';
	char *const sep = strchr(s, ':');
	if (sep == NULL) {
		return;
	}
	const size_t userlen = (size_t)(sep - s);
	*creds = (struct ruleset_credentials){
		.username = s,
		.username_len = userlen,
		.password = sep + 1,
		.password_len = dstlen - userlen - 1,
	};
}

static void
process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct http_ctx *restrict ctx = watcher->data;
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	ASSERT(ctx->state == STATE_PROCESS);

	unsigned char buf[512];
	struct ruleset_credentials creds = { 0 };
	parse_proxy_auth(
		buf, sizeof(buf), &creds,
		ctx->conn.hdr.proxy_authorization.type,
		ctx->conn.hdr.proxy_authorization.credentials);
	if (ctx->s->conf->auth_required &&
	    (ruleset == NULL || creds.username == NULL)) {
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

	if (ruleset == NULL) {
		http_connect_direct(loop, ctx);
		return;
	}

	char request[DIALADDR_STRLEN + 1];
	const int n = dialaddr_format(request, sizeof(request), &ctx->addr);
	ASSERT(n >= 0 && (size_t)n < sizeof(request));
	(void)n;
	const bool ok = ruleset_resolve(
		ruleset, &ctx->ruleset_state, request, &creds,
		&ctx->ruleset_callback);
	if (!ok) {
		/* the context stays alive to flush the error page, but leaves
		 * STATE_PROCESS and no longer expects the callback */
		cancel_ruleset(loop, ctx);
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
}
#endif /* WITH_RULESET */

static void
http_proxy_handle(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->conn.msg;
	/* only CONNECT tunneling is supported; HTTP request forwarding
	 * (proxy_pass) was removed */
	if (strcmp(msg->req.method, "CONNECT") != 0) {
		HTTP_CTX_LOG_F(
			VERBOSE, ctx, "http: unsupported method `%s'",
			msg->req.method);
		send_errpage(loop, ctx, HTTP_NOT_IMPLEMENTED);
		return;
	}

	const char *const addr_str = ctx->conn.msg.req.url;
	HTTP_CTX_LOG_F(VERBOSE, ctx, "http: CONNECT `%s'", addr_str);
	/* RFC 9110 §9.3.6: the CONNECT request-target is authority-form only,
	 * so one that is not a dialable "host:port" is a malformed request
	 * whichever path routes it */
	if (!dialaddr_parse(&ctx->addr, addr_str, strlen(addr_str))) {
		send_errpage(loop, ctx, HTTP_BAD_REQUEST);
		return;
	}
#if WITH_RULESET
	const struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif

	http_connect_direct(loop, ctx);
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
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_ctx *restrict ctx = watcher->data;
	ctx->s->stats.num_reject_timeout++;
	switch (ctx->state) {
	case STATE_PROCESS:
		/* the request parsed but routing it outlived the deadline: the
		 * context stops expecting the ruleset callback */
		HTTP_CTX_LOG(WARNING, ctx, "process timeout");
#if WITH_RULESET
		ev_idle_stop(loop, &ctx->w_process);
		cancel_ruleset(loop, ctx);
#endif /* WITH_RULESET */
		break;
	case STATE_CONNECT:
		HTTP_CTX_LOG(WARNING, ctx, "connect timeout");
		dialer_cancel(&ctx->dialer, loop);
		break;
	default:
		/* the client never finished its request, or never drained the
		 * response: there is no one to answer, just close */
		gc_unref(&ctx->gcbase);
		return;
	}
	/* answer 504 rather than closing the client with no status */
	send_errpage(loop, ctx, HTTP_GATEWAY_TIMEOUT);
	/* the one-shot deadline stopped itself before this callback, so re-arm
	 * it: a client that never reads the queued error page would otherwise
	 * pin the context with no deadline left */
	ev_timer_set(&ctx->w_timeout, ctx->s->conf->timeout, 0.0);
	ev_timer_start(loop, &ctx->w_timeout);
}

static void dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct http_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	if (fd < 0) {
		char errbuf[128];
		HTTP_CTX_LOG_F(
			ERROR, ctx, "dialer: %s",
			dialer_errorstr(errbuf, sizeof(errbuf), &ctx->dialer));
		ctx->s->stats.num_reject_upstream++;
		send_errpage(loop, ctx, HTTP_BAD_GATEWAY);
		return;
	}
	http_commit(loop, ctx, fd);
}

static bool parse_header(void *data, const char *key, char *value)
{
	struct http_ctx *restrict ctx = (struct http_ctx *)data;
	struct http_conn *restrict p = &ctx->conn;

	/* http_parsehdr() has already rejected a field name that is not a
	 * token and a value carrying any CTL but HTAB (RFC 9110 §5.5), so
	 * key and value arrive well-formed. */

	/* The shared parser validates Host before this callback. CONNECT only
	 * acts on Proxy-Authorization here; other fields are ignored. */
	if (http_token_equal(key, "Proxy-Authorization")) {
		/* RFC 9110 §11.4: credentials = auth-scheme [ 1*SP ( token68 /
		 * #auth-param ) ] — the credentials part is optional and any
		 * number of SP may separate it from the scheme */
		p->hdr.proxy_authorization.type = value;
		p->hdr.proxy_authorization.credentials = NULL;
		char *const sep = strchr(value, ' ');
		if (sep == NULL) {
			return true;
		}
		*sep = '\0';
		p->hdr.proxy_authorization.credentials =
			sep + 1 + strspn(sep + 1, " ");
		return true;
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
	ctx->ruleset_callback.forward = http_forward_commit;
	ctx->ruleset_state = NULL;
#endif
	ctx->dialreq = NULL;
	const struct dialer_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(
		&ctx->dialer, &cb, &s->stats.byt_dial_send,
		&s->stats.byt_dial_recv);
	const struct http_parsehdr_cb on_header = {
		.func = parse_header,
		.ctx = ctx,
	};
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
		socket_close(accepted_fd);
		return;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	http_ctx_start(loop, ctx);
}
