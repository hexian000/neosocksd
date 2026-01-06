/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "http_proxy.h"

#include "conf.h"
#include "dialer.h"
#include "httputil.h"
#include "ruleset.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "transfer.h"
#include "util.h"

#include "codec/base64.h"
#include "net/http.h"
#include "utils/buffer.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <strings.h>

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
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct server;

struct http_ctx {
	struct session ss;
	struct server *s;
	enum http_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	ev_timer w_timeout;
	union {
		/* state < STATE_CONNECTED */
		struct {
			ev_io w_recv, w_send;
#if WITH_RULESET
			ev_idle w_ruleset;
			struct ruleset_callback ruleset_callback;
			struct ruleset_state *ruleset_state;
#endif
			struct dialreq *dialreq;
			struct dialer dialer;
			struct http_parser parser;
		};
		/* state >= STATE_CONNECTED */
		struct {
			struct transfer uplink, downlink;
		};
	};
};
ASSERT_SUPER(struct session, struct http_ctx, ss);

static int format_status(
	char *restrict s, const size_t maxlen,
	const struct http_ctx *restrict ctx)
{
	char caddr[64];
	format_sa(caddr, sizeof(caddr), &ctx->accepted_sa.sa);
	if (ctx->state != STATE_CONNECT) {
		return snprintf(s, maxlen, "[%d] %s", ctx->accepted_fd, caddr);
	}
	return snprintf(
		s, maxlen, "[%d] %s -> `%s'", ctx->accepted_fd, caddr,
		ctx->parser.msg.req.url);
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
	const uint16_t code)
{
	ASSERT(4 <= (code / 100) && (code / 100) <= 5);
	http_resp_errpage(&ctx->parser, code);
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
		ev_idle_stop(loop, &ctx->w_ruleset);
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
	case STATE_CONNECTED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_halfopen--;
		return;
	case STATE_ESTABLISHED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_sessions--;
		break;
	}
	HTTP_CTX_LOG_F(VERBOSE, ctx, "closed, %zu active", stats->num_sessions);
}

static void http_ctx_close(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	HTTP_CTX_LOG_F(
		VERBOSE, ctx, "closing state=%d", ctx->accepted_fd, ctx->state);

	http_ctx_stop(loop, ctx);
	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	session_del(&ctx->ss);
	if (ctx->state < STATE_CONNECTED) {
		dialreq_free(ctx->dialreq);
	}
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	free(ctx);
}

static void
http_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct http_ctx *restrict ctx =
		DOWNCAST(struct session, struct http_ctx, ss, ss);
	http_ctx_close(loop, ctx);
}

static struct dialreq *make_dialreq(const char *restrict addr_str)
{
	struct dialreq *req = dialreq_new(0);
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
	dialer_do(&ctx->dialer, loop, ctx->dialreq);
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
	struct ruleset *restrict ruleset = G.ruleset;
	ASSERT(ruleset != NULL);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);

	unsigned char buf[512];
	const char *username = NULL;
	const char *password = NULL;
	parse_proxy_auth(
		buf, sizeof(buf), &username, &password,
		ctx->parser.hdr.proxy_authorization.type,
		ctx->parser.hdr.proxy_authorization.credentials);
	if (G.conf->auth_required && (username == NULL || password == NULL)) {
		RESPHDR_BEGIN(
			ctx->parser.wbuf, HTTP_PROXY_AUTHENTICATION_REQUIRED);
		BUF_APPENDSTR(
			ctx->parser.wbuf, "Proxy-Authenticate: Basic\r\n");
		RESPHDR_FINISH(ctx->parser.wbuf);
		send_response(loop, ctx);
		return;
	}

	const char *addr_str = ctx->parser.msg.req.url;
	const bool ok = ruleset_resolve(
		ruleset, &ctx->ruleset_state, addr_str, username, password,
		&ctx->ruleset_callback);
	if (!ok) {
		send_errpage(loop, ctx, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
}
#endif

static void http_proxy_pass(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	/* not supported */
	send_errpage(loop, ctx, HTTP_FORBIDDEN);
}

static void
http_proxy_handle(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	const struct http_message *restrict msg = &ctx->parser.msg;
	if (strcmp(msg->req.method, "CONNECT") != 0) {
		http_proxy_pass(loop, ctx);
		return;
	}

	const char *addr_str = ctx->parser.msg.req.url;
	HTTP_CTX_LOG_F(VERBOSE, ctx, "http: CONNECT `%s'", addr_str);
#if WITH_RULESET
	const struct ruleset *restrict ruleset = G.ruleset;
	if (ruleset != NULL) {
		ev_idle_start(loop, &ctx->w_ruleset);
		return;
	}
#endif

	ctx->dialreq = make_dialreq(addr_str);
	http_connect(loop, ctx);
}

static void on_established(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;
	stats->num_sessions++;
	stats->num_success++;
	HTTP_CTX_LOG_F(
		DEBUG, ctx, "established, %zu active", stats->num_sessions);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	if (ctx->uplink.state == XFER_FINISHED ||
	    ctx->downlink.state == XFER_FINISHED) {
		http_ctx_close(loop, ctx);
		return;
	}
	if (ctx->state == STATE_CONNECTED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		ctx->state = STATE_ESTABLISHED;
		on_established(loop, ctx);
		return;
	}
}

static void http_ctx_hijack(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	/* cleanup before state change */
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);
	dialreq_free(ctx->dialreq);

	if (G.conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
	} else {
		ctx->state = STATE_ESTABLISHED;
		on_established(loop, ctx);
	}

	const struct transfer_state_cb cb = {
		.func = xfer_state_cb,
		.data = ctx,
	};
	struct server_stats *restrict stats = &ctx->s->stats;
	transfer_init(
		&ctx->uplink, &cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, &cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static void recv_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);
	struct http_ctx *restrict ctx = watcher->data;

	const int want = http_parser_recv(&ctx->parser);
	if (want < 0) {
		http_ctx_close(loop, ctx);
		return;
	}
	if (want > 0) {
		return;
	}
	ctx->state = STATE_PROCESS;
	ev_io_stop(loop, watcher);

	switch (ctx->parser.state) {
	case STATE_PARSE_OK: {
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_request++;
	} break;
	case STATE_PARSE_ERROR:
		send_errpage(loop, ctx, ctx->parser.http_status);
		return;
	default:
		FAIL();
	}

	http_proxy_handle(loop, ctx);
}

static void send_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE);

	const int fd = watcher->fd;
	const unsigned char *buf = ctx->parser.wbuf.data + ctx->parser.wpos;
	size_t len = ctx->parser.wbuf.len - ctx->parser.wpos;
	int err = socket_send(fd, buf, &len);
	if (err != 0) {
		HTTP_CTX_LOG_F(WARNING, ctx, "send: %s", fd, strerror(err));
		http_ctx_close(loop, ctx);
		return;
	}
	ctx->parser.wpos += len;
	if (ctx->parser.wpos < ctx->parser.wbuf.len) {
		return;
	}

	if (ctx->parser.cbuf != NULL) {
		const struct vbuffer *restrict cbuf = ctx->parser.cbuf;
		buf = cbuf->data + ctx->parser.cpos;
		len = cbuf->len - ctx->parser.cpos;
		err = socket_send(fd, buf, &len);
		if (err != 0) {
			HTTP_CTX_LOG_F(WARNING, ctx, "send: %s", strerror(err));
			http_ctx_close(loop, ctx);
			return;
		}
		ctx->parser.cpos += len;
		if (ctx->parser.cpos < cbuf->len) {
			return;
		}
	}
	/* Connection: close */
	http_ctx_close(loop, ctx);
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_ctx *restrict ctx = watcher->data;
	http_ctx_close(loop, ctx);
}

static void dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct http_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	if (fd < 0) {
		const int err = ctx->dialer.syserr;
		if (err != 0) {
			HTTP_CTX_LOG_F(ERROR, ctx, "dialer: %s", strerror(err));
		}
		send_errpage(loop, ctx, HTTP_BAD_GATEWAY);
		return;
	}
	HTTP_CTX_LOG_F(DEBUG, ctx, "connected, fd=%d", fd);
	ctx->dialed_fd = fd;

	/* CONNECT proxy */
	if (!http_resp_established(&ctx->parser)) {
		http_ctx_close(loop, ctx);
		return;
	}
	ctx->s->stats.num_success++;
	http_ctx_hijack(loop, ctx);
}

static bool parse_header(void *data, const char *key, char *value)
{
	struct http_ctx *restrict ctx = (struct http_ctx *)data;
	struct http_parser *restrict p = &ctx->parser;

	/* hop-by-hop headers */
	if (strcasecmp(key, "Connection") == 0) {
		p->hdr.connection = value;
		return true;
	}
	if (strcasecmp(key, "Keep-Alive") == 0) {
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
	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(p, value);
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		return parsehdr_transfer_encoding(p, value);
	}
	/* ignore other headers */
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

	ev_timer_init(&ctx->w_timeout, timeout_cb, G.conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
	ev_io_init(&ctx->w_recv, recv_cb, fd, EV_READ);
	ctx->w_recv.data = ctx;
	ev_io_init(&ctx->w_send, send_cb, fd, EV_WRITE);
	ctx->w_send.data = ctx;
#if WITH_RULESET
	ev_idle_init(&ctx->w_ruleset, process_cb);
	ctx->w_ruleset.data = ctx;
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
	http_parser_init(&ctx->parser, fd, STATE_PARSE_REQUEST, on_header);

	ctx->ss.close = http_ss_close;
	session_add(&ctx->ss);
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
		CLOSE_FD(accepted_fd);
		return;
	}
	copy_sa(&ctx->accepted_sa.sa, accepted_sa);
	http_ctx_start(loop, ctx);
}
