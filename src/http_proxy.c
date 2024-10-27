/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
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

#include <stddef.h>
#include <string.h>

struct http_ctx;

/* never rollback */
enum http_state {
	STATE_INIT,
	STATE_REQUEST,
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
	struct ev_timer w_timeout;
	union {
		struct {
			struct ev_io w_recv, w_send;
			const char *host;
			struct dialreq *dialreq;
			struct dialer dialer;
			struct http_parser parser;
		};
		struct { /* connected */
			struct transfer uplink, downlink;
		};
	};
};
ASSERT_SUPER(struct session, struct http_ctx, ss);

#define HTTP_CTX_LOG_F(level, ctx, format, ...)                                \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char caddr[64];                                                \
		format_sa(&(ctx)->accepted_sa.sa, caddr, sizeof(caddr));       \
		if ((ctx)->state != STATE_CONNECT) {                           \
			LOG_F(level, "client `%s': " format, caddr,            \
			      __VA_ARGS__);                                    \
			break;                                                 \
		}                                                              \
		LOG_F(level, "`%s' -> `%s': " format, caddr,                   \
		      (ctx)->parser.msg.req.url, __VA_ARGS__);                 \
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
	case STATE_RESPONSE:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		ev_io_stop(loop, &ctx->w_recv);
		ev_io_stop(loop, &ctx->w_send);
		dialer_cancel(&ctx->dialer, loop);
		dialreq_free(ctx->dialreq);
		ctx->dialreq = NULL;
		stats->num_halfopen--;
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
	HTTP_CTX_LOG_F(DEBUG, ctx, "closed, %zu active", stats->num_sessions);
}

static void http_ctx_close(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	HTTP_CTX_LOG_F(
		VERBOSE, ctx, "close fd=%d state=%d", ctx->accepted_fd,
		ctx->state);
	http_ctx_stop(loop, ctx);

	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	ctx->parser.cbuf = VBUF_FREE(ctx->parser.cbuf);
	session_del(&ctx->ss);
	free(ctx);
}

static void
http_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct http_ctx *restrict ctx =
		DOWNCAST(struct session, struct http_ctx, ss, ss);
	http_ctx_close(loop, ctx);
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct http_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		HTTP_CTX_LOG_F(
			DEBUG, ctx, "unable to establish client connection: %s",
			strerror(ctx->dialer.syserr));
		http_resp_errpage(&ctx->parser, HTTP_BAD_GATEWAY);
		ctx->state = STATE_RESPONSE;
		ev_io_start(loop, &ctx->w_send);
		return;
	}
	HTTP_CTX_LOG_F(DEBUG, ctx, "connected, fd=%d", fd);

	ctx->dialed_fd = fd;
	BUF_APPENDSTR(
		ctx->parser.wbuf,
		"HTTP/1.1 200 Connection established\r\n\r\n");
	ev_io_start(loop, &ctx->w_send);
}

static struct dialreq *make_dialreq(const char *addr_str)
{
#if WITH_RULESET
	struct ruleset *ruleset = G.ruleset;
	if (ruleset != NULL) {
		return ruleset_resolve(ruleset, addr_str, NULL, NULL);
	}
#endif
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
	return;
}

static bool req_connect(
	struct http_ctx *restrict ctx, const char *username,
	const char *password)
{
	const char *addr_str = ctx->parser.msg.req.url;
	HTTP_CTX_LOG_F(
		VERBOSE, ctx, "http: CONNECT `%s' username=`%s'", addr_str,
		username);
#if WITH_RULESET
	struct ruleset *restrict r = G.ruleset;
	if (r != NULL) {
		struct dialreq *req =
			ruleset_resolve(r, addr_str, username, password);
		if (req == NULL) {
			return false;
		}
		ctx->dialreq = req;
		return true;
	}
#else
	UNUSED(username);
	UNUSED(password);
#endif
	ctx->dialreq = make_dialreq(addr_str);
	return true;
}

static void http_proxy_pass(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	/* TODO */
	UNUSED(loop);
	http_resp_errpage(&ctx->parser, HTTP_FORBIDDEN);
	ctx->state = STATE_RESPONSE;
	ev_io_start(loop, &ctx->w_send);
}

static void
http_proxy_handle(struct ev_loop *loop, struct http_ctx *restrict ctx)
{
	ctx->dialreq = NULL;
	const struct http_message *restrict msg = &ctx->parser.msg;
	if (strcmp(msg->req.method, "CONNECT") != 0) {
		http_proxy_pass(loop, ctx);
		return;
	}

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
		return;
	}

	if (!req_connect(ctx, username, password)) {
		http_resp_errpage(&ctx->parser, HTTP_FORBIDDEN);
		return;
	}
	if (ctx->dialreq == NULL) {
		http_resp_errpage(&ctx->parser, HTTP_INTERNAL_SERVER_ERROR);
		return;
	}
	HTTP_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	const struct event_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, cb);
	dialer_start(&ctx->dialer, loop, ctx->dialreq);
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
	ev_io_stop(loop, &ctx->w_recv);
	ev_io_stop(loop, &ctx->w_send);

	if (G.conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
	} else {
		ctx->state = STATE_ESTABLISHED;
		on_established(loop, ctx);
	}

	const struct event_cb cb = {
		.func = xfer_state_cb,
		.data = ctx,
	};
	struct server_stats *restrict stats = &ctx->s->stats;
	transfer_init(
		&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static void recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
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
	switch (ctx->parser.state) {
	case STATE_PARSE_OK: {
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_request++;
		http_proxy_handle(loop, ctx);
	} break;
	case STATE_PARSE_ERROR:
		http_resp_errpage(&ctx->parser, ctx->parser.http_status);
		ctx->state = STATE_RESPONSE;
		ev_io_start(loop, &ctx->w_send);
		break;
	default:
		FAIL();
	}
}

static void send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_WRITE);
	struct http_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_RESPONSE || ctx->state == STATE_CONNECT);

	const int fd = watcher->fd;
	const unsigned char *buf = ctx->parser.wbuf.data + ctx->parser.wpos;
	size_t len = ctx->parser.wbuf.len - ctx->parser.wpos;
	int err = socket_send(fd, buf, &len);
	if (err != 0) {
		HTTP_CTX_LOG_F(
			WARNING, ctx, "send: fd=%d %s", fd, strerror(err));
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
		err = socket_send(watcher->fd, buf, &len);
		if (err != 0) {
			HTTP_CTX_LOG_F(
				WARNING, ctx, "send: fd=%d %s", fd,
				strerror(err));
			http_ctx_close(loop, ctx);
			return;
		}
		ctx->parser.cpos += len;
		if (ctx->parser.cpos < cbuf->len) {
			return;
		}
	}

	if (ctx->state == STATE_CONNECT) {
		/* CONNECT proxy */
		http_ctx_hijack(loop, ctx);
		return;
	}
	/* Connection: close */
	http_ctx_close(loop, ctx);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct http_ctx *restrict ctx = watcher->data;
	http_ctx_close(loop, ctx);
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
	if (strcasecmp(key, "Proxy-Connection") == 0) {
		/* TODO */
		return true;
	}
	if (strcasecmp(key, "TE") == 0) {
		return parsehdr_accept_te(p, value);
	}
	if (strcasecmp(key, "Transfer-Encoding") == 0) {
		return parsehdr_transfer_encoding(p, value);
	}
	if (strcasecmp(key, "Trailer") == 0) {
		/* TODO */
		return true;
	}
	if (strcasecmp(key, "Upgrade") == 0) {
		return true;
	}

	/* Host */
	if (strcasecmp(key, "Host") == 0) {
		ctx->host = value;
		/* fallthrough */
	}

	/* copy other headers */
	BUF_APPENDF(p->wbuf, "%s: %s\r\n", key, value);
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

	{
		struct ev_timer *restrict w_timeout = &ctx->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, G.conf->timeout, 0.0);
		w_timeout->data = ctx;
	}
	{
		struct ev_io *restrict w_recv = &ctx->w_recv;
		ev_io_init(w_recv, recv_cb, fd, EV_READ);
		w_recv->data = ctx;
	}
	{
		struct ev_io *restrict w_send = &ctx->w_send;
		ev_io_init(w_send, send_cb, fd, EV_WRITE);
		w_send->data = ctx;
	}
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
