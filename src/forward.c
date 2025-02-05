/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "forward.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset.h"
#include "server.h"
#include "session.h"
#include "sockutil.h"
#include "transfer.h"
#include "util.h"

#include "utils/class.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* never rollback */
enum forward_state {
	STATE_INIT,
	STATE_PROCESS,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct forward_ctx {
	struct session ss;
	struct server *s;
	enum forward_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	struct ev_timer w_timeout;
	union {
		/* connecting */
		struct {
#if WITH_RULESET
			struct ev_idle w_ruleset;
			struct ruleset_state *ruleset_state;
#endif
			struct dialreq *dialreq;
			struct dialer dialer;
		};
		/* connected */
		struct {
			struct transfer uplink, downlink;
		};
	};
};
ASSERT_SUPER(struct session, struct forward_ctx, ss);

#define FW_CTX_LOG_F(level, ctx, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char caddr[64];                                                \
		format_sa(caddr, sizeof(caddr), &(ctx)->accepted_sa.sa);       \
		LOG_F(level, "[%d] %s: " format, (ctx)->accepted_fd, caddr,    \
		      __VA_ARGS__);                                            \
	} while (0)
#define FW_CTX_LOG(level, ctx, message) FW_CTX_LOG_F(level, ctx, "%s", message)

static void
forward_ctx_stop(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	switch (ctx->state) {
	case STATE_INIT:
		return;
	case STATE_PROCESS:
#if WITH_RULESET
		ev_idle_stop(loop, &ctx->w_ruleset);
		if (ctx->ruleset_state != NULL) {
			ruleset_cancel(ctx->ruleset_state);
			ctx->ruleset_state = NULL;
		}
#endif
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		dialer_cancel(&ctx->dialer, loop);
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
	default:
		FAIL();
	}
	FW_CTX_LOG_F(DEBUG, ctx, "closed, %zu active", stats->num_sessions);
}

static void
forward_ctx_close(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	FW_CTX_LOG_F(VERBOSE, ctx, "close, state=%d", ctx->state);
	forward_ctx_stop(loop, ctx);

	if (ctx->state < STATE_CONNECTED) {
		dialreq_free(ctx->dialreq);
	}
	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	session_del(&ctx->ss);
	free(ctx);
}

static void
forward_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct forward_ctx *restrict ctx =
		DOWNCAST(struct session, struct forward_ctx, ss, ss);
	forward_ctx_close(loop, ctx);
}

static void
on_established(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;
	stats->num_sessions++;
	stats->num_success++;
	FW_CTX_LOG_F(
		DEBUG, ctx, "established, %zu active", stats->num_sessions);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct forward_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECTED ||
	       ctx->state == STATE_ESTABLISHED);

	if (ctx->uplink.state == XFER_FINISHED ||
	    ctx->downlink.state == XFER_FINISHED) {
		forward_ctx_close(loop, ctx);
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

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct forward_ctx *restrict ctx = watcher->data;

	switch (ctx->state) {
	case STATE_INIT:
	case STATE_PROCESS:
	case STATE_CONNECT:
		FW_CTX_LOG(WARNING, ctx, "connection timeout");
		break;
	case STATE_CONNECTED:
		FW_CTX_LOG(WARNING, ctx, "handshake timeout");
		break;
	case STATE_ESTABLISHED:
		return;
	default:
		FAIL();
	}
	forward_ctx_close(loop, ctx);
}

static void dialer_cb(struct ev_loop *loop, void *data)
{
	struct forward_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);

	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		FW_CTX_LOG_F(
			DEBUG, ctx, "unable to establish client connection: %s",
			strerror(ctx->dialer.syserr));
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialed_fd = fd;

	FW_CTX_LOG_F(DEBUG, ctx, "connected, fd=%d", fd);
	/* cleanup before state change */
	dialreq_free(ctx->dialreq);

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
		&ctx->uplink, &cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, &cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static void forward_ctx_start(
	struct ev_loop *loop, struct forward_ctx *restrict ctx,
	const struct dialreq *req)
{
	FW_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_request++;
	stats->num_halfopen++;
	dialer_do(&ctx->dialer, loop, req);
}

#if WITH_RULESET
static void
forward_ruleset_cb(struct ev_loop *loop, void *data, struct dialreq *req)
{
	struct forward_ctx *restrict ctx = data;
	ctx->ruleset_state = NULL;
	if (req == NULL) {
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialreq = req;
	forward_ctx_start(loop, ctx, req);
}

static void
forward_process_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct forward_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	struct ruleset *restrict ruleset = G.ruleset;
	ASSERT(ruleset != NULL);
	const struct dialreq *restrict req = G.basereq;
	const struct dialaddr *restrict addr = &req->addr;

	const size_t cap =
		addr->type == ATYP_DOMAIN ? addr->domain.len + 7 : 64;
	char request[cap];
	const int len = dialaddr_format(request, cap, addr);
	CHECK(len >= 0 && (size_t)len < cap);
	const struct ruleset_request_cb callback = {
		.func = forward_ruleset_cb,
		.loop = loop,
		.data = ctx,
	};
	bool ok;
	switch (addr->type) {
	case ATYP_INET:
		ok = ruleset_route(
			ruleset, &ctx->ruleset_state, request, NULL, NULL,
			&callback);
		break;
	case ATYP_INET6:
		ok = ruleset_route6(
			ruleset, &ctx->ruleset_state, request, NULL, NULL,
			&callback);
		break;
	case ATYP_DOMAIN:
		ok = ruleset_resolve(
			ruleset, &ctx->ruleset_state, request, NULL, NULL,
			&callback);
		break;
	default:
		FAIL();
	}
	if (!ok) {
		forward_ctx_close(loop, ctx);
		return;
	}
}
#endif

static struct forward_ctx *
forward_ctx_new(struct server *restrict s, const int accepted_fd)
{
	struct forward_ctx *restrict ctx = malloc(sizeof(struct forward_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->s = s;
	ctx->state = STATE_INIT;
	ctx->accepted_fd = accepted_fd;
	ctx->dialed_fd = -1;

	{
		struct ev_timer *restrict w_timeout = &ctx->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, G.conf->timeout, 0.0);
		w_timeout->data = ctx;
	}
#if WITH_RULESET
	{
		struct ev_idle *restrict w_ruleset = &ctx->w_ruleset;
		ev_idle_init(w_ruleset, NULL);
		w_ruleset->data = ctx;
	}
	ctx->ruleset_state = NULL;
#endif

	ctx->dialreq = NULL;
	const struct event_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	dialer_init(&ctx->dialer, &cb);
	ctx->ss.close = forward_ss_close;
	session_add(&ctx->ss);
	return ctx;
}

void forward_serve(
	struct server *restrict s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct forward_ctx *restrict ctx = forward_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		CLOSE_FD(accepted_fd);
		return;
	}
	copy_sa(&ctx->accepted_sa.sa, accepted_sa);

	ctx->state = STATE_PROCESS;
	ev_timer_start(loop, &ctx->w_timeout);

#if WITH_RULESET
	struct ruleset *ruleset = G.ruleset;
	if (ruleset != NULL) {
		ev_set_cb(&ctx->w_ruleset, forward_process_cb);
		ev_idle_start(loop, &ctx->w_ruleset);
		return;
	}
#endif
	const struct dialreq *req = G.basereq;
	forward_ctx_start(loop, ctx, req);
}

#if WITH_TPROXY

#if WITH_RULESET
static void
tproxy_ruleset_cb(struct ev_loop *loop, void *data, struct dialreq *req)
{
	struct forward_ctx *restrict ctx = data;
	ctx->ruleset_state = NULL;
	if (req == NULL) {
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialreq = req;
	forward_ctx_start(loop, ctx, req);
}

static void
tproxy_idle_cb(struct ev_loop *loop, struct ev_idle *watcher, int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct forward_ctx *restrict ctx = watcher->data;
	struct ruleset *restrict ruleset = G.ruleset;
	ASSERT(ruleset != NULL);

	union sockaddr_max dest;
	socklen_t len = sizeof(dest);
	if (getsockname(ctx->accepted_fd, &dest.sa, &len) != 0) {
		FW_CTX_LOG_F(ERROR, ctx, "getsockname: %s", strerror(errno));
		forward_ctx_close(loop, ctx);
		return;
	}
	switch (dest.sa.sa_family) {
	case AF_INET:
		CHECK(len >= sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		CHECK(len >= sizeof(struct sockaddr_in6));
		break;
	default:
		FW_CTX_LOG_F(
			ERROR, ctx, "tproxy: unsupported af:%jd",
			(intmax_t)dest.sa.sa_family);
		forward_ctx_close(loop, ctx);
		return;
	}

	char addr_str[64];
	format_sa(addr_str, sizeof(addr_str), &dest.sa);
	const struct ruleset_request_cb callback = {
		.func = tproxy_ruleset_cb,
		.loop = loop,
		.data = ctx,
	};
	bool ok;
	switch (dest.sa.sa_family) {
	case AF_INET:
		ok = ruleset_route(
			ruleset, &ctx->ruleset_state, addr_str, NULL, NULL,
			&callback);
		break;
	case AF_INET6:
		ok = ruleset_route6(
			ruleset, &ctx->ruleset_state, addr_str, NULL, NULL,
			&callback);
		break;
	default:
		FAIL();
	}
	if (!ok) {
		forward_ctx_close(loop, ctx);
		return;
	}
}
#endif

static struct dialreq *tproxy_makereq(struct forward_ctx *restrict ctx)
{
	union sockaddr_max dest;
	socklen_t len = sizeof(dest);
	if (getsockname(ctx->accepted_fd, &dest.sa, &len) != 0) {
		FW_CTX_LOG_F(ERROR, ctx, "getsockname: %s", strerror(errno));
		return NULL;
	}
	switch (dest.sa.sa_family) {
	case AF_INET:
		CHECK(len >= sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		CHECK(len >= sizeof(struct sockaddr_in6));
		break;
	default:
		FW_CTX_LOG_F(
			ERROR, ctx, "tproxy: unsupported af:%jd",
			(intmax_t)dest.sa.sa_family);
		return NULL;
	}

	struct dialreq *req = dialreq_new(0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	switch (dest.sa.sa_family) {
	case AF_INET:
		req->addr.type = ATYP_INET;
		req->addr.in = dest.in.sin_addr;
		req->addr.port = ntohs(dest.in.sin_port);
		break;
	case AF_INET6:
		req->addr.type = ATYP_INET6;
		req->addr.in6 = dest.in6.sin6_addr;
		req->addr.port = ntohs(dest.in6.sin6_port);
		break;
	}
	return req;
}

void tproxy_serve(
	struct server *restrict s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct forward_ctx *restrict ctx = forward_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		CLOSE_FD(accepted_fd);
		return;
	}
	copy_sa(&ctx->accepted_sa.sa, accepted_sa);

	ctx->state = STATE_PROCESS;
	ev_timer_start(loop, &ctx->w_timeout);

#if WITH_RULESET
	struct ruleset *ruleset = G.ruleset;
	if (ruleset != NULL) {
		ev_set_cb(&ctx->w_ruleset, tproxy_idle_cb);
		ev_idle_start(loop, &ctx->w_ruleset);
		return;
	}
#endif

	struct dialreq *req = tproxy_makereq(ctx);
	if (req == NULL) {
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialreq = req;
	forward_ctx_start(loop, ctx, req);
}
#endif /* WITH_TPROXY */
