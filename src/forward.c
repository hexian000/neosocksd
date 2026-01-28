/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* never rollback */
enum forward_state {
	STATE_INIT,
	STATE_PROCESS,
	STATE_CONNECT,
	STATE_ESTABLISHED,
	STATE_BIDIRECTIONAL,
};

struct forward_ctx {
	struct session ss;
	struct server *s;
	enum forward_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	ev_timer w_timeout;
	union {
		/* state < STATE_CONNECTED */
		struct {
#if WITH_RULESET
			ev_idle w_ruleset;
			struct ruleset_callback ruleset_callback;
			struct ruleset_state *ruleset_state;
#endif
			struct dialreq *dialreq;
			struct dialer dialer;
		};
		/* state >= STATE_CONNECTED */
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
			ruleset_cancel(loop, ctx->ruleset_state);
			ctx->ruleset_state = NULL;
		}
#endif
		stats->num_halfopen--;
		return;
	case STATE_CONNECT:
		dialer_cancel(&ctx->dialer, loop);
		stats->num_halfopen--;
		return;
	case STATE_ESTABLISHED:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_halfopen--;
		break;
	case STATE_BIDIRECTIONAL:
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
		stats->num_sessions--;
		break;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
	FW_CTX_LOG_F(VERBOSE, ctx, "closed, %zu active", stats->num_sessions);
}

static void
forward_ctx_close(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	FW_CTX_LOG_F(VERBOSE, ctx, "closing, state=%d", ctx->state);

	forward_ctx_stop(loop, ctx);
	if (ctx->accepted_fd != -1) {
		CLOSE_FD(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		CLOSE_FD(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	session_del(&ctx->ss);
	if (ctx->state < STATE_ESTABLISHED) {
		dialreq_free(ctx->dialreq);
	}
	free(ctx);
}

static void
forward_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct forward_ctx *restrict ctx =
		DOWNCAST(struct session, struct forward_ctx, ss, ss);
	forward_ctx_close(loop, ctx);
}

static void mark_ready(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);

	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;
	stats->num_sessions++;
	stats->num_success++;
	FW_CTX_LOG_F(
		DEBUG, ctx, "ready, %zu active sessions", stats->num_sessions);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct forward_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_ESTABLISHED ||
	       ctx->state == STATE_BIDIRECTIONAL);

	if (ctx->uplink.state == XFER_FINISHED &&
	    ctx->downlink.state == XFER_FINISHED) {
		forward_ctx_close(loop, ctx);
		return;
	}
	if (ctx->state == STATE_ESTABLISHED &&
	    ctx->uplink.state == XFER_CONNECTED &&
	    ctx->downlink.state == XFER_CONNECTED) {
		mark_ready(loop, ctx);
		return;
	}
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct forward_ctx *restrict ctx = watcher->data;

	switch (ctx->state) {
	case STATE_INIT:
	case STATE_PROCESS:
	case STATE_CONNECT:
		FW_CTX_LOG(WARNING, ctx, "connection timeout");
		break;
	case STATE_ESTABLISHED:
		FW_CTX_LOG(WARNING, ctx, "handshake timeout");
		break;
	case STATE_BIDIRECTIONAL:
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
	forward_ctx_close(loop, ctx);
}

static void dialer_cb(struct ev_loop *loop, void *data, const int fd)
{
	struct forward_ctx *restrict ctx = data;
	ASSERT(ctx->state == STATE_CONNECT);
	if (fd < 0) {
		const enum dialer_error err = ctx->dialer.err;
		const int syserr = ctx->dialer.syserr;
		if (syserr != 0) {
			FW_CTX_LOG_F(
				ERROR, ctx, "dialer: %s ([%d] %s)",
				dialer_strerror(err), syserr, strerror(syserr));
		} else {
			FW_CTX_LOG_F(
				ERROR, ctx, "dialer: %s", dialer_strerror(err));
		}
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialed_fd = fd;

	FW_CTX_LOG_F(VERBOSE, ctx, "connected, fd=%d", fd);
	/* cleanup before state change */
	dialreq_free(ctx->dialreq);

	if (G.conf->bidir_timeout) {
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
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, &cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);

	FW_CTX_LOG_F(
		DEBUG, ctx,
		"transfer start: uplink [%d->%d], downlink [%d->%d]",
		ctx->accepted_fd, ctx->dialed_fd, ctx->dialed_fd,
		ctx->accepted_fd);
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
ruleset_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct forward_ctx *restrict ctx = watcher->data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->ruleset_state = NULL;
	struct dialreq *req = ctx->ruleset_callback.request.req;
	if (req == NULL) {
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialreq = req;
	forward_ctx_start(loop, ctx, req);
}
#endif /* WITH_RULESET */

#if WITH_RULESET
static void
forward_process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
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
	bool ok;
	switch (addr->type) {
	case ATYP_INET:
		ok = ruleset_route(
			ruleset, &ctx->ruleset_state, request, NULL, NULL,
			&ctx->ruleset_callback);
		break;
	case ATYP_INET6:
		ok = ruleset_route6(
			ruleset, &ctx->ruleset_state, request, NULL, NULL,
			&ctx->ruleset_callback);
		break;
	case ATYP_DOMAIN:
		ok = ruleset_resolve(
			ruleset, &ctx->ruleset_state, request, NULL, NULL,
			&ctx->ruleset_callback);
		break;
	default:
		FAILMSGF("unexpected address type: %d", addr->type);
	}
	if (!ok) {
		forward_ctx_close(loop, ctx);
		return;
	}
}
#endif /* WITH_RULESET */

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

	ev_timer_init(&ctx->w_timeout, timeout_cb, G.conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
#if WITH_RULESET
	ev_idle_init(&ctx->w_ruleset, NULL);
	ctx->w_ruleset.data = ctx;
	ev_init(&ctx->ruleset_callback.w_finish, NULL);
	ctx->ruleset_callback.w_finish.data = ctx;
	ctx->ruleset_state = NULL;
#endif

	ctx->dialreq = NULL;
	const struct dialer_cb cb = {
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
	const struct ruleset *ruleset = G.ruleset;
	if (ruleset != NULL) {
		ev_set_cb(&ctx->w_ruleset, forward_process_cb);
		ev_set_cb(&ctx->ruleset_callback.w_finish, ruleset_cb);
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
tproxy_process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct forward_ctx *restrict ctx = watcher->data;
	struct ruleset *restrict ruleset = G.ruleset;
	ASSERT(ruleset != NULL);

	union sockaddr_max dest;
	socklen_t len = sizeof(dest);
	if (getsockname(ctx->accepted_fd, &dest.sa, &len) != 0) {
		const int err = errno;
		FW_CTX_LOG_F(
			ERROR, ctx, "getsockname: [%d] %s", err, strerror(err));
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
	bool ok;
	switch (dest.sa.sa_family) {
	case AF_INET:
		ok = ruleset_route(
			ruleset, &ctx->ruleset_state, addr_str, NULL, NULL,
			&ctx->ruleset_callback);
		break;
	case AF_INET6:
		ok = ruleset_route6(
			ruleset, &ctx->ruleset_state, addr_str, NULL, NULL,
			&ctx->ruleset_callback);
		break;
	default:
		FAILMSGF("unexpected address family: %d", dest.sa.sa_family);
	}
	if (!ok) {
		forward_ctx_close(loop, ctx);
		return;
	}
}
#endif /* WITH_RULESET */

static struct dialreq *tproxy_makereq(const struct forward_ctx *restrict ctx)
{
	union sockaddr_max dest;
	socklen_t len = sizeof(dest);
	if (getsockname(ctx->accepted_fd, &dest.sa, &len) != 0) {
		const int err = errno;
		FW_CTX_LOG_F(
			ERROR, ctx, "getsockname: [%d] %s", err, strerror(err));
		return NULL;
	}
	struct dialreq *req = dialreq_new(0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	if (!dialaddr_set(&req->addr, &dest.sa, len)) {
		FW_CTX_LOG_F(
			ERROR, ctx, "tproxy: unsupported af:%jd",
			(intmax_t)dest.sa.sa_family);
		dialreq_free(req);
		return NULL;
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
	const struct ruleset *ruleset = G.ruleset;
	if (ruleset != NULL) {
		ev_set_cb(&ctx->w_ruleset, tproxy_process_cb);
		ev_set_cb(&ctx->ruleset_callback.w_finish, ruleset_cb);
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
