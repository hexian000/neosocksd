/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "forward.h"

#include "conf.h"
#include "dialer.h"
#include "ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "os/clock.h"
#include "os/socket.h"
#include "utils/arraysize.h"
#include "utils/class.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <errno.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
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
	STATE_BIDIRECTIONAL,
};

struct forward_ctx {
	struct gcbase gcbase;
	struct server *s;
	enum forward_state state;
	int accepted_fd, dialed_fd;
	union sockaddr_max accepted_sa;
	intmax_t accepted_ns;
	ev_timer w_timeout;
	/* state < STATE_BIDIRECTIONAL */
	struct {
#if WITH_RULESET
		ev_idle w_process;
		struct ruleset_callback ruleset_callback;
		struct ruleset_state *ruleset_state;
#endif
		struct dialreq *dialreq;
		struct dialer dialer;
	};
};
ASSERT_SUPER(struct gcbase, struct forward_ctx, gcbase);

#define FW_CTX_LOG_F(level, ctx, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char caddr[64];                                                \
		sa_format(caddr, sizeof(caddr), &(ctx)->accepted_sa.sa);       \
		LOG_F(level, "[fd:%d] %s: " format, (ctx)->accepted_fd, caddr, \
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
		ev_idle_stop(loop, &ctx->w_process);
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
	case STATE_BIDIRECTIONAL:
		/* transfer_ctx is self-owned; nothing to do */
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
}

static void forward_ctx_finalize(struct gcbase *restrict obj)
{
	struct forward_ctx *restrict ctx =
		DOWNCAST(struct gcbase, struct forward_ctx, gcbase, obj);
	FW_CTX_LOG_F(VERBOSE, ctx, "closing, state=%d", ctx->state);

	forward_ctx_stop(ctx->s->loop, ctx);
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
	}
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_TIMER);
	struct forward_ctx *restrict ctx = watcher->data;

	switch (ctx->state) {
	case STATE_INIT:
	case STATE_PROCESS:
	case STATE_CONNECT:
		FW_CTX_LOG(WARNING, ctx, "connection timeout");
		break;
	case STATE_BIDIRECTIONAL:
		return;
	default:
		FAILMSGF("unexpected state: %d", ctx->state);
	}
	ctx->s->stats.num_reject_timeout++;
	gc_unref(&ctx->gcbase);
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
				ERROR, ctx, "dialer: %s (%d) %s",
				dialer_strerror(err), syserr, strerror(syserr));
		} else {
			FW_CTX_LOG_F(
				ERROR, ctx, "dialer: %s", dialer_strerror(err));
		}
		ctx->s->stats.num_reject_upstream++;
		gc_unref(&ctx->gcbase);
		return;
	}
	ctx->dialed_fd = fd;

	FW_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	/* cleanup before state change */
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	const int acc_fd = ctx->accepted_fd, dial_fd = ctx->dialed_fd;
	ctx->accepted_fd = ctx->dialed_fd = -1;
	/*
	 * Transition to STATE_BIDIRECTIONAL before transfer_start so that
	 * forward_ctx_stop becomes a no-op if gc_unref is called below.
	 */
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_halfopen--;

	FW_CTX_LOG_F(DEBUG, ctx, "transfer start: [%d<->%d]", acc_fd, dial_fd);
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
	FW_CTX_LOG_F(DEBUG, ctx, "ready, %zu active sessions", cur);
	gc_unref(&ctx->gcbase);
}

static void forward_ctx_start(
	struct ev_loop *loop, struct forward_ctx *restrict ctx,
	const struct dialreq *req)
{
	FW_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	ctx->s->stats.num_request++;
	dialer_do(&ctx->dialer, loop, req, ctx->s->conf, ctx->s->resolver);
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
		ctx->s->stats.num_reject_ruleset++;
		gc_unref(&ctx->gcbase);
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
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	ASSERT(ruleset != NULL);
	const struct dialreq *restrict req = ctx->s->basereq;
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
		gc_unref(&ctx->gcbase);
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

	ev_timer_init(&ctx->w_timeout, timeout_cb, s->conf->timeout, 0.0);
	ctx->w_timeout.data = ctx;
#if WITH_RULESET
	ev_idle_init(&ctx->w_process, NULL);
	ctx->w_process.data = ctx;
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
	gc_register(&ctx->gcbase, forward_ctx_finalize);
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
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	ctx->accepted_ns = clock_monotonic_ns();

	ctx->state = STATE_PROCESS;
	ev_timer_start(loop, &ctx->w_timeout);
	ctx->s->stats.num_halfopen++;

#if WITH_RULESET
	const struct ruleset *ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		ev_set_cb(&ctx->w_process, forward_process_cb);
		ev_set_cb(&ctx->ruleset_callback.w_finish, ruleset_cb);
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif
	const struct dialreq *req = ctx->s->basereq;
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
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	ASSERT(ruleset != NULL);

	union sockaddr_max dest;
	socklen_t len = sizeof(dest);
	if (getsockname(ctx->accepted_fd, &dest.sa, &len) != 0) {
		const int err = errno;
		FW_CTX_LOG_F(
			ERROR, ctx, "getsockname: (%d) %s", err, strerror(err));
		gc_unref(&ctx->gcbase);
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
		gc_unref(&ctx->gcbase);
		return;
	}

	char addr_str[64];
	sa_format(addr_str, sizeof(addr_str), &dest.sa);
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
		gc_unref(&ctx->gcbase);
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
			ERROR, ctx, "getsockname: (%d) %s", err, strerror(err));
		return NULL;
	}
	struct dialreq *req = dialreq_new(ctx->s->basereq, 0);
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
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);
	ctx->accepted_ns = clock_monotonic_ns();

	ctx->state = STATE_PROCESS;
	ev_timer_start(loop, &ctx->w_timeout);
	ctx->s->stats.num_halfopen++;

#if WITH_RULESET
	const struct ruleset *ruleset = ctx->s->ruleset;
	if (ruleset != NULL) {
		ev_set_cb(&ctx->w_process, tproxy_process_cb);
		ev_set_cb(&ctx->ruleset_callback.w_finish, ruleset_cb);
		ev_idle_start(loop, &ctx->w_process);
		return;
	}
#endif

	struct dialreq *req = tproxy_makereq(ctx);
	if (req == NULL) {
		gc_unref(&ctx->gcbase);
		return;
	}
	ctx->dialreq = req;
	forward_ctx_start(loop, ctx, req);
}
#endif /* WITH_TPROXY */
