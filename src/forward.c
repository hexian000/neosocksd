/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "forward.h"

#include "conf.h"
#include "dialer.h"
#include "proto/domain.h"
#include "ruleset/ruleset.h"
#include "server.h"
#include "transfer.h"
#include "util.h"

#include "meta/class.h"
#include "os/socket.h"
#include "utils/debug.h"
#include "utils/gc.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <netinet/in.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

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

/* Log with an explicit fd for the correlation prefix, for the hand-off path
 * that has already moved the accepted fd out of the context. */
#define FW_FD_LOG_F(level, ctx, fd, format, ...)                               \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char caddr[64];                                                \
		sa_format(caddr, sizeof(caddr), &(ctx)->accepted_sa.sa);       \
		LOG_F(level, "[fd:%d] %s: " format, (fd), caddr, __VA_ARGS__); \
	} while (0)
#define FW_CTX_LOG_F(level, ctx, format, ...)                                  \
	FW_FD_LOG_F(level, ctx, (ctx)->accepted_fd, format, __VA_ARGS__)
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
		socket_close(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		socket_close(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}

	if (ctx->state < STATE_BIDIRECTIONAL) {
		dialreq_free(ctx->dialreq);
	}
}

static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	(void)loop;
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

/* start the transfer between the client and @p fd; takes ownership of @p fd */
static void forward_commit(
	struct ev_loop *loop, struct forward_ctx *restrict ctx, const int fd)
{
	ctx->dialed_fd = fd;

	FW_CTX_LOG_F(VERBOSE, ctx, "connected, [fd:%d]", fd);
	/* cleanup before state change */
	dialreq_free(ctx->dialreq);
	ctx->dialreq = NULL;

	const int acc_fd = ctx->accepted_fd, dial_fd = ctx->dialed_fd;
	ctx->accepted_fd = ctx->dialed_fd = -1;
	/* Set state before transfer_start — ctx_stop is a no-op if gc_unref fires below. */
	ctx->state = STATE_BIDIRECTIONAL;
	ev_timer_stop(loop, &ctx->w_timeout);
	ctx->s->stats.num_halfopen--;

	FW_FD_LOG_F(
		DEBUG, ctx, acc_fd, "transfer start: [%d<->%d]", acc_fd,
		dial_fd);
	const size_t cur = server_start_session(ctx->s, acc_fd, dial_fd);
	if (cur == 0) {
		LOGOOM();
		socket_close(acc_fd);
		socket_close(dial_fd);
		gc_unref(&ctx->gcbase);
		return;
	}
	FW_FD_LOG_F(DEBUG, ctx, acc_fd, "ready, %zu active sessions", cur);
	gc_unref(&ctx->gcbase);
}

#if WITH_RULESET
/* await.forward() commit hook */
static void forward_forward_commit(
	struct ev_loop *loop, struct ruleset_callback *restrict cb,
	const int fd)
{
	struct forward_ctx *restrict ctx = cb->w_finish.data;
	ASSERT(ctx->state == STATE_PROCESS);
	ctx->ruleset_state = NULL;
	forward_commit(loop, ctx, fd);
}
#endif /* WITH_RULESET */

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
	forward_commit(loop, ctx, fd);
}

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
	ctx->ruleset_callback.forward = forward_forward_commit;
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
	gc_register(&ctx->gcbase, forward_ctx_finalize);
	return ctx;
}

/* Create a context for a newly accepted connection, copy the peer address, and
 * enter STATE_PROCESS with the half-open accounting started. Returns NULL (and
 * closes accepted_fd) on OOM. Shared by forward_serve and tproxy_serve. */
static struct forward_ctx *forward_ctx_accept(
	struct server *restrict s, struct ev_loop *restrict loop,
	const int accepted_fd, const struct sockaddr *restrict accepted_sa)
{
	struct forward_ctx *restrict ctx = forward_ctx_new(s, accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		socket_close(accepted_fd);
		return NULL;
	}
	sa_copy(&ctx->accepted_sa.sa, accepted_sa);

	ctx->state = STATE_PROCESS;
	ev_timer_start(loop, &ctx->w_timeout);
	ctx->s->stats.num_halfopen++;
	ctx->s->stats.num_request++;
	return ctx;
}

static void forward_ctx_start(
	struct ev_loop *loop, struct forward_ctx *restrict ctx,
	const struct dialreq *req)
{
	FW_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	dialer_do(
		&ctx->dialer, loop, req, ctx->s->conf, ctx->s->resolver,
		ctx->s);
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
		/* the ruleset gave up: reject by policy */
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
	if (ruleset == NULL) {
		/* SIGHUP may have cleared s->ruleset between the
		 * forward_serve check and this callback. Fall back
		 * to the no-ruleset direct-dial path. */
		FW_CTX_LOG(VERBOSE, ctx, "ruleset gone, fallback to direct");
		forward_ctx_start(loop, ctx, ctx->s->basereq);
		return;
	}
	const struct dialreq *restrict req = ctx->s->basereq;
	const struct dialaddr *restrict addr = &req->addr;

	char request[DIALADDR_STRLEN + 1];
	const int len = dialaddr_format(request, sizeof(request), addr);
	CHECK(len >= 0 && (size_t)len < sizeof(request));
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
		ctx->s->stats.num_reject_ruleset++;
		gc_unref(&ctx->gcbase);
		return;
	}
}
#endif /* WITH_RULESET */

void forward_serve(
	struct server *restrict s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct forward_ctx *restrict ctx =
		forward_ctx_accept(s, loop, accepted_fd, accepted_sa);
	if (ctx == NULL) {
		return;
	}

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

/* Read the original destination address of the transparently-intercepted
 * connection into a zero-initialized *dest, logging on failure. */
static bool tproxy_getdest(
	const struct forward_ctx *restrict ctx,
	union sockaddr_max *restrict dest, socklen_t *restrict len)
{
	*dest = (union sockaddr_max){ 0 };
	*len = sizeof(*dest);
	if (getsockname(ctx->accepted_fd, &dest->sa, len) != 0) {
		const int err = errno;
		FW_CTX_LOG_F(
			ERROR, ctx, "getsockname: (%d) %s", err, strerror(err));
		return false;
	}
	return true;
}

#if WITH_RULESET
static void
tproxy_process_cb(struct ev_loop *loop, ev_idle *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_IDLE);
	ev_idle_stop(loop, watcher);
	struct forward_ctx *restrict ctx = watcher->data;
	struct ruleset *restrict ruleset = ctx->s->ruleset;
	if (ruleset == NULL) {
		/* SIGHUP may have cleared s->ruleset between the
		 * forward_serve check and this callback. TPROXY mode
		 * cannot proceed without a ruleset. */
		FW_CTX_LOG(ERROR, ctx, "ruleset gone, cannot route tproxy");
		ctx->s->stats.num_reject_ruleset++;
		gc_unref(&ctx->gcbase);
		return;
	}

	union sockaddr_max dest;
	socklen_t len;
	if (!tproxy_getdest(ctx, &dest, &len)) {
		gc_unref(&ctx->gcbase);
		return;
	}

	char addr_str[64];
	sa_format(addr_str, sizeof(addr_str), &dest.sa);
	bool ok;
	switch (dest.sa.sa_family) {
	case AF_INET:
		CHECK(len >= sizeof(struct sockaddr_in));
		ok = ruleset_route(
			ruleset, &ctx->ruleset_state, addr_str, NULL, NULL,
			&ctx->ruleset_callback);
		break;
	case AF_INET6:
		CHECK(len >= sizeof(struct sockaddr_in6));
		ok = ruleset_route6(
			ruleset, &ctx->ruleset_state, addr_str, NULL, NULL,
			&ctx->ruleset_callback);
		break;
	default:
		FW_CTX_LOG_F(
			ERROR, ctx, "tproxy: unsupported af:%u",
			(unsigned int)dest.sa.sa_family);
		gc_unref(&ctx->gcbase);
		return;
	}
	if (!ok) {
		ctx->s->stats.num_reject_ruleset++;
		gc_unref(&ctx->gcbase);
		return;
	}
}
#endif /* WITH_RULESET */

static struct dialreq *tproxy_makereq(const struct forward_ctx *restrict ctx)
{
	union sockaddr_max dest;
	socklen_t len;
	if (!tproxy_getdest(ctx, &dest, &len)) {
		return NULL;
	}
	struct dialreq *req = dialreq_new(ctx->s->basereq, 0);
	if (req == NULL) {
		LOGOOM();
		return NULL;
	}
	if (!dialaddr_set(&req->addr, &dest.sa, len)) {
		FW_CTX_LOG_F(
			ERROR, ctx, "tproxy: unsupported af:%u",
			(unsigned int)dest.sa.sa_family);
		dialreq_free(req);
		return NULL;
	}
	return req;
}

void tproxy_serve(
	struct server *restrict s, struct ev_loop *loop, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	struct forward_ctx *restrict ctx =
		forward_ctx_accept(s, loop, accepted_fd, accepted_sa);
	if (ctx == NULL) {
		return;
	}

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
