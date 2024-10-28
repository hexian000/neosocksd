/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
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
		LOG_F(level, "client `%s': " format, caddr, __VA_ARGS__);      \
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
	case STATE_CONNECT:
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
	default:
		FAIL();
	}
	FW_CTX_LOG_F(DEBUG, ctx, "closed, %zu active", stats->num_sessions);
}

static void
forward_ctx_close(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	FW_CTX_LOG_F(
		VERBOSE, ctx, "close fd=%d state=%d", ctx->accepted_fd,
		ctx->state);
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
		&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd,
		&stats->byt_up);
	transfer_init(
		&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd,
		&stats->byt_down);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
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

	{
		struct ev_timer *restrict w_timeout = &ctx->w_timeout;
		ev_timer_init(w_timeout, timeout_cb, G.conf->timeout, 0.0);
		w_timeout->data = ctx;
	}

	const struct event_cb cb = {
		.func = dialer_cb,
		.data = ctx,
	};
	ctx->dialreq = NULL;
	dialer_init(&ctx->dialer, cb);
	ctx->ss.close = forward_ss_close;
	session_add(&ctx->ss);
	return ctx;
}

static void forward_ctx_start(
	struct ev_loop *loop, struct forward_ctx *restrict ctx,
	struct dialreq *req)
{
	dialer_start(&ctx->dialer, loop, req);
	ev_timer_start(loop, &ctx->w_timeout);

	FW_CTX_LOG(VERBOSE, ctx, "connect");
	ctx->state = STATE_CONNECT;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_request++;
	stats->num_halfopen++;
}

#if WITH_RULESET
static struct dialreq *
forward_route(struct ruleset *r, const struct dialaddr *restrict addr)
{
	const size_t cap =
		addr->type == ATYP_DOMAIN ? addr->domain.len + 7 : 64;
	char request[cap];
	const int len = dialaddr_format(request, cap, addr);
	CHECK(len >= 0 && (size_t)len < cap);
	switch (addr->type) {
	case ATYP_INET:
		return ruleset_route(r, request, NULL, NULL);
	case ATYP_INET6:
		return ruleset_route6(r, request, NULL, NULL);
	case ATYP_DOMAIN:
		return ruleset_resolve(r, request, NULL, NULL);
	}
	FAIL();
}
#endif

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
	struct dialreq *req = G.basereq;
#if WITH_RULESET
	struct ruleset *r = G.ruleset;
	if (r != NULL) {
		req = forward_route(r, &req->addr);
		if (req == NULL) {
			forward_ctx_close(loop, ctx);
			return;
		}
		/* need to be freed */
		ctx->dialreq = req;
	}
#endif
	forward_ctx_start(loop, ctx, req);
}

#if WITH_TPROXY

#if WITH_RULESET
static struct dialreq *
tproxy_route(struct ruleset *r, const struct sockaddr *restrict sa)
{
	char addr_str[64];
	format_sa(addr_str, sizeof(addr_str), sa);
	switch (sa->sa_family) {
	case AF_INET:
		return ruleset_route(r, addr_str, NULL, NULL);
	case AF_INET6:
		return ruleset_route6(r, addr_str, NULL, NULL);
	}
	FAIL();
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

#if WITH_RULESET
	struct ruleset *r = G.ruleset;
	if (r != NULL) {
		return tproxy_route(r, &dest.sa);
	}
#endif

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
	struct dialreq *req = tproxy_makereq(ctx);
	if (req == NULL) {
		forward_ctx_close(loop, ctx);
		return;
	}
	/* need to be freed */
	ctx->dialreq = req;
	forward_ctx_start(loop, ctx, req);
}
#endif /* WITH_TPROXY */
