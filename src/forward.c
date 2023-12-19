/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "forward.h"
#include "session.h"
#include "utils/debug.h"
#include "utils/slog.h"
#include "utils/object.h"
#include "conf.h"
#include "util.h"
#include "server.h"
#include "dialer.h"
#include "sockutil.h"
#include "transfer.h"
#include "ruleset.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
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
	sockaddr_max_t accepted_sa;
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

#define FW_CTX_LOG_F(level, ctx, format, ...)                                  \
	do {                                                                   \
		if (!LOGLEVEL(level)) {                                        \
			break;                                                 \
		}                                                              \
		char laddr[64];                                                \
		format_sa(&(ctx)->accepted_sa.sa, laddr, sizeof(laddr));       \
		LOG_F(level, "\"%s\": " format, laddr, __VA_ARGS__);           \
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
	FW_CTX_LOG_F(INFO, ctx, "closed, %zu active", stats->num_sessions);
}

static void forward_ctx_free(struct forward_ctx *restrict ctx)
{
	if (ctx == NULL) {
		return;
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
forward_ctx_close(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	FW_CTX_LOG_F(
		DEBUG, ctx, "close fd=%d state=%d", ctx->accepted_fd,
		ctx->state);
	forward_ctx_stop(loop, ctx);
	forward_ctx_free(ctx);
}

static void
forward_ss_close(struct ev_loop *restrict loop, struct session *restrict ss)
{
	struct forward_ctx *restrict ctx =
		DOWNCAST(struct session, struct forward_ctx, ss, ss);
	forward_ctx_close(loop, ctx);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct forward_ctx *restrict ctx = data;
	assert(ctx->state == STATE_CONNECTED ||
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
		struct server_stats *restrict stats = &ctx->s->stats;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		FW_CTX_LOG_F(
			INFO, ctx, "established, %zu active",
			stats->num_sessions);
		ev_timer_stop(loop, &ctx->w_timeout);
		return;
	}
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
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
	assert(ctx->state == STATE_CONNECT);

	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		FW_CTX_LOG(DEBUG, ctx, "unable to establish client connection");
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialed_fd = fd;

	FW_CTX_LOG(DEBUG, ctx, "connected");
	/* cleanup before state change */
	dialreq_free(ctx->dialreq);

	struct server_stats *restrict stats = &ctx->s->stats;
	if (G.conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
	} else {
		ev_timer_stop(loop, &ctx->w_timeout);
		ctx->state = STATE_ESTABLISHED;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		FW_CTX_LOG_F(
			INFO, ctx, "established, %zu active",
			stats->num_sessions);
	}

	struct event_cb cb = {
		.cb = xfer_state_cb,
		.ctx = ctx,
	};
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
		ev_set_priority(w_timeout, EV_MINPRI);
		w_timeout->data = ctx;
	}

	struct event_cb cb = (struct event_cb){
		.cb = dialer_cb,
		.ctx = ctx,
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

	ctx->state = STATE_CONNECT;
	struct server_stats *restrict stats = &ctx->s->stats;
	stats->num_request++;
	stats->num_halfopen++;
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
	(void)memcpy(
		&ctx->accepted_sa.sa, accepted_sa, getsocklen(accepted_sa));
	forward_ctx_start(loop, ctx, G.basereq);
}

#if WITH_TPROXY
static struct dialreq *make_tproxy(struct forward_ctx *restrict ctx)
{
	sockaddr_max_t dest;
	socklen_t len = sizeof(dest);
	if (getsockname(ctx->accepted_fd, &dest.sa, &len) != 0) {
		const int err = errno;
		FW_CTX_LOG_F(ERROR, ctx, "getsockname: %s", strerror(err));
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
	if (G.ruleset != NULL) {
		char addr_str[64];
		format_sa(&dest.sa, addr_str, sizeof(addr_str));
		switch (dest.sa.sa_family) {
		case AF_INET:
			return ruleset_route(G.ruleset, addr_str);
		case AF_INET6:
			return ruleset_route6(G.ruleset, addr_str);
		}
		return NULL;
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
	(void)memcpy(
		&ctx->accepted_sa.sa, accepted_sa, getsocklen(accepted_sa));
	struct dialreq *req = make_tproxy(ctx);
	if (req == NULL) {
		forward_ctx_close(loop, ctx);
		return;
	}
	ctx->dialreq = req;
	forward_ctx_start(loop, ctx, req);
}
#endif /* WITH_TPROXY */
