/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "forward.h"
#include "conf.h"
#include "server.h"
#include "dialer.h"
#include "sockutil.h"
#include "transfer.h"
#include "util.h"
#include "utils/check.h"
#include "utils/slog.h"

#include <ev.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum forward_state {
	STATE_INIT,
	STATE_CONNECT,
	STATE_CONNECTED,
	STATE_ESTABLISHED,
};

struct forward_ctx {
	struct server *s;
	int accepted_fd, dialed_fd;
	enum forward_state state;
	sockaddr_max_t accepted_sa;
	struct ev_timer w_timeout;
	union {
		/* connecting */
		struct {
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
		dialer_stop(&ctx->dialer, loop);
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
	FW_CTX_LOG_F(
		LOG_LEVEL_INFO, ctx, "closed, %zu active", stats->num_sessions);
}

static void forward_ctx_free(struct forward_ctx *restrict ctx)
{
	if (ctx == NULL) {
		return;
	}
	if (ctx->accepted_fd != -1) {
		(void)close(ctx->accepted_fd);
		ctx->accepted_fd = -1;
	}
	if (ctx->dialed_fd != -1) {
		(void)close(ctx->dialed_fd);
		ctx->dialed_fd = -1;
	}
	free(ctx);
}

static void
forward_ctx_close(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	FW_CTX_LOG_F(
		LOG_LEVEL_DEBUG, ctx, "close fd=%d state=%d", ctx->accepted_fd,
		ctx->state);
	forward_ctx_stop(loop, ctx);
	forward_ctx_free(ctx);
}

static void xfer_state_cb(struct ev_loop *loop, void *data)
{
	struct forward_ctx *restrict ctx = data;
	assert(ctx->state == STATE_CONNECTED ||
	       ctx->state == STATE_ESTABLISHED);

	if (ctx->uplink.state == XFER_CLOSED ||
	    ctx->downlink.state == XFER_CLOSED) {
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
			LOG_LEVEL_INFO, ctx, "established, %zu active",
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
		FW_CTX_LOG(LOG_LEVEL_WARNING, ctx, "connection timeout");
		break;
	case STATE_CONNECTED:
		FW_CTX_LOG(LOG_LEVEL_WARNING, ctx, "handshake timeout");
		break;
	case STATE_ESTABLISHED:
		return;
	default:
		FAIL();
	}
	forward_ctx_close(loop, ctx);
}

static void connected_cb(struct ev_loop *loop, void *data)
{
	struct forward_ctx *restrict ctx = data;
	assert(ctx->state == STATE_CONNECT);

	const int fd = dialer_get(&ctx->dialer);
	if (fd < 0) {
		FW_CTX_LOG_F(
			LOG_LEVEL_ERROR, ctx, "dialer: %s",
			dialer_strerror(&ctx->dialer));
		forward_ctx_free(ctx);
		return;
	}
	ctx->dialed_fd = fd;

	FW_CTX_LOG(LOG_LEVEL_DEBUG, ctx, "connected");

	const struct config *restrict conf = ctx->s->conf;
	struct server_stats *restrict stats = &ctx->s->stats;
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	if (conf->proto_timeout) {
		ctx->state = STATE_CONNECTED;
		ev_timer_start(loop, w_timeout);
	} else {
		ctx->state = STATE_ESTABLISHED;
		stats->num_halfopen--;
		stats->num_sessions++;
		stats->num_success++;
		FW_CTX_LOG_F(
			LOG_LEVEL_INFO, ctx, "established, %zu active",
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

	const struct config *restrict conf = s->conf;

	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_init(w_timeout, timeout_cb, conf->timeout, 0.0);
	w_timeout->data = ctx;

	dialer_init(
		&ctx->dialer, conf,
		&(struct event_cb){
			.ctx = ctx,
			.cb = connected_cb,
		});
	return ctx;
}

static void forward_ctx_start(
	struct ev_loop *loop, struct forward_ctx *restrict ctx,
	const struct config *restrict conf)
{
	struct dialaddr addr;
	if (conf->forward != NULL) {
		if (!dialaddr_set(&addr, conf->forward, strlen(conf->forward))) {
			forward_ctx_close(loop, ctx);
			return;
		}
#if WITH_TPROXY
	} else if (conf->transparent) {
		sockaddr_max_t dest;
		socklen_t len = sizeof(dest);
		if (getsockname(ctx->accepted_fd, &dest.sa, &len) != 0) {
			const int err = errno;
			FW_CTX_LOG_F(
				LOG_LEVEL_ERROR, ctx, "getsockname: %s",
				strerror(err));
			forward_ctx_close(loop, ctx);
			return;
		}
		switch (dest.sa.sa_family) {
		case AF_INET:
			assert(len == sizeof(struct sockaddr_in));
			addr = (struct dialaddr){
				.type = ATYP_INET,
				.in = dest.in.sin_addr,
				.port = ntohs(dest.in.sin_port),
			};
			break;
		case AF_INET6:
			assert(len == sizeof(struct sockaddr_in6));
			addr = (struct dialaddr){
				.type = ATYP_INET6,
				.in6 = dest.in6.sin6_addr,
				.port = ntohs(dest.in6.sin6_port),
			};
			break;
		default:
			FW_CTX_LOG_F(
				LOG_LEVEL_ERROR, ctx,
				"getsockname: unknown af %jd",
				(intmax_t)dest.sa.sa_family);
			forward_ctx_close(loop, ctx);
			return;
		}
#endif
	} else {
		FAIL();
	}

	struct dialreq *req = dialreq_new(&addr, 0);
	if (req == NULL) {
		LOGOOM();
		forward_ctx_close(loop, ctx);
		return;
	}

	if (!dialer_start(&ctx->dialer, loop, req)) {
		forward_ctx_close(loop, ctx);
		return;
	}

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
		(void)close(accepted_fd);
		return;
	}
	(void)memcpy(
		&ctx->accepted_sa.sa, accepted_sa, getsocklen(accepted_sa));
	forward_ctx_start(loop, ctx, s->conf);
}
