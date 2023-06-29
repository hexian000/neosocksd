/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "forward.h"
#include "net/addr.h"
#include "utils/check.h"
#include "utils/slog.h"
#include "transfer.h"
#include "resolver.h"
#include "util.h"

#include <ev.h>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

static struct stats stats = { 0 };

struct forward_ctx {
	int accepted_fd, dialed_fd;
	bool is_connected;
	union {
		/* connecting */
		struct {
			struct ev_timer w_timeout;
			struct ev_io w_connect;
		};
		/* connected */
		struct {
			struct transfer uplink, downlink;
		};
	};
};

static void forward_stop(struct ev_loop *loop, struct forward_ctx *restrict ctx)
{
	if (!ctx->is_connected) {
		ev_timer_stop(loop, &ctx->w_timeout);
		ev_io_stop(loop, &ctx->w_connect);
		stats.num_halfopen--;
	} else {
		transfer_stop(loop, &ctx->uplink);
		transfer_stop(loop, &ctx->downlink);
	}
}

static void forward_free(struct forward_ctx *restrict ctx)
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

static void forward_close_cb(struct ev_loop *loop, void *ctx)
{
	forward_stop(loop, ctx);
	forward_free(ctx);
}

static void
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_timer_stop(loop, watcher);

	struct forward_ctx *restrict ctx = watcher->data;
	if (ctx->uplink.state < XFER_CONNECTED ||
	    ctx->downlink.state < XFER_CONNECTED) {
		LOGW("connection timeout");
		forward_stop(loop, ctx);
		forward_free(ctx);
		return;
	}
}

static void
connected_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_io_stop(loop, watcher);

	struct forward_ctx *restrict ctx = watcher->data;
	ev_timer_stop(loop, &ctx->w_timeout);

	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char laddr[64], raddr[64];
		sockaddr_max_t addr;
		socklen_t salen = sizeof(addr);
		if (getpeername(ctx->accepted_fd, &addr.sa, &salen) != 0) {
			const int err = errno;
			LOGE_F("getpeername: %s", strerror(err));
			(void)strcpy(laddr, "???");
		} else {
			format_sa(&addr.sa, laddr, sizeof(laddr));
		}
		salen = sizeof(addr);
		if (getpeername(ctx->dialed_fd, &addr.sa, &salen) != 0) {
			const int err = errno;
			LOGE_F("getpeername: %s", strerror(err));
			(void)strcpy(raddr, "???");
		} else {
			format_sa(&addr.sa, raddr, sizeof(raddr));
		}
		LOGI_F("forward: %s <-> %s", laddr, raddr);
	}

	ctx->is_connected = true;
	stats.num_halfopen--;
	struct event_cb cb = {
		.cb = forward_close_cb,
		.ctx = ctx,
	};
	transfer_init(&ctx->uplink, cb, ctx->accepted_fd, ctx->dialed_fd);
	transfer_init(&ctx->downlink, cb, ctx->dialed_fd, ctx->accepted_fd);
	transfer_start(loop, &ctx->uplink);
	transfer_start(loop, &ctx->downlink);
}

static struct forward_ctx *forward_new(const int accepted_fd)
{
	struct forward_ctx *restrict ctx = malloc(sizeof(struct forward_ctx));
	if (ctx == NULL) {
		return NULL;
	}
	ctx->is_connected = false;
	ctx->accepted_fd = accepted_fd;
	ctx->dialed_fd = -1;
	return ctx;
}

static bool
resolve(struct sockaddr *sa, socklen_t *len, const char *endpoint,
	const int family)
{
	const size_t addrlen = strlen(endpoint);
	char buf[FQDN_MAX_LENGTH + 1 + 5 + 1];
	if (addrlen >= sizeof(buf)) {
		return false;
	}
	memcpy(buf, endpoint, addrlen);
	buf[addrlen] = '\0';
	char *hostname, *service;
	if (!splithostport(buf, &hostname, &service)) {
		return false;
	}
	struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG,
	};
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(hostname, service, &hints, &result);
	if (err != 0) {
		LOGE_F("resolve: %s", gai_strerror(err));
		return false;
	}
	bool ok = false;
	for (const struct addrinfo *it = result; it; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
		case AF_INET6:
			break;
		default:
			continue;
		}
		memcpy(sa, it->ai_addr, it->ai_addrlen);
		*len = it->ai_addrlen;
		ok = true;
		break;
	}
	freeaddrinfo(result);
	return ok;
}

static void forward_start(
	struct ev_loop *loop, struct forward_ctx *restrict ctx,
	const struct config *restrict conf)
{
	stats.num_request++;

	sockaddr_max_t addr;
	socklen_t len = sizeof(addr);
	if (conf->forward != NULL) {
		if (!resolve(&addr.sa, &len, conf->forward, conf->resolve_pf)) {
			LOGE_F("failed resolving address: \"%s\"",
			       conf->forward);
			forward_stop(loop, ctx);
			forward_free(ctx);
			return;
		}
#if WITH_TPROXY
	} else if (conf->transparent) {
		if (getsockname(ctx->accepted_fd, &addr.sa, &len) != 0) {
			const int err = errno;
			LOGE_F("getsockname: %s", strerror(err));
			forward_stop(loop, ctx);
			forward_free(ctx);
			return;
		}
#endif
	} else {
		FAIL();
	}
	const int domain = addr.sa.sa_family;
	const int dialed_fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);
	if (dialed_fd < 0) {
		const int err = errno;
		LOGE_F("socket: %s", strerror(err));
		forward_stop(loop, ctx);
		forward_free(ctx);
		return;
	}
	ctx->dialed_fd = dialed_fd;
	if (!socket_set_nonblock(dialed_fd)) {
		const int err = errno;
		LOGE_F("fcntl: %s", strerror(err));
		forward_stop(loop, ctx);
		forward_free(ctx);
		return;
	}
	socket_set_tcp(dialed_fd, true, false);

	if (connect(dialed_fd, &addr.sa, getsocklen(&addr.sa)) != 0) {
		const int err = errno;
		if (err != EINTR && err != EINPROGRESS) {
			LOGE_F("connect: %s", strerror(err));
			forward_stop(loop, ctx);
			forward_free(ctx);
			return;
		}
	}
	if (LOGLEVEL(LOG_LEVEL_VERBOSE)) {
		char addr_str[64];
		format_sa(&addr.sa, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_VERBOSE, "connect: fd=%d to \"%s\"", dialed_fd,
		      addr_str);
	}

	struct ev_io *restrict w_connect = &ctx->w_connect;
	ev_io_init(w_connect, connected_cb, dialed_fd, EV_WRITE);
	w_connect->data = ctx;
	ev_io_start(loop, w_connect);
	struct ev_timer *restrict w_timeout = &ctx->w_timeout;
	ev_timer_init(w_timeout, timeout_cb, conf->timeout, 0.0);
	w_timeout->data = ctx;
	ev_timer_start(loop, w_timeout);

	stats.num_halfopen++;
}

void forward_serve(
	struct ev_loop *loop, struct server *s, const int accepted_fd,
	const struct sockaddr *accepted_sa)
{
	UNUSED(accepted_sa);
	const struct config *restrict conf = s->conf;
	struct forward_ctx *restrict ctx = forward_new(accepted_fd);
	if (ctx == NULL) {
		LOGOOM();
		(void)close(accepted_fd);
		return;
	}
	forward_start(loop, ctx, conf);
}

void forward_read_stats(struct stats *restrict out_stats)
{
	*out_stats = stats;
}
