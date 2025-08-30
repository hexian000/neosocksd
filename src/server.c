/* neosocksd (c) 2023-2025 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "conf.h"
#include "sockutil.h"
#include "util.h"

#include "math/rand.h"
#include "utils/slog.h"

#include <ev.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool is_startup_limited(const struct server *restrict s)
{
	const struct config *restrict conf = G.conf;
	const struct server_stats *restrict stats = &s->stats;

	/* Check maximum session limit */
	if (conf->max_sessions > 0 &&
	    stats->num_sessions > (size_t)conf->max_sessions) {
		LOGVV("session limit exceeded, rejecting new connection");
		return true;
	}

	/* Check full startup limit */
	if (conf->startup_limit_full > 0 &&
	    stats->num_halfopen > (size_t)conf->startup_limit_full) {
		LOGVV("full startup limit exceeded, rejecting new connection");
		return true;
	}

	/* Check probabilistic startup limit */
	if (conf->startup_limit_start > 0 &&
	    stats->num_halfopen > (size_t)conf->startup_limit_start) {
		if (frand() < conf->startup_limit_rate) {
			LOGVV("startup limit reached, rejecting new connection");
			return true;
		}
	}
	return false;
}

static void
accept_cb(struct ev_loop *loop, ev_io *restrict watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct server *restrict s = watcher->data;
	const struct config *restrict conf = G.conf;
	struct listener_stats *restrict lstats = &s->l.stats;

	/* Accept connections in a loop until no more are available */
	for (;;) {
		union sockaddr_max addr;
		socklen_t addrlen = sizeof(addr);
		const int fd = accept(watcher->fd, &addr.sa, &addrlen);
		if (fd < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break; /* No more connections to accept */
			}
			LOGE_F("accept: %s", strerror(err));
			/* Sleep until next timer, see timer_cb */
			ev_io_stop(loop, watcher);
			ev_timer_start(loop, &s->l.w_timer);
			return;
		}

		lstats->num_accept++;

		/* Log accepted connection if verbose logging is enabled */
		if (LOGLEVEL(VERBOSE)) {
			char addr_str[64];
			format_sa(addr_str, sizeof(addr_str), &addr.sa);
			LOG_F(VERBOSE, "accept from listener %d: [%d] %s",
			      watcher->fd, fd, addr_str);
		}

		/* Apply rate limiting and connection throttling */
		if (is_startup_limited(s)) {
			CLOSE_FD(fd);
			return;
		}

		/* Configure the accepted socket */
		if (!socket_set_nonblock(fd)) {
			LOGE_F("fcntl: %s", strerror(errno));
			CLOSE_FD(fd);
			return;
		}
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		lstats->num_serve++;
		/* Delegate to user-defined serve function */
		s->serve(s, loop, fd, &addr.sa);
	}
}

/* This callback is used to restart the accept I/O watcher after a temporary error condition. */
static void timer_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct listener *restrict l = watcher->data;
	ev_io_start(loop, &l->w_accept);
}

void server_init(
	struct server *restrict s, struct ev_loop *loop, const serve_fn serve,
	void *data)
{
	*s = (struct server){
		.loop = loop,
		.serve = serve,
		.data = data,
		.stats = { .started = -1 },
	};
}

bool server_start(
	struct server *restrict s, const struct sockaddr *restrict bindaddr)
{
	/* Create TCP socket */
	const int fd = socket(bindaddr->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		LOGE_F("socket: %s", strerror(errno));
		return false;
	}

	/* Set socket to non-blocking mode */
	if (!socket_set_nonblock(fd)) {
		LOGE_F("fcntl: %s", strerror(errno));
		CLOSE_FD(fd);
		return false;
	}

	const struct config *restrict conf = G.conf;

	/* Apply socket options based on configuration */
#if WITH_REUSEPORT
	socket_set_reuseport(fd, conf->reuseport);
#else
	socket_set_reuseport(fd, false);
#endif
#if WITH_TPROXY
	if (conf->transparent) {
		socket_set_transparent(fd, true);
	}
#endif
	const int backlog = SOMAXCONN;
#if WITH_TCP_FASTOPEN
	if (conf->tcp_fastopen) {
		socket_set_fastopen(fd, backlog);
	}
#endif
	socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
	socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

	/* Log bind address if notice logging is enabled */
	if (LOGLEVEL(NOTICE)) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), bindaddr);
		LOG_F(NOTICE, "listen: %s", addr_str);
	}

	/* Bind socket to address */
	if (bind(fd, bindaddr, getsocklen(bindaddr)) != 0) {
		LOGE_F("bind error: %s", strerror(errno));
		CLOSE_FD(fd);
		return false;
	}

	/* Start listening for connections */
	if (listen(fd, backlog)) {
		LOGE_F("listen error: %s", strerror(errno));
		CLOSE_FD(fd);
		return false;
	}

	/* Initialize libev watchers */
	ev_io *restrict w_accept = &s->l.w_accept;
	ev_io_init(w_accept, accept_cb, fd, EV_READ);
	w_accept->data = s;
	ev_timer *restrict w_timer = &s->l.w_timer;
	ev_timer_init(w_timer, timer_cb, 0.5, 0.0);
	w_timer->data = s;

	/* Start the server and record start time */
	struct ev_loop *loop = s->loop;
	s->stats.started = clock_monotonic();
	ev_io_start(loop, w_accept);
	return true;
}

void server_stop(struct server *restrict s)
{
	/* Check if server is running */
	if (s->stats.started == -1) {
		return; /* Server not running */
	}

	struct ev_loop *loop = s->loop;

	/* Stop accept watcher and close listening socket */
	ev_io *restrict w_accept = &s->l.w_accept;
	ev_io_stop(loop, w_accept);
	CLOSE_FD(w_accept->fd);

	/* Stop timer watcher */
	ev_timer *restrict w_timer = &s->l.w_timer;
	ev_timer_stop(loop, w_timer);

	/* Mark server as stopped */
	s->stats.started = -1;
}
