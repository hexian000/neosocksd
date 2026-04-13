/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "conf.h"
#include "util.h"

#include "math/rand.h"
#include "os/clock.h"
#include "os/socket.h"
#include "utils/slog.h"

#include <ev.h>
#include <sys/socket.h>

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool is_startup_limited(const struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
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

static void accept_cb(
	struct ev_loop *restrict loop, ev_io *restrict watcher,
	const int revents)
{
	CHECK_REVENTS(revents, EV_READ);

	struct listener *restrict l = watcher->data;
	struct server *restrict s = l->server;
	const struct config *restrict conf = s->conf;

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
			LOGE_F("accept: (%d) %s", err, strerror(err));
			/* Sleep until next timer, see timer_cb */
			ev_io_stop(loop, watcher);
			ev_timer_start(loop, &l->w_timer);
			return;
		}

		l->stats.num_accept++;

		if (LOGLEVEL(VERYVERBOSE)) {
			char addr_str[64];
			sa_format(addr_str, sizeof(addr_str), &addr.sa);
			LOG_F(VERYVERBOSE, "accepted from [fd:%d]: [fd:%d] %s",
			      watcher->fd, fd, addr_str);
		}

		/* Apply rate limiting and connection throttling */
		if (is_startup_limited(s)) {
			CLOSE_FD(fd);
			return;
		}

		/* Configure the accepted socket */
		if (!socket_set_nonblock(fd)) {
			const int err = errno;
			LOGE_F("fcntl: (%d) %s", err, strerror(err));
			CLOSE_FD(fd);
			return;
		}
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		l->stats.num_serve++;
		/* Delegate to listener-specific serve function */
		l->serve(s, loop, fd, (const struct sockaddr *)&addr.sa);
	}
}

/* This callback is used to restart the accept I/O watcher after a temporary error condition. */
static void
timer_cb(struct ev_loop *restrict loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct listener *restrict l = watcher->data;
	ev_io_start(loop, &l->w_accept);
}

void server_init(struct server *restrict s, struct ev_loop *loop)
{
	*s = (struct server){
		.loop = loop,
		.stats = { .started = -1 },
	};
}

bool server_add_listener(
	struct server *restrict s, const struct sockaddr *restrict bindaddr,
	serve_fn serve)
{
	/* Check if server is full */
	if (s->num_listeners >= SERVER_LISTENERS_MAX) {
		LOGE_F("cannot add listener: max %d listeners reached",
		       SERVER_LISTENERS_MAX);
		return false;
	}

	/* Create TCP socket */
	const int fd = socket(bindaddr->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: (%d) %s", err, strerror(err));
		return false;
	}

	/* Set socket to non-blocking mode */
	if (!socket_set_nonblock(fd)) {
		const int err = errno;
		LOGE_F("fcntl: (%d) %s", err, strerror(err));
		CLOSE_FD(fd);
		return false;
	}

	const struct config *restrict conf = s->conf;

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
		sa_format(addr_str, sizeof(addr_str), bindaddr);
		LOG_F(NOTICE, "listen: %s", addr_str);
	}

	/* Bind socket to address */
	if (bind(fd, bindaddr, sa_len(bindaddr)) != 0) {
		const int err = errno;
		LOGE_F("bind: (%d) %s", err, strerror(err));
		CLOSE_FD(fd);
		return false;
	}

	/* Start listening for connections */
	if (listen(fd, backlog)) {
		const int err = errno;
		LOGE_F("listen: (%d) %s", err, strerror(err));
		CLOSE_FD(fd);
		return false;
	}

	/* Get the next available listener slot */
	struct listener *restrict l = &s->listeners[s->num_listeners];
	l->server = s;
	l->serve = serve;

	/* Initialize libev watchers */
	ev_io_init(&l->w_accept, accept_cb, fd, EV_READ);
	l->w_accept.data = l;
	ev_timer_init(&l->w_timer, timer_cb, 0.5, 0.0);
	l->w_timer.data = l;

	/* Start the listener and record start time if this is the first one */
	struct ev_loop *loop = s->loop;
	if (s->num_listeners == 0) {
		s->stats.started = clock_monotonic_ns();
	}
	ev_io_start(loop, &l->w_accept);
	s->num_listeners++;
	return true;
}

void server_stop(struct server *restrict s)
{
	/* Check if server is running */
	if (s->stats.started == -1) {
		return; /* Server not running */
	}

	struct ev_loop *loop = s->loop;

	/* Stop all listeners */
	for (size_t i = 0; i < s->num_listeners; i++) {
		struct listener *restrict l = &s->listeners[i];

		/* Stop accept watcher and close listening socket */
		ev_io_stop(loop, &l->w_accept);
		CLOSE_FD(l->w_accept.fd);

		/* Stop timer watcher */
		ev_timer_stop(loop, &l->w_timer);
	}

	/* Mark server as stopped only after all listeners are down */
	s->stats.started = -1;
}

void server_stats(
	const struct server *restrict s, struct server_stats *restrict out)
{
	*out = s->stats;
	out->num_accept = 0;
	out->num_serve = 0;
	for (size_t i = 0; i < s->num_listeners; i++) {
		const struct listener_stats *restrict lst =
			&s->listeners[i].stats;
		out->num_accept += lst->num_accept;
		out->num_serve += lst->num_serve;
	}
}
