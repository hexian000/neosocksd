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
	if (conf->max_sessions > 0 &&
	    stats->num_sessions > (size_t)conf->max_sessions) {
		LOGVV("session limit exceeded, rejecting new connection");
		return true;
	}
	if (conf->startup_limit_full > 0 &&
	    stats->num_halfopen > (size_t)conf->startup_limit_full) {
		LOGVV("full startup limit exceeded, rejecting new connection");
		return true;
	}
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

	for (;;) {
		union sockaddr_max addr;
		socklen_t addrlen = sizeof(addr);
		/* accept client request */
		const int fd = accept(watcher->fd, &addr.sa, &addrlen);
		if (fd < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("accept: %s", strerror(err));
			/* sleep until next timer, see timer_cb */
			ev_io_stop(loop, watcher);
			ev_timer_start(loop, &s->l.w_timer);
			return;
		}
		lstats->num_accept++;
		if (LOGLEVEL(VERBOSE)) {
			char addr_str[64];
			format_sa(addr_str, sizeof(addr_str), &addr.sa);
			LOG_F(VERBOSE, "accept from listener %d: [%d] %s",
			      watcher->fd, fd, addr_str);
		}
		if (is_startup_limited(s)) {
			CLOSE_FD(fd);
			return;
		}
		if (!socket_set_nonblock(fd)) {
			LOGE_F("fcntl: %s", strerror(errno));
			CLOSE_FD(fd);
			return;
		}
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		lstats->num_serve++;
		s->serve(s, loop, fd, &addr.sa);
	}
}

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
		.stats = { .started = TSTAMP_NIL },
	};
}

bool server_start(
	struct server *restrict s, const struct sockaddr *restrict bindaddr)
{
	const int fd = socket(bindaddr->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		LOGE_F("socket: %s", strerror(errno));
		return false;
	}
	if (!socket_set_nonblock(fd)) {
		LOGE_F("fcntl: %s", strerror(errno));
		CLOSE_FD(fd);
		return false;
	}

	const struct config *restrict conf = G.conf;
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
	if (LOGLEVEL(NOTICE)) {
		char addr_str[64];
		format_sa(addr_str, sizeof(addr_str), bindaddr);
		LOG_F(NOTICE, "listen: %s", addr_str);
	}
	if (bind(fd, bindaddr, getsocklen(bindaddr)) != 0) {
		LOGE_F("bind error: %s", strerror(errno));
		CLOSE_FD(fd);
		return false;
	}
	if (listen(fd, backlog)) {
		LOGE_F("listen error: %s", strerror(errno));
		CLOSE_FD(fd);
		return false;
	}

	ev_io *restrict w_accept = &s->l.w_accept;
	ev_io_init(w_accept, accept_cb, fd, EV_READ);
	w_accept->data = s;
	ev_timer *restrict w_timer = &s->l.w_timer;
	ev_timer_init(w_timer, timer_cb, 0.5, 0.0);
	w_timer->data = s;

	struct ev_loop *loop = s->loop;
	s->stats.started = ev_now(loop);
	ev_io_start(loop, w_accept);
	return true;
}

void server_stop(struct server *restrict s)
{
	if (s->stats.started == TSTAMP_NIL) {
		return;
	}
	struct ev_loop *loop = s->loop;
	ev_io *restrict w_accept = &s->l.w_accept;
	ev_io_stop(loop, w_accept);
	CLOSE_FD(w_accept->fd);
	ev_timer *restrict w_timer = &s->l.w_timer;
	ev_timer_stop(loop, w_timer);
	s->stats.started = TSTAMP_NIL;
}
