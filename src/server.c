/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"
#include "algo/rand.h"
#include "utils/slog.h"
#include "conf.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

static bool is_startup_limited(struct listener *restrict l)
{
	const struct config *restrict conf = l->s->conf;
	const struct server_stats *restrict stats = l->s->stats;
	if (conf->max_sessions > 0 &&
	    stats->num_sessions >= conf->max_sessions) {
		LOGV("session limit exceeded, rejecting new connection");
		return true;
	}
	if (stats->num_halfopen >= conf->startup_limit_full) {
		LOGV("full startup limit exceeded, rejecting new connection");
		return true;
	}
	if (stats->num_halfopen >= conf->startup_limit_start) {
		const double rate = (double)conf->startup_limit_rate / 100.0;
		if (frand() < rate) {
			LOGV("startup limit reached, rejecting new connection");
			return true;
		}
	}
	return false;
}

static void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct listener *restrict l = (struct listener *)watcher->data;
	struct server *restrict s = l->s;
	struct server_stats *restrict stats = s->stats;

	for (;;) {
		sockaddr_max_t m_sa;
		socklen_t sa_len = sizeof(m_sa);
		/* accept client request */
		const int fd = accept(watcher->fd, &m_sa.sa, &sa_len);
		if (fd < 0) {
			const int err = errno;
			if (IS_TRANSIENT_ERROR(err)) {
				break;
			}
			LOGE_F("accept: %s", strerror(err));
			/* sleep until next timer, see timer_cb */
			ev_io_stop(loop, watcher);
			struct ev_timer *restrict w_timer = &l->w_timer;
			ev_timer_start(loop, w_timer);
			return;
		}
		LOGV_F("accept: fd=%d", fd);
		if (is_startup_limited(l)) {
			stats->num_rejected++;
			if (close(fd) != 0) {
				const int err = errno;
				LOGW_F("close: %s", strerror(err));
			}
			return;
		}
		if (!socket_set_nonblock(fd)) {
			const int err = errno;
			LOGE_F("fcntl: %s", strerror(err));
			(void)close(fd);
			return;
		}
		socket_set_tcp(fd, true, true);

		s->serve(s, loop, fd, &m_sa.sa);
	}
}

static void
timer_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents);
	ev_timer_stop(loop, watcher);
	struct listener *restrict s = (struct listener *)watcher->data;
	struct ev_io *restrict w_accept = &s->w_accept;
	ev_io_start(loop, w_accept);
}

void listener_init(struct listener *l, struct server *s)
{
	l->s = s;
}

bool listener_start(
	struct listener *restrict l, struct ev_loop *loop,
	const struct sockaddr *bindaddr)
{
	struct server *restrict s = l->s;

	const int fd = socket(bindaddr->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: %s", strerror(err));
		return false;
	}
	socket_set_nonblock(fd);

#if WITH_REUSEPORT
	socket_set_reuseport(fd, s->conf->reuseport);
#else
	socket_set_reuseport(fd, false);
#endif
#if WITH_FASTOPEN
	if (s->conf->fastopen) {
		socket_set_fastopen(fd, 256);
	}
#endif
#if WITH_TPROXY
	if (s->conf->transparent) {
		socket_set_transparent(fd, true);
	}
#endif
	if (bind(fd, bindaddr, getsocklen(bindaddr)) != 0) {
		const int err = errno;
		LOGE_F("bind error: %s", strerror(err));
		(void)close(fd);
		return false;
	}
	if (listen(fd, 16)) {
		const int err = errno;
		LOGE_F("listen error: %s", strerror(err));
		(void)close(fd);
		return false;
	}
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(bindaddr, addr_str, sizeof(addr_str));
		LOG_F(LOG_LEVEL_INFO, "listen: %s", addr_str);
	}

	struct ev_io *restrict w_accept = &l->w_accept;
	ev_io_init(w_accept, accept_cb, fd, EV_READ);
	w_accept->data = l;
	struct ev_timer *restrict w_timer = &l->w_timer;
	ev_timer_init(w_timer, timer_cb, 0.5, 0.0);
	w_timer->data = l;

	s->stats->started = ev_now(loop);
	ev_io_start(loop, &l->w_accept);
	return true;
}

void listener_stop(struct listener *restrict l, struct ev_loop *loop)
{
	ev_io_stop(loop, &l->w_accept);
	ev_timer_stop(loop, &l->w_timer);
	(void)close(l->w_accept.fd);
}
