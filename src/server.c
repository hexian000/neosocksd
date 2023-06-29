/* neosocksd (c) 2023 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"
#include "utils/slog.h"
#include "utils/check.h"
#include "conf.h"
#include "sockutil.h"
#include "util.h"

#include <ev.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	CHECK_EV_ERROR(revents);

	struct server *s = (struct server *)watcher->data;

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
			return;
		}
		LOGV_F("accept: fd=%d", fd);
		if (!socket_set_nonblock(fd)) {
			const int err = errno;
			LOGE_F("fcntl: %s", strerror(err));
			(void)close(fd);
			return;
		}
		socket_set_tcp(fd, true, false);

		s->serve_cb(loop, s, fd, &m_sa.sa);
	}
}

struct server *server_new(
	const struct sockaddr *bindaddr, const struct config *conf,
	struct ruleset *ruleset, const serve_fn serve_cb)
{
	const int fd = socket(bindaddr->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: %s", strerror(err));
		return NULL;
	}
	socket_set_nonblock(fd);
#if WITH_REUSEPORT
	socket_set_reuseport(fd, conf->reuseport);
#else
	socket_set_reuseport(fd, false);
#endif
#if WITH_TPROXY
	if (conf->transparent) {
		socket_set_tproxy(fd, conf->transparent);
	}
#endif
	if (bind(fd, bindaddr, getsocklen(bindaddr)) != 0) {
		const int err = errno;
		LOGE_F("bind error: %s", strerror(err));
		(void)close(fd);
		return NULL;
	}
	if (listen(fd, 16)) {
		const int err = errno;
		LOGE_F("listen error: %s", strerror(err));
		(void)close(fd);
		return NULL;
	}
	if (LOGLEVEL(LOG_LEVEL_INFO)) {
		char addr_str[64];
		format_sa(bindaddr, addr_str, sizeof(addr_str));
		LOGI_F("listen: %s", addr_str);
	}

	struct server *restrict s = malloc(sizeof(struct server));
	if (s == NULL) {
		LOGOOM();
		(void)close(fd);
		return NULL;
	}
	s->conf = conf;
	s->ruleset = ruleset;
	s->serve_cb = serve_cb;
	struct ev_io *restrict w_accept = &s->w_accept;
	ev_io_init(w_accept, accept_cb, fd, EV_READ);
	s->w_accept.data = s;
	s->uptime = TSTAMP_NIL;
	return s;
}

void server_start(struct server *restrict s, struct ev_loop *loop)
{
	s->uptime = ev_now(loop);
	ev_io_start(loop, &s->w_accept);
}

void server_stop(struct server *restrict s, struct ev_loop *loop)
{
	ev_io_stop(loop, &s->w_accept);
}

void server_free(struct server *restrict s)
{
	if (s != NULL) {
		(void)close(s->w_accept.fd);
	}
	free(s);
}

double server_get_uptime(struct server *restrict s, const ev_tstamp now)
{
	return now - s->uptime;
}
