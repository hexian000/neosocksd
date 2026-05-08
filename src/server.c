/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "api_server.h"
#include "conf.h"
#include "forward.h"
#include "http_proxy.h"
#include "proto/domain.h"
#if WITH_RULESET
#include "ruleset.h"
#endif
#include "socks.h"
#include "util.h"

#include "math/rand.h"
#include "net/addr.h"
#include "os/clock.h"
#include "os/daemon.h"
#include "os/socket.h"
#include "utils/slog.h"

#include <ev.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <string.h>
#include <sys/socket.h>

static bool is_startup_limited(const struct server *restrict s)
{
	const struct config *restrict conf = s->conf;
	const struct server_stats *restrict stats = &s->stats;

	if (conf->max_sessions > 0) {
#if WITH_THREADS
		const size_t n = atomic_load_explicit(
			&s->num_sessions, memory_order_relaxed);
#else
		const size_t n = s->num_sessions;
#endif
		if (n > (size_t)conf->max_sessions) {
			LOGVV("session limit exceeded, rejecting new connection");
			return true;
		}
	}

	if (conf->startup_limit_full > 0 &&
	    stats->num_halfopen > (size_t)conf->startup_limit_full) {
		LOGVV("full startup limit exceeded, rejecting new connection");
		return true;
	}

	if (conf->startup_limit_start > 0 &&
	    stats->num_halfopen > (size_t)conf->startup_limit_start) {
		if ((frand() * 100.0) < (double)conf->startup_limit_rate) {
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

	for (;;) {
		union sockaddr_max addr;
		socklen_t addrlen = sizeof(addr);
		const int fd = accept(watcher->fd, &addr.sa, &addrlen);
		if (fd < 0) {
			const int err = errno;
			if (err == EAGAIN || err == EWOULDBLOCK) {
				break;
			}
			if (err == EINTR || err == ECONNABORTED) {
				continue;
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

		if (is_startup_limited(s)) {
			CLOSE_FD(fd);
			return;
		}

		{
			int err = socket_set_cloexec(fd);
			if (err != 0) {
				CLOSE_FD(fd);
				return;
			}
			err = socket_set_nonblock(fd);
			if (err != 0) {
				CLOSE_FD(fd);
				return;
			}
		}
		socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
		socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		l->stats.num_serve++;
		l->serve(s, loop, fd, (const struct sockaddr *)&addr.sa);
	}
}

/* Restart the accept watcher after a temporary accept failure. */
static void
timer_cb(struct ev_loop *restrict loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	ev_timer_stop(loop, watcher);
	struct listener *restrict l = watcher->data;
	ev_io_start(loop, &l->w_accept);
}

static bool add_listener(
	struct server *restrict s, const struct sockaddr *restrict bindaddr,
	serve_fn serve)
{
	if (s->num_listeners >= SERVER_LISTENERS_MAX) {
		LOGE_F("cannot add listener: max %d listeners reached",
		       SERVER_LISTENERS_MAX);
		return false;
	}

	const int fd = socket(bindaddr->sa_family, SOCK_STREAM, 0);
	if (fd < 0) {
		const int err = errno;
		LOGE_F("socket: (%d) %s", err, strerror(err));
		return false;
	}

	{
		int err = socket_set_cloexec(fd);
		if (err != 0) {
			CLOSE_FD(fd);
			return false;
		}
		err = socket_set_nonblock(fd);
		if (err != 0) {
			CLOSE_FD(fd);
			return false;
		}
	}

	const struct config *restrict conf = s->conf;

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
		sa_format(addr_str, sizeof(addr_str), bindaddr);
		LOG_F(NOTICE, "listen: %s", addr_str);
	}

	if (bind(fd, bindaddr, sa_len(bindaddr)) != 0) {
		const int err = errno;
		LOGE_F("bind: (%d) %s", err, strerror(err));
		CLOSE_FD(fd);
		return false;
	}

	if (listen(fd, backlog)) {
		const int err = errno;
		LOGE_F("listen: (%d) %s", err, strerror(err));
		CLOSE_FD(fd);
		return false;
	}

	struct listener *restrict l = &s->listeners[s->num_listeners];
	l->server = s;
	l->serve = serve;

	ev_io_init(&l->w_accept, accept_cb, fd, EV_READ);
	l->w_accept.data = l;
	ev_timer_init(&l->w_timer, timer_cb, 0.5, 0.0);
	l->w_timer.data = l;

	struct ev_loop *loop = s->loop;
	if (s->num_listeners == 0) {
		s->stats.started = clock_monotonic_ns();
	}
	ev_io_start(loop, &l->w_accept);
	s->num_listeners++;
	return true;
}

static void
signal_cb(struct ev_loop *loop, ev_signal *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_SIGNAL);

	struct server *restrict s = watcher->data;
	switch (watcher->signum) {
	case SIGHUP: {
		(void)systemd_notify(SYSTEMD_STATE_RELOADING);
		if (!conf_reload(s->conf)) {
			(void)systemd_notify(SYSTEMD_STATE_READY);
			break;
		}
#if WITH_RULESET
		struct ruleset *restrict ruleset = s->ruleset;
		if (s->conf->ruleset != NULL && ruleset != NULL) {
			const bool ok =
				ruleset_loadfile(ruleset, s->conf->ruleset);
			if (!ok) {
				LOGW_F("reload: ruleset error: %s",
				       ruleset_geterror(ruleset, NULL));
				(void)systemd_notify(SYSTEMD_STATE_READY);
				break;
			}
		}
#endif
		LOGN("reload: config successfully reloaded");
		(void)systemd_notify(SYSTEMD_STATE_READY);
	} break;
	case SIGINT:
	case SIGTERM:
		LOGD_F("signal %d received, breaking", watcher->signum);
		(void)systemd_notify(SYSTEMD_STATE_STOPPING);
		ev_break(loop, EVBREAK_ALL);
		break;
	default:
		break;
	}
}

static bool
resolve_addr(const char *restrict addrstr, union sockaddr_max *restrict out)
{
	const size_t bufsize = FQDN_MAX_LENGTH + sizeof(":65535");
	const size_t addrlen = strlen(addrstr);
	if (addrlen >= bufsize) {
		LOGF_F("address too long: %s", addrstr);
		return false;
	}
	char buf[bufsize];
	memcpy(buf, addrstr, addrlen + 1);
	char *host, *port;
	if (!splithostport(buf, &host, &port)) {
		LOGF_F("unable to parse address: %s", addrstr);
		return false;
	}
	if (!sa_resolve_tcpbind(out, host, port)) {
		LOGF_F("unable to resolve address: %s", addrstr);
		return false;
	}
	return true;
}

bool server_init(
	struct server *restrict s, struct ev_loop *loop,
	struct config *restrict conf, struct resolver *resolver,
	struct transfer *xfer, struct dialreq *basereq, struct ruleset *ruleset)
{
	UNUSED(ruleset);
	*s = (struct server){
		.loop = loop,
		.conf = conf,
		.resolver = resolver,
		.xfer = xfer,
		.basereq = basereq,
#if WITH_RULESET
		.ruleset = ruleset,
#endif
		.stats = { .started = -1 },
	};
	s->data = s;

	if (conf->listen != NULL) {
		serve_fn proxy_serve;
		if (conf->forward != NULL) {
			proxy_serve = forward_serve;
		}
#if WITH_TPROXY
		else if (conf->transparent) {
			proxy_serve = tproxy_serve;
		}
#endif
		else {
			proxy_serve = socks_serve;
		}
		union sockaddr_max bindaddr;
		if (!resolve_addr(conf->listen, &bindaddr)) {
			return false;
		}
		if (sa_ipclassify(&bindaddr.sa) == IPCLASS_UNSPECIFIED) {
			LOGW("binding to wildcard address may be insecure");
		}
		if (!add_listener(s, &bindaddr.sa, proxy_serve)) {
			return false;
		}
	}
	if (conf->http_listen != NULL) {
		union sockaddr_max httpaddr;
		if (!resolve_addr(conf->http_listen, &httpaddr)) {
			return false;
		}
		if (sa_ipclassify(&httpaddr.sa) == IPCLASS_UNSPECIFIED) {
			LOGW("binding to wildcard address may be insecure");
		}
		if (!add_listener(s, &httpaddr.sa, http_proxy_serve)) {
			return false;
		}
	}
	if (conf->restapi != NULL) {
		union sockaddr_max apiaddr;
		if (!resolve_addr(conf->restapi, &apiaddr)) {
			return false;
		}
		const enum ipclass cls = sa_ipclassify(&apiaddr.sa);
		if (cls != IPCLASS_LOOPBACK && cls != IPCLASS_LINKLOCAL &&
		    cls != IPCLASS_SITELOCAL) {
			LOGW("binding API server to non-local address may be insecure");
		}
		if (!add_listener(s, &apiaddr.sa, api_serve)) {
			return false;
		}
	}

	ev_signal_init(&s->w_sighup, signal_cb, SIGHUP);
	s->w_sighup.data = s;
	ev_set_priority(&s->w_sighup, EV_MAXPRI);
	ev_signal_start(loop, &s->w_sighup);

	ev_signal_init(&s->w_sigint, signal_cb, SIGINT);
	s->w_sigint.data = s;
	ev_set_priority(&s->w_sigint, EV_MAXPRI);
	ev_signal_start(loop, &s->w_sigint);

	ev_signal_init(&s->w_sigterm, signal_cb, SIGTERM);
	s->w_sigterm.data = s;
	ev_set_priority(&s->w_sigterm, EV_MAXPRI);
	ev_signal_start(loop, &s->w_sigterm);

	return true;
}

void server_stop(struct server *restrict s)
{
	if (s->stats.started == -1) {
		return;
	}

	struct ev_loop *loop = s->loop;

	ev_signal_stop(loop, &s->w_sighup);
	ev_signal_stop(loop, &s->w_sigint);
	ev_signal_stop(loop, &s->w_sigterm);

	for (size_t i = 0; i < s->num_listeners; i++) {
		struct listener *restrict l = &s->listeners[i];

		ev_io_stop(loop, &l->w_accept);
		CLOSE_FD(l->w_accept.fd);

		ev_timer_stop(loop, &l->w_timer);
	}

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
#if WITH_THREADS
	out->num_sessions =
		atomic_load_explicit(&s->num_sessions, memory_order_relaxed);
	out->byt_up = atomic_load_explicit(&s->byt_up, memory_order_relaxed);
	out->byt_down =
		atomic_load_explicit(&s->byt_down, memory_order_relaxed);
#else
	out->num_sessions = s->num_sessions;
	out->byt_up = s->byt_up;
	out->byt_down = s->byt_down;
#endif
}
