/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "server.h"

#include "api_server.h"
#include "conf.h"
#include "dialer.h"
#include "forward.h"
#include "http_proxy.h"
#include "proto/domain.h"
#if WITH_RULESET
#include "ruleset/ruleset.h"
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
#if WITH_THREADS
#include <stdatomic.h>
#endif
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
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
		/* count halfopen (accepted, not yet committed) connections
		 * too: num_sessions alone only reflects fully committed
		 * transfers, so a burst of connections that are all still
		 * mid-dial would otherwise all pass this check and commit
		 * past max_sessions at once. */
		if (n + stats->num_halfopen >= (size_t)conf->max_sessions) {
			LOGVV("session limit exceeded, rejecting new connection");
			return true;
		}
	}

	if (conf->startup_limit_full > 0 &&
	    stats->num_halfopen >= (size_t)conf->startup_limit_full) {
		LOGVV("full startup limit exceeded, rejecting new connection");
		return true;
	}

	if (conf->startup_limit_start > 0 &&
	    stats->num_halfopen >= (size_t)conf->startup_limit_start) {
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
			socket_close(fd);
			continue;
		}

		if (!socket_set_cloexec(fd) || !socket_set_nonblock(fd)) {
			socket_close(fd);
			continue;
		}
		/* best-effort tuning; failure does not affect correctness */
		(void)socket_set_tcp(
			fd, conf->tcp_nodelay, conf->tcp_keepalive);
		(void)socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

		l->stats.num_serve++;
		l->serve(s, loop, fd, (const struct sockaddr *)&addr.sa);
	}
}

/* Restart the accept watcher after a temporary accept failure. */
static void timer_cb(
	struct ev_loop *restrict loop, ev_timer *restrict watcher,
	const int revents)
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
		LOGF_F("socket: (%d) %s", err, strerror(err));
		return false;
	}

	if (!socket_set_cloexec(fd) || !socket_set_nonblock(fd)) {
		socket_close(fd);
		return false;
	}

	const struct config *restrict conf = s->conf;

	/* failure surfaces later via the bind() check below */
#if WITH_REUSEPORT
	(void)socket_set_reuseport(fd, conf->reuseport);
#else
	(void)socket_set_reuseport(fd, false);
#endif
#if WITH_TPROXY
	/* transparent mode applies only to the primary proxy listener, not to
	 * a co-configured --api/--http listener */
	if (conf->transparent && serve == tproxy_serve) {
		socket_set_transparent(fd, true);
	}
#endif
	const int backlog = SOMAXCONN;
#if WITH_TCP_FASTOPEN
	if (conf->tcp_fastopen) {
		/* opportunistic; falls back to a normal handshake on failure */
		(void)socket_set_fastopen(fd, backlog);
	}
#endif
	/* best-effort tuning; failure does not affect correctness */
	(void)socket_set_tcp(fd, conf->tcp_nodelay, conf->tcp_keepalive);
	(void)socket_set_buffer(fd, conf->tcp_sndbuf, conf->tcp_rcvbuf);

	if (LOGLEVEL(NOTICE)) {
		char addr_str[64];
		sa_format(addr_str, sizeof(addr_str), bindaddr);
		LOG_F(NOTICE, "listen: %s", addr_str);
	}

	if (bind(fd, bindaddr, sa_len(bindaddr)) != 0) {
		const int err = errno;
		LOGF_F("bind: (%d) %s", err, strerror(err));
		socket_close(fd);
		return false;
	}

	if (listen(fd, backlog)) {
		const int err = errno;
		LOGF_F("listen: (%d) %s", err, strerror(err));
		socket_close(fd);
		return false;
	}

	struct listener *restrict l = &s->listeners[s->num_listeners];
	l->server = s;
	l->serve = serve;

	ev_io_init(&l->w_accept, accept_cb, fd, EV_READ);
	l->w_accept.data = l;
	ev_timer_init(&l->w_timer, timer_cb, 0.5, 0.0);
	l->w_timer.data = l;

	ev_io_start(s->loop, &l->w_accept);
	s->num_listeners++;
	return true;
}

#if WITH_RULESET
/* The boot configuration may change the forward/proxy settings, so the
 * base dial request is rebuilt on reload; on failure the old one is kept. */
static void server_reload_basereq(struct server *restrict s)
{
	if (!dialreq_replace(&s->basereq, s->conf->forward, s->conf->proxy)) {
		LOGW("reload: unable to parse outbound configuration; keeping the previous one");
		return;
	}
	if (s->ruleset != NULL) {
		ruleset_setbasereq(s->ruleset, s->basereq);
	}
}

/* Reload ruleset from the command-line file; previous ruleset kept on failure. */
static bool server_reload_ruleset(struct server *restrict s)
{
	if (s->conf->boot == NULL && s->conf->ruleset == NULL) {
		return true;
	}
	struct ruleset *restrict ruleset = s->ruleset;
	const bool created = (ruleset == NULL);
	if (created) {
		ruleset =
			ruleset_new(s->loop, s->conf, s->resolver, s->basereq);
		if (ruleset == NULL) {
			LOGOOM();
			return false;
		}
	}
	bool ok;
	if (s->conf->boot != NULL) {
		ok = ruleset_loadconfig(ruleset, s->conf->boot);
		if (!ok) {
			LOGW_F("reload: config error: %s",
			       ruleset_geterror(ruleset, NULL));
		}
	} else {
		ok = ruleset_loadfile(ruleset, s->conf->ruleset);
		if (!ok) {
			LOGW_F("reload: ruleset error: %s",
			       ruleset_geterror(ruleset, NULL));
		}
	}
	if (!ok) {
		if (created) {
			ruleset_free(ruleset);
		}
		return false;
	}
	/* drop the engine if no ruleset was installed */
	if (!ruleset_isvalid(ruleset)) {
		ruleset_free(ruleset);
		s->ruleset = NULL;
	} else if (created) {
		ruleset_setserver(ruleset, s);
		s->ruleset = ruleset;
	}
	return true;
}
#endif /* WITH_RULESET */

static void signal_cb(
	struct ev_loop *restrict loop, ev_signal *restrict watcher,
	const int revents)
{
	CHECK_REVENTS(revents, EV_SIGNAL);

	switch (watcher->signum) {
	case SIGHUP: {
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_RELOADING);
#if WITH_RULESET
		struct server *restrict s = watcher->data;
		if (s->conf->boot != NULL || s->conf->ruleset != NULL) {
			if (server_reload_ruleset(s)) {
				if (s->conf->boot != NULL) {
					server_reload_basereq(s);
				}
				LOGN("reload: config successfully reloaded");
			}
		} else {
			LOGD("reload: no reloadable configuration");
		}
#else
		LOGD("reload: no reloadable configuration");
#endif /* WITH_RULESET */
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_READY);
	} break;
	case SIGINT:
	case SIGTERM:
		LOGD_F("signal %d received, shutting down", watcher->signum);
		(void)systemd_notify(DAEMON_SYSTEMD_STATE_STOPPING);
		ev_break(loop, EVBREAK_ALL);
		break;
	default:
		break;
	}
}

static bool
resolve_addr(union sockaddr_max *restrict out, const char *restrict addrstr)
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
	if (!sa_resolve_bind(out, host, port, SA_RESOLVE_TCP)) {
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
	(void)ruleset;
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
	/* mark the server started before adding listeners so server_stop()
	 * always tears down (signal watchers, basereq) even with zero
	 * listeners, and so uptime spans the whole server lifetime */
	s->stats.started = (int_least64_t)clock_monotonic_ns();

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
		if (!resolve_addr(&bindaddr, conf->listen)) {
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
		if (!resolve_addr(&httpaddr, conf->http_listen)) {
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
		if (!resolve_addr(&apiaddr, conf->restapi)) {
			return false;
		}
		const enum ipclass cls = sa_ipclassify(&apiaddr.sa);
		if (cls != IPCLASS_LOOPBACK) {
			LOGW("binding API server to non-loopback address is insecure: the API allows any client to execute arbitrary code");
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
		socket_close(l->w_accept.fd);

		ev_timer_stop(loop, &l->w_timer);
	}

	dialreq_free(s->basereq);
	s->basereq = NULL;
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
#else /* WITH_THREADS */
	out->num_sessions = s->num_sessions;
	out->byt_up = s->byt_up;
	out->byt_down = s->byt_down;
#endif /* WITH_THREADS */
}
