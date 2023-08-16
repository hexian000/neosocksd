#include "resolver.h"
#include "utils/check.h"
#include "utils/slog.h"
#include "utils/posixtime.h"
#include "utils/minmax.h"
#include "conf.h"
#include "util.h"
#include "sockutil.h"

#include <ev.h>
#if WITH_CARES
#include <ares.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct resolver {
	struct ev_loop *loop;
	struct resolver_stats stats;
	bool async_enabled;
#if WITH_CARES
	ares_channel channel;
	struct ev_timer w_timeout;
	size_t num_socket;
	struct ev_io w_socket;
#endif
};

static void
done_cb(struct ev_loop *loop, struct ev_watcher *watcher, const int revents)
{
	UNUSED(revents);
	struct resolve_query *restrict q = watcher->data;
	if (q->done_cb.cb == NULL) {
		/* cancelled */
		return;
	}
	q->resolver->stats.num_success++;
	q->done_cb.cb(loop, q->done_cb.ctx);
}

#if WITH_CARES
static void socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	UNUSED(loop);
	CHECK_EV_ERROR(revents);
	struct resolver *restrict r = watcher->data;
	const int fd = watcher->fd;
	const ares_socket_t readable =
		(revents & EV_READ) ? fd : ARES_SOCKET_BAD;
	const ares_socket_t writable =
		(revents & EV_WRITE) ? fd : ARES_SOCKET_BAD;
	LOGV_F("io: fd=%d revents=0x%x", fd, revents);
	ares_process_fd(r->channel, readable, writable);
}

static void
sched_update(struct ev_loop *loop, struct ev_timer *restrict watcher)
{
	struct resolver *restrict r = watcher->data;
	struct timeval tv;
	if (ares_timeout(r->channel, NULL, &tv) == NULL) {
		LOGD("timeout: no active query, stopped");
		ev_timer_stop(loop, watcher);
		return;
	}
	const double next = tv.tv_sec * 1.0 + tv.tv_usec * 1e-6;
	LOGD_F("timeout: next update after %.3fs", next);
	watcher->repeat = next;
	ev_timer_again(loop, watcher);
}

static void
update_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	UNUSED(revents);
	struct resolver *restrict r = watcher->data;
	ares_process_fd(r->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

	/* purge inactive watchers */
	size_t num_purged = 0;
	struct ev_io **pw_socket = (struct ev_io **)&r->w_socket.next;
	for (struct ev_io *w_socket = *pw_socket; w_socket != NULL;
	     w_socket = *pw_socket) {
		if (ev_is_active(w_socket)) {
			pw_socket = (struct ev_io **)&w_socket->next;
			continue;
		}
		*pw_socket = (struct ev_io *)w_socket->next;
		free(w_socket);
		num_purged++;
	}
	if (num_purged > 0) {
		LOGD_F("resolve: %zu inactive watchers purged", num_purged);
	}

	sched_update(loop, watcher);
}

static void sock_state_cb(
	void *data, const ares_socket_t fd, const int readable,
	const int writable)
{
	struct resolver *restrict r = data;
	const int events = (readable ? EV_READ : 0) | (writable ? EV_WRITE : 0);
	LOGV_F("io: fd=%d events=0x%x", fd, events);

	struct ev_io *w_socket = NULL;
	for (struct ev_io *it = &r->w_socket; it != NULL;
	     it = (struct ev_io *)it->next) {
		if (!ev_is_active(it)) {
			w_socket = it;
			continue;
		}
		if (it->fd == fd) {
			w_socket = it;
			break;
		}
	}
	if (w_socket == NULL) {
		w_socket = malloc(sizeof(struct ev_io));
		if (w_socket == NULL) {
			LOGE_F("io: attach fd=%d failed", fd);
			return;
		}
		ev_io_init(w_socket, socket_cb, fd, events);
		w_socket->data = r;
		w_socket->next = r->w_socket.next;
		r->w_socket.next = (struct ev_watcher_list *)w_socket;
	} else {
		ev_io_set(w_socket, fd, events);
	}
	if (events == EV_NONE) {
		ev_io_stop(r->loop, w_socket);
		LOGV_F("io: detach fd=%d num_socket=%zu", fd, --r->num_socket);
	} else {
		ev_io_start(r->loop, w_socket);
		LOGV_F("io: attach fd=%d num_socket=%zu", fd, ++r->num_socket);
	}
}

static bool
find_addrinfo(sockaddr_max_t *addr, const struct ares_addrinfo_node *it)
{
	for (; it != NULL; it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in));
			addr->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			CHECK(it->ai_addrlen == sizeof(struct sockaddr_in6));
			addr->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}
		return true;
	}
	return false;
}

static void
addrinfo_cb(void *arg, int status, int timeouts, struct ares_addrinfo *info)
{
	UNUSED(timeouts);
	struct resolve_query *restrict q = arg;
	struct resolver *restrict r = q->resolver;
	switch (status) {
	case ARES_SUCCESS:
		if (info != NULL) {
			q->ok = find_addrinfo(&q->addr, info->nodes);
			ares_freeaddrinfo(info);
		}
		break;
	case ARES_EDESTRUCTION:
		return;
	default:
		LOGW_F("ares: %s", ares_strerror(status));
		break;
	}
	ev_feed_event(r->loop, &q->w_done, EV_CUSTOM);
	LOGV_F("resolve: [%p] finished ok=%d", (void *)q, q->ok);
}
#endif

void resolver_atexit_cb(void)
{
#if WITH_CARES
	if (ares_library_initialized() == ARES_ENOTINITIALIZED) {
		return;
	}
	ares_library_cleanup();
#endif
}

void resolver_free(struct resolver *restrict r)
{
	if (r == NULL) {
		return;
	}
	if (r->async_enabled) {
#if WITH_CARES
		ares_destroy(r->channel);
#endif
	}
	free(r);
}

bool resolver_async_init(struct resolver *restrict r, const struct config *conf)
{
#if WITH_CARES
	int ret = ares_library_initialized();
	if (ret == ARES_ENOTINITIALIZED) {
		ret = ares_library_init(ARES_LIB_INIT_ALL);
		if (ret != ARES_SUCCESS) {
			LOGE_F("ares: %s", ares_strerror(ret));
			return false;
		}
	}

	const double timeout = MIN(conf->timeout, 30.0);
	struct ares_options options;
	options.timeout = timeout * 1e+3;
	options.sock_state_cb = sock_state_cb;
	options.sock_state_cb_data = r;
	ret = ares_init_options(
		&r->channel, &options,
		ARES_OPT_TIMEOUTMS | ARES_OPT_SOCK_STATE_CB);
	if (ret != ARES_SUCCESS) {
		LOGE_F("ares: %s", ares_strerror(ret));
		return false;
	}
	ev_timer_init(&r->w_timeout, update_cb, timeout, timeout);
	r->w_timeout.data = r;

	const char *nameserver = conf->nameserver;
	if (nameserver == NULL) {
		return true;
	}
	struct ares_addr_node svr = { .next = NULL };
	if (inet_pton(AF_INET, nameserver, &svr.addr.addr4) == 1) {
		svr.family = AF_INET;
	} else if (inet_pton(AF_INET6, nameserver, &svr.addr.addr6) == 1) {
		svr.family = AF_INET6;
	} else {
		LOGE_F("failed parsing address: \"%s\"", nameserver);
		return false;
	}
	ret = ares_set_servers(r->channel, &svr);
	if (ret != ARES_SUCCESS) {
		LOGE_F("failed using nameserver \"%s\": %s", nameserver,
		       ares_strerror(ret));
		return true;
	}
	return true;
#else
	UNUSED(r);
	UNUSED(conf);
	return false;
#endif
}

struct resolver *resolver_new(struct ev_loop *loop, const struct config *conf)
{
	struct resolver *restrict r = malloc(sizeof(struct resolver));
	if (r == NULL) {
		return NULL;
	}
	*r = (struct resolver){
		.loop = loop,
	};
#if WITH_CARES
	ev_io_init(&r->w_socket, socket_cb, -1, EV_NONE);
	r->w_socket.data = r;
#endif
	r->async_enabled = resolver_async_init(r, conf);
	return r;
}

const struct resolver_stats *resolver_stats(struct resolver *r)
{
	return &r->stats;
}

void resolve_init(
	struct resolver *r, struct resolve_query *restrict q,
	const struct event_cb cb)
{
	q->resolver = r;
	ev_init(&q->w_done, done_cb);
	q->w_done.data = q;
	q->done_cb = cb;
	q->ok = false;
}

bool resolve_start(
	struct resolve_query *q, const char *name, const char *service,
	const int family)
{
	LOGV_F("resolve: [%p] start name=\"%s\" service=%s pf=%d", (void *)q,
	       name, service, family);
	struct resolver *restrict r = q->resolver;
	r->stats.num_query++;
#if WITH_CARES
	if (r->async_enabled) {
		const struct ares_addrinfo_hints hints = {
			.ai_family = family,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
			.ai_flags = ARES_AI_V4MAPPED | ARES_AI_ADDRCONFIG,
		};
		ares_getaddrinfo(
			r->channel, name, service, &hints, addrinfo_cb, q);
		struct ev_timer *restrict w_timeout = &r->w_timeout;
		if (!ev_is_active(w_timeout)) {
			sched_update(r->loop, w_timeout);
		}
		return true;
	}
#endif
	q->ok = resolve_addr(&q->addr, name, service, family);
	ev_feed_event(r->loop, &q->w_done, EV_CUSTOM);
	LOGV_F("resolve: [%p] finished ok=%d", (void *)q, q->ok);
	return true;
}

void resolve_cancel(struct resolve_query *ctx)
{
	ctx->done_cb = (struct event_cb){
		.cb = NULL,
		.ctx = NULL,
	};
}

const struct sockaddr *resolve_get(const struct resolve_query *restrict ctx)
{
	return ctx->ok ? &ctx->addr.sa : NULL;
}
