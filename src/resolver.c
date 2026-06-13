/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "resolver.h"

#include "conf.h"
#include "util.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#if WITH_CARES
/* under strict POSIX feature macros, ares.h needs fd_set from sys/select.h */
#include <sys/select.h>

#include <ares.h>
#endif
#include <ev.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if WITH_CARES
#include <sys/time.h>
#endif
#include <sys/socket.h>

struct io_node {
	ev_io watcher;
	struct io_node *next;
};

struct resolver {
	struct ev_loop *loop;
	struct resolver_stats stats;
#if WITH_CARES
	bool async_enabled;
	ares_channel channel;
	ev_timer w_timeout;
	size_t num_socket;
	struct io_node sockets;
#endif
};

struct resolve_query {
	struct resolver *resolver;
	struct resolve_cb done_cb;
	ev_watcher w_finish;
	bool ok : 1;
	union sockaddr_max addr;
	const char *name, *service;
	int family;
	char buf[];
};

static void
finish_cb(struct ev_loop *restrict loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct resolve_query *restrict q = watcher->data;
	if (q->ok) {
		char addr[64];
		sa_format(addr, sizeof(addr), &q->addr.sa);
		LOGD_F("resolve `%s:%s': %s", q->name, q->service, addr);
	} else {
		LOGD_F("resolve `%s:%s': failed", q->name, q->service);
	}

	/* Check if query was cancelled */
	if (q->done_cb.func == NULL) {
		free(q);
		return;
	}

	if (!q->ok) {
		q->done_cb.func(q, loop, q->done_cb.data, NULL);
		free(q);
		return;
	}

	q->resolver->stats.num_success++;
	q->done_cb.func(q, loop, q->done_cb.data, &q->addr.sa);
	free(q);
}

#if WITH_CARES
static void
socket_cb(struct ev_loop *restrict loop, ev_io *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct resolver *restrict r = watcher->data;
	const int fd = watcher->fd;

	const ares_socket_t readable =
		(revents & EV_READ) ? fd : ARES_SOCKET_BAD;
	const ares_socket_t writable =
		(revents & EV_WRITE) ? fd : ARES_SOCKET_BAD;

	LOGV_F("io: [fd:%d] revents=0x%x", fd, revents);
	ares_process_fd(r->channel, readable, writable);
}

static void
sched_update(struct ev_loop *restrict loop, ev_timer *restrict watcher)
{
	struct resolver *restrict r = watcher->data;
	struct timeval tv;

	if (ares_timeout(r->channel, NULL, &tv) == NULL) {
		ev_timer_stop(loop, watcher);
		return;
	}

	const double next = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
	LOGV_F("timeout: next check after %.3fs", next);
	watcher->repeat = next;
	ev_timer_again(loop, watcher);
}

static size_t purge_watchers(struct resolver *restrict r)
{
	size_t num_purged = 0;
	struct io_node *prev = &r->sockets;

	for (struct io_node *it = prev->next; it != NULL; it = prev->next) {
		if (ev_is_active(&it->watcher)) {
			prev = it;
			continue;
		}

		prev->next = it->next;
		free(it);
		num_purged++;
	}
	return num_purged;
}

static void
timeout_cb(struct ev_loop *restrict loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct resolver *restrict r = watcher->data;

	/* Process c-ares timeouts (no specific sockets) */
	ares_process_fd(r->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

	size_t num_purged = purge_watchers(r);
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

	/* Find existing watcher for this fd or an inactive watcher to reuse;
	 * the embedded list head is itself a usable watcher node */
	struct io_node *restrict node = NULL;
	struct io_node *it = &r->sockets;
	do {
		if (it->watcher.fd == fd) {
			node = it;
			break;
		}
		if (!ev_is_active(&it->watcher)) {
			node = it;
		}
		it = it->next;
	} while (it != NULL);

	if (events == EV_NONE) {
		if (node == NULL || !ev_is_active(&node->watcher)) {
			return;
		}
		LOGV_F("io: stop [fd:%d] num_socket=%zu", fd, --r->num_socket);
		ev_io_stop(r->loop, &node->watcher);
		return;
	}

	if (node == NULL) {
		struct io_node *const new_node = malloc(sizeof(struct io_node));
		if (new_node == NULL) {
			LOGOOM();
			return;
		}
		ev_io_init(&new_node->watcher, socket_cb, fd, events);
		new_node->watcher.data = r;
		new_node->next = r->sockets.next;
		r->sockets.next = new_node;
		node = new_node;
	} else {
		ev_io_stop(r->loop, &node->watcher);
		ev_io_set(&node->watcher, fd, events);
	}

	LOGV_F("io: [fd:%d] events=0x%x num_socket=%zu", fd, events,
	       ++r->num_socket);
	ev_io_start(r->loop, &node->watcher);
}

static bool find_addrinfo(
	union sockaddr_max *restrict addr,
	const struct ares_addrinfo_node *restrict node)
{
	for (const struct ares_addrinfo_node *restrict it = node; it != NULL;
	     it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			if (it->ai_addrlen != sizeof(struct sockaddr_in)) {
				LOGE_F("resolve: invalid ai_addrlen %ju (af=%d)",
				       (uintmax_t)it->ai_addrlen,
				       it->ai_family);
				continue;
			}
			addr->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			if (it->ai_addrlen != sizeof(struct sockaddr_in6)) {
				LOGE_F("resolve: invalid ai_addrlen %ju (af=%d)",
				       (uintmax_t)it->ai_addrlen,
				       it->ai_family);
				continue;
			}
			addr->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			continue;
		}
		return true;
	}
	return false;
}

static void addrinfo_cb(
	void *arg, const int status, const int timeouts,
	struct ares_addrinfo *info)
{
	UNUSED(timeouts);
	struct resolve_query *restrict q = arg;

	switch (status) {
	case ARES_SUCCESS:
		if (info != NULL) {
			q->ok = find_addrinfo(&q->addr, info->nodes);
			ares_freeaddrinfo(info);
		}
		break;
	case ARES_EDESTRUCTION:
		/* c-ares channel is being destroyed, don't process */
		return;
	default:
		LOGW_F("c-ares: resolve error: (%d) %s", status,
		       ares_strerror(status));
		break;
	}

	/* Trigger query completion callback (deferred, matching the synchronous
	 * path, so callers can reliably set their query pointer before it fires) */
	ev_feed_event(q->resolver->loop, &q->w_finish, EV_CUSTOM);
}
#endif /* WITH_CARES */

void resolver_init(void)
{
#if WITH_CARES
	LOGD_F("c-ares: %s", ares_version(NULL));
#if CARES_HAVE_ARES_LIBRARY_INIT
	const int ret = ares_library_init(ARES_LIB_INIT_ALL);
	CHECKMSGF(
		ret == ARES_SUCCESS, "c-ares: (%d) %s", ret,
		ares_strerror(ret));
#endif
#endif
}

void resolver_cleanup(void)
{
#if WITH_CARES && CARES_HAVE_ARES_LIBRARY_CLEANUP
	ares_library_cleanup();
#endif
}

void resolver_free(struct resolver *restrict r)
{
	if (r == NULL) {
		return;
	}
#if WITH_CARES
	if (r->async_enabled) {
		ares_destroy(r->channel);
		(void)purge_watchers(r);

		ASSERT(!ev_is_active(&r->sockets.watcher));
		ASSERT(!ev_is_pending(&r->sockets.watcher));
		ASSERT(r->sockets.next == NULL);
	}
#endif
	free(r);
}

#if WITH_CARES
static bool resolver_async_init(
	struct resolver *restrict r, const struct config *restrict conf)
{
	int ret;
	struct ares_options options;

	options.sock_state_cb = sock_state_cb;
	options.sock_state_cb_data = r;
	ret = ares_init_options(&r->channel, &options, ARES_OPT_SOCK_STATE_CB);
	if (ret != ARES_SUCCESS) {
		LOGE_F("c-ares: (%d) %s", ret, ares_strerror(ret));
		return false;
	}

	ev_timer_init(&r->w_timeout, timeout_cb, 0.0, 0.0);
	r->w_timeout.data = r;

	const char *nameserver = conf->nameserver;
	if (nameserver == NULL) {
		return true;
	}
	ret = ares_set_servers_ports_csv(r->channel, nameserver);
	if (ret != ARES_SUCCESS) {
		LOGE_F("c-ares: failed to set nameserver `%s': (%d) %s",
		       nameserver, ret, ares_strerror(ret));
		/* Continue with default nameservers */
		return true;
	}
	return true;
}
#endif /* WITH_CARES */

struct resolver *
resolver_new(struct ev_loop *restrict loop, const struct config *restrict conf)
{
	struct resolver *restrict r = malloc(sizeof(struct resolver));
	if (r == NULL) {
		return NULL;
	}

	*r = (struct resolver){
		.loop = loop,
	};

#if WITH_CARES
	/* Initialize the head socket watcher (used as list head) */
	{
		ev_io *restrict w_socket = &r->sockets.watcher;
		ev_io_init(w_socket, socket_cb, -1, EV_NONE);
		w_socket->data = r;
	}

	r->async_enabled = resolver_async_init(r, conf);
#else
	UNUSED(conf);
#endif
	return r;
}

const struct resolver_stats *resolver_stats(const struct resolver *restrict r)
{
	return &r->stats;
}

void resolve_start(struct resolver *restrict r, struct resolve_query *restrict q)
{
	LOGD_F("resolve `%s:%s': start pf=%d", q->name, q->service, q->family);
	r->stats.num_query++;

#if WITH_CARES
	if (r->async_enabled) {
		const struct ares_addrinfo_hints hints = {
			.ai_family = q->family,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
			.ai_flags = ARES_AI_ADDRCONFIG,
		};
		ares_getaddrinfo(
			r->channel, q->name, q->service, &hints, addrinfo_cb,
			q);

		ev_timer *restrict w_timeout = &r->w_timeout;
		if (!ev_is_active(w_timeout)) {
			sched_update(r->loop, w_timeout);
		}
		return;
	}
#endif /* WITH_CARES */

	/* Fall back to synchronous resolution */
	q->ok = sa_resolve(
		&q->addr, q->name, q->service, SA_RESOLVE_TCP, q->family);
	ev_feed_event(r->loop, &q->w_finish, EV_CUSTOM);
}

struct resolve_query *resolve_do(
	struct resolver *restrict r, const struct resolve_cb cb,
	const char *restrict name, const char *restrict service,
	const int family)
{
	const size_t namelen = (name != NULL) ? strlen(name) + 1 : 0;
	const size_t servlen = (service != NULL) ? strlen(service) + 1 : 0;

	struct resolve_query *restrict q =
		malloc(sizeof(struct resolve_query) + namelen + servlen);
	if (q == NULL) {
		LOGOOM();
		return NULL;
	}

	q->resolver = r;
	q->done_cb = cb;
	ev_init(&q->w_finish, finish_cb);
	q->w_finish.data = q;
	q->ok = false;

	if (name != NULL) {
		q->name = memcpy(q->buf, name, namelen);
	} else {
		q->name = NULL;
	}
	if (service != NULL) {
		q->service = memcpy(q->buf + namelen, service, servlen);
	} else {
		q->service = NULL;
	}
	q->family = family;

	resolve_start(r, q);
	return q;
}

void resolve_cancel(struct resolve_query *restrict q)
{
	if (q == NULL) {
		return;
	}
	LOGD_F("resolve `%s:%s': cancel", q->name, q->service);

	/* Clear the callback to indicate cancellation */
	q->done_cb = (struct resolve_cb){
		.func = NULL,
		.data = NULL,
	};
}
