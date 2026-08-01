/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "resolver.h"

#include "conf.h"
#include "util.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#if WITH_CARES
/* under strict POSIX feature macros, ares.h needs fd_set from sys/select.h */
#include <sys/select.h>

#include <ares.h>
#endif
#include <sys/socket.h>
#if WITH_CARES
#include <sys/time.h>
#endif

struct io_node {
	ev_io watcher;
	struct io_node *next;
};

struct resolver {
	struct ev_loop *loop;
	struct resolver_stats stats;
	/* queries whose deferred finish event has been fed to the loop but not
	 * yet dispatched; drained by resolver_free() so a teardown before the
	 * event fires neither leaks the query nor invokes its callback */
	struct resolve_query *pending;
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
	struct resolve_query *next;
	struct resolve_cb done_cb;
	ev_watcher w_finish;
	bool ok : 1;
	union sockaddr_max addr;
	const char *name, *service;
	int family;
	char buf[];
};

/* Track a completed query on the resolver's pending list and schedule its
 * deferred completion callback. It stays on the list until finish_cb
 * dispatches it, letting resolver_free() reclaim any still-undispatched query
 * at teardown. */
static void finish_defer(struct resolve_query *restrict q)
{
	struct resolver *restrict r = q->resolver;
	q->next = r->pending;
	r->pending = q;
	ev_feed_event(r->loop, &q->w_finish, EV_CUSTOM);
}

/* Remove a query from the resolver's pending list. */
static void finish_unlink(struct resolve_query *restrict q)
{
	struct resolve_query **pp = &q->resolver->pending;
	for (struct resolve_query *it = *pp; it != NULL;
	     pp = &it->next, it = it->next) {
		if (it == q) {
			*pp = it->next;
			return;
		}
	}
}

static void
finish_cb(struct ev_loop *restrict loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct resolve_query *restrict q = watcher->data;
	finish_unlink(q);
	const char *const name = q->name != NULL ? q->name : "";
	const char *const service = q->service != NULL ? q->service : "";
	if (q->ok) {
		char addr[64];
		sa_format(addr, sizeof(addr), &q->addr.sa);
		LOGD_F("resolve `%s:%s': %s", name, service, addr);
	} else {
		LOGD_F("resolve `%s:%s': failed", name, service);
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
	(void)loop;
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

	const size_t num_purged = purge_watchers(r);
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

	bool was_active = false;
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
		was_active = ev_is_active(&node->watcher);
		ev_io_stop(r->loop, &node->watcher);
		ev_io_set(&node->watcher, fd, events);
	}

	/* count only an inactive->active transition; a pure interest change on
	 * an already-active watcher must not re-increment the counter */
	if (!was_active) {
		r->num_socket++;
	}
	LOGV_F("io: [fd:%d] events=0x%x num_socket=%zu", fd, events,
	       r->num_socket);
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
				LOGE_F("resolve: invalid ai_addrlen %zu (af=%d)",
				       (size_t)it->ai_addrlen, it->ai_family);
				continue;
			}
			addr->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			if (it->ai_addrlen != sizeof(struct sockaddr_in6)) {
				LOGE_F("resolve: invalid ai_addrlen %zu (af=%d)",
				       (size_t)it->ai_addrlen, it->ai_family);
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
	(void)timeouts;
	struct resolve_query *restrict q = arg;

	switch (status) {
	case ARES_SUCCESS:
		if (info != NULL) {
			q->ok = find_addrinfo(&q->addr, info->nodes);
			ares_freeaddrinfo(info);
		}
		break;
	case ARES_EDESTRUCTION:
		/* resolver_free() cancels pending queries without invoking
		 * callbacks (see resolver.h); free the query directly since
		 * finish_cb -- which normally does so -- is never reached
		 * from this path. */
		free(q);
		return;
	default:
		LOGW_F("c-ares: resolve error: (%d) %s", status,
		       ares_strerror(status));
		break;
	}

	/* Trigger query completion callback (deferred, matching the synchronous
	 * path, so callers can reliably set their query pointer before it fires) */
	finish_defer(q);
}
#endif /* WITH_CARES */

void resolver_init(void)
{
#if WITH_CARES
	LOGI_F("c-ares %s", ares_version(NULL));
#if CARES_HAVE_ARES_LIBRARY_INIT
	const int ret = ares_library_init(ARES_LIB_INIT_ALL);
	CHECKMSGF(
		ret == ARES_SUCCESS, "c-ares: (%d) %s", ret,
		ares_strerror(ret));
#endif
#endif /* WITH_CARES */
}

void resolver_cleanup(void)
{
#if WITH_CARES && CARES_HAVE_ARES_LIBRARY_CLEANUP
	ares_library_cleanup();
#endif
}

#if WITH_CARES
/* (Re)configure the c-ares channel's upstream servers from a CSV nameserver
 * string; a NULL string leaves the current (system-default) servers in place. */
static void
apply_nameserver(struct resolver *restrict r, const char *restrict nameserver)
{
	if (nameserver == NULL) {
		return;
	}
	const int ret = ares_set_servers_ports_csv(r->channel, nameserver);
	if (ret != ARES_SUCCESS) {
		LOGE_F("c-ares: failed to set nameserver `%s': (%d) %s",
		       nameserver, ret, ares_strerror(ret));
		/* Continue with default nameservers */
	}
}

static bool
async_init(struct resolver *restrict r, const struct config *restrict conf)
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

	apply_nameserver(r, conf->nameserver);
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

	*r = (struct resolver){ .loop = loop };

#if WITH_CARES
	/* Initialize the head socket watcher (used as list head) */
	{
		ev_io *restrict w_socket = &r->sockets.watcher;
		ev_io_init(w_socket, socket_cb, -1, EV_NONE);
		w_socket->data = r;
	}

	r->async_enabled = async_init(r, conf);
#else /* WITH_CARES */
	(void)conf;
#endif /* WITH_CARES */
	return r;
}

void resolver_setnameserver(
	struct resolver *restrict r, const struct config *restrict conf)
{
#if WITH_CARES
	if (!r->async_enabled) {
		return;
	}
	apply_nameserver(r, conf->nameserver);
#else /* WITH_CARES */
	(void)r;
	(void)conf;
#endif /* WITH_CARES */
}

const struct resolver_stats *resolver_stats(const struct resolver *restrict r)
{
	return &r->stats;
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
#endif /* WITH_CARES */
	/* Reclaim queries that completed but whose deferred finish event has
	 * not been dispatched yet: clear the pending event and free them
	 * without invoking their callbacks, per this function's contract. */
	for (struct resolve_query *q = r->pending; q != NULL;) {
		struct resolve_query *const next = q->next;
		ev_clear_pending(r->loop, &q->w_finish);
		free(q);
		q = next;
	}
	free(r);
}

static void
resolve_start(struct resolver *restrict r, struct resolve_query *restrict q)
{
	LOGD_F("resolve `%s:%s': start pf=%d", q->name != NULL ? q->name : "",
	       q->service != NULL ? q->service : "", q->family);
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
	finish_defer(q);
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
	LOGD_F("resolve `%s:%s': cancel", q->name != NULL ? q->name : "",
	       q->service != NULL ? q->service : "");

	/* Clear the callback to indicate cancellation */
	q->done_cb = (struct resolve_cb){
		.func = NULL,
		.data = NULL,
	};
}
