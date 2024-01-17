/* neosocksd (c) 2023-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "resolver.h"
#include "conf.h"
#include "sockutil.h"
#include "util.h"

#include "utils/debug.h"
#include "utils/minmax.h"
#include "utils/slog.h"

#include <ev.h>
#if WITH_CARES
#include <sys/select.h>
/* ^ for POSIX fd_set */
#include <ares.h>
#endif

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct io_node {
	struct ev_io watcher;
	struct io_node *next;
};

struct resolver {
	struct ev_loop *loop;
	struct resolver_stats stats;
	bool async_enabled;
#if WITH_CARES
	ares_channel channel;
	struct ev_timer w_timeout;
	size_t num_socket;
	struct io_node sockets; /* linked list with the 1st element inlined */
#endif
};

struct resolve_query {
	struct resolver *resolver;
	struct resolve_cb done_cb;
	struct ev_watcher w_start;
	bool ok : 1;
	union sockaddr_max addr;
	const char *name, *service;
	int family;
	char buf[];
};

static void
resolve_finish(struct resolve_query *restrict q, struct ev_loop *loop)
{
	LOGV_F("resolve: [%p] finished ok=%d", (void *)q, q->ok);
	if (q->done_cb.cb == NULL) { /* cancelled */
		free(q);
		return;
	}
	const handle_type h = handle_make(q);
	const struct resolve_cb done_cb = q->done_cb;
	if (!q->ok) {
		free(q);
		done_cb.cb(h, loop, done_cb.ctx, NULL);
		return;
	}
	const union sockaddr_max addr = q->addr;
	q->resolver->stats.num_success++;
	free(q);
	done_cb.cb(h, loop, done_cb.ctx, &addr.sa);
}

#define RESOLVE_RETURN(q, loop)                                                \
	do {                                                                   \
		resolve_finish((q), (loop));                                   \
		return;                                                        \
	} while (0)

#if WITH_CARES
static void socket_cb(struct ev_loop *loop, struct ev_io *watcher, int revents)
{
	UNUSED(loop);
	CHECK_EV_ERROR(revents, EV_READ | EV_WRITE);
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
		ev_timer_stop(loop, watcher);
		return;
	}
	const double next = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
	LOGD_F("timeout: next check after %.3fs", next);
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
timeout_cb(struct ev_loop *loop, struct ev_timer *watcher, int revents)
{
	CHECK_EV_ERROR(revents, EV_TIMER);
	struct resolver *restrict r = watcher->data;
	ares_process_fd(r->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

	/* purge inactive watchers */
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

	/* find an active watcher on same fd or an inactive watcher to reuse */
	struct io_node *node = NULL;
	for (struct io_node *it = &r->sockets; it != NULL; it = it->next) {
		if (it->watcher.fd == fd) {
			node = it;
			break;
		}
		if (!ev_is_active(it)) {
			node = it;
			continue;
		}
	}
	if (events == EV_NONE) {
		if (node == NULL || !ev_is_active(&node->watcher)) {
			/* currently not watching, nothing to do */
			return;
		}
		LOGV_F("io: stop fd=%d num_socket=%zu", fd, --r->num_socket);
		ev_io_stop(r->loop, &node->watcher);
		return;
	}
	if (node == NULL) {
		/* if no suitable node exists, create one */
		node = malloc(sizeof(struct io_node));
		if (node == NULL) {
			LOGOOM();
			return;
		}
		struct ev_io *restrict w_socket = &node->watcher;
		ev_io_init(w_socket, socket_cb, fd, events);
		w_socket->data = r;
		/* insert */
		node->next = r->sockets.next;
		r->sockets.next = node;
	} else {
		/* or modify the existing watcher */
		ev_io_stop(r->loop, &node->watcher);
		ev_io_set(&node->watcher, fd, events);
	}

	/* start the watcher */
	LOGV_F("io: fd=%d events=0x%x num_socket=%zu", fd, events,
	       ++r->num_socket);
	ev_io_start(r->loop, &node->watcher);
}

static bool
find_addrinfo(union sockaddr_max *addr, const struct ares_addrinfo_node *it)
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
	RESOLVE_RETURN(q, r->loop);
}
#endif /* WITH_CARES */

void resolver_init(void)
{
#if WITH_CARES
	LOGD_F("c-ares: %s", ares_version(NULL));
#if CARES_HAVE_ARES_LIBRARY_INIT
	const int ret = ares_library_init(ARES_LIB_INIT_ALL);
	CHECKMSGF(ret == ARES_SUCCESS, "c-ares: %s", ares_strerror(ret));
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
	if (r->async_enabled) {
#if WITH_CARES
		ares_destroy(r->channel);
		(void)purge_watchers(r);
		assert(!ev_is_active(&r->sockets.watcher) &&
		       r->sockets.next == NULL);
#endif
	}
	free(r);
}

bool resolver_async_init(struct resolver *restrict r, const struct config *conf)
{
#if WITH_CARES
	int ret;
	struct ares_options options;
	options.sock_state_cb = sock_state_cb;
	options.sock_state_cb_data = r;
	ret = ares_init_options(&r->channel, &options, ARES_OPT_SOCK_STATE_CB);
	if (ret != ARES_SUCCESS) {
		LOGE_F("ares: %s", ares_strerror(ret));
		return false;
	}
	ev_timer_init(&r->w_timeout, timeout_cb, 0.0, 0.0);
	ev_set_priority(&r->w_timeout, EV_MINPRI);
	r->w_timeout.data = r;

	const char *nameserver = conf->nameserver;
	if (nameserver == NULL) {
		return true;
	}
	ret = ares_set_servers_ports_csv(r->channel, nameserver);
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
#endif /* WITH_CARES */
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
	{
		struct ev_io *restrict w_socket = &r->sockets.watcher;
		ev_io_init(w_socket, socket_cb, -1, EV_NONE);
		w_socket->data = r;
	}
#endif
	r->async_enabled = resolver_async_init(r, conf);
	return r;
}

const struct resolver_stats *resolver_stats(struct resolver *r)
{
	return &r->stats;
}

static void
start_cb(struct ev_loop *loop, struct ev_watcher *watcher, int revents)
{
	CHECK_EV_ERROR(revents, EV_CUSTOM);
	struct resolve_query *restrict q = watcher->data;
	LOGV_F("resolve: [%p] start name=\"%s\" service=%s pf=%d", (void *)q,
	       q->name, q->service, q->family);
	struct resolver *restrict r = q->resolver;
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
		struct ev_timer *restrict w_timeout = &r->w_timeout;
		if (!ev_is_active(w_timeout)) {
			sched_update(r->loop, w_timeout);
		}
		return;
	}
#endif /* WITH_CARES */
	q->ok = resolve_addr(&q->addr, q->name, q->service, q->family);
	RESOLVE_RETURN(q, loop);
}

handle_type resolve_do(
	struct resolver *r, struct resolve_cb cb, const char *name,
	const char *service, const int family)
{
	const size_t namelen = name != NULL ? strlen(name) + 1 : 0;
	const size_t servlen = service != NULL ? strlen(service) + 1 : 0;
	struct resolve_query *restrict q =
		malloc(sizeof(struct resolve_query) + namelen + servlen);
	if (q == NULL) {
		LOGOOM();
		return INVALID_HANDLE;
	}
	q->resolver = r;
	q->done_cb = cb;
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
	ev_init(&q->w_start, start_cb);
	q->w_start.data = q;
	ev_feed_event(r->loop, &q->w_start, EV_CUSTOM);
	return handle_make(q);
}

void resolve_cancel(handle_type h)
{
	struct resolve_query *q = handle_toptr(h);
	LOGV_F("resolve: [%p] cancel", (void *)q);
	q->done_cb = (struct resolve_cb){
		.cb = NULL,
		.ctx = NULL,
	};
}
