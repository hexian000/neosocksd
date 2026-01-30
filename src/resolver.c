/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

/**
 * @file resolver.c
 * @brief DNS resolver implementation with optional c-ares support
 *
 * This implementation provides both synchronous and asynchronous DNS resolution.
 * When compiled with c-ares support (WITH_CARES), it uses the c-ares library
 * for non-blocking DNS queries integrated with libev. Without c-ares, it falls
 * back to synchronous getaddrinfo() calls.
 *
 * Key features:
 * - Asynchronous DNS resolution with c-ares
 * - Fallback to synchronous resolution
 * - Socket event management for c-ares integration
 * - Query cancellation support
 * - Statistics tracking
 */

#include "resolver.h"

#include "conf.h"
#include "sockutil.h"
#include "util.h"

#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>
#if WITH_CARES
#include <ares.h>
#endif

#include <netinet/in.h>
#include <sys/socket.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief I/O watcher node for c-ares socket management
 *
 * Represents a single socket watcher in a singly-linked list. Used to manage
 * multiple sockets that c-ares may create for DNS queries. Inactive watchers
 * are kept in the list for reuse and periodically purged by purge_watchers().
 *
 * The head node (resolver.sockets) is embedded in the resolver struct and
 * serves as both a list sentinel and a reusable watcher node.
 */
struct io_node {
	ev_io watcher;
	struct io_node *next;
};

/**
 * @brief DNS resolver instance
 *
 * Contains the resolver state, statistics, and c-ares integration data.
 * The resolver maintains a linked list of socket watchers for c-ares I/O.
 */
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

/**
 * @brief DNS query context
 *
 * Represents a single DNS resolution request with its completion callback
 * and result storage. Uses a flexible array member to store the hostname
 * and service strings contiguously with the structure.
 */
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

/**
 * @brief Query completion callback handler
 *
 * Called when a DNS query finishes (either successfully or with failure).
 * Invokes the user callback and cleans up the query structure.
 *
 * @param loop Event loop
 * @param watcher The completion watcher
 * @param revents Event flags (should be EV_CUSTOM)
 */
static void
finish_cb(struct ev_loop *loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct resolve_query *restrict q = watcher->data;
	if (q->ok) {
		char addr[64];
		format_sa(addr, sizeof(addr), &q->addr.sa);
		LOGD_F("resolve `%s:%s': %s", q->name, q->service, addr);
	} else {
		LOGD_F("resolve `%s:%s': failed", q->name, q->service);
	}

	/* Check if query was cancelled */
	if (q->done_cb.func == NULL) {
		free(q);
		return;
	}

	/* Handle resolution failure */
	if (!q->ok) {
		q->done_cb.func(q, loop, q->done_cb.data, NULL);
		free(q);
		return;
	}

	/* Handle successful resolution */
	q->resolver->stats.num_success++;
	q->done_cb.func(q, loop, q->done_cb.data, &q->addr.sa);
	free(q);
}

#if WITH_CARES
/**
 * @brief Socket I/O event callback for c-ares
 *
 * Called when a c-ares socket becomes readable or writable. Notifies
 * c-ares to process the socket events.
 *
 * @param loop Event loop (unused)
 * @param watcher The I/O watcher that triggered
 * @param revents Event flags (EV_READ and/or EV_WRITE)
 */
static void socket_cb(struct ev_loop *loop, ev_io *watcher, const int revents)
{
	UNUSED(loop);
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct resolver *restrict r = watcher->data;
	const int fd = watcher->fd;

	/* Convert libev events to c-ares socket states */
	const ares_socket_t readable =
		(revents & EV_READ) ? fd : ARES_SOCKET_BAD;
	const ares_socket_t writable =
		(revents & EV_WRITE) ? fd : ARES_SOCKET_BAD;

	LOGV_F("io: [fd:%d] revents=0x%x", fd, revents);
	ares_process_fd(r->channel, readable, writable);
}

/**
 * @brief Update the timeout timer for c-ares
 *
 * Queries c-ares for the next timeout and schedules the timer accordingly.
 * If no timeout is needed, stops the timer.
 *
 * @param loop Event loop
 * @param watcher The timeout timer watcher
 */
static void sched_update(struct ev_loop *loop, ev_timer *restrict watcher)
{
	struct resolver *restrict r = watcher->data;
	struct timeval tv;

	/* Check if c-ares needs a timeout */
	if (ares_timeout(r->channel, NULL, &tv) == NULL) {
		ev_timer_stop(loop, watcher);
		return;
	}

	/* Convert timeval to seconds and schedule timer */
	const double next = (double)tv.tv_sec + (double)tv.tv_usec * 1e-6;
	LOGV_F("timeout: next check after %.3fs", next);
	watcher->repeat = next;
	ev_timer_again(loop, watcher);
}

/**
 * @brief Remove inactive socket watchers from the linked list
 *
 * Iterates through the socket watcher list and frees any inactive watchers
 * to prevent memory leaks. This is called periodically during timeout processing.
 *
 * @param r Resolver instance
 * @return Number of watchers purged
 */
static size_t purge_watchers(struct resolver *restrict r)
{
	size_t num_purged = 0;
	struct io_node *prev = &r->sockets;

	/* Walk the linked list and remove inactive watchers */
	for (struct io_node *it = prev->next; it != NULL; it = prev->next) {
		if (ev_is_active(&it->watcher)) {
			/* Keep active watchers */
			prev = it;
			continue;
		}

		/* Remove and free inactive watchers */
		prev->next = it->next;
		free(it);
		num_purged++;
	}
	return num_purged;
}

/**
 * @brief Timeout callback for c-ares
 *
 * Called when the c-ares timeout expires. Processes any pending timeouts,
 * purges inactive watchers, and reschedules the next timeout.
 *
 * @param loop Event loop
 * @param watcher The timeout timer watcher
 * @param revents Event flags (should be EV_TIMER)
 */
static void
timeout_cb(struct ev_loop *loop, ev_timer *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_TIMER);
	struct resolver *restrict r = watcher->data;

	/* Process c-ares timeouts (no specific sockets) */
	ares_process_fd(r->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

	/* Clean up inactive socket watchers to prevent memory leaks */
	size_t num_purged = purge_watchers(r);
	if (num_purged > 0) {
		LOGD_F("resolve: %zu inactive watchers purged", num_purged);
	}

	/* Schedule the next timeout check */
	sched_update(loop, watcher);
}

/**
 * @brief Socket state change callback for c-ares
 *
 * Called by c-ares when it wants to monitor or stop monitoring a socket.
 * This function manages the libev I/O watchers for c-ares sockets, creating
 * new watchers as needed and reusing inactive ones.
 *
 * @param data User data (resolver instance)
 * @param fd Socket file descriptor
 * @param readable Whether socket should be monitored for reading
 * @param writable Whether socket should be monitored for writing
 */
static void sock_state_cb(
	void *data, const ares_socket_t fd, const int readable,
	const int writable)
{
	struct resolver *restrict r = data;
	const int events = (readable ? EV_READ : 0) | (writable ? EV_WRITE : 0);

	/* Find existing watcher for this fd or an inactive watcher to reuse */
	struct io_node *restrict node = NULL;
	for (struct io_node *it = &r->sockets; it != NULL; it = it->next) {
		if (it->watcher.fd == fd) {
			/* Found exact match for this fd */
			node = it;
			break;
		}
		if (!ev_is_active(&it->watcher)) {
			/* Remember inactive watcher for potential reuse */
			node = it;
			continue;
		}
	}

	/* Handle request to stop monitoring */
	if (events == EV_NONE) {
		if (node == NULL || !ev_is_active(&node->watcher)) {
			/* Not currently watching, nothing to do */
			return;
		}
		LOGV_F("io: stop [fd:%d] num_socket=%zu", fd, --r->num_socket);
		ev_io_stop(r->loop, &node->watcher);
		return;
	}

	/* Need to start/modify monitoring */
	if (node == NULL) {
		/* No suitable node exists, create a new one */
		node = malloc(sizeof(struct io_node));
		if (node == NULL) {
			LOGOOM();
			return;
		}
		ev_io_init(&node->watcher, socket_cb, fd, events);
		node->watcher.data = r;
		/* Insert at head of list */
		node->next = r->sockets.next;
		r->sockets.next = node;
	} else {
		/* Modify existing watcher */
		ev_io_stop(r->loop, &node->watcher);
		ev_io_set(&node->watcher, fd, events);
	}

	/* Start the watcher */
	LOGV_F("io: [fd:%d] events=0x%x num_socket=%zu", fd, events,
	       ++r->num_socket);
	ev_io_start(r->loop, &node->watcher);
}

/**
 * @brief Extract the first usable address from c-ares address info
 *
 * Searches through the linked list of address info nodes returned by c-ares
 * and copies the first IPv4 or IPv6 address to the provided storage.
 *
 * @param addr Storage for the resolved address
 * @param node Head of the address info linked list
 * @return true if a valid address was found and copied, false otherwise
 */
static bool
find_addrinfo(union sockaddr_max *addr, const struct ares_addrinfo_node *node)
{
	for (const struct ares_addrinfo_node *restrict it = node; it != NULL;
	     it = it->ai_next) {
		switch (it->ai_family) {
		case AF_INET:
			/* Validate IPv4 address structure size */
			if (it->ai_addrlen != sizeof(struct sockaddr_in)) {
				LOGE_F("resolve: invalid ai_addrlen %ju (af=%d)",
				       (uintmax_t)it->ai_addrlen,
				       it->ai_family);
				continue;
			}
			addr->in = *(struct sockaddr_in *)it->ai_addr;
			break;
		case AF_INET6:
			/* Validate IPv6 address structure size */
			if (it->ai_addrlen != sizeof(struct sockaddr_in6)) {
				LOGE_F("resolve: invalid ai_addrlen %ju (af=%d)",
				       (uintmax_t)it->ai_addrlen,
				       it->ai_family);
				continue;
			}
			addr->in6 = *(struct sockaddr_in6 *)it->ai_addr;
			break;
		default:
			/* Skip unsupported address families */
			continue;
		}
		return true;
	}
	return false;
}

/**
 * @brief c-ares address info completion callback
 *
 * Called when c-ares completes a getaddrinfo request. Extracts the resolved
 * address and triggers the query completion.
 *
 * @param arg User data (resolve_query pointer)
 * @param status c-ares status code
 * @param timeouts Number of timeouts that occurred (unused)
 * @param info Address info result (freed after processing)
 */
static void addrinfo_cb(
	void *arg, const int status, const int timeouts,
	struct ares_addrinfo *info)
{
	UNUSED(timeouts);
	struct resolve_query *restrict q = arg;

	switch (status) {
	case ARES_SUCCESS:
		if (info != NULL) {
			/* Extract first usable address from result */
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

	/* Trigger query completion callback */
	ev_invoke(q->resolver->loop, &q->w_finish, EV_CUSTOM);
}
#endif /* WITH_CARES */

void resolver_init(void)
{
#if WITH_CARES
	LOGD_F("c-ares: %s", ares_version(NULL));
#if CARES_HAVE_ARES_LIBRARY_INIT
	/* Initialize c-ares library if available */
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
	/* Clean up c-ares library resources */
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
		/* Clean up c-ares channel and associated resources */
		ares_destroy(r->channel);
		(void)purge_watchers(r);

		/* Verify all watchers are properly cleaned up */
		ASSERT(!ev_is_active(&r->sockets.watcher));
		ASSERT(!ev_is_pending(&r->sockets.watcher));
		ASSERT(r->sockets.next == NULL);
	}
#endif
	free(r);
}

#if WITH_CARES
/**
 * @brief Initialize c-ares asynchronous resolver
 *
 * Sets up the c-ares channel with socket state callback and configures
 * the nameserver if specified in the configuration.
 *
 * @param r Resolver instance to initialize
 * @param conf Configuration containing nameserver settings
 * @return true on success, false on failure
 */
static bool resolver_async_init(
	struct resolver *restrict r, const struct config *restrict conf)
{
	int ret;
	struct ares_options options;

	/* Configure c-ares to use our socket state callback */
	options.sock_state_cb = sock_state_cb;
	options.sock_state_cb_data = r;
	ret = ares_init_options(&r->channel, &options, ARES_OPT_SOCK_STATE_CB);
	if (ret != ARES_SUCCESS) {
		LOGE_F("c-ares: (%d) %s", ret, ares_strerror(ret));
		return false;
	}

	/* Initialize timeout timer */
	ev_timer_init(&r->w_timeout, timeout_cb, 0.0, 0.0);
	r->w_timeout.data = r;

	/* Configure custom nameserver if specified */
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
resolver_new(struct ev_loop *loop, const struct config *restrict conf)
{
	struct resolver *restrict r = malloc(sizeof(struct resolver));
	if (r == NULL) {
		return NULL;
	}

	/* Initialize resolver structure */
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

	/* Attempt to initialize c-ares for async resolution */
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

/**
 * @brief Start DNS resolution for a query (internal)
 *
 * Initiates DNS resolution using either c-ares (if available and enabled)
 * or synchronous getaddrinfo(). Updates statistics.
 *
 * For c-ares: schedules async resolution and returns immediately.
 * For sync: blocks until resolution completes, then feeds completion event.
 *
 * @param r Resolver instance
 * @param q Query to start resolving (must be fully initialized)
 */
void resolve_start(struct resolver *restrict r, struct resolve_query *restrict q)
{
	LOGD_F("resolve `%s:%s': start pf=%d", q->name, q->service, q->family);
	r->stats.num_query++;

#if WITH_CARES
	if (r->async_enabled) {
		/* Use c-ares for asynchronous resolution */
		const struct ares_addrinfo_hints hints = {
			.ai_family = q->family,
			.ai_socktype = SOCK_STREAM,
			.ai_protocol = IPPROTO_TCP,
			.ai_flags = ARES_AI_ADDRCONFIG,
		};
		ares_getaddrinfo(
			r->channel, q->name, q->service, &hints, addrinfo_cb,
			q);

		/* Ensure timeout timer is active */
		ev_timer *restrict w_timeout = &r->w_timeout;
		if (!ev_is_active(w_timeout)) {
			sched_update(r->loop, w_timeout);
		}
		return;
	}
#endif /* WITH_CARES */

	/* Fall back to synchronous resolution */
	q->ok = resolve_addr(&q->addr, q->name, q->service, q->family);
	ev_feed_event(r->loop, &q->w_finish, EV_CUSTOM);
}

struct resolve_query *resolve_do(
	struct resolver *restrict r, const struct resolve_cb cb,
	const char *restrict name, const char *restrict service,
	const int family)
{
	/* Calculate space needed for name and service strings */
	const size_t namelen = (name != NULL) ? strlen(name) + 1 : 0;
	const size_t servlen = (service != NULL) ? strlen(service) + 1 : 0;

	/* Allocate query structure with variable-length buffer */
	struct resolve_query *restrict q =
		malloc(sizeof(struct resolve_query) + namelen + servlen);
	if (q == NULL) {
		LOGOOM();
		return NULL;
	}

	/* Initialize query structure */
	q->resolver = r;
	q->done_cb = cb;
	ev_init(&q->w_finish, finish_cb);
	q->w_finish.data = q;
	q->ok = false;

	/* Copy name and service strings to the variable buffer */
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

	/* Start the resolution process */
	resolve_start(r, q);
	return q;
}

void resolve_cancel(struct resolve_query *q)
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
