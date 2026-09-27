/* neosocksd (c) 2023-2026 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#include "resolver.h"

#include "conf.h"
#include "util.h"

#include "os/socket.h"
#include "utils/debug.h"
#include "utils/slog.h"

#include <ev.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
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
	size_t num_addr;
	union sockaddr_max addr[RESOLVE_MAX_ADDR];
	const char *name, *service;
	int family;
	char buf[];
};

/* Count a completed query's outcome, track it on the resolver's pending list
 * and schedule its deferred completion callback. It stays on the list until
 * finish_cb dispatches it, letting resolver_free() reclaim any
 * still-undispatched query at teardown. */
static void finish_defer(struct resolve_query *restrict q)
{
	struct resolver *restrict r = q->resolver;
	/* the counters describe lookups, not callback deliveries: a lookup that
	 * succeeded counts even if its caller has cancelled it since */
	if (q->num_addr > 0) {
		r->stats.num_success++;
	}
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

#define RESOLVE_NAME(q) ((q)->name != NULL ? (q)->name : "")
#define RESOLVE_SERVICE(q) ((q)->service != NULL ? (q)->service : "")

/* Log about a query, with its name in the log's text extra rather than in the
 * line itself: the dialer resolves the name its peer wrote, and a SOCKS5
 * DOMAINNAME is an arbitrary byte string (RFC 1928, 5), so a newline in it
 * would end the line there and let the peer write whatever follows. The
 * service is the caller's own service name or port string and stays in the
 * line. */
#define RESOLVE_LOG_F(level, q, format, ...)                                   \
	LOG_TXT_F(                                                             \
		level, RESOLVE_NAME(q), strlen(RESOLVE_NAME(q)), 0,            \
		"resolve `:%s': " format, RESOLVE_SERVICE(q), __VA_ARGS__)
#define RESOLVE_LOG(level, q, message) RESOLVE_LOG_F(level, q, "%s", message)

static void
finish_cb(struct ev_loop *restrict loop, ev_watcher *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_CUSTOM);
	struct resolve_query *restrict q = watcher->data;
	finish_unlink(q);
	if (q->num_addr == 0) {
		RESOLVE_LOG(DEBUG, q, "failed");
	} else {
		char addr[64];
		sa_format(addr, sizeof(addr), &q->addr[0].sa);
		if (q->num_addr > 1) {
			RESOLVE_LOG_F(
				DEBUG, q, "%s and %zu more", addr,
				q->num_addr - 1);
		} else {
			RESOLVE_LOG_F(DEBUG, q, "%s", addr);
		}
	}

	/* Check if query was cancelled */
	if (q->done_cb.func == NULL) {
		free(q);
		return;
	}

	if (q->num_addr == 0) {
		q->done_cb.func(q, loop, q->done_cb.data, NULL, 0);
		free(q);
		return;
	}

	q->done_cb.func(q, loop, q->done_cb.data, q->addr, q->num_addr);
	free(q);
}

/* Working room for one answer before it is cut down to what the query carries:
 * up to RESOLVE_MAX_ADDR addresses of each family, the most either one can
 * contribute to the final list once the two are interleaved. */
#define RESOLVE_WORK_ADDR ((size_t)RESOLVE_MAX_ADDR * 2)

/* One answer being collected. The resolver's own ordering (RFC 6724) groups the
 * families, so the answer is walked until both are full rather than cut at a
 * total: a name with many records of the leading family must still contribute
 * the other family's to the list interleave_family() alternates. */
struct addr_work {
	union sockaddr_max addr[RESOLVE_WORK_ADDR];
	size_t num;
	size_t num_inet, num_inet6;
};

static bool addr_work_full(const struct addr_work *restrict w)
{
	return w->num_inet >= RESOLVE_MAX_ADDR &&
	       w->num_inet6 >= RESOLVE_MAX_ADDR;
}

/* How many addresses a query answers with. A pinned family answers with one,
 * exactly as it did before there was any fallback to a second address: `-4' /
 * `-6' is the operator saying which family to use, not which to start with.
 * Only an unpinned query carries the whole list. */
static size_t query_maxaddr(const struct resolve_query *restrict q)
{
	return q->family == AF_UNSPEC ? RESOLVE_MAX_ADDR : 1;
}

/* Append one address of an answer, dropping a family that cannot be dialed, a
 * node whose length does not match the family it claims, and an address of a
 * family that already has all the room it can use. */
static void addr_append(
	struct addr_work *restrict w, const int family,
	const struct sockaddr *restrict sa, const size_t salen)
{
	switch (family) {
	case AF_INET:
		if (salen != sizeof(struct sockaddr_in)) {
			LOGE_F("resolve: invalid addrlen %zu (af=%d)", salen,
			       family);
			return;
		}
		if (w->num_inet >= RESOLVE_MAX_ADDR) {
			return;
		}
		w->addr[w->num].in = *(const struct sockaddr_in *)sa;
		w->num_inet++;
		break;
	case AF_INET6:
		if (salen != sizeof(struct sockaddr_in6)) {
			LOGE_F("resolve: invalid addrlen %zu (af=%d)", salen,
			       family);
			return;
		}
		if (w->num_inet6 >= RESOLVE_MAX_ADDR) {
			return;
		}
		w->addr[w->num].in6 = *(const struct sockaddr_in6 *)sa;
		w->num_inet6++;
		break;
	default:
		return;
	}
	w->num++;
}

/* Reorder one answer as RFC 8305 4 prescribes: each family keeps its own
 * order, but the two alternate, so a caller walking the list never spends two
 * hops in a row on a family this host may have no working route for. The
 * family that led the answer still leads the list -- that is where the
 * resolver's own ordering has already put the address most likely to work. */
static void
interleave_family(union sockaddr_max *restrict addr, const size_t num)
{
	ASSERT(num <= RESOLVE_WORK_ADDR);
	if (num < 3) {
		/* fewer than three addresses already alternate */
		return;
	}
	const int preferred = addr[0].sa.sa_family;
	union sockaddr_max out[RESOLVE_WORK_ADDR];
	/* where each family's unconsumed addresses start */
	size_t next[2] = { 0, 0 };
	bool want_preferred = true;
	size_t n = 0;
	while (n < num) {
		const size_t which = want_preferred ? 0 : 1;
		size_t i = next[which];
		while (i < num) {
			const bool is_preferred =
				(addr[i].sa.sa_family == preferred);
			if (is_preferred == want_preferred) {
				break;
			}
			i++;
		}
		next[which] = i;
		if (i < num) {
			out[n++] = addr[i];
			next[which] = i + 1;
		}
		/* an exhausted family leaves its turn to the other, which then
		 * supplies every remaining address */
		want_preferred = !want_preferred;
	}
	memcpy(addr, out, num * sizeof(*addr));
}

/* Interleave the families of a collected answer, then keep as many of the
 * addresses as the query carries. */
static size_t addr_finish(
	union sockaddr_max *restrict addr, const size_t maxlen,
	struct addr_work *restrict w)
{
	interleave_family(w->addr, w->num);
	const size_t n = w->num < maxlen ? w->num : maxlen;
	if (n > 0) {
		memcpy(addr, w->addr, n * sizeof(*addr));
	}
	return n;
}

#if WITH_CARES
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
	/* c-ares clamps an already-expired query's remaining time to {0,0}, so
	 * `next` can be 0.0. ev_timer_again with repeat == 0 stops the timer
	 * (and no-ops an inactive one), which would leave an already-due timeout
	 * unprocessed until an unrelated event. Clamp to a small positive delay
	 * so it fires on the next loop iteration instead. */
	watcher->repeat = next > 0.0 ? next : 1e-3;
	ev_timer_again(loop, watcher);
}

static void
socket_cb(struct ev_loop *restrict loop, ev_io *watcher, const int revents)
{
	CHECK_REVENTS(revents, EV_READ | EV_WRITE);
	struct resolver *restrict r = watcher->data;
	const int fd = watcher->fd;

	const ares_socket_t readable =
		(revents & EV_READ) ? fd : ARES_SOCKET_BAD;
	const ares_socket_t writable =
		(revents & EV_WRITE) ? fd : ARES_SOCKET_BAD;

	LOGV_F("io: [fd:%d] revents=0x%x", fd, revents);
	ares_process_fd(r->channel, readable, writable);
	/* re-evaluate the timeout after processing: a socket event may have
	 * advanced or completed queries, changing the next deadline */
	sched_update(loop, &r->w_timeout);
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
		/* decrement in its own statement: LOGV_F does not evaluate its
		 * arguments below VERBOSE level, so a decrement inside the macro
		 * argument would be skipped and the counter would drift */
		r->num_socket--;
		LOGV_F("io: stop [fd:%d] num_socket=%zu", fd, r->num_socket);
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

static size_t collect_addrinfo(
	union sockaddr_max *restrict addr, const size_t maxlen,
	const struct ares_addrinfo_node *restrict node)
{
	struct addr_work work = { .num = 0 };
	for (const struct ares_addrinfo_node *restrict it = node;
	     it != NULL && !addr_work_full(&work); it = it->ai_next) {
		addr_append(
			&work, it->ai_family, it->ai_addr,
			(size_t)it->ai_addrlen);
	}
	return addr_finish(addr, maxlen, &work);
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
			q->num_addr = collect_addrinfo(
				q->addr, query_maxaddr(q), info->nodes);
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

/* Ceiling on the cached lifetime of a reply, matching the c-ares default; a
 * record's own TTL still applies below it. */
#define RESOLVER_QCACHE_MAX_TTL 3600

static bool
async_init(struct resolver *restrict r, const struct config *restrict conf)
{
	int ret;
	struct ares_options options;
	int optmask = ARES_OPT_SOCK_STATE_CB;

	options.sock_state_cb = sock_state_cb;
	options.sock_state_cb_data = r;
#ifdef ARES_OPT_QUERY_CACHE
	/* every dial to a hostname queries the resolver, so ask for the cache
	 * rather than inheriting whatever this c-ares defaults to */
	options.qcache_max_ttl = RESOLVER_QCACHE_MAX_TTL;
	optmask |= ARES_OPT_QUERY_CACHE;
#endif
	ret = ares_init_options(&r->channel, &options, optmask);
	if (ret != ARES_SUCCESS) {
		LOGE_F("c-ares: (%d) %s", ret, ares_strerror(ret));
		return false;
	}
#ifdef ARES_OPT_QUERY_CACHE
	LOGD_F("c-ares: query cache max ttl %d", RESOLVER_QCACHE_MAX_TTL);
#else
	LOGW("c-ares: no query cache in this version, every dial re-queries");
#endif

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
		/* the async path arms w_timeout; stop it before the resolver
		 * storage is freed, or a later ev_run would fire timeout_cb on
		 * freed memory (ares_destroy stops the I/O watchers via
		 * sock_state_cb, but nothing stops the timer) */
		ev_timer_stop(r->loop, &r->w_timeout);
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

/* getaddrinfo() consults the resolver only for a real host name: a numeric
 * address is parsed locally. AI_ADDRCONFIG guards against a lookup answering
 * with a family this host has no address for, which is all it is good for --
 * anywhere else it only does harm, glibc not counting a loopback address as
 * configured, so a host with only `lo' up would reject 127.0.0.1 and ::1 too. */
static bool needs_resolver(const char *restrict name)
{
	if (name == NULL) {
		return false;
	}
	struct in_addr in;
	struct in6_addr in6;
	return inet_pton(AF_INET, name, &in) != 1 &&
	       inet_pton(AF_INET6, name, &in6) != 1;
}

/* Resolve synchronously, blocking the event loop: the fallback for a build
 * without c-ares. sa_resolve() answers with a single address, which is what a
 * caller needs the whole list to avoid, so getaddrinfo() is driven here
 * directly. The name is peer-supplied, so it stays out of the log lines the
 * same way RESOLVE_LOG_F keeps it out of the others. */
static size_t resolve_sync(
	union sockaddr_max *restrict addr, const size_t maxlen,
	const char *restrict name, const char *restrict service,
	const int family)
{
	const struct addrinfo hints = {
		.ai_family = family,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = needs_resolver(name) ? AI_ADDRCONFIG : 0,
	};
	struct addrinfo *result = NULL;
	const int err = getaddrinfo(name, service, &hints, &result);
	if (err != 0) {
		if (err == EAI_SYSTEM) {
			/* EAI_SYSTEM defers to errno; gai_strerror would only
			 * yield a generic "System error", so report the real OS
			 * error, captured before any call can clobber errno */
			const int syserr = errno;
			LOGE_F("getaddrinfo: (%d) %s", syserr,
			       strerror(syserr));
		} else {
			LOGE_F("getaddrinfo: (%d) %s", err, gai_strerror(err));
		}
		return 0;
	}
	struct addr_work work = { .num = 0 };
	for (const struct addrinfo *restrict it = result;
	     it != NULL && !addr_work_full(&work); it = it->ai_next) {
		addr_append(
			&work, it->ai_family, it->ai_addr,
			(size_t)it->ai_addrlen);
	}
	freeaddrinfo(result);
	return addr_finish(addr, maxlen, &work);
}

static void
resolve_start(struct resolver *restrict r, struct resolve_query *restrict q)
{
	RESOLVE_LOG_F(DEBUG, q, "start pf=%d", q->family);
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

		/* Re-evaluate the timeout deadline after every ares_getaddrinfo
		 * (standard c-ares event-loop integration): a newer query may
		 * have an earlier deadline than the one the timer is armed for,
		 * so reschedule unconditionally rather than only when inactive. */
		sched_update(r->loop, &r->w_timeout);
		return;
	}
#endif /* WITH_CARES */

	/* Fall back to synchronous resolution */
	q->num_addr = resolve_sync(
		q->addr, query_maxaddr(q), q->name, q->service, q->family);
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
	q->num_addr = 0;

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
	RESOLVE_LOG(DEBUG, q, "cancel");

	/* Clear the callback to indicate cancellation */
	q->done_cb = (struct resolve_cb){
		.func = NULL,
		.data = NULL,
	};
}
